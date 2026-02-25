/* eslint-disable @typescript-eslint/no-explicit-any */

import {
  BaseStreamMessage,
  CollectionOfferEventPayload,
  EventType,
  ItemReceivedBidEventPayload,
  Network,
  OpenSeaStreamClient,
  TraitOfferEventPayload,
} from "@opensea/stream-js";
import {
  ItemCancelledEventPayload,
  ItemListedEventPayload,
  OrderValidationEventPayload,
} from "@opensea/stream-js/dist/types";
import * as Sdk from "@reservoir0x/sdk";
import { WebSocket } from "ws";
import { logger } from "@/common/logger";
import { doesLockExist, redis } from "@/common/redis";
import { now, toBuffer } from "@/common/utils";
import { config } from "@/config/index";
import { OpenseaOrderParams } from "@/orderbook/orders/seaport-v1.1";
import { generateHash } from "@/websockets/opensea/utils";
import { GenericOrderInfo } from "@/jobs/orderbook/utils";
import { handleEvent as handleItemListedEvent } from "@/websockets/opensea/handlers/item_listed";
import { handleEvent as handleItemReceivedBidEvent } from "@/websockets/opensea/handlers/item_received_bid";
import { handleEvent as handleCollectionOfferEvent } from "@/websockets/opensea/handlers/collection_offer";
import { handleEvent as handleItemCancelled } from "@/websockets/opensea/handlers/item_cancelled";
import { handleEvent as handleOrderRevalidate } from "@/websockets/opensea/handlers/order_revalidate";
import { handleEvent as handleTraitOfferEvent } from "@/websockets/opensea/handlers/trait_offer";

import { openseaBidsQueueJob } from "@/jobs/orderbook/opensea-bids-queue-job";
import { openseaListingsJob } from "@/jobs/orderbook/opensea-listings-job";
import { getOpenseaChainName } from "@/config/network";
import { Collections } from "@/models/collections";
import { metadataIndexFetchJob } from "@/jobs/metadata-index/metadata-fetch-job";
import { ridb } from "@/common/db";

let lastReceivedEventTimestamp: number;

if (config.doWebsocketWork && config.openSeaApiKey) {
  const network = config.isTestnet ? Network.TESTNET : Network.MAINNET;
  const maxBidsSize = 1;
  const bidsEvents: GenericOrderInfo[] = [];

  const client = new OpenSeaStreamClient({
    token: config.openSeaApiKey,
    network,
    connectOptions: {
      transport: WebSocket,
    },
    onError: async (error) => {
      logger.warn("opensea-websocket", `network=${network}, error=${JSON.stringify(error)}`);
    },
  });

  client.connect();

  logger.info("opensea-websocket", `Connected! network=${network}`);

  // Determine subscription topic: optionally narrow to a single collection slug
  (async () => {
    let topicSlug = "*";
    if (config.focusCollectionAddress) {
      if (config.focusCollectionSlug) {
        topicSlug = config.focusCollectionSlug;
      } else {
        try {
          const row = await ridb.oneOrNone(
            `SELECT slug FROM collections WHERE contract = $/contract/ ORDER BY created_at DESC LIMIT 1`,
            { contract: toBuffer(config.focusCollectionAddress) }
          );
          if (row?.slug) {
            topicSlug = row.slug;
          }
        } catch {
          // ignore lookup errors; fallback to wildcard
        }
      }
    }

    logger.info(
      "opensea-websocket",
      JSON.stringify({ topic: "subscription", subscribe: topicSlug })
    );

    client.onEvents(
      topicSlug,
      [
        EventType.ITEM_LISTED,
        EventType.COLLECTION_OFFER,
        EventType.ITEM_RECEIVED_BID,
        EventType.TRAIT_OFFER,
        EventType.ITEM_CANCELLED,
        EventType.ORDER_REVALIDATE,
      ],
      async (event) => {
        try {
          const chainName = (event.payload as any).chain;

          lastReceivedEventTimestamp = now();

          if (chainName && getOpenseaChainName() != chainName) {
            return;
          }

          if (await isDuplicateEvent(event)) {
            return;
          }

          const eventType = event.event_type as EventType;
          const openSeaOrderParams = await handleEvent(eventType, event.payload);

          logger.info(
            "opensea-websocket",
            JSON.stringify({
              topic: "opensea-websocket-metrics",
              message: "Processing event.",
              network,
              event,
              isSupported: !!openSeaOrderParams,
              chainName,
              hasChainName: !!chainName,
            })
          );

          if (openSeaOrderParams) {
            // Focus guard: if a focus collection is configured, only accept
            // OpenSea websocket orders whose target contract matches focus.
            if (config.focusCollectionAddress) {
              const focus = config.focusCollectionAddress.toLowerCase();
              const target = openSeaOrderParams.contract?.toLowerCase();
              if (target && target !== focus) {
                logger.info(
                  "opensea-websocket",
                  JSON.stringify({
                    topic: "focus-gate",
                    message: "Skipping non-focus OpenSea order",
                    focus,
                    target,
                    hash: openSeaOrderParams.hash,
                    kind: openSeaOrderParams.kind,
                    side: openSeaOrderParams.side,
                    slug: openSeaOrderParams.collectionSlug,
                  })
                );
                return;
              }
            }
            const protocolData = parseProtocolData(event.payload);

            let orderInfo: GenericOrderInfo;
            if (protocolData) {
              orderInfo = {
                kind: protocolData.kind,
                info: {
                  orderParams: protocolData.order.params,
                  metadata: {
                    originatedAt: event.sent_at,
                  },
                  isOpenSea: true,
                  openSeaOrderParams,
                },
                validateBidValue: true,
                ingestMethod: "websocket",
              } as GenericOrderInfo;

              if (eventType === EventType.ITEM_LISTED) {
                await openseaListingsJob.addToQueue([orderInfo]);
              } else {
                bidsEvents.push(orderInfo);

                if (bidsEvents.length >= maxBidsSize) {
                  const orderInfoBatch = bidsEvents.splice(0, bidsEvents.length);

                  await openseaBidsQueueJob.addToQueue(orderInfoBatch);
                }
              }
            }
          }
        } catch (error) {
          logger.error(
            "opensea-websocket",
            `network=${network}, event=${JSON.stringify(event)}, error=${error}`
          );
        }
      }
    );
    // Also subscribe to item metadata updates on the same topic
    client.onItemMetadataUpdated(topicSlug, async (event) => {
      try {
        if (config.disableRealtimeMetadataRefresh) {
          return;
        }

        if (getOpenseaChainName() != event.payload.item.chain.name) {
          return;
        }

        if (await isDuplicateEvent(event)) {
          return;
        }

        const [, contract, tokenId] = event.payload.item.nft_id.split("/");

        if (config.focusCollectionAddress) {
          const focus = config.focusCollectionAddress.toLowerCase();
          if (contract.toLowerCase() !== focus) {
            return;
          }
        }

        // Check: token doesn't exist
        const tokenExists = await ridb.oneOrNone(
          `SELECT 1 FROM tokens WHERE tokens.contract = $/contract/ AND tokens.token_id=$/tokenId/`,
          {
            contract: toBuffer(contract),
            tokenId,
          }
        );

        if (!tokenExists) {
          return;
        }

        const lockExists = await doesLockExist(`refresh-new-token-metadata:${contract}:${tokenId}`);

        if (!lockExists) {
          const collection = await Collections.getByContractAndTokenId(contract, Number(tokenId));

          await metadataIndexFetchJob.addToQueue([
            {
              kind: "single-token",
              data: {
                method: config.metadataIndexingMethod,
                contract,
                tokenId,
                collection: collection?.id || contract,
              },
              context: "opensea-websocket",
            },
          ]);
        }
      } catch (error) {
        logger.error(
          "opensea-websocket-item-metadata-update-event",
          JSON.stringify({
            message: `Error. network=${network}, event=${JSON.stringify(event)}, error=${error}`,
            error,
          })
        );
      }
    });
  })();
}

export const getEventHash = (event: BaseStreamMessage<unknown>): string => {
  /* eslint-disable @typescript-eslint/no-explicit-any */
  switch (event.event_type) {
    case EventType.ITEM_METADATA_UPDATED:
      return generateHash(
        event.event_type,
        (event.payload as any).item.nft_id,
        (event.payload as any).sent_at
      );
    default:
      return generateHash(event.event_type, (event.payload as any).order_hash);
  }
};

export const isDuplicateEvent = async (event: BaseStreamMessage<unknown>): Promise<boolean> => {
  const eventHash = getEventHash(event);

  const setResult = await redis.set(`opensea-websocket-event:${eventHash}`, now(), "EX", 60, "NX");

  return setResult === null;
};

export const handleEvent = async (
  type: EventType,
  payload: unknown
  // `PartialOrderComponents` has the same types for both `seaport` and `seaport-v1.4`
): Promise<OpenseaOrderParams | null> => {
  switch (type) {
    case EventType.ITEM_LISTED:
      return handleItemListedEvent(payload as ItemListedEventPayload);
    case EventType.ITEM_RECEIVED_BID:
      return handleItemReceivedBidEvent(payload as ItemReceivedBidEventPayload);
    case EventType.COLLECTION_OFFER:
      return handleCollectionOfferEvent(payload as CollectionOfferEventPayload);
    case EventType.TRAIT_OFFER:
      return handleTraitOfferEvent(payload as TraitOfferEventPayload);
    case EventType.ITEM_CANCELLED:
      return await handleItemCancelled(payload as ItemCancelledEventPayload);
    case EventType.ORDER_REVALIDATE:
      return await handleOrderRevalidate(payload as OrderValidationEventPayload);
    default:
      return null;
  }
};

type ProtocolData =
  | {
      kind: "seaport";
      order: Sdk.SeaportV11.Order;
    }
  | {
      kind: "seaport-v1.4";
      order: Sdk.SeaportV14.Order;
    }
  | {
      kind: "seaport-v1.5";
      order: Sdk.SeaportV15.Order;
    }
  | {
      kind: "seaport-v1.6";
      order: Sdk.SeaportV16.Order;
    };

export const parseProtocolData = (payload: unknown): ProtocolData | undefined => {
  try {
    const protocolData = (payload as any).protocol_data;
    if (!protocolData) {
      logger.warn(
        "opensea-websocket",
        `parseProtocolData missing. payload=${JSON.stringify(payload)}`
      );
      return undefined;
    }

    const protocol = (payload as any).protocol_address;
    // Normalize odd payload shapes (eg. negative counter from OS stream)
    const rawCounter = protocolData.parameters.counter;
    const counter =
      typeof rawCounter === "number" ? (rawCounter < 0 ? "0" : `${rawCounter}`) : `${rawCounter}`;

    const startTime =
      typeof protocolData.parameters.startTime === "string"
        ? Number(protocolData.parameters.startTime)
        : protocolData.parameters.startTime;
    const endTime =
      typeof protocolData.parameters.endTime === "string"
        ? Number(protocolData.parameters.endTime)
        : protocolData.parameters.endTime;

    const orderComponents = {
      endTime,
      startTime,
      consideration: protocolData.parameters.consideration,
      offer: protocolData.parameters.offer,
      conduitKey: protocolData.parameters.conduitKey,
      salt: protocolData.parameters.salt,
      zone: protocolData.parameters.zone,
      zoneHash: protocolData.parameters.zoneHash,
      offerer: protocolData.parameters.offerer,
      counter,
      orderType: protocolData.parameters.orderType,
      signature: protocolData.signature || undefined,
    };

    if (protocol === Sdk.SeaportV11.Addresses.Exchange[config.chainId]) {
      return {
        kind: "seaport",
        order: new Sdk.SeaportV11.Order(config.chainId, orderComponents),
      };
    } else if (protocol === Sdk.SeaportV14.Addresses.Exchange[config.chainId]) {
      return {
        kind: "seaport-v1.4",
        order: new Sdk.SeaportV14.Order(config.chainId, orderComponents),
      };
    } else if (protocol === Sdk.SeaportV15.Addresses.Exchange[config.chainId]) {
      return {
        kind: "seaport-v1.5",
        order: new Sdk.SeaportV15.Order(config.chainId, orderComponents),
      };
    } else if (protocol === Sdk.SeaportV16.Addresses.Exchange[config.chainId]) {
      return {
        kind: "seaport-v1.6",
        order: new Sdk.SeaportV16.Order(config.chainId, orderComponents),
      };
    }

    // Unknown protocol address; log for visibility
    logger.warn(
      "opensea-websocket",
      JSON.stringify({
        topic: "unknown-protocol",
        message: "Unsupported OpenSea protocol address",
        protocol,
        chainId: config.chainId,
        payload: (payload as any)?.order_hash || (payload as any)?.payload?.order_hash,
      })
    );
  } catch (error) {
    logger.error(
      "opensea-websocket",
      `parseProtocolData error. payload=${JSON.stringify(payload)}, error=${error}`
    );
  }

  return undefined;
};

export const getLastReceivedEventTimestamp = (): number => {
  return lastReceivedEventTimestamp;
};
