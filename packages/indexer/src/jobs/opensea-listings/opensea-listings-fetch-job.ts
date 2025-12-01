/* eslint-disable @typescript-eslint/no-explicit-any */

import axios from "axios";
import { AbstractRabbitMqJobHandler, BackoffStrategy } from "@/jobs/abstract-rabbit-mq-job-handler";
import { PendingRefreshOpenseaListingsCollections } from "@/models/pending-refresh-opensea-listings-collections";
import { extendLock, releaseLock } from "@/common/redis";
import { config } from "@/config/index";
import { logger } from "@/common/logger";
import { parseProtocolData } from "@/websockets/opensea";
import { GenericOrderInfo } from "@/jobs/orderbook/utils";
import { orderbookOrdersJob } from "@/jobs/orderbook/orderbook-orders-job";
import { getOpenseaBaseUrl } from "@/config/network";

export class OpenseaListingsFetchJob extends AbstractRabbitMqJobHandler {
  queueName = "opensea-listings-fetch-queue";
  maxRetries = 10;
  concurrency = 1;
  timeout = 5 * 60 * 1000;
  singleActiveConsumer = true;
  backoff = {
    type: "fixed",
    delay: 5000,
  } as BackoffStrategy;

  public async process() {
    const pending = new PendingRefreshOpenseaListingsCollections();
    const items = await pending.get(1);
    if (!items.length) {
      await releaseLock(this.getLockName());
      return;
    }

    const { slug, contract } = items[0];

    let cursor: string | undefined = undefined;
    let throttledDelay = 0;

    do {
      try {
        const url = `${getOpenseaBaseUrl()}/v2/listings/collection/${slug}/best`;
        const headers: any = config.isTestnet
          ? { "Content-Type": "application/json" }
          : { "Content-Type": "application/json", "X-Api-Key": config.openSeaApiKey };

        const resp = await axios.get(url, {
          headers,
          params: { limit: 100, next: cursor },
        });

        const { listings, next } = resp.data as { listings: any[]; next?: string };

        for (const listing of listings) {
          // Build protocol order via existing parser
          const proto = parseProtocolData(listing);
          if (!proto) continue;

          // Derive target token/contract from protocol_data.offer if possible
          let tokenId: string | undefined;
          try {
            const offer = listing.protocol_data?.parameters?.offer?.[0];
            const token = offer?.token?.toLowerCase?.();
            const kind = Number(offer?.itemType);
            const ident = offer?.identifierOrCriteria as string | undefined;
            if (token && token !== contract.toLowerCase()) {
              // Defensive: skip if the listing doesn’t match requested contract
              continue;
            }
            if (ident && (kind === 2 || kind === 3)) {
              tokenId = String(ident);
            }
          } catch {
            // ignore extraction errors; we can still save the order
          }

          const orderInfo: GenericOrderInfo = {
            kind: proto.kind,
            info: {
              orderParams: (proto as any).order.params,
              metadata: {
                originatedAt: new Date().toISOString(),
              },
              isOpenSea: true,
              openSeaOrderParams: {
                kind: tokenId ? "single-token" : "contract-wide",
                side: "sell",
                hash: listing.order_hash,
                contract,
                tokenId,
                collectionSlug: slug,
              },
            },
            validateBidValue: false,
            ingestMethod: "rest",
          } as any;

          await orderbookOrdersJob.addToQueue([orderInfo]);
        }

        cursor = next;

        if (await extendLock(this.getLockName(), 60 * 5)) {
          // continue
        }
      } catch (error: any) {
        if (error?.response?.status === 429) {
          logger.info(this.queueName, `Throttled. error=${JSON.stringify(error?.response?.data)}`);
          throttledDelay = 5;
          break;
        } else if (error?.response?.status === 401) {
          logger.error(
            this.queueName,
            JSON.stringify({
              topic: "opensea-unauthorized-api-key",
              message: `UnauthorizedError. message=${error?.message}, url=${error?.config?.url}`,
              requestHeaders: error?.config?.headers,
              responseData: JSON.stringify(error?.response?.data),
            })
          );
          break;
        } else if (error?.response?.status === 404) {
          logger.warn(this.queueName, `Collection Not Found. slug=${slug}`);
          // No retry; move on
          cursor = undefined;
          break;
        } else {
          logger.error(this.queueName, `fetchListings failed. slug=${slug}, error=${error}`);
          // Best effort: stop on unexpected errors
          break;
        }
      }
    } while (cursor);

    if (throttledDelay || cursor) {
      if (await extendLock(this.getLockName(), 60 * 5 + throttledDelay)) {
        await this.addToQueue(throttledDelay * 1000);
      }
    } else {
      await releaseLock(this.getLockName());
    }
  }

  public getLockName() {
    return `${this.queueName}`;
  }

  public async addToQueue(delay = 0) {
    await this.send({}, delay);
  }
}

export const openseaListingsFetchJob = new OpenseaListingsFetchJob();
