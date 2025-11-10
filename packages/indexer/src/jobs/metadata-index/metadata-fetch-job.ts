import { redb } from "@/common/db";
import { fromBuffer, toBuffer } from "@/common/utils";
import { AbstractRabbitMqJobHandler, BackoffStrategy } from "@/jobs/abstract-rabbit-mq-job-handler";
import _ from "lodash";
import { config } from "@/config/index";
import { PendingRefreshTokens, RefreshTokens } from "@/models/pending-refresh-tokens";
import { logger } from "@/common/logger";
import { AddressZero } from "@ethersproject/constants";
import { metadataIndexProcessJob } from "@/jobs/metadata-index/metadata-process-job";
import { onchainMetadataFetchTokenUriJob } from "@/jobs/metadata-index/onchain-metadata-fetch-token-uri-job";
import { acquireLock } from "@/common/redis";

export type MetadataIndexFetchJobPayload =
  | {
      kind: "full-collection";
      data: {
        method: string;
        collection: string;
        continuation?: string;
        onlyTokensWithMissingImages?: boolean;
      };
      context?: string;
    }
  | {
      kind: "single-token";
      data: {
        method: string;
        collection: string;
        contract: string;
        tokenId: string;
        isFallback?: boolean;
      };
      context?: string;
    };

export default class MetadataIndexFetchJob extends AbstractRabbitMqJobHandler {
  queueName = "metadata-index-fetch-queue";
  maxRetries = 10;
  concurrency = 5;
  timeout = 60000;
  priorityQueue = true;
  backoff = {
    type: "exponential",
    delay: 20000,
  } as BackoffStrategy;

  public async process(payload: MetadataIndexFetchJobPayload) {
    // Do nothing if the indexer is running in liquidity-only mode
    if (config.liquidityOnly) {
      return;
    }

    // logger.log(
    //   config.debugMetadataIndexingCollections.includes(payload.data.collection) ? "info" : "debug",
    //   this.queueName,
    //   JSON.stringify({
    //     topic: "tokenMetadataIndexing",
    //     message: `Start. collection=${payload.data.collection}, tokenId=${
    //       payload.kind === "single-token" ? payload.data.tokenId : ""
    //     }, context=${payload.context}`,
    //     payload,
    //     debugMetadataIndexingCollection: config.debugMetadataIndexingCollections.includes(
    //       payload.data.collection
    //     ),
    //   })
    // );

    const { kind, data } = payload;

    // Focus-mode gate: only index metadata for the focus collection/contract
    if (config.focusCollectionAddress) {
      const focus = config.focusCollectionAddress.toLowerCase();
      const collectionId = data.collection?.toLowerCase?.();
      const inferContractFromCollection = (id?: string) =>
        id && id.startsWith("0x") && id.length >= 42 ? id.slice(0, 42) : undefined;
      const collectionContract = inferContractFromCollection(collectionId);

      if (kind === "single-token") {
        const tokenContract = data.contract?.toLowerCase?.();
        if (tokenContract && tokenContract !== focus) {
          return;
        }
        if (!tokenContract && collectionContract && collectionContract !== focus) {
          return;
        }
      } else if (kind === "full-collection") {
        if (collectionContract && collectionContract !== focus) {
          return;
        }
      }
    }
    const prioritized = !_.isUndefined(this.rabbitMqMessage?.prioritized);
    const limit = 1000;
    let refreshTokens: RefreshTokens[] = [];

    if (kind === "full-collection") {
      logger.info(
        this.queueName,
        JSON.stringify({
          message: `Full collection. collection=${payload.data.collection}`,
          data,
          prioritized,
        })
      );

      // Get batch of tokens for the collection
      const [contract, tokenId] = data.continuation
        ? data.continuation.split(":")
        : [AddressZero, "0"];
      refreshTokens = await this.getTokensForCollection(
        data.collection,
        contract,
        tokenId,
        limit,
        data.onlyTokensWithMissingImages,
        true
      );

      // If no more tokens found
      if (_.isEmpty(refreshTokens)) {
        logger.warn(this.queueName, `No more tokens found for collection: ${data.collection}`);
        return;
      }

      // If there are potentially more tokens to refresh
      if (_.size(refreshTokens) == limit) {
        const lastToken = refreshTokens[limit - 1];
        const continuation = `${lastToken.contract}:${lastToken.tokenId}`;

        logger.info(
          this.queueName,
          JSON.stringify({
            message: `Trigger token sync continuation. collection=${payload.data.collection}, continuation=${continuation}`,
            data,
            prioritized,
          })
        );

        await this.addToQueue(
          [
            {
              kind,
              data: {
                ...data,
                continuation,
              },
            },
          ],
          prioritized
        );
      }
    } else if (kind === "single-token") {
      const acquiredLock = await acquireLock(
        `${this.queueName}-lock:single-token:${data.method}:${data.contract}:${data.tokenId}`,
        60
      );

      if (!acquiredLock) {
        if (
          payload.context &&
          [
            "opensea-websocket",
            "onchain-metadata-update-batch-tokens",
            "onchain-metadata-update-single-token",
          ].includes(payload.context)
        ) {
          return;
        }

        logger.debug(
          this.queueName,
          JSON.stringify({
            message: `Unable to acquire lock. method=${data.method}, contract=${data.contract}, tokenId=${data.tokenId}, context=${payload.context}, prioritized=${prioritized}`,
            data,
            prioritized,
            context: payload.context,
          })
        );
      }

      // Create the single token from the params
      refreshTokens.push({
        collection: data.collection,
        contract: data.contract,
        tokenId: data.tokenId,
        isFallback: data.isFallback,
      });
    }

    // Add the tokens to the list
    const pendingRefreshTokens = new PendingRefreshTokens(data.method);
    await pendingRefreshTokens.add(refreshTokens, prioritized);

    if (data.method === "onchain") {
      await onchainMetadataFetchTokenUriJob.addToQueue();
    } else {
      await metadataIndexProcessJob.addToQueue({ method: data.method });
    }
  }

  public async getTokensForCollection(
    collection: string,
    contract: string,
    tokenId: string,
    limit: number,
    onlyTokensWithMissingImages = false,
    excludeBurnt = false
  ) {
    const tokens = await redb.manyOrNone(
      `SELECT tokens.contract, tokens.token_id
            FROM tokens
            WHERE tokens.collection_id = $/collection/
            ${onlyTokensWithMissingImages ? "AND tokens.image IS NULL" : ""}
            ${excludeBurnt ? "AND remaining_supply > 0" : ""}
            AND (tokens.contract, tokens.token_id) > ($/contract/, $/tokenId/)
            ORDER BY contract, token_id 
            LIMIT ${limit}`,
      {
        collection: collection,
        contract: toBuffer(contract),
        tokenId: tokenId,
      }
    );

    return tokens.map((t) => {
      return { collection, contract: fromBuffer(t.contract), tokenId: t.token_id } as RefreshTokens;
    });
  }

  public async addToQueue(
    metadataIndexInfos: MetadataIndexFetchJobPayload[],
    prioritized = false,
    delayInSeconds = 0
  ) {
    // Focus-mode: skip enqueue for non-focus collections/contracts to reduce noise upstream
    let filtered = metadataIndexInfos;
    if (config.focusCollectionAddress) {
      const focus = config.focusCollectionAddress.toLowerCase();
      const inferContractFromCollection = (id?: string) =>
        id && id.startsWith("0x") && id.length >= 42 ? id.slice(0, 42) : undefined;

      filtered = metadataIndexInfos.filter((info) => {
        if (info.kind === "single-token") {
          const c = info.data.contract?.toLowerCase?.();
          if (c) return c === focus;
          const colC = inferContractFromCollection(info.data.collection?.toLowerCase?.());
          return !colC || colC === focus;
        } else {
          const colC = inferContractFromCollection(info.data.collection?.toLowerCase?.());
          return !colC || colC === focus;
        }
      });
      if (filtered.length === 0) {
        return;
      }
    }

    await this.sendBatch(
      filtered.map((metadataIndexInfo) => ({
        payload: metadataIndexInfo,
        delay: delayInSeconds * 1000,
        priority: prioritized ? 0 : 0,
      }))
    );
  }
}

export const metadataIndexFetchJob = new MetadataIndexFetchJob();
