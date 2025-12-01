import { AbstractRabbitMqJobHandler, BackoffStrategy } from "@/jobs/abstract-rabbit-mq-job-handler";
import { PendingRefreshOpenseaListingsCollections } from "@/models/pending-refresh-opensea-listings-collections";
import { acquireLock } from "@/common/redis";
import { openseaListingsFetchJob } from "@/jobs/opensea-listings/opensea-listings-fetch-job";

export type OpenseaListingsProcessJobPayload = {
  contract: string;
  collectionId: string;
  collectionSlug: string;
  prioritized?: boolean;
};

export class OpenseaListingsProcessJob extends AbstractRabbitMqJobHandler {
  queueName = "opensea-listings-process-queue";
  maxRetries = 10;
  concurrency = 5;
  timeout = 60000;
  backoff = {
    type: "exponential",
    delay: 20000,
  } as BackoffStrategy;

  public async process(payload: OpenseaListingsProcessJobPayload) {
    const pending = new PendingRefreshOpenseaListingsCollections();
    await pending.add(
      [
        {
          contract: payload.contract,
          collection: payload.collectionId,
          slug: payload.collectionSlug,
        },
      ],
      Boolean(payload.prioritized)
    );

    if (await acquireLock(openseaListingsFetchJob.getLockName(), 60 * 5)) {
      await openseaListingsFetchJob.addToQueue();
    }
  }

  public async addToQueue(infos: OpenseaListingsProcessJobPayload[], delayInSeconds = 0) {
    await this.sendBatch(infos.map((info) => ({ payload: info, delay: delayInSeconds * 1000 })));
  }
}

export const openseaListingsProcessJob = new OpenseaListingsProcessJob();
