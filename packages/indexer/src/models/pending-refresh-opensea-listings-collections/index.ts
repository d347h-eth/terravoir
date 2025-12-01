import _ from "lodash";
import { redis } from "@/common/redis";

export type PendingRefreshOpenseaListingsCollection = {
  slug: string;
  contract: string;
  collection: string;
};

export class PendingRefreshOpenseaListingsCollections {
  public key = "pending-refresh-opensea-listings-collections";

  public async add(items: PendingRefreshOpenseaListingsCollection[], prioritized = false) {
    if (prioritized) {
      return await redis.lpush(
        this.key,
        _.map(items, (i) => JSON.stringify(i))
      );
    } else {
      return await redis.rpush(
        this.key,
        _.map(items, (i) => JSON.stringify(i))
      );
    }
  }

  public async get(count = 1): Promise<PendingRefreshOpenseaListingsCollection[]> {
    const raw = await redis.lpop(this.key, count);
    if (raw) {
      return _.map(raw, (r) => JSON.parse(r) as PendingRefreshOpenseaListingsCollection);
    }
    return [];
  }
}
