import cron from "node-cron";

import { config } from "@/config/index";
import { redb } from "@/common/db";
import { toBuffer } from "@/common/utils";
import { logger } from "@/common/logger";
import { redlock } from "@/common/redis";
import { openseaListingsProcessJob } from "@/jobs/opensea-listings/opensea-listings-process-job";

// Run an OpenSea listings snapshot for the focus collection every 20 minutes.
// Only enable when background work is on, collection metadata indexing uses OpenSea,
// and a focus collection is configured.
if (
  config.doBackgroundWork &&
  config.focusCollectionAddress
) {
  cron.schedule("*/20 * * * *", async () => {
    if (!config.focusCollectionAddress) {
      return;
    }
    const lockTtlMs = 20 * 60 * 1000 - 5000; // hold lock for the window minus a small buffer
    try {
      await redlock
        .acquire([`opensea-snapshot-listings-cron-lock:${config.focusCollectionAddress}`], lockTtlMs)
        .then(async () => {
          try {
            const row = await redb.oneOrNone(
              `SELECT id, slug FROM collections WHERE contract = $/contract/ LIMIT 1`,
              { contract: toBuffer(config.focusCollectionAddress as string) }
            );

            if (!row) {
              logger.warn(
                "opensea-snapshot-cron",
                JSON.stringify({
                  message: "focus collection not found in DB; skipping snapshot",
                  contract: config.focusCollectionAddress,
                })
              );
              return;
            }

            await openseaListingsProcessJob.addToQueue([
              {
                contract: config.focusCollectionAddress as string,
                collectionId: row.id,
                collectionSlug: row.slug,
                prioritized: false,
              },
            ]);

            logger.info(
              "opensea-snapshot-cron",
              JSON.stringify({ message: "enqueued", contract: config.focusCollectionAddress, collectionId: row.id, slug: row.slug })
            );
          } catch (err) {
            logger.error(
              "opensea-snapshot-cron",
              `failed to enqueue snapshot for focus collection: ${err}`
            );
          }
        })
        .catch(() => {
          // Another instance holds the lock – skip this run
        });
    } catch {
      // Ignore lock errors
    }
  });
}
