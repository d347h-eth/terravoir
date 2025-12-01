import { AbstractRabbitMqJobHandler } from "@/jobs/abstract-rabbit-mq-job-handler";
import { config } from "@/config/index";
import { baseProvider } from "@/common/provider";
import { logger } from "@/common/logger";
import { FocusOwnerSnapshots } from "@/models/focus-owner-snapshots";
import { Contract } from "@ethersproject/contracts";

export type FocusOwnerSnapshotJobPayload = {
  tokenId: string;
  blockNumber?: number;
  source?: string;
};

const erc721Abi = ["function ownerOf(uint256 tokenId) view returns (address)"];
let cachedContract: Contract | null = null;

const getContract = () => {
  if (!config.focusCollectionAddress) {
    return null;
  }

  if (!cachedContract) {
    cachedContract = new Contract(config.focusCollectionAddress, erc721Abi, baseProvider);
  }

  return cachedContract;
};

export class FocusOwnerSnapshotJob extends AbstractRabbitMqJobHandler {
  queueName = "focus-owner-snapshot";
  maxRetries = 5;
  concurrency = 4;
  timeout = 2 * 60 * 1000;

  public async process(payload: FocusOwnerSnapshotJobPayload) {
    if (!config.focusCollectionAddress) {
      logger.warn(this.queueName, "focus owner snapshot invoked without focus mode");
      return;
    }

    const contract = getContract();
    if (!contract) {
      logger.warn(this.queueName, "focus owner snapshot missing contract instance");
      return;
    }

    try {
      const callOverrides = payload.blockNumber ? { blockTag: payload.blockNumber } : undefined;
      const owner: string = callOverrides
        ? await contract.ownerOf(payload.tokenId, callOverrides)
        : await contract.ownerOf(payload.tokenId);

      await FocusOwnerSnapshots.upsertMany([
        {
          contract: config.focusCollectionAddress,
          tokenId: payload.tokenId,
          owner,
          blockNumber: payload.blockNumber,
          source: payload.source ?? "ownerOf",
        },
      ]);
    } catch (error: any) {
      const message = error?.error?.message || error?.message || "";

      // ownerOf reverts for tokens that do not exist yet; log and continue without failing the job
      if (
        message.toLowerCase().includes("nonexistent token") ||
        message.toLowerCase().includes("invalid token id")
      ) {
        await FocusOwnerSnapshots.deleteForTokens(config.focusCollectionAddress, [payload.tokenId]);
        logger.info(
          this.queueName,
          JSON.stringify({
            tokenId: payload.tokenId,
            blockNumber: payload.blockNumber,
            message: "token not minted yet; snapshot cleared",
          })
        );
        return;
      }

      throw error;
    }
  }

  public async addToQueue(payloads: FocusOwnerSnapshotJobPayload[]) {
    await this.sendBatch(payloads.map((payload) => ({ payload })));
  }
}

export const focusOwnerSnapshotJob = new FocusOwnerSnapshotJob();
