import _ from "lodash";

import { idb, pgp } from "@/common/db";
import { toBuffer } from "@/common/utils";

export type FocusOwnerSnapshotUpsertParams = {
  contract: string;
  tokenId: string;
  owner: string;
  blockNumber?: string | number | null;
  source?: string;
};

const table = new pgp.helpers.TableName({ table: "focus_owner_snapshots" });
const upsertColumns = new pgp.helpers.ColumnSet(
  ["contract", "token_id", "owner", "block_number", "source"],
  { table }
);

export class FocusOwnerSnapshots {
  public static async upsertMany(payloads: FocusOwnerSnapshotUpsertParams[]) {
    if (!payloads.length) {
      return;
    }

    const rows = payloads.map((p) => ({
      contract: toBuffer(p.contract),
      token_id: p.tokenId,
      owner: toBuffer(p.owner),
      block_number: p.blockNumber ?? null,
      source: p.source ?? "ownerOf",
    }));

    const contractBuffer = toBuffer(payloads[0].contract);
    const tokenIds = rows.map((row) => row.token_id);

    const insertQuery = `${pgp.helpers.insert(rows, upsertColumns)}
      ON CONFLICT (contract, token_id) DO UPDATE SET
        owner = EXCLUDED.owner,
        block_number = EXCLUDED.block_number,
        source = EXCLUDED.source,
        retrieved_at = now()
    `;

    await idb.tx(async (tx) => {
      await tx.none(insertQuery);

      await tx.none(
        `
          DELETE FROM focus_owner_snapshots fos
          WHERE fos.contract = $/contract/
            AND fos.token_id IN ($/tokenIds:csv/)
            AND EXISTS (
              SELECT 1 FROM nft_balances nb
              WHERE nb.contract = fos.contract
                AND nb.token_id = fos.token_id
                AND nb.amount > 0
            )
        `,
        {
          contract: contractBuffer,
          tokenIds,
        }
      );
    });
  }

  public static async deleteForTokens(contract: string, tokenIds: string[]) {
    if (!tokenIds.length) {
      return;
    }

    const chunks = _.chunk(tokenIds, 500);

    for (const chunk of chunks) {
      await idb.none(
        `
          DELETE FROM focus_owner_snapshots
          WHERE contract = $/contract/
            AND token_id IN ($/tokenIds:csv/)
        `,
        {
          contract: toBuffer(contract),
          tokenIds: chunk,
        }
      );
    }
  }
}
