-- Up Migration

CREATE TABLE IF NOT EXISTS "focus_owner_snapshots" (
  "contract" BYTEA NOT NULL,
  "token_id" NUMERIC(78, 0) NOT NULL,
  "owner" BYTEA NOT NULL,
  "block_number" NUMERIC(78, 0),
  "retrieved_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
  "source" TEXT NOT NULL DEFAULT 'ownerOf',
  PRIMARY KEY ("contract", "token_id")
);

CREATE INDEX IF NOT EXISTS "focus_owner_snapshots_owner_idx"
  ON "focus_owner_snapshots" ("owner")
  WHERE "owner" IS NOT NULL;

CREATE OR REPLACE FUNCTION focus_get_owner(contract BYTEA, token_id NUMERIC)
RETURNS BYTEA
LANGUAGE SQL
STABLE
AS $$
  SELECT COALESCE(
    (
      SELECT nb.owner
      FROM nft_balances nb
      WHERE nb.contract = contract
        AND nb.token_id = token_id
        AND nb.amount > 0
      LIMIT 1
    ),
    (
      SELECT fos.owner
      FROM focus_owner_snapshots fos
      WHERE fos.contract = contract
        AND fos.token_id = token_id
        AND NOT EXISTS (
          SELECT 1
          FROM nft_balances nb2
          WHERE nb2.contract = fos.contract
            AND nb2.token_id = fos.token_id
            AND nb2.amount > 0
        )
      LIMIT 1
    )
  );
$$;

-- Down Migration

DROP FUNCTION IF EXISTS focus_get_owner(BYTEA, NUMERIC);
DROP TABLE IF EXISTS "focus_owner_snapshots";
