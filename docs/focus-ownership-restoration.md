# Focus Ownership Restoration Log

This doc is the running log for efforts to rebuild a reliable owner snapshot for the focus collection without a full historical backfill.

## Context

- Full backfill (~10M blocks) would take 2+ weeks even with focus mode enabled.
- Live sync has only been running ~2 weeks, so `nft_balances` is sparse and ownership data is incomplete.
- Goal: capture a trustworthy "current ownership" snapshot for all 10k tokens on a single indexer instance, without mutating the primary `nft_balances` accounting.

## Acceleration ideas (running list)

| Option | Summary | Status |
| ------ | ------- | ------ |
| 1 | Ownership-only backfill (`syncEventsOnly`, `skipTransactions`, `eventsType: ["nftTransferEvents"]`). | Not pursued yet. Heavy RPC load; still needs sequential block windows. |
| 2 | Re-enable `syncDetails.method="address"` + eventsType shortcut while in focus mode. | Parking lot. Worth revisiting if we need log-level sharding. |
| 3 | `ownershipOnly` flag that skips downstream queues (order updates, metadata, etc.) during focus-only backfills. | Not started. Still requires full decoding. |
| 4 | Dedicated "focus transfer importer" that only fetches ERC-721 transfer logs for the focus contract and pipes them through the existing storage layer. | Not started. Requires custom log pagination + parsing. |
| 5 | Snapshot every token via `ownerOf()` and serve it as a focus-only fallback without touching `nft_balances`. | **Active**. First slice shipped (snapshot table + admin job + read fallback on tokens API). |

## Decision (Option 5)

- Add a new table (`focus_owner_snapshots`) that stores `{ contract, token_id, owner, block_number, source }` for the focus collection.
- Populate it manually by iterating `ownerOf(tokenId)` for the desired range via an admin-triggered Rabbit job.
- Keep this data completely separate from `nft_balances`, and delete snapshot rows automatically once real transfer events arrive for those tokens.
- Expose the snapshot via the SQL helper `focus_get_owner(contract BYTEA, token_id NUMERIC)`, which returns the canonical `nft_balances` owner when present and otherwise falls back to the snapshot row. The latest `/tokens` endpoints now call this helper so the UI sees either realtime balances or snapshot data transparently.

## Snapshot pipeline (current state)

1. **Storage**: `focus_owner_snapshots` (see migration `1739315000000_focus-owner-snapshots.sql`) keeps `{ contract, token_id, owner, block_number, source, retrieved_at }`. The contract is always the configured `FOCUS_COLLECTION_ADDRESS`.
2. **Admin API**: `POST /admin/focus/snapshot-ownership` accepts either `tokenIds[]` or a `{ start, end }` range plus optional `blockNumber`. It enqueues `focus-owner-snapshot` jobs in batches (default 100 tokens per batch) and is gated behind the admin API key. Example payload:

```
curl -X POST https://localhost:3000/admin/focus/snapshot-ownership \
  -H "x-admin-api-key: $ADMIN_API_KEY" \
  -H "content-type: application/json" \
  -d '{
        "range": { "start": 0, "end": 9999 },
        "blockNumber": 19750000,
        "chunkSize": 250
      }'
```
3. **Job/queue**: `focus-owner-snapshot` pulls token ids, calls `ownerOf()` via the base RPC provider (optionally at a fixed block), and upserts rows through `FocusOwnerSnapshots.upsertMany`. If the contract reverts with `nonexistent token`, the job deletes any stale snapshot row and moves on.
4. **Read fallback**: SQL function `focus_get_owner(contract, token_id)` first checks `nft_balances` for an owner with `amount > 0`. If nothing exists, it returns the snapshot owner. `/tokens/v5-7` now select `focus_get_owner(t.contract, t.token_id)` so responses always include an owner string when either source has data.
5. **Cleanup**: When focus-mode transfers flow through the normal pipeline, `processOnChainData` now deletes snapshot rows for every token that just produced an on-chain transfer. Once a token has canonical history, its snapshot disappears automatically.

## Work log / next steps

- [x] Capture baseline docs (this file + `docs/nft-ownership-pipeline.md`).
- [x] Create DB table + model helpers for `focus_owner_snapshots`.
- [x] Add admin endpoint + Rabbit job to batch `ownerOf` calls and upsert rows.
- [x] Install read-time fallback for the `/tokens` APIs via `focus_get_owner(...)`.
- [x] Wire snapshot invalidation into the normal transfer pipeline so real events delete stale rows.
- [ ] Document the operator flow (trigger job, verify counts, disable once full backfill happens).
- [ ] Track metrics (counts of missing tokens) to know when snapshot still dominates.
- [ ] Extend the fallback to the other ownership-heavy endpoints (`/tokens/{token}/owners`, `/collections/{id}/owners`, user portfolio, etc.).

_Add notes + timestamps as we iterate._
