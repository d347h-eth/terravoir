# NFT Ownership Pipeline (Block -> DB)

This walkthrough describes how a new Ethereum block turns into `nft_transfer_events` and `nft_balances` rows when the indexer is running in realtime or backfill mode. File references use repository-relative paths.

## 1. Block Detection and Queueing

1. **Producers** - `packages/indexer/src/jobs/events-sync/index.ts` schedules realtime work through `events-sync-realtime` whenever the polling cron or WebSocket listener observes a new block. Env flags `CATCHUP`, `MASTER`, and `ENABLE_WEB_SOCKET` control which producers are on.
2. **Realtime job** - `packages/indexer/src/jobs/events-sync/events-sync-realtime-job.ts` pulls the block number from RabbitMQ, updates the `latest-block-realtime` Redis key, and calls `syncEvents({ fromBlock: N, toBlock: N })`. After the block is processed it enqueues `traceSyncJob` for trace enrichment and invokes `checkForOrphanedBlock` for reorg safety.
3. **Backfill job** - `packages/indexer/src/jobs/events-sync/events-sync-backfill-job.ts` chunks manual `/admin/sync-events` requests into batches and drives the same `syncEvents`/`syncEventsOnly` helpers, optionally with `syncDetails`, `skipTransactions`, or dedicated RPC providers.

## 2. Block Fetch + Log Capture (`syncEvents`)

Core logic lives in `packages/indexer/src/sync/events/index.ts`.

1. **Block window** - `syncEvents` bounds the request (`fromBlock`, `toBlock`), clamps to `config.genesisBlock`, and loads headers/transactions via the appropriate provider (base/archive/backfill URL based on the options).
2. **Log filter** - by default a single `eth_getLogs` call is issued with every topic defined in `getEventData()`. Two narrowing knobs exist:
   - `syncDetails.method === "events"`: reduces the topic array to a named subset (e.g. `erc721-transfer`, `erc1155-transfer-single`, etc.).
   - `syncDetails.method === "address"`: normally constrains `eventFilter.address`, but note that when `FOCUS_COLLECTION_ADDRESS` is set address-mode filters are ignored to keep marketplace/payment logs intact.
3. **Transactions cache** - realtime (single-block) runs cache `eth_getBlockWithTransactions` results in Redis for other jobs. Multi-block backfills persist transactions unless (a) `skipTransactions=true` or (b) focus mode is enabled, in which case transaction persistence is skipped entirely to save IO.
4. **Enhanced events** - each log is parsed through `parseEvent` and matched against `getEventData()` metadata. The result is an `EnhancedEvent` `{ kind, subKind, baseEventParams, log }` appended to a batch grouped by transaction via `extractEventsBatches`.

## 3. Handler Stage (`processEventsBatchV2`)

`packages/indexer/src/sync/events/handlers/index.ts` fans batches out by `EventKind` (erc721, erc1155, seaport, etc.). Every handler receives a mutable `OnChainData` object prepared by `initOnChainData()`.

Key data structures:

- `OnChainData.nftTransferEvents`: future inserts into `nft_transfer_events` and `nft_balances`.
- `OnChainData.orderInfos`, `makerInfos`, `permitInfos`: inputs for downstream Rabbit jobs.
- `OnChainData.fillEvents*`, `ftTransferEvents`, `mintInfos`, etc. - other domain data that share the same persistence pass.

To skip unrelated work during ownership-only backfills you can supply `syncDetails.eventsType` (e.g. `["nftTransferEvents"]`). Any keys not listed are zeroed before persistence, drastically reducing queue fan-out.

## 4. ERC-721 / ERC-1155 Handlers

`packages/indexer/src/sync/events/handlers/erc721.ts` and `erc1155.ts` are responsible for translating raw logs into ownership deltas.

1. **Parsing** - `eventData.abi.parseLog(log)` decodes `from`, `to`, `tokenId`, and amount (always `1` for standard ERC-721 transfers).
2. **On-chain bookkeeping** - each transfer pushes an `nftTransferEvents` entry and two `makerInfos` (`from` and `to`) that later cause order-balance revalidation. Mint-origin transfers also enqueue `mintInfos`/`mints` so the mint pipeline can tag freshly created tokens.
3. **Spam detection** - handlers track transfer bursts per recipient and emit `collectionCheckSpamJob` jobs for suspicious activity (same recipient >=900 transfers or large `consecutiveTransfer` ranges).
4. **Special cases** - consecutive transfer ranges over 100 tokens are fanned out to `processConsecutiveTransferJob` so each tokenId still lands in `nft_balances` with discrete rows.

## 5. Focus-Mode Filtering

Before any rows hit the DB, `processOnChainData` calls `filterOnChainDataByCollection` when `FOCUS_COLLECTION_ADDRESS` is configured (`packages/indexer/src/sync/events/handlers/utils/index.ts`).

- Only `nftTransferEvents`, `nftApprovalEvents`, fills, mint data, and swaps whose `contract` equals the focus address survive.
- Companion ERC-20 transfers (used for payments), swaps, and permits are retained iff they share the same transaction hash, ensuring balance tweaks keep context.
- Order/maker updates and cancels are allowed through because they only mutate rows that already exist for the focus collection.

## 6. Persistence + Write Buffers

`processOnChainData` (same file) persists the `OnChainData` payload and pushes follow-up jobs.

1. **Fill-first rule** - fill events are committed before transfers so orders transition to `filled` instead of `no-balance`.
2. **Transfer persistence** - `packages/indexer/src/sync/events/storage/nft-transfer-events.ts` builds batched CTEs that:
   - Insert rows into `nft_transfer_events` (deduped by `(tx_hash, log_index, batch_index, block_hash)`), marking cancels as `is_deleted=0`.
   - Upsert balances in `nft_balances` by summing `[-amount, +amount]` for `[from, to]` respectively, updating `acquired_at` and `is_airdropped` flags.
   - Create/refresh `tokens` rows (supply, `minted_timestamp`, remaining supply) and, for ERC-1155, enqueue `tokenReclacSupplyJob` for supply recompute.
   - Optionally defer ERC-1155 balance decrements for mint/airdrop heavy addresses by inserting `DeferUpdateAddressBalance` records.
3. **Write buffers** - during backfill the CTE queries are sent to `events-sync-nft-transfers-write` (see `packages/indexer/src/jobs/events-sync/write-buffers/nft-transfers-job.ts`) to serialize writes and avoid Postgres deadlocks. Realtime applies them inline so dependent jobs read fresh data immediately.
4. **Reorg safety** - if `checkForOrphanedBlock` detects a hash mismatch, `unsyncEvents` kicks in and `nft_transfer_events.removeEvents()` reverses their balance deltas via a mirrored `WITH ... INSERT ... ON CONFLICT` statement.

## 7. Ownership-Derived Jobs

After persistence, several jobs ensure ownership stays consistent everywhere else:

- **`transfer-updates`** (`packages/indexer/src/jobs/transfer-updates/transfer-updates-job.ts`): copies `last_token_appraisal_value` from seller to buyer so appraisals follow the token.
- **`mint-queue` / `mints-process`**: track mint metadata (`packages/indexer/src/jobs/token-updates/mint-queue-job.ts`, `packages/indexer/src/jobs/mints/mints-process-job.ts`).
- **`fill-updates`** (`packages/indexer/src/jobs/fill-updates/fill-updates-job.ts`): maintains `tokens.last_sale_*` fields and syncs `nft_balances.last_token_appraisal_value` for the fill taker.
- **`recalc-owner-count-queue`** (`packages/indexer/src/jobs/collection-updates/recalc-owner-count-queue-job.ts`): recomputes `collections.owner_count` for the touched contract/tokenId pairs.
- **Activities** - `processActivityEventJob` receives fill and transfer payloads so Elasticsearch (if enabled) reflects the ownership change.

## 8. Failure Modes & Guards

- **Redis transaction cache** - realtime runs save the block's transactions to Redis; `saveRedisTransactionsJob` flushes them later so other jobs can reference the calldata without extra RPC hits.
- **Gap detection** - if a realtime block yields no transfers (`logs.length === 0`) and `config.enableNoTransfersResync` is true, the same block is re-enqueued twice (5s & 30s delays) for redundancy.
- **Backfill throttling** - `scripts/backfill_focus_sequential.sh` ensures `events-sync-backfill` and both write-buffer queues drain between windows, preventing runaway balance drift.

## 9. Practical Hooks for Ownership Work

| Stage | File(s) | Purpose |
| --- | --- | --- |
| Job enqueue | `packages/indexer/src/jobs/events-sync/events-sync-realtime-job.ts` | Detects new blocks and calls `syncEvents` |
| Event parsing | `packages/indexer/src/sync/events/index.ts` | Fetches logs/transactions, builds `EnhancedEvent` batches |
| ERC-721 decode | `packages/indexer/src/sync/events/handlers/erc721.ts` | Turns logs into `nftTransferEvents`, mint info, maker balance triggers |
| Focus gating | `packages/indexer/src/sync/events/handlers/utils/index.ts` | Filters `OnChainData` to the configured collection |
| Persistence | `packages/indexer/src/sync/events/storage/nft-transfer-events.ts` | Writes `nft_transfer_events`, `nft_balances`, and token metadata |
| Write buffers | `packages/indexer/src/jobs/events-sync/write-buffers/nft-transfers-job.ts` | Serializes transfer writes during backfill |
| Downstream ownership jobs | `packages/indexer/src/jobs/transfer-updates/transfer-updates-job.ts`, `.../recalc-owner-count-queue-job.ts`, etc. | Keep derived caches (owner counts, appraisals, activities) accurate |
| Focus snapshot fallback | `docs/focus-ownership-restoration.md`, `packages/indexer/src/jobs/focus/focus-owner-snapshot-job.ts`, `packages/indexer/src/migrations/1739315000000_focus-owner-snapshots.sql` | optional ownerOf snapshot + `focus_get_owner()` helper that fills gaps when `nft_balances` is sparse |

This pipeline is identical for realtime and backfill; the only differences are (a) whether transactions are cached vs persisted, and (b) whether write buffers are inserted between the handlers and the database.
