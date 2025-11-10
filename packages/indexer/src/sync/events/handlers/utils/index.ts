import { Log } from "@ethersproject/abstract-provider";
import { AddressZero } from "@ethersproject/constants";
import _ from "lodash";

import { concat } from "@/common/utils";
import { EventKind, EventSubKind } from "@/events-sync/data";
import {
  assignMintCommentToFillEvents,
  assignSourceToFillEvents,
} from "@/events-sync/handlers/utils/fills";
export { assignMintCommentToFillEvents } from "@/events-sync/handlers/utils/fills";
import { BaseEventParams } from "@/events-sync/parser";
import * as es from "@/events-sync/storage";
import * as pendingTxs from "@/utils/pending-txs";

import { GenericOrderInfo } from "@/jobs/orderbook/utils";
import {
  recalcOwnerCountQueueJob,
  RecalcOwnerCountQueueJobPayload,
} from "@/jobs/collection-updates/recalc-owner-count-queue-job";
import { mintQueueJob, MintQueueJobPayload } from "@/jobs/token-updates/mint-queue-job";
import {
  processActivityEventJob,
  EventKind as ProcessActivityEventKind,
  ProcessActivityEventJobPayload,
} from "@/jobs/elasticsearch/activities/process-activity-event-job";
import { fillUpdatesJob, FillUpdatesJobPayload } from "@/jobs/fill-updates/fill-updates-job";
import { fillPostProcessJob } from "@/jobs/fill-updates/fill-post-process-job";
import { mintsProcessJob, MintsProcessJobPayload } from "@/jobs/mints/mints-process-job";
import {
  orderUpdatesByIdJob,
  OrderUpdatesByIdJobPayload,
} from "@/jobs/order-updates/order-updates-by-id-job";
import {
  orderUpdatesByMakerJob,
  OrderUpdatesByMakerJobPayload,
} from "@/jobs/order-updates/order-updates-by-maker-job";
import { orderbookOrdersJob } from "@/jobs/orderbook/orderbook-orders-job";
import { transferUpdatesJob } from "@/jobs/transfer-updates/transfer-updates-job";
import {
  permitUpdatesJob,
  PermitUpdatesJobPayload,
} from "@/jobs/permit-updates/permit-updates-job";
import { format } from "date-fns";
import { NftTransferEventInfo } from "@/elasticsearch/indexes/activities/event-handlers/base";
import { config } from "@/config/index";
import { fetchTransaction } from "@/events-sync/utils";
import { saveTransactionsV2, Transaction as DbTransaction } from "@/models/transactions";

// Semi-parsed and classified event
export type EnhancedEvent = {
  kind: EventKind;
  subKind: EventSubKind;
  baseEventParams: BaseEventParams;
  log: Log;
};

export type MintComment = {
  token: string;
  tokenId?: string;
  quantity: number;
  comment: string;
  baseEventParams: BaseEventParams;
};

export type Swap = {
  wallet: string;
  fromToken: string;
  fromAmount: string;
  toToken: string;
  toAmount: string;
  baseEventParams: BaseEventParams;
};

// Data extracted from purely on-chain information
export type OnChainData = {
  // Fills
  fillEvents: es.fills.Event[];
  fillEventsPartial: es.fills.Event[];
  fillEventsOnChain: es.fills.Event[];

  // Cancels
  cancelEvents: es.cancels.Event[];
  cancelEventsOnChain: es.cancels.Event[];
  bulkCancelEvents: es.bulkCancels.Event[];
  nonceCancelEvents: es.nonceCancels.Event[];

  // Approvals
  // Due to some complexities around them, ft approvals are handled
  // differently (eg. ft approvals can decrease implicitly when the
  // spender transfers from the owner's balance, without any events
  // getting emitted)
  nftApprovalEvents: es.nftApprovals.Event[];

  // Transfers
  ftTransferEvents: es.ftTransfers.Event[];
  nftTransferEvents: es.nftTransfers.Event[];

  // For keeping track of mints and last sales
  fillInfos: FillUpdatesJobPayload[];
  mintInfos: MintQueueJobPayload[];
  mints: MintsProcessJobPayload[];
  mintComments: MintComment[];

  // For properly keeping orders validated on the go
  orderInfos: OrderUpdatesByIdJobPayload[];
  makerInfos: OrderUpdatesByMakerJobPayload[];

  // For properly keeping permits validated on the go
  permitInfos: PermitUpdatesJobPayload[];

  // For keeping track of swaps
  swaps: Swap[];

  // Orders
  orders: GenericOrderInfo[];
};

export const initOnChainData = (): OnChainData => ({
  fillEvents: [],
  fillEventsOnChain: [],
  fillEventsPartial: [],

  cancelEvents: [],
  cancelEventsOnChain: [],
  bulkCancelEvents: [],
  nonceCancelEvents: [],

  nftApprovalEvents: [],

  ftTransferEvents: [],
  nftTransferEvents: [],

  fillInfos: [],
  mintInfos: [],
  mints: [],
  mintComments: [],

  orderInfos: [],
  makerInfos: [],

  permitInfos: [],

  swaps: [],

  orders: [],
});

// Process on-chain data (save to db, trigger any further processes, ...)
// Helper: filter on-chain data to a single focus collection while preserving
// companion signals from the same transactions (payments, ft transfers, etc.).
const filterOnChainDataByCollection = async (data: OnChainData, focusAddress: string) => {
  const focus = focusAddress.toLowerCase();

  const relevantTxs = new Set<string>();

  // Identify explicitly-related events and collect their tx hashes
  const keepNftTransfer = (e: es.nftTransfers.Event) =>
    e.baseEventParams.address.toLowerCase() === focus;
  const keepNftApproval = (e: es.nftApprovals.Event) =>
    e.baseEventParams.address.toLowerCase() === focus;
  const keepFill = (e: es.fills.Event) => e.contract.toLowerCase() === focus;
  const keepMintInfo = (e: MintQueueJobPayload) => e.contract.toLowerCase() === focus;
  const keepFillInfo = (e: FillUpdatesJobPayload) => e.contract.toLowerCase() === focus;
  const keepMint = (e: MintsProcessJobPayload) => (e as any).contract?.toLowerCase?.() === focus;

  data.nftTransferEvents = data.nftTransferEvents.filter((e) => {
    const keep = keepNftTransfer(e);
    if (keep) relevantTxs.add(e.baseEventParams.txHash);
    return keep;
  });

  data.nftApprovalEvents = data.nftApprovalEvents.filter((e) => {
    const keep = keepNftApproval(e);
    if (keep) relevantTxs.add(e.baseEventParams.txHash);
    return keep;
  });

  data.fillEvents = data.fillEvents.filter((e) => {
    const keep = keepFill(e);
    if (keep) relevantTxs.add(e.baseEventParams.txHash);
    return keep;
  });
  data.fillEventsPartial = data.fillEventsPartial.filter((e) => {
    const keep = keepFill(e);
    if (keep) relevantTxs.add(e.baseEventParams.txHash);
    return keep;
  });
  data.fillEventsOnChain = data.fillEventsOnChain.filter((e) => {
    const keep = keepFill(e);
    if (keep) relevantTxs.add(e.baseEventParams.txHash);
    return keep;
  });

  data.mintInfos = data.mintInfos.filter(keepMintInfo);
  data.mints = data.mints.filter(keepMint);
  data.mintComments = data.mintComments.filter(
    (e) => (e as any).contract?.toLowerCase?.() === focus
  );
  data.fillInfos = data.fillInfos.filter(keepFillInfo);

  // Companion signals: include if in the same tx as explicitly-related items
  data.ftTransferEvents = data.ftTransferEvents.filter((e) =>
    relevantTxs.has(e.baseEventParams.txHash)
  );

  // Do not filter cancels in focus mode. The storage layer updates only
  // existing orders, so non-focus cancel events become no-ops without
  // adding complexity here.

  // Order/maker updates: keep when tokenSetId references the focus contract
  // Allow all order/maker updates to pass (they only mutate existing orders)
  // so behavior remains identical to wide mode in focus deployments.

  // Permits and swaps: include if in relevant txs
  data.permitInfos = data.permitInfos.filter(() => false);
  data.swaps = data.swaps.filter((e) => relevantTxs.has(e.baseEventParams.txHash));
};

export const processOnChainData = async (data: OnChainData, backfill?: boolean) => {
  if (config.focusCollectionAddress) {
    await filterOnChainDataByCollection(data, config.focusCollectionAddress);
  }
  // Post-process fill events

  const allFillEvents = concat(data.fillEvents, data.fillEventsPartial, data.fillEventsOnChain);
  const nonFillTransferEvents = _.filter(data.nftTransferEvents, (transfer) => {
    return (
      transfer.from !== AddressZero &&
      !_.some(
        allFillEvents,
        (fillEvent) =>
          fillEvent.baseEventParams.txHash === transfer.baseEventParams.txHash &&
          fillEvent.baseEventParams.logIndex === transfer.baseEventParams.logIndex &&
          fillEvent.baseEventParams.batchIndex === transfer.baseEventParams.batchIndex
      )
    );
  });

  const startAssignMintCommentToFillEvents = Date.now();
  if (!backfill) {
    await Promise.all([assignMintCommentToFillEvents(allFillEvents, data.mintComments)]);
  }
  const endAssignMintCommentToFillEvents = Date.now();

  const startAssignSourceToFillEvents = Date.now();
  if (!backfill) {
    await Promise.all([
      assignSourceToFillEvents(allFillEvents),
      pendingTxs.onFillEventsCallback(allFillEvents),
    ]);
  }
  const endAssignSourceToFillEvents = Date.now();

  // Persist events
  // WARNING! Fills should always come first in order to properly mark
  // the fillability status of orders as 'filled' and not 'no-balance'
  const startPersistEvents = Date.now();
  await Promise.all([
    es.fills.addEvents(data.fillEvents),
    es.fills.addEventsPartial(data.fillEventsPartial),
    es.fills.addEventsOnChain(data.fillEventsOnChain),
  ]);
  const endPersistEvents = Date.now();

  // Persist other events
  const startPersistOtherEvents = Date.now();
  await Promise.all([
    es.cancels.addEvents(data.cancelEvents),
    es.cancels.addEventsOnChain(data.cancelEventsOnChain),
    es.bulkCancels.addEvents(data.bulkCancelEvents),
    es.nonceCancels.addEvents(data.nonceCancelEvents),
    es.nftApprovals.addEvents(data.nftApprovalEvents),
    es.ftTransfers.addEvents(data.ftTransferEvents, Boolean(backfill)),
    es.nftTransfers.addEvents(data.nftTransferEvents, Boolean(backfill)),
  ]);

  const endPersistOtherEvents = Date.now();

  const startAddingToQueues = Date.now();
  // Trigger further processes:
  // - revalidate potentially-affected orders
  // - store on-chain orders
  if (!backfill) {
    // WARNING! It's very important to guarantee that the previous
    // events are persisted to the database before any of the jobs
    // below are executed. Otherwise, the jobs can potentially use
    // stale data which will cause inconsistencies (eg. orders can
    // have wrong statuses)
    await Promise.all([
      orderUpdatesByIdJob.addToQueue(data.orderInfos),
      orderUpdatesByMakerJob.addToQueue(data.makerInfos),
      permitUpdatesJob.addToQueue(data.permitInfos),
      orderbookOrdersJob.addToQueue(data.orders),
    ]);
  }
  const endAddingToQueues = Date.now();

  // Mints and last sales
  const startAddingToQueuesMintAndLastSales = Date.now();
  await transferUpdatesJob.addToQueue(nonFillTransferEvents);
  await mintQueueJob.addToQueue(data.mintInfos);
  await fillUpdatesJob.addToQueue(data.fillInfos);
  const endAddingToQueuesMintAndLastSales = Date.now();

  const startMintProcess = Date.now();
  if (!backfill) {
    await mintsProcessJob.addToQueue(data.mints);
  }
  const endMintProcess = Date.now();

  const startFillPostProcess = Date.now();
  if (allFillEvents.length) {
    await fillPostProcessJob.addToQueue([allFillEvents]);
  }
  const endFillPostProcess = Date.now();

  // TODO: Is this the best place to handle activities?

  const recalcCollectionOwnerCountInfo: RecalcOwnerCountQueueJobPayload[] =
    data.nftTransferEvents.map((event) => ({
      context: "event-sync",
      kind: "contactAndTokenId",
      data: {
        contract: event.baseEventParams.address,
        tokenId: event.tokenId,
      },
    }));

  const startProcessRecalcOwnerCount = Date.now();
  if (recalcCollectionOwnerCountInfo.length) {
    await recalcOwnerCountQueueJob.addToQueue(recalcCollectionOwnerCountInfo);
  }
  const endProcessRecalcOwnerCount = Date.now();

  // Process fill activities
  const fillActivityInfos: ProcessActivityEventJobPayload[] = allFillEvents.map((event) => {
    return {
      kind: ProcessActivityEventKind.fillEvent,
      data: {
        txHash: event.baseEventParams.txHash,
        logIndex: event.baseEventParams.logIndex,
        batchIndex: event.baseEventParams.batchIndex,
      },
    };
  });

  const startProcessActivityEvent = Date.now();
  await processActivityEventJob.addToQueue(fillActivityInfos);
  const endProcessActivityEvent = Date.now();

  const filteredNftTransferEvents = data.nftTransferEvents.filter((event) => {
    if (event.from !== AddressZero) {
      return true;
    }

    return !fillActivityInfos.some((fillActivityInfo) => {
      const fillActivityInfoData = fillActivityInfo.data as NftTransferEventInfo;

      return (
        fillActivityInfoData.txHash === event.baseEventParams.txHash &&
        fillActivityInfoData.logIndex === event.baseEventParams.logIndex &&
        fillActivityInfoData.batchIndex === event.baseEventParams.batchIndex
      );
    });
  });

  // Process transfer activities
  const transferActivityInfos: ProcessActivityEventJobPayload[] = filteredNftTransferEvents.map(
    (event) => ({
      kind: ProcessActivityEventKind.nftTransferEvent,
      data: {
        txHash: event.baseEventParams.txHash,
        logIndex: event.baseEventParams.logIndex,
        batchIndex: event.baseEventParams.batchIndex,
      },
    })
  );

  const startProcessTransferActivityEvent = Date.now();
  await processActivityEventJob.addToQueue(transferActivityInfos);
  const endProcessTransferActivityEvent = Date.now();

  // Process swap activities
  const startProcessSwapActivityEvent = Date.now();

  if (config.enableElasticsearchFtActivities) {
    const swapActivityInfos: ProcessActivityEventJobPayload[] = data.swaps.map((event) => ({
      kind: ProcessActivityEventKind.swapCreated,
      data: {
        block: event.baseEventParams.block,
        blockTimestamp: event.baseEventParams.timestamp,
        txHash: event.baseEventParams.txHash,
        wallet: event.wallet,
        fromToken: event.fromToken,
        fromAmount: event.fromAmount,
        toToken: event.toToken,
        toAmount: event.toAmount,
      },
    }));

    if (swapActivityInfos.length) {
      await processActivityEventJob.addToQueue(swapActivityInfos);
    }
  }

  const endProcessSwapActivityEvent = Date.now();

  // Optionally persist only relevant transactions in focus mode (post‑gating)
  if (config.focusCollectionAddress && config.focusPersistRelevantTx) {
    const txHashes = new Set<string>();
    const collect = (arr: { baseEventParams: { txHash: string } }[]) =>
      arr.forEach((e) => e?.baseEventParams?.txHash && txHashes.add(e.baseEventParams.txHash));

    collect(data.nftTransferEvents as any);
    collect(data.nftApprovalEvents as any);
    collect(data.fillEvents as any);
    collect(data.fillEventsPartial as any);
    collect(data.fillEventsOnChain as any);
    collect(data.ftTransferEvents as any);

    // Persist distinct transactions
    if (txHashes.size) {
      const txs: DbTransaction[] = [];
      await Promise.all(
        [...txHashes].map(async (txHash) => {
          try {
            const tx = (await fetchTransaction(txHash)) as DbTransaction;
            if (tx) txs.push(tx);
          } catch {
            // best-effort; skip failures
          }
        })
      );

      if (txs.length) {
        await saveTransactionsV2(txs);
      }
    }
  }

  return {
    addingToQueues: endAddingToQueues - startAddingToQueues,
    addingToQueuesMintAndLastSales:
      endAddingToQueuesMintAndLastSales - startAddingToQueuesMintAndLastSales,
    mintProcess: endMintProcess - startMintProcess,
    // Return the time it took to process each step
    processRecalcOwnerCount: endProcessRecalcOwnerCount - startProcessRecalcOwnerCount,
    assignMintCommentToFillEvents:
      endAssignMintCommentToFillEvents - startAssignMintCommentToFillEvents,
    assignSourceToFillEvents: endAssignSourceToFillEvents - startAssignSourceToFillEvents,
    persistEvents: endPersistEvents - startPersistEvents,
    endPersistEvents: format(new Date(endPersistEvents), "yyyy-MM-dd HH:mm:ss.SSS"),
    persistOtherEvents: endPersistOtherEvents - startPersistOtherEvents,
    fillPostProcess: endFillPostProcess - startFillPostProcess,
    processActivityEvent: endProcessActivityEvent - startProcessActivityEvent,
    processTransferActivityEvent:
      endProcessTransferActivityEvent - startProcessTransferActivityEvent,
    processSwapActivityEvent: endProcessSwapActivityEvent - startProcessSwapActivityEvent,

    // Return the number of events processed
    fillEvents: data.fillEvents.length,
    fillEventsPartial: data.fillEventsPartial.length,
    fillEventsOnChain: data.fillEventsOnChain.length,
    cancelEvents: data.cancelEvents.length,
    cancelEventsOnChain: data.cancelEventsOnChain.length,
    bulkCancelEvents: data.bulkCancelEvents.length,
    nonceCancelEvents: data.nonceCancelEvents.length,
    nftApprovalEvents: data.nftApprovalEvents.length,
    ftTransferEvents: data.ftTransferEvents.length,
    nftTransferEvents: data.nftTransferEvents.length,
    fillInfos: data.fillInfos.length,
    orderInfos: data.orderInfos.length,
    makerInfos: data.makerInfos.length,
    permitInfos: data.permitInfos.length,
    orders: data.orders.length,
    mints: data.mints.length,
    mintComments: data.mintComments.length,
    mintInfos: data.mintInfos.length,
    swaps: data.swaps.length,
  };
};
