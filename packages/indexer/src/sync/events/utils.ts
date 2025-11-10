/* eslint-disable @typescript-eslint/no-explicit-any */

import { Interface } from "@ethersproject/abi";
import { BlockWithTransactions } from "@ethersproject/abstract-provider";
import { AddressZero } from "@ethersproject/constants";
import { Formatter, JsonRpcProvider } from "@ethersproject/providers";
import { getTxTraces } from "@georgeroman/evm-tx-simulator";
import { CallTrace } from "@georgeroman/evm-tx-simulator/dist/types";
import * as Sdk from "@reservoir0x/sdk";
import { getSourceV1 } from "@reservoir0x/sdk/dist/utils";
import _ from "lodash";

import { logger } from "@/common/logger";
import { archiveProvider, baseProvider } from "@/common/provider";
import { redis } from "@/common/redis";
import { bn } from "@/common/utils";
import { config } from "@/config/index";
import { extractNestedTx } from "@/events-sync/handlers/attribution";
import { collectionNewContractDeployedJob } from "@/jobs/collections/collection-contract-deployed";
import { Sources } from "@/models/sources";
import { SourcesEntity } from "@/models/sources/sources-entity";
import {
  Transaction,
  getTransaction,
  saveTransaction,
  saveTransactionsV2,
} from "@/models/transactions";
import { getTransactionLogs, saveTransactionLogs } from "@/models/transaction-logs";
import {
  TransactionTrace,
  getTransactionTraces,
  saveTransactionTraces,
} from "@/models/transaction-traces";
import { OrderKind, getOrderSourceByOrderId, getOrderSourceByOrderKind } from "@/orderbook/orders";
import { getRouters } from "@/utils/routers";

const chainsWithoutCallTracer = [324];

export type ContractAddress = {
  address: string;
  deploymentTxHash: string;
  deploymentSender: string;
  deploymentFactory: string;
  bytecode: string;
};

export const fetchTransaction = async (txHash: string) => {
  const redisTx = await redis.get(`tx:${txHash}`);
  if (redisTx) {
    return JSON.parse(redisTx);
  }

  // Get from database
  const dbTx = await getTransaction(txHash);
  if (dbTx) {
    return dbTx;
  }

  // Get from provider
  let tx = await baseProvider.getTransaction(txHash);
  if (!tx) {
    return undefined;
  }

  if (!tx.timestamp) {
    const block = await baseProvider.getBlock(tx.blockNumber!);
    tx = {
      ...tx,
      timestamp: block.timestamp,
    };
  }

  const normalized = {
    hash: tx.hash.toLowerCase(),
    from: tx.from.toLowerCase(),
    to: (tx.to || AddressZero).toLowerCase(),
    value: tx.value.toString(),
    data: tx.data.toLowerCase(),
    blockNumber: tx.blockNumber!,
    blockTimestamp: tx.timestamp!,
    blockHash: tx.blockHash ? tx.blockHash.toLowerCase() : null,
  };

  // In focus mode, avoid persisting transactions to the database to keep
  // irrelevant rows from accumulating during wide capture/backfills. We still
  // return the normalized transaction for attribution logic.
  if (config.focusCollectionAddress) {
    return normalized;
  }

  return saveTransaction(normalized);
};

const normalizeHexValue = (value?: string | null) => {
  if (typeof value !== "string" || !value.length) {
    return "0x";
  }

  const prefixed = value.startsWith("0x") || value.startsWith("0X") ? value : `0x${value}`;
  return prefixed.toLowerCase();
};

const sanitizeCallTraceNode = (node: CallTrace): CallTrace => {
  const sanitized: CallTrace = {
    ...node,
    from: node.from?.toLowerCase?.() ?? AddressZero,
    to: node.to?.toLowerCase?.() ?? AddressZero,
    input: normalizeHexValue(node.input),
    output: normalizeHexValue(node.output),
    gas: normalizeHexValue(node.gas),
    gasUsed: normalizeHexValue(node.gasUsed),
  };

  if (Array.isArray(node.calls) && node.calls.length) {
    sanitized.calls = node.calls
      .filter((call): call is CallTrace => Boolean(call))
      .map((call) => sanitizeCallTraceNode(call));
  } else {
    delete sanitized.calls;
  }

  return sanitized;
};

export const getTraceCallRoot = (calls?: CallTrace | CallTrace[] | null) => {
  if (!calls) {
    return undefined;
  }

  if (!Array.isArray(calls)) {
    return sanitizeCallTraceNode(calls);
  }

  const sanitizedChildren = calls
    .filter((call): call is CallTrace => Boolean(call))
    .map((call) => sanitizeCallTraceNode(call));

  if (!sanitizedChildren.length) {
    return undefined;
  }

  return {
    type: "call",
    from: sanitizedChildren[0].from ?? AddressZero,
    to: sanitizedChildren[0].to ?? AddressZero,
    input: "0x",
    output: "0x",
    gas: "0x0",
    gasUsed: "0x0",
    calls: sanitizedChildren,
  } as CallTrace;
};

export const fetchTransactionTraces = async (txHashes: string[], provider?: JsonRpcProvider) => {
  // Some traces might already exist
  const existingTraces = await getTransactionTraces(txHashes);
  const existingTxHashes = Object.fromEntries(existingTraces.map(({ hash }) => [hash, true]));

  // Only fetch those that don't yet exist
  const missingTxHashes = txHashes.filter((txHash) => !existingTxHashes[txHash]);
  if (missingTxHashes.length) {
    // For efficiency, fetch in multiple small batches
    const batches = _.chunk(missingTxHashes, 10);
    const missingTraces = (
      await Promise.all(
        batches.map(async (batch) => {
          let parsed: TransactionTrace[] = [];
          try {
            const raw = await getTxTraces(
              batch.map((hash) => ({ hash })),
              provider ?? baseProvider
            );

            // raw is an object mapping txHash -> calls (array) or possibly other shapes
            parsed = Object.entries(raw)
              .map(([hash, calls]) => {
                if (Array.isArray(calls)) {
                  return { hash, calls: calls as unknown as CallTrace } as TransactionTrace;
                }
                // Some providers return a single call trace under `result`
                if (calls && (calls as any).result) {
                  return { hash, calls: (calls as any).result as CallTrace } as TransactionTrace;
                }
                return null;
              })
              .filter((t): t is TransactionTrace => Boolean(t && (t as any).calls));

            if (parsed.length) {
              await saveTransactionTraces(parsed);
            }
          } catch (e) {
            logger.warn(
              "tx-traces",
              JSON.stringify({
                topic: "getTxTraces",
                message: `Failed to fetch traces for batch; attempting per-tx fallback`,
                size: batch.length,
                error: `${e}`,
              })
            );
          }

          // Fallback: any hashes not covered by parsed -> try debug_traceTransaction individually
          const covered = new Set(parsed.map((t) => t.hash));
          const fallback: TransactionTrace[] = [];
          for (const hash of batch) {
            if (covered.has(hash)) continue;
            try {
              const single = await getTransactionTraceFromRPC(hash);
              if (single) {
                // Derive a `calls` payload from `calls` or `result`
                const calls = (single as any).calls || (single as any).result;
                if (calls) {
                  const t = { hash, calls: calls as CallTrace } as TransactionTrace;
                  fallback.push(t);
                }
              }
            } catch (e) {
              // Skip silently; we'll proceed with what we have
            }
          }

          if (fallback.length) {
            await saveTransactionTraces(fallback);
            logger.info(
              "tx-traces",
              JSON.stringify({ topic: "fallbackPerTx", salvaged: fallback.length })
            );
          }

          return parsed.concat(fallback);
        })
      )
    ).flat();

    return existingTraces.concat(missingTraces as TransactionTrace[]);
  } else {
    return existingTraces;
  }
};

export const fetchTransactionTrace = async (txHash: string) => {
  try {
    const traces = await fetchTransactionTraces([txHash]);
    if (!traces.length) {
      return undefined;
    }
    return traces[0];
  } catch (e) {
    logger.warn(
      "tx-trace",
      JSON.stringify({ topic: "fetchTransactionTrace", txHash, error: `${e}` })
    );
    return undefined;
  }
};

export const fetchTransactionLogs = async (txHash: string) =>
  getTransactionLogs(txHash).catch(async () => {
    const receipt = await baseProvider.getTransactionReceipt(txHash);

    return saveTransactionLogs({
      hash: txHash,
      logs: receipt.logs,
    });
  });

export const extractAttributionData = async (
  txHash: string,
  orderKind: OrderKind,
  options?: {
    address?: string;
    orderId?: string;
  }
) => {
  const sources = await Sources.getInstance();

  let aggregatorSource: SourcesEntity | undefined;
  let fillSource: SourcesEntity | undefined;
  let taker: string | undefined;

  let orderSource: SourcesEntity | undefined;
  if (options?.orderId) {
    // First try to get the order's source by id
    orderSource = await getOrderSourceByOrderId(options.orderId);
  }
  if (!orderSource) {
    // Default to getting the order's source by kind
    orderSource = await getOrderSourceByOrderKind(orderKind, options?.address);
  }

  // Handle internal transactions
  let tx: Pick<Transaction, "hash" | "from" | "to" | "data"> = await fetchTransaction(txHash);
  try {
    const nestedTx = await extractNestedTx(tx, true);
    if (nestedTx) {
      tx = nestedTx;
    }
  } catch {
    // Skip errors
  }

  // Properly set the taker when filling through router contracts
  const routers = await getRouters();

  let router = routers.get(tx.to);
  if (!router) {
    // Handle cases where we transfer directly to the router when filling bids
    if (tx.data.startsWith("0xb88d4fde")) {
      const iface = new Interface([
        "function safeTransferFrom(address from, address to, uint256 tokenId, bytes data)",
      ]);
      const result = iface.decodeFunctionData("safeTransferFrom", tx.data);
      router = routers.get(result.to.toLowerCase());
    } else if (tx.data.startsWith("0xf242432a")) {
      const iface = new Interface([
        "function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes data)",
      ]);
      const result = iface.decodeFunctionData("safeTransferFrom", tx.data);
      router = routers.get(result.to.toLowerCase());
    }
  }

  if (router) {
    taker = tx.from;

    // The taker will be wrong if this is a transaction where the recipient
    // is different from `msg.sender`. In this case we parse the executions
    // (under the assumption that this can only happen when filling via our
    // router contract) and extract the actual taker from there.

    const sdkRouter = new Sdk.RouterV6.Router(config.chainId, baseProvider);
    const executions = sdkRouter.parseExecutions(tx.data);
    if (executions.length) {
      // Only check the first execution
      const { params } = executions[0];
      const viaRelayer = params.fillTo.toLowerCase() !== params.refundTo.toLowerCase();
      if (viaRelayer) {
        taker = params.fillTo;
      }
    }
  }

  let source = getSourceV1(tx.data);
  if (!source) {
    const last4Bytes = "0x" + tx.data.slice(-8);
    source = sources.getByDomainHash(last4Bytes)?.domain;
  }

  // Reference: https://github.com/reservoirprotocol/core/issues/22#issuecomment-1191040945
  if (source) {
    if (source === "gem.xyz") {
      aggregatorSource = await sources.getOrInsert("gem.xyz");
    } else if (source === "blur.io") {
      aggregatorSource = await sources.getOrInsert("blur.io");
    } else if (source === "alphasharks.io") {
      aggregatorSource = await sources.getOrInsert("alphasharks.io");
    } else if (source === "magically.gg") {
      aggregatorSource = await sources.getOrInsert("magically.gg");
    } else if (router) {
      aggregatorSource = router;
    }
    fillSource = await sources.getOrInsert(source);
  } else if (router) {
    fillSource = router;
    aggregatorSource = router;
  } else {
    fillSource = orderSource;
  }

  const secondSource = sources.getByDomainHash("0x" + tx.data.slice(-16, -8));
  const viaReservoir = secondSource?.domain === "reservoir.tools";
  if (viaReservoir) {
    aggregatorSource = secondSource;
  }

  return {
    orderSource,
    fillSource,
    aggregatorSource,
    taker,
  };
};

export const fetchBlock = async (blockNumber: number, provider?: JsonRpcProvider) => {
  if (provider) {
    logger.debug(
      "fetchBlock",
      JSON.stringify({
        topic: "dedicatedRpcNode",
        message: `fetchBlock. blockNumber=${blockNumber}`,
        providerUrl: provider.connection.url,
      })
    );
  }

  // For SEI only update the formatter to allow null for the value with default 0
  if ([1329, 713715].includes(config.chainId)) {
    const bigNumber = bn.bind(Formatter);
    baseProvider.formatter.formats.transaction = {
      ...baseProvider.formatter.getDefaultFormats().transaction,
      value: Formatter.allowNull(bigNumber, bn("0x0")),
    };
  }

  return provider
    ? await provider.getBlockWithTransactions(blockNumber)
    : await baseProvider.getBlockWithTransactions(blockNumber);
};

export const saveBlockTransactions = async (block: BlockWithTransactions) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const transactions = block.transactions.map((tx: any) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawTx = tx.raw as any;

    let value;
    // if its from redis, its a bigNumber object like  "value": {
    // "type": "BigNumber",
    // "hex": "0x06f05b59d3b20000"
    // },

    if (tx.value && tx.value?.type && tx.value?.type === "BigNumber") {
      value = Number(tx.value.hex).toString();
    } else {
      value = tx.value.toString();
    }

    let gasPrice;
    if (tx.gasPrice && tx.gasPrice?.type && tx.gasPrice?.type === "BigNumber") {
      gasPrice = Number(tx.gasPrice.hex).toString();
    } else {
      gasPrice = tx.gasPrice?.toString();
    }

    const gasUsed = rawTx?.gas ? bn(rawTx.gas).toString() : undefined;
    const gasFee = gasPrice && gasUsed ? bn(gasPrice).mul(gasUsed).toString() : undefined;

    return {
      hash: tx.hash.toLowerCase(),
      from: tx.from.toLowerCase(),
      to: (tx.to || AddressZero).toLowerCase(),
      value: value,
      data: tx.data.toLowerCase(),
      blockNumber: block.number,
      blockTimestamp: block.timestamp,
      blockHash: block.hash.toLowerCase(),
      gasPrice,
      gasUsed,
      gasFee,
    };
  });

  // Save all transactions within the block
  await saveTransactionsV2(transactions);
};

export const saveBlockTransactionsRedis = async (block: BlockWithTransactions) => {
  // Create transactions array to store
  const transactions = block.transactions.map((tx) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawTx = tx.raw as any;

    const gasPrice = tx.gasPrice?.toString();
    const gasUsed = rawTx?.gas ? bn(rawTx.gas).toString() : undefined;
    const gasFee = gasPrice && gasUsed ? bn(gasPrice).mul(gasUsed).toString() : undefined;

    return {
      hash: tx.hash.toLowerCase(),
      from: tx.from.toLowerCase(),
      to: (tx.to || AddressZero).toLowerCase(),
      value: tx.value.toString(),
      data: tx.data.toLowerCase(),
      blockNumber: block.number,
      blockTimestamp: block.timestamp,
      gasPrice,
      gasUsed,
      gasFee,
    };
  });

  // Save all transactions within the block to redis
  await Promise.all(
    transactions.map(async (tx) => {
      // This gets deletes once it gets flushed to the database
      await redis.set(`tx:${tx.hash}`, JSON.stringify(tx), "EX", 60 * 60);
    })
  );

  // Save the block data to redis
  await redis.set(`block:${block.number}`, JSON.stringify(block), "EX", 60 * 60);
};

export const _getTransactionTraces = async (
  Txs: { hash: string }[],
  block: number,
  provider?: JsonRpcProvider
) => {
  const timerStart = Date.now();
  let traces;

  try {
    traces = (await getTracesFromBlock(block, 5, provider)) as TransactionTrace[];
  } catch (e) {
    logger.warn(`get-transactions-traces`, `Failed to get traces from block ${block}, ${e}`);
  }

  if (!traces) {
    return {
      traces: [],
      getTransactionTracesTime: 0,
    };
  }

  // traces don't have the transaction hash, so we need to add it by using the txs array we are passing in by using the index of the trace
  traces = traces.map((trace, index) => {
    if (!Txs[index]) {
      logger.warn(`get-transactions-traces`, `Failed to get tx for trace ${trace}`);
      return null;
    }

    return {
      ...trace,
      hash: Txs[index].hash,
    };
  });

  traces = traces.filter((trace) => trace !== null) as TransactionTrace[];

  const timerEnd = Date.now();

  return {
    traces,
    getTransactionTracesTime: timerEnd - timerStart,
  };
};

export const getTracesFromBlock = async (
  blockNumber: number,
  retryMax = 5,
  provider?: JsonRpcProvider
) => {
  let traces: TransactionTrace[] | undefined;
  let retries = 0;

  if (provider) {
    logger.debug(
      "getTracesFromBlock",
      JSON.stringify({
        topic: "dedicatedRpcNode",
        message: `getTracesFromBlock. blockNumber=${blockNumber}`,
        providerUrl: provider.connection.url,
      })
    );
  }

  // eslint-disable-next-line
  const params: any[] = [blockNumberToHex(blockNumber)];
  if (!chainsWithoutCallTracer.includes(config.chainId)) {
    params.push({ tracer: "callTracer" });
  }

  while (!traces && retries < retryMax) {
    try {
      traces = provider
        ? await provider.send("debug_traceBlockByNumber", params)
        : await baseProvider.send("debug_traceBlockByNumber", params);
    } catch (error) {
      logger.warn(
        "getTracesFromBlock",
        JSON.stringify({
          topic: "dedicatedRpcNode",
          message: `Failed to get traces from provider - Retrying. blockNumber=${blockNumber}, error=${
            (error as any)?.error?.message
          }, retries=${retries}, retryMax=${retryMax}`,
          blockNumber,
          error,
          rpcErrorCode: (error as any)?.error?.code,
          rpcErrorMessage: (error as any)?.error?.message,
          providerUrl: provider?.connection.url,
          baseProviderUrl: baseProvider.connection.url,
        })
      );

      retries++;

      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  if (!traces && retries >= retryMax) {
    try {
      traces = await archiveProvider.send("debug_traceBlockByNumber", params);
    } catch (error) {
      logger.warn(
        "getTracesFromBlock",
        JSON.stringify({
          topic: "dedicatedRpcNode",
          message: `Failed to get traces from archive provider. blockNumber=${blockNumber}, error=${
            (error as any)?.error?.message
          }, retries=${retries}, retryMax=${retryMax}`,
          blockNumber,
          error,
          rpcErrorCode: (error as any)?.error?.code,
          rpcErrorMessage: (error as any)?.error?.message,
          archiveProviderUrl: archiveProvider.connection.url,
        })
      );
    }

    if (!traces && retries > 0) {
      logger.error(
        "getTracesFromBlock",
        JSON.stringify({
          topic: "dedicatedRpcNode",
          message: `Failed to get traces from provider - Stopped Retrying. blockNumber=${blockNumber}, retries=${retries}, retryMax=${retryMax}`,
          blockNumber,
          providerUrl: provider?.connection.url,
          baseProviderUrl: baseProvider.connection.url,
        })
      );
    }
  }

  return traces;
};

export const getTracesFromHashes = async (txHashes: string[]) => {
  const traces = await Promise.all(
    txHashes.map(async (txHash) => {
      const trace = await getTransactionTraceFromRPC(txHash);
      if (!trace) {
        logger.error("sync-events-v2", `Failed to get trace for tx: ${txHash}`);
        return null;
      }

      return {
        ...trace,
        hash: txHash,
      };
    })
  );
  return traces;
};

export const getTransactionTraceFromRPC = async (hash: string, retryMax = 10) => {
  let trace: TransactionTrace | undefined;
  let retries = 0;
  while (!trace && retries < retryMax) {
    try {
      // eslint-disable-next-line
      const params: any[] = [hash];

      if (!chainsWithoutCallTracer.includes(config.chainId)) {
        params.push({ tracer: "callTracer" });
      }
      trace = await baseProvider.send("debug_traceTransaction", params);
    } catch (e) {
      retries++;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  return trace;
};

export const blockNumberToHex = (blockNumber: number) => {
  return "0x" + blockNumber.toString(16);
};

const processCall = (trace: TransactionTrace, call: CallTrace) => {
  const processedCalls = [];
  if (
    (call.type.toUpperCase() as "CALL" | "STATICCALL" | "DELEGATECALL" | "CREATE" | "CREATE2") ===
      "CREATE" ||
    (call.type.toUpperCase() as "CALL" | "STATICCALL" | "DELEGATECALL" | "CREATE" | "CREATE2") ===
      "CREATE2"
  ) {
    processedCalls.push({
      address: call.to,
      deploymentTxHash: trace.hash,
      deploymentSender: call.from,
      deploymentFactory: call?.to || AddressZero,
      bytecode: call.input,
    });
  }

  if (call?.calls) {
    call.calls.forEach((c) => {
      const processedCall = processCall(trace, c);
      if (processedCall) {
        processedCalls.push(...processedCall);
      }
    });

    return processedCalls;
  }

  return processedCalls.length ? processedCalls : undefined;
};

export const processContractAddresses = async (
  traces: TransactionTrace[],
  blockTimestamp: number
) => {
  let contractAddresses: ContractAddress[] = [];

  for (const trace of traces) {
    // eslint-disable-next-line
    // @ts-ignore
    if (trace.result && !trace.result.error && !trace?.calls) {
      // eslint-disable-next-line
      // @ts-ignore
      const processedCall = processCall(trace, trace.result);
      if (processedCall) {
        contractAddresses.push(...processedCall);
      }
      // eslint-disable-next-line
      // @ts-ignore
    } else if (trace?.calls?.length > 0) {
      // eslint-disable-next-line
      // @ts-ignore
      trace?.calls?.forEach((call) => {
        const processedCall = processCall(trace, call);
        if (processedCall) {
          contractAddresses.push(...processedCall);
        }
      });
    }
  }

  // Filter out null/undefined contract addresses and those with null address property
  contractAddresses = contractAddresses.filter((ca) => ca && ca.address);

  // Focus-mode gate: only enqueue deployment jobs for the focus collection
  if (config.focusCollectionAddress) {
    const focus = config.focusCollectionAddress.toLowerCase();
    contractAddresses = contractAddresses.filter((ca) => ca.address.toLowerCase() === focus);
  }

  contractAddresses.forEach(async (ca) => {
    collectionNewContractDeployedJob.addToQueue({
      contract: ca.address,
      deployer: ca.deploymentSender,
      blockTimestamp,
    });
  });
};
