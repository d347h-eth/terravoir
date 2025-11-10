import { searchForCall } from "@georgeroman/evm-tx-simulator";
import * as Sdk from "@reservoir0x/sdk";

import { bn } from "@/common/utils";
import { config } from "@/config/index";
import { logger } from "@/common/logger";
import { getEventData } from "@/events-sync/data";
import { EnhancedEvent, OnChainData } from "@/events-sync/handlers/utils";
import * as utils from "@/events-sync/utils";
import { getUSDAndNativePrices } from "@/utils/prices";

export const handleEvents = async (events: EnhancedEvent[], onChainData: OnChainData) => {
  // For keeping track of all individual trades per transaction
  const trades = {
    order: new Map<string, number>(),
  };

  // Handle the events
  for (const { subKind, baseEventParams } of events) {
    switch (subKind) {
      case "blur-v2-execution":
      case "blur-v2-execution-721-packed":
      case "blur-v2-execution-721-taker-fee-packed":
      case "blur-v2-execution-721-maker-fee-packed": {
        const txHash = baseEventParams.txHash;
        const txTrace = await utils.fetchTransactionTrace(txHash);
        if (!txTrace) {
          // Skip any failed attempts to get the trace
          // Emit diagnostic so we can see why fills are missing
          // (e.g., RPC missing debug tracer)
          logger.info(
            "blur-v2-handler",
            JSON.stringify({ topic: "no-trace", txHash })
          );
          break;
        }

        const exchangeAddrEnv = process.env.BLUR_V2_EXCHANGE_ADDRESS?.toLowerCase();
        const exchangeAddrSdk = Sdk.BlurV2.Addresses.Exchange[config.chainId]?.toLowerCase();
        const fallbackMainnet = "0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5";
        const resolvedExchangeAddress =
          exchangeAddrEnv || exchangeAddrSdk || (config.chainId === 1 ? fallbackMainnet : undefined);

        if (!resolvedExchangeAddress) {
          // Cannot resolve exchange address for this chain; skip
          break;
        }

        const exchange = new Sdk.BlurV2.Exchange(config.chainId);
        const exchangeAddress = resolvedExchangeAddress;
        const methods = [
          {
            selector: "0x3925c3c3",
            name: "takeAsk",
          },
          {
            selector: "0x70bce2d6",
            name: "takeAskSingle",
          },
          {
            selector: "0x133ba9a6",
            name: "takeAskPool",
          },
          {
            selector: "0x336d8206",
            name: "takeAskSinglePool",
          },
          {
            selector: "0x7034d120",
            name: "takeBid",
          },
          {
            selector: "0xda815cb5",
            name: "takeBidSingle",
          },
        ];

        const tradeRank = trades.order.get(`${txHash}-${exchangeAddress}`) ?? 0;
        // Some providers return traces with missing fields (e.g., input). Sanitize tree.
        const sanitize = (node: any): any => {
          if (!node) return node;
          if (typeof node.input !== "string") node.input = "0x";
          if (node.calls && Array.isArray(node.calls)) {
            node.calls = node.calls.map(sanitize);
          }
          return node;
        };

        // Debug: log the actual structure we received
        // logger.debug(
        //   "blur-v2-handler",
        //   JSON.stringify({
        //     topic: "trace-structure-debug",
        //     txHash,
        //     hasHashProp: "hash" in (txTrace as any),
        //     hasCallsProp: "calls" in (txTrace as any),
        //     hasResultProp: "result" in (txTrace as any),
        //     hasToProp: "to" in (txTrace as any),
        //     hasInputProp: "input" in (txTrace as any),
        //     topLevelKeys: Object.keys(txTrace as any).sort(),
        //     callsType: Array.isArray((txTrace as any).calls) ? "array" : typeof (txTrace as any).calls,
        //   })
        // );

        // txTrace can have two shapes:
        // 1. Direct from RPC: { from, to, input, calls: [...], ... }
        // 2. From DB wrapper: { hash, calls: [...] } where calls is an ARRAY
        //    In this case, the root trace is the top-level object we're looking for,
        //    but it's been flattened - the root call properties are lost and only
        //    nested calls are preserved in the array.

        let rawTrace: any;
        if ((txTrace as any).hash && "calls" in (txTrace as any)) {
          // DB wrapper detected - calls is an array
          // We need to reconstruct by wrapping the calls array or use result if present
          if ((txTrace as any).result) {
            rawTrace = (txTrace as any).result;
          } else if (Array.isArray((txTrace as any).calls) && (txTrace as any).calls.length > 0) {
            // The root call IS the transaction itself - use the first call in the array
            // as it represents the entry point (the actual marketplace call)
            rawTrace = (txTrace as any).calls[0];
          } else {
            // Fallback: create a synthetic root with the calls array
            rawTrace = { calls: (txTrace as any).calls, input: "0x" };
          }
        } else {
          // Direct RPC format
          rawTrace = txTrace;
        }

        // Sanitize the entire trace tree
        const sanitizedTrace = sanitize(rawTrace);

        // Support trace.result if present (some RPC formats)
        const rootTrace = (sanitizedTrace as any).result || sanitizedTrace;

        // Debug: log what we extracted
        // logger.debug(
        //   "blur-v2-handler",
        //   JSON.stringify({
        //     topic: "trace-extracted-debug",
        //     txHash,
        //     rootTraceTo: rootTrace.to,
        //     rootTraceInput: rootTrace.input?.slice(0, 20),
        //     rootTraceHasCalls: !!rootTrace.calls,
        //     rootTraceCallsLength: rootTrace.calls?.length,
        //   })
        // );

        let executeCallTrace: any;

        // First, check if the root trace itself is the Exchange call
        const selectors = new Set(methods.map((m) => m.selector));
        const rootTo = rootTrace.to?.toLowerCase();
        const rootFrom = rootTrace.from?.toLowerCase();
        const rootInput = rootTrace.input;
        const rootSelector = rootInput?.slice(0, 10);

        // Match if:
        // 1. Regular CALL: to === Exchange and input matches, OR
        // 2. DELEGATECALL: from === Exchange and input matches (common when Exchange delegates to implementation)
        if (
          rootInput &&
          selectors.has(rootSelector) &&
          (rootTo === exchangeAddress || rootFrom === exchangeAddress)
        ) {
          executeCallTrace = rootTrace;
          // logger.info(
          //   "blur-v2-handler",
          //   JSON.stringify({ topic: "found-at-root", txHash, matchedVia: rootTo === exchangeAddress ? "to" : "from" })
          // );
        } else if (rootTrace.to || rootTrace.input) {
          // Log why root check didn't match (only if trace has data)
          logger.debug(
            "blur-v2-handler",
            JSON.stringify({
              topic: "root-check-miss",
              txHash,
              rootTo,
              rootFrom,
              exchangeAddress,
              toMatches: rootTo === exchangeAddress,
              fromMatches: rootFrom === exchangeAddress,
              hasInput: !!rootInput,
              rootSelector,
              selectorMatches: rootSelector ? selectors.has(rootSelector) : false,
            })
          );
        }

        // If not found at root, search within nested calls
        if (!executeCallTrace && rootTrace.calls && Array.isArray(rootTrace.calls) && rootTrace.calls.length > 0) {
          try {
            executeCallTrace = searchForCall(
              rootTrace.calls,
              {
                to: exchangeAddress,
                // do not constrain type; some nodes may be DELEGATECALL depending on client
                sigHashes: methods.map((c) => c.selector),
              } as any,
              tradeRank
            );
          } catch (err) {
            // searchForCall can fail if the calls array has unexpected structure
            logger.debug(
              "blur-v2-handler",
              JSON.stringify({ topic: "searchForCall-error", txHash, error: String(err) })
            );
          }
        }

        // Fallback: also try the Delegate contract in nested calls
        if (!executeCallTrace && rootTrace.calls && Array.isArray(rootTrace.calls) && rootTrace.calls.length > 0) {
          try {
            const delegateAddrEnv = process.env.BLUR_V2_DELEGATE_ADDRESS?.toLowerCase();
            const delegateAddrSdk = Sdk.BlurV2.Addresses.Delegate[config.chainId]?.toLowerCase();
            const delegateAddress = delegateAddrEnv || delegateAddrSdk;
            if (delegateAddress) {
              executeCallTrace = searchForCall(
                rootTrace.calls,
                {
                  to: delegateAddress,
                  sigHashes: methods.map((c) => c.selector),
                } as any,
                tradeRank
              );
            }
          } catch (err) {
            // searchForCall can fail if the calls array has unexpected structure
            logger.debug(
              "blur-v2-handler",
              JSON.stringify({ topic: "searchForCall-delegate-error", txHash, error: String(err) })
            );
          }
        }

        // Fallback: scan the entire trace tree (including root) for matching selector
        if (!executeCallTrace) {
          const dfs = (node: any): any => {
            if (!node) return null;
            if (typeof node.input === "string" && selectors.has(node.input.slice(0, 10))) {
              return node;
            }
            if (node.calls && Array.isArray(node.calls)) {
              for (const c of node.calls) {
                const found = dfs(c);
                if (found) return found;
              }
            }
            return null;
          };
          const found = dfs(rootTrace);
          if (found) {
            executeCallTrace = found;
            logger.info(
              "blur-v2-handler",
              JSON.stringify({ topic: "fallback-match-anywhere", txHash })
            );
          }
        }
        if (!executeCallTrace) {
          logger.info(
            "blur-v2-handler",
            JSON.stringify({ topic: "no-executeCallTrace", txHash, exchangeAddress })
          );
          break;
        }

        const matchMethod = methods.find((c) => executeCallTrace.input.includes(c.selector));
        if (!matchMethod) {
          logger.info(
            "blur-v2-handler",
            JSON.stringify({ topic: "no-matchMethod", txHash, selectors: methods.map((m)=>m.name) })
          );
          break;
        }

        const inputData = exchange.contract.interface.decodeFunctionData(
          matchMethod.name,
          executeCallTrace.input
        );

        const isTakeAsk = ["takeAsk", "takeAskSingle", "takeAskPool", "takeAskSinglePool"].includes(
          matchMethod.name
        );

        const tx = await utils.fetchTransaction(baseEventParams.txHash);
        const isBatchCall = ["takeAsk", "takeAskPool", "takeBid"].includes(matchMethod.name);
        const isBuyToBorrow = [
          "0x8593d5fc", // buyToBorrow
          "0xbe5898ff", // buyToBorrowV2ETH
          "0xd386b343", // buyToBorrowV2
        ].some((c) => tx.data.includes(c));

        const rawInput = inputData.inputs;
        const inputs = !isBatchCall
          ? [inputData.inputs]
          : // eslint-disable-next-line @typescript-eslint/no-explicit-any
            inputData.inputs.exchanges.map((exchange: any) => {
              return {
                order: inputData.inputs.orders[exchange.index],
                exchange,
              };
            });

        for (let i = 0; i < inputs.length; i++) {
          const { order, exchange } = inputs[i];

          const listing = exchange.listing;
          const takerData = exchange.taker;

          const tokenRecipient =
            isTakeAsk && !isBuyToBorrow
              ? rawInput.tokenRecipient.toLowerCase()
              : tx.from.toLowerCase();

          const trader = order.trader.toLowerCase();
          const collection = order.collection.toLowerCase();
          const tokenId = takerData.tokenId.toString();
          const amount = takerData.amount.toString();

          const maker = trader;
          let taker = tokenRecipient;
          const currencyPrice = listing.price.toString();
          const orderSide = isTakeAsk ? "sell" : "buy";

          // Handle: attribution
          const orderKind = "blur-v2";
          const attributionData = await utils.extractAttributionData(
            baseEventParams.txHash,
            orderKind
          );
          if (attributionData.taker) {
            taker = attributionData.taker;
          }

          // Handle: prices
          const currency = isTakeAsk
            ? Sdk.Common.Addresses.Native[config.chainId]
            : Sdk.Blur.Addresses.Beth[config.chainId];

          const priceData = await getUSDAndNativePrices(
            currency,
            currencyPrice,
            baseEventParams.timestamp
          );

          if (!priceData.nativePrice) {
            // We must always have the native price
            break;
          }

          const relevantEvent = events.find((e) => {
            if (e.kind === "blur-v2") {
              const eventData = getEventData([e.subKind])[0];
              const { args } = eventData.abi.parseLog(e.log);
              if (e.subKind === "blur-v2-execution") {
                const evCollection = args["transfer"].collection.toLowerCase();
                const evTokenId = args["transfer"].id.toString();
                return evCollection === collection && evTokenId === tokenId;
              } else {
                // Last 20 bytes (make sure to pad)
                const evCollection =
                  "0x" +
                  args["collectionPriceSide"]
                    .toHexString()
                    .slice(2)
                    .padStart(64, "0")
                    .slice(24)
                    .toLowerCase();
                // First 20 bytes (make sure to pad)
                const evTokenId = bn(
                  "0x" +
                    args["tokenIdListingIndexTrader"]
                      .toHexString()
                      .slice(2)
                      .padStart(64, "0")
                      .slice(0, 22)
                ).toString();
                return evCollection === collection && evTokenId === tokenId;
              }
            }
          });

          if (relevantEvent) {
            const eventData = getEventData([relevantEvent.subKind])[0];
            const { args } = eventData.abi.parseLog(relevantEvent.log);

            const orderId = args.orderHash.toLowerCase();
            onChainData.fillEventsPartial.push({
              orderId,
              orderKind,
              orderSide,
              maker,
              taker,
              price: priceData.nativePrice,
              currency,
              currencyPrice,
              usdPrice: priceData.usdPrice,
              contract: collection.toLowerCase(),
              tokenId: tokenId.toString(),
              amount: amount.toString(),
              orderSourceId: attributionData.orderSource?.id,
              aggregatorSourceId: attributionData.aggregatorSource?.id,
              fillSourceId: attributionData.fillSource?.id,
              baseEventParams: {
                ...baseEventParams,
                // TODO: The log index is wrong (should be taken from `relevantEvent`)
                logIndex: baseEventParams.logIndex + i,
              },
            });

            onChainData.fillInfos.push({
              context: `${orderId}-${baseEventParams.txHash}-${baseEventParams.logIndex + i}`,
              orderId: orderId,
              orderSide,
              contract: collection.toLowerCase(),
              tokenId: tokenId.toString(),
              amount: amount.toString(),
              price: priceData.nativePrice,
              timestamp: baseEventParams.timestamp,
              maker,
              taker,
            });
          } else {
            logger.info(
              "blur-v2-handler",
              JSON.stringify({
                topic: "no-relevantEvent",
                txHash,
                collection,
                tokenId,
                subKinds: events.filter((e)=>e.kind==="blur-v2").map((e)=>e.subKind)
              })
            );
          }
        }

        trades.order.set(`${txHash}-${exchangeAddress}`, tradeRank + 1);

        break;
      }
    }
  }
};
