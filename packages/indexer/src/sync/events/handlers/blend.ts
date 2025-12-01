import { getEventData } from "@/events-sync/data";
import { EnhancedEvent, OnChainData } from "@/events-sync/handlers/utils";
import { getUSDAndNativePrices } from "@/utils/prices";
import * as utils from "@/events-sync/utils";
import * as Sdk from "@reservoir0x/sdk";
import { config } from "@/config/index";
import { logger } from "@/common/logger";
import { searchForCall } from "@georgeroman/evm-tx-simulator";
import * as commonHelpers from "@/orderbook/orders/common/helpers";

export const handleEvents = async (events: EnhancedEvent[], onChainData: OnChainData) => {
  // For keeping track of all individual trades per transaction
  const trades = {
    order: new Map<string, number>(),
  };

  // Handle the events
  for (const { subKind, baseEventParams, log } of events) {
    const eventData = getEventData([subKind])[0];
    switch (subKind) {
      case "blend-nonce-incremented": {
        const parsedLog = eventData.abi.parseLog(log);
        const maker = parsedLog.args["user"].toLowerCase();
        const newNonce = parsedLog.args["newNonce"].toString();
        onChainData.bulkCancelEvents.push({
          orderKind: "blend",
          maker,
          minNonce: newNonce,
          baseEventParams,
        });
        break;
      }

      case "blend-buy-locked": {
        const txHash = baseEventParams.txHash;
        const txTrace = await utils.fetchTransactionTrace(txHash);
        if (!txTrace) {
          break;
        }

        const exchange = new Sdk.Blend.Exchange(config.chainId);
        const exchangeAddress = exchange.contract.address;
        const methods = [
          {
            selector: "0xe7efc178",
            name: "buyLocked",
          },
          {
            selector: "0x8553b234",
            name: "buyLockedETH",
          },
          {
            selector: "0x2e2fb18b",
            name: "buyToBorrowLocked",
          },
          {
            selector: "0xb2a0bb86",
            name: "buyToBorrowLockedETH",
          },
        ];

        const tradeRank = trades.order.get(`${txHash}-${exchangeAddress}`) ?? 0;
        // Sanitize trace tree (some providers omit input)
        const sanitize = (node: any): any => {
          if (!node) return node;
          if (typeof node.input !== "string") node.input = "0x";
          if (node.calls && Array.isArray(node.calls)) {
            node.calls = node.calls.map(sanitize);
          }
          return node;
        };

        // txTrace can have two shapes:
        // 1. Direct from RPC: { from, to, input, calls: [...], ... }
        // 2. From DB wrapper: { hash, calls: [...] } where calls is an ARRAY

        let rawTrace: any;
        if ((txTrace as any).hash && "calls" in (txTrace as any)) {
          // DB wrapper detected
          if ((txTrace as any).result) {
            rawTrace = (txTrace as any).result;
          } else if (Array.isArray((txTrace as any).calls) && (txTrace as any).calls.length > 0) {
            // calls is an array - use the first element as the root trace
            rawTrace = (txTrace as any).calls[0];
          } else {
            // Fallback
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

        let executeCallTrace: any;

        // First, check if the root trace itself is the Exchange call
        const selectors = new Set(methods.map((m) => m.selector));
        const rootTo = rootTrace.to?.toLowerCase();
        const rootFrom = rootTrace.from?.toLowerCase();
        const rootInput = rootTrace.input;
        const rootSelector = rootInput?.slice(0, 10);

        // Match if:
        // 1. Regular CALL: to === Exchange and input matches, OR
        // 2. DELEGATECALL: from === Exchange and input matches
        if (
          rootInput &&
          selectors.has(rootSelector) &&
          (rootTo === exchangeAddress || rootFrom === exchangeAddress)
        ) {
          executeCallTrace = rootTrace;
          logger.info(
            "blend-handler",
            JSON.stringify({
              topic: "found-at-root",
              txHash,
              matchedVia: rootTo === exchangeAddress ? "to" : "from",
            })
          );
        }

        // If not found at root, search within nested calls
        if (
          !executeCallTrace &&
          rootTrace.calls &&
          Array.isArray(rootTrace.calls) &&
          rootTrace.calls.length > 0
        ) {
          try {
            executeCallTrace = searchForCall(
              rootTrace.calls,
              {
                to: exchangeAddress,
                type: "call",
                sigHashes: methods.map((c) => c.selector),
              },
              tradeRank
            );
          } catch (err) {
            // searchForCall can fail if the calls array has unexpected structure
            logger.debug(
              "blend-handler",
              JSON.stringify({ topic: "searchForCall-error", txHash, error: String(err) })
            );
          }
        }

        // Fallback: scan the entire trace tree for matching selector
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
              "blend-handler",
              JSON.stringify({ topic: "fallback-match-anywhere", txHash })
            );
          }
        }

        if (!executeCallTrace) {
          logger.info(
            "blend-handler",
            JSON.stringify({ topic: "no-executeCallTrace", txHash, exchangeAddress })
          );
          break;
        }

        const matchMethod = methods.find((c) => executeCallTrace.input.includes(c.selector));
        if (!matchMethod) {
          logger.info(
            "blend-handler",
            JSON.stringify({
              topic: "no-matchMethod",
              txHash,
              selectors: methods.map((m) => m.name),
            })
          );
          break;
        }

        const inputData = exchange.contract.interface.decodeFunctionData(
          matchMethod.name,
          executeCallTrace.input
        );

        // Handle: prices
        const currency = Sdk.Common.Addresses.Native[config.chainId];
        const isBuyToBorrow = matchMethod?.name.includes("buyToBorrowLocked");

        const offer = isBuyToBorrow ? inputData.sellInput.offer : inputData.offer;
        const lien = inputData.lien;
        const signature = isBuyToBorrow ? inputData.sellInput.signature : inputData.signature;

        const currencyPrice = offer.price.toString();

        const priceData = await getUSDAndNativePrices(
          currency,
          currencyPrice,
          baseEventParams.timestamp
        );

        if (!priceData.nativePrice) {
          // We must always have the native price
          break;
        }

        const minNonce = await commonHelpers.getMinNonce("blend", offer.borrower);
        const order = new Sdk.Blend.Order(config.chainId, {
          borrower: offer.borrower,
          lienId: offer.lienId.toString(),
          price: offer.price.toString(),
          expirationTime: offer.expirationTime,
          salt: offer.salt,
          oracle: offer.oracle,
          fees: offer.fees,
          nonce: minNonce.toString(),
          signature: signature,
        });

        let isValidated = false;
        const orderId = order.hash();
        for (let nonce = minNonce.toNumber(); nonce >= 0; nonce--) {
          order.params.nonce = nonce.toString();
          try {
            order.checkSignature();
            isValidated = true;
            break;
          } catch {
            // skip error
          }
        }

        if (!isValidated) {
          // not validated
          return;
        }

        // Handle: attribution
        const orderKind = "blend";

        let taker = executeCallTrace.from;
        const attributionData = await utils.extractAttributionData(
          baseEventParams.txHash,
          orderKind,
          { orderId }
        );

        if (attributionData.taker) {
          taker = attributionData.taker;
        }

        const maker = offer.borrower.toLowerCase();
        onChainData.fillEvents.push({
          orderKind: "blend",
          orderId,
          orderSide: "sell",
          maker,
          taker,
          price: priceData.nativePrice,
          currency,
          currencyPrice,
          usdPrice: priceData.usdPrice,
          contract: lien.collection.toLowerCase(),
          tokenId: lien.tokenId.toString(),
          amount: "1",
          orderSourceId: attributionData.orderSource?.id,
          aggregatorSourceId: attributionData.aggregatorSource?.id,
          fillSourceId: attributionData.fillSource?.id,
          baseEventParams,
        });

        onChainData.fillInfos.push({
          context: `${orderId}-${baseEventParams.txHash}-${baseEventParams.logIndex}`,
          orderId: orderId,
          orderSide: "sell",
          contract: lien.collection.toLowerCase(),
          tokenId: lien.tokenId.toString(),
          amount: "1",
          price: priceData.nativePrice,
          timestamp: baseEventParams.timestamp,
          maker,
          taker,
        });

        trades.order.set(`${txHash}-${exchangeAddress}`, tradeRank + 1);

        break;
      }
    }
  }
};
