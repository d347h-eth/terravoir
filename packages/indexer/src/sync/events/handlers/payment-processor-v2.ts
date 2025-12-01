import { Result, defaultAbiCoder } from "@ethersproject/abi";
import { Log } from "@ethersproject/abstract-provider";
import { AddressZero, HashZero } from "@ethersproject/constants";
import { searchForCalls } from "@georgeroman/evm-tx-simulator";
import * as Sdk from "@reservoir0x/sdk";

import { logger } from "@/common/logger";
import { bn } from "@/common/utils";
import { config } from "@/config/index";
import { getEventData } from "@/events-sync/data";
import { EnhancedEvent, OnChainData } from "@/events-sync/handlers/utils";
import { getERC20Transfer } from "@/events-sync/handlers/utils/erc20";
import * as utils from "@/events-sync/utils";
import { orderFixesJob } from "@/jobs/order-fixes/order-fixes-job";
import * as commonHelpers from "@/orderbook/orders/common/helpers";
import * as paymentProcessorV2Utils from "@/utils/payment-processor-v2";
import { getUSDAndNativePrices } from "@/utils/prices";
import _ from "lodash";

export const handleEvents = async (events: EnhancedEvent[], onChainData: OnChainData) => {
  // Keep track of all events within the currently processing transaction
  let currentTx: string | undefined;
  let currentTxLogs: Log[] = [];

  const orderKind = "payment-processor-v2";

  // Handle the events
  for (const { subKind, baseEventParams, log } of events) {
    if (currentTx !== baseEventParams.txHash) {
      currentTx = baseEventParams.txHash;
      currentTxLogs = [];
    }
    currentTxLogs.push(log);

    const eventData = getEventData([subKind])[0];

    switch (subKind) {
      case "payment-processor-v2-nonce-invalidated": {
        const parsedLog = eventData.abi.parseLog(log);
        const maker = parsedLog.args["account"].toLowerCase();
        const nonce = parsedLog.args["nonce"].toString();

        onChainData.nonceCancelEvents.push({
          orderKind,
          maker,
          nonce,
          baseEventParams,
        });

        break;
      }

      case "payment-processor-v2-master-nonce-invalidated": {
        const parsedLog = eventData.abi.parseLog(log);
        const maker = parsedLog.args["account"].toLowerCase();
        const newNonce = parsedLog.args["nonce"].toString();

        // Cancel all maker's orders
        onChainData.bulkCancelEvents.push({
          orderKind,
          maker,
          minNonce: bn(newNonce).add(1).toString(),
          acrossAll: true,
          baseEventParams,
        });

        break;
      }

      case "payment-processor-v2-accept-offer-erc1155":
      case "payment-processor-v2-accept-offer-erc721":
      case "payment-processor-v2-buy-listing-erc1155":
      case "payment-processor-v2-buy-listing-erc721": {
        // Again the events are extremely poorly designed (order hash is not emitted)
        // so we have to rely on complex tricks (using call tracing) to associate the
        // sales to order ids

        const parsedLog = eventData.abi.parseLog(log);

        const txHash = baseEventParams.txHash;

        const exchange = new Sdk.PaymentProcessorV2.Exchange(config.chainId);
        const exchangeAddress = exchange.contract.address;

        const tokenIdOfEvent = parsedLog.args["tokenId"].toString();
        const tokenAddressOfEvent = parsedLog.args["tokenAddress"].toLowerCase();
        const tokenAmountOfEvent = (parsedLog.args["amount"] ?? 1).toString();
        const paymentCoinOfEvent = parsedLog.args["paymentCoin"].toLowerCase();

        const methods = [
          {
            selector: "0xc32dacae",
            name: "buyListing",
            abi: [
              "bytes32 domainSeparator",
              `(
                uint8 protocol,
                address maker,
                address beneficiary,
                address marketplace,
                address fallbackRoyaltyRecipient,
                address paymentMethod,
                address tokenAddress,
                uint256 tokenId,
                uint248 amount,
                uint256 itemPrice,
                uint256 nonce,
                uint256 expiration,
                uint256 marketplaceFeeNumerator,
                uint256 maxRoyaltyFeeNumerator,
                uint248 requestedFillAmount,
                uint248 minimumFillAmount
              ) saleDetails`,
              "(uint8 v, bytes32 r, bytes32 s) sellerSignature",
              "(address signer, address taker, uint256 expiration, uint8 v, bytes32 r, bytes32 s) cosignature",
              "(address recipient, uint256 amount) feeOnTop",
            ],
          },
          {
            selector: "0x08fdd68e",
            name: "acceptOffer",
            abi: [
              "bytes32 domainSeparator",
              "bool isCollectionLevelOffer",
              `(
                uint8 protocol,
                address maker,
                address beneficiary,
                address marketplace,
                address fallbackRoyaltyRecipient,
                address paymentMethod,
                address tokenAddress,
                uint256 tokenId,
                uint248 amount,
                uint256 itemPrice,
                uint256 nonce,
                uint256 expiration,
                uint256 marketplaceFeeNumerator,
                uint256 maxRoyaltyFeeNumerator,
                uint248 requestedFillAmount,
                uint248 minimumFillAmount
              ) saleDetails`,
              "(uint8 v, bytes32 r, bytes32 s) buyerSignature",
              "(bytes32 rootHash, bytes32[] proof) tokenSetProof",
              "(address signer, address taker, uint256 expiration, uint8 v, bytes32 r, bytes32 s) cosignature",
              "(address recipient, uint256 amount) feeOnTop",
            ],
          },
          {
            selector: "0x88d64fe8",
            name: "bulkAcceptOffers",
            abi: [
              "bytes32 domainSeparator",
              `(
                bool[] isCollectionLevelOfferArray,
                (
                  uint8 protocol,
                  address maker,
                  address beneficiary,
                  address marketplace,
                  address fallbackRoyaltyRecipient,
                  address paymentMethod,
                  address tokenAddress,
                  uint256 tokenId,
                  uint248 amount,
                  uint256 itemPrice,
                  uint256 nonce,
                  uint256 expiration,
                  uint256 marketplaceFeeNumerator,
                  uint256 maxRoyaltyFeeNumerator,
                  uint248 requestedFillAmount,
                  uint248 minimumFillAmount
                )[] saleDetailsArray,
                (uint8 v, bytes32 r, bytes32 s)[] buyerSignaturesArray,
                (bytes32 rootHash, bytes32[] proof)[] tokenSetProofsArray,
                (address signer, address taker, uint256 expiration, uint8 v, bytes32 r, bytes32 s)[] cosignaturesArray,
                (address recipient, uint256 amount)[] feesOnTopArray
              ) params`,
            ],
          },
          {
            selector: "0x863eb2d2",
            name: "bulkBuyListings",
            abi: [
              "bytes32 domainSeparator",
              "(uint8 protocol, address maker, address beneficiary, address marketplace, address fallbackRoyaltyRecipient, address paymentMethod, address tokenAddress, uint256 tokenId, uint248 amount, uint256 itemPrice, uint256 nonce, uint256 expiration, uint256 marketplaceFeeNumerator, uint256 maxRoyaltyFeeNumerator, uint248 requestedFillAmount, uint248 minimumFillAmount)[] saleDetailsArray",
              "(uint8 v, bytes32 r, bytes32 s)[] sellerSignatures",
              "(address signer, address taker, uint256 expiration, uint8 v, bytes32 r, bytes32 s)[] cosignatures",
              "(address recipient, uint256 amount)[] feesOnTop",
            ],
          },
          {
            selector: "0x96c3ae25",
            name: "sweepCollection",
            abi: [
              "bytes32 domainSeparator",
              "(address recipient, uint256 amount) feeOnTop",
              "(uint8 protocol, address tokenAddress, address paymentMethod, address beneficiary) sweepOrder",
              "(address maker, address marketplace, address fallbackRoyaltyRecipient, uint256 tokenId, uint248 amount, uint256 itemPrice, uint256 nonce, uint256 expiration, uint256 marketplaceFeeNumerator, uint256 maxRoyaltyFeeNumerator)[] items",
              "(uint8 v, bytes32 r, bytes32 s)[] signedSellOrders",
              "(address signer, address taker, uint256 expiration, uint8 v, bytes32 r, bytes32 s)[] cosignatures",
            ],
          },
        ];

        const relevantCalls: string[] = [];

        const txTrace = await utils.fetchTransactionTrace(txHash);
        if (txTrace) {
          try {
            const callTree =
              (txTrace as any).calls ||
              (txTrace as any).result?.calls ||
              ((txTrace as any).result && Array.isArray((txTrace as any).result)
                ? (txTrace as any).result[0]?.calls
                : []);

            if (!callTree || !Array.isArray(callTree)) {
              logger.info(
                "pp-v2",
                JSON.stringify({
                  msg: "Could not get transaction trace",
                  log,
                  parsingError: true,
                  reason: "no-calls-in-trace",
                })
              );
              break;
            }

            const calls = searchForCalls(callTree as any, {
              to: exchangeAddress,
              type: "call",
              sigHashes: methods.map((c) => c.selector),
            });
            for (const call of calls) {
              relevantCalls.push(call.input ?? "0x");
            }
          } catch (error) {
            logger.info(
              "pp-v2",
              JSON.stringify({
                msg: "Could not get transaction trace",
                log,
                parsingError: true,
                error,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                stack: (error as any).stack,
              })
            );
            break;
          }
        } else {
          logger.info(
            "pp-v2",
            JSON.stringify({ msg: "Could not get transaction trace", log, isMissingTrace: true })
          );
          break;
        }

        const saleDetailsArray = [];
        const saleSignatures = [];
        const tokenSetProofs = [];
        const cosignatures = [];
        const isCollectionLevelOffers = [];

        const allFillEvents = events.filter(
          (c) =>
            c.baseEventParams.txHash === txHash &&
            [
              "payment-processor-v2-accept-offer-erc1155",
              "payment-processor-v2-accept-offer-erc721",
              "payment-processor-v2-buy-listing-erc1155",
              "payment-processor-v2-buy-listing-erc721",
            ].includes(c.subKind)
        );

        const currentFillIndex = allFillEvents.findIndex(
          (c) =>
            c.baseEventParams.logIndex === baseEventParams.logIndex &&
            c.baseEventParams.txHash === txHash
        );
        for (const relevantCalldata of relevantCalls) {
          const matchedMethod = methods.find((c) => relevantCalldata.includes(c.selector));
          if (!matchedMethod) {
            logger.info(
              "pp-v2",
              JSON.stringify({ msg: "Missing matched method", log, relevantCalldata })
            );
            continue;
          }

          const args = exchange.contract.interface.decodeFunctionData(
            matchedMethod.name,
            relevantCalldata
          );

          const inputData = defaultAbiCoder.decode(matchedMethod.abi, args.data);
          let saleDetailsArrayTemp = [inputData.saleDetails];
          let saleSignaturesTemp = [inputData.buyerSignature || inputData.sellerSignature];
          let tokenSetProofsTemp = [inputData.tokenSetProof];
          let cosignaturesTemp = [inputData.cosignature];

          const isCollectionLevelOffer = inputData.isCollectionLevelOffer;

          if (matchedMethod.name === "sweepCollection") {
            const sweepOrder = inputData.sweepOrder;
            saleSignaturesTemp = inputData.signedSellOrders;
            saleDetailsArrayTemp = inputData.items.map((c: Result) => {
              return {
                protocol: sweepOrder.protocol,
                tokenAddress: sweepOrder.tokenAddress,
                paymentMethod: sweepOrder.paymentMethod,
                beneficiary: sweepOrder.beneficiary,
                maker: c.maker,
                itemPrice: c.itemPrice,
                tokenId: c.tokenId,
                amount: c.amount,
                marketplace: c.marketplace,
                marketplaceFeeNumerator: c.marketplaceFeeNumerator,
                maxRoyaltyFeeNumerator: c.maxRoyaltyFeeNumerator,
                expiration: c.expiration,
                nonce: c.nonce,
              };
            });
          } else if (matchedMethod.name === "bulkBuyListings") {
            saleDetailsArrayTemp = inputData.saleDetailsArray;
            saleSignaturesTemp = inputData.sellerSignatures;
            cosignaturesTemp = inputData.cosignatures;
          } else if (matchedMethod.name === "bulkAcceptOffers") {
            saleDetailsArrayTemp = inputData.params.saleDetailsArray;
            saleSignaturesTemp = inputData.params.buyerSignaturesArray;
            tokenSetProofsTemp = inputData.params.tokenSetProofsArray;
            cosignaturesTemp = inputData.params.cosignaturesArray;
          }

          saleDetailsArray.push(...saleDetailsArrayTemp);
          saleSignatures.push(...saleSignaturesTemp);
          tokenSetProofs.push(...tokenSetProofsTemp);
          cosignatures.push(...cosignaturesTemp);
          isCollectionLevelOffers.push(
            ...new Array(saleDetailsArrayTemp.length).fill(isCollectionLevelOffer)
          );
        }

        const [saleDetail, saleSignature, cosignature, isCollectionLevelOffer] = [
          saleDetailsArray[currentFillIndex],
          saleSignatures[currentFillIndex],
          cosignatures[currentFillIndex],
          isCollectionLevelOffers[currentFillIndex],
        ];
        if (!saleDetail) {
          continue;
        }

        const tokenAddress = saleDetail["tokenAddress"].toLowerCase();
        const tokenId = saleDetail["tokenId"].toString();
        const currency = saleDetail["paymentMethod"].toLowerCase();
        const currencyPrice = saleDetail["itemPrice"].div(saleDetail["amount"]).toString();

        if (
          !(
            tokenAddress === tokenAddressOfEvent &&
            tokenId === tokenIdOfEvent &&
            currency === paymentCoinOfEvent
          )
        ) {
          // Skip
          continue;
        }

        const isBuyOrder = subKind.includes("accept-offer");
        let maker = isBuyOrder
          ? parsedLog.args["buyer"].toLowerCase()
          : parsedLog.args["seller"].toLowerCase();

        let taker = isBuyOrder
          ? parsedLog.args["seller"].toLowerCase()
          : parsedLog.args["buyer"].toLowerCase();

        const orderSide = !isBuyOrder ? "sell" : "buy";
        const makerMinNonce = await commonHelpers.getMinNonce(orderKind, maker);

        const orderSignature = saleSignature;
        const signature = {
          r: orderSignature.r,
          s: orderSignature.s,
          v: orderSignature.v,
        };

        let order: Sdk.PaymentProcessorV2.Order;

        const cosigner = cosignature ? cosignature.signer.toLowerCase() : AddressZero;

        if (isCollectionLevelOffer) {
          const tokenSetProof = tokenSetProofs[currentFillIndex];
          if (tokenSetProof.rootHash === HashZero) {
            const builder = new Sdk.PaymentProcessorV2.Builders.ContractWide(config.chainId);
            order = builder.build({
              protocol: saleDetail["protocol"],
              marketplace: saleDetail["marketplace"],
              beneficiary: saleDetail["beneficiary"],
              marketplaceFeeNumerator: saleDetail["marketplaceFeeNumerator"],
              maxRoyaltyFeeNumerator: saleDetail["maxRoyaltyFeeNumerator"],
              maker: saleDetail["maker"],
              tokenAddress: saleDetail["tokenAddress"],
              amount: saleDetail["amount"],
              itemPrice: saleDetail["itemPrice"],
              expiration: saleDetail["expiration"],
              nonce: saleDetail["nonce"],
              paymentMethod: saleDetail["paymentMethod"],
              masterNonce: makerMinNonce,
              cosigner,
              ...signature,
            });
          } else {
            const builder = new Sdk.PaymentProcessorV2.Builders.TokenList(config.chainId);
            order = builder.build({
              protocol: saleDetail["protocol"],
              marketplace: saleDetail["marketplace"],
              beneficiary: saleDetail["beneficiary"],
              marketplaceFeeNumerator: saleDetail["marketplaceFeeNumerator"],
              maxRoyaltyFeeNumerator: saleDetail["maxRoyaltyFeeNumerator"],
              maker: saleDetail["maker"],
              tokenAddress: saleDetail["tokenAddress"],
              amount: saleDetail["amount"],
              itemPrice: saleDetail["itemPrice"],
              expiration: saleDetail["expiration"],
              nonce: saleDetail["nonce"],
              paymentMethod: saleDetail["paymentMethod"],
              masterNonce: makerMinNonce,
              tokenSetMerkleRoot: tokenSetProof.rootHash,
              tokenIds: [],
              cosigner,
              ...signature,
            });
          }
        } else {
          const builder = new Sdk.PaymentProcessorV2.Builders.SingleToken(config.chainId);
          order = builder.build({
            protocol: saleDetail["protocol"],
            marketplace: saleDetail["marketplace"],
            marketplaceFeeNumerator: saleDetail["marketplaceFeeNumerator"],
            maxRoyaltyFeeNumerator: saleDetail["maxRoyaltyFeeNumerator"],
            tokenAddress: saleDetail["tokenAddress"],
            amount: saleDetail["amount"],
            tokenId: saleDetail["tokenId"],
            expiration: saleDetail["expiration"],
            itemPrice: saleDetail["itemPrice"],
            maker: saleDetail["maker"],
            ...(isBuyOrder
              ? {
                  beneficiary: saleDetail["beneficiary"],
                }
              : {}),
            nonce: saleDetail["nonce"],
            paymentMethod: saleDetail["paymentMethod"],
            masterNonce: makerMinNonce,
            cosigner,
            ...signature,
          });
        }

        let isValidated = false;
        const MAX_ITERATIONS = 100;
        const minNonceToCheck = Math.max(Number(order.params.masterNonce) - MAX_ITERATIONS, 0);
        for (let nonce = Number(order.params.masterNonce); nonce >= minNonceToCheck; nonce--) {
          order.params.masterNonce = nonce.toString();
          try {
            order.checkSignature();
            isValidated = true;
            break;
          } catch {
            // Skip errors
          }
        }

        const priceData = await getUSDAndNativePrices(
          currency,
          currencyPrice,
          baseEventParams.timestamp
        );
        if (!priceData.nativePrice) {
          // We must always have the native price
          break;
        }

        let orderId = isValidated ? order.hash() : undefined;

        // If we couldn't parse the order id from the calldata try to get it from our db
        if (!orderId) {
          orderId = await commonHelpers.getOrderIdFromNonce(
            orderKind,
            order.params.sellerOrBuyer,
            order.params.nonce
          );
        }

        if (
          orderId &&
          order.params.protocol === Sdk.PaymentProcessorV2.Types.OrderProtocols.ERC1155_FILL_PARTIAL
        ) {
          await orderFixesJob.addToQueue([{ by: "id", data: { id: orderId } }], 5000);
        }

        // Handle: attribution
        const attributionData = await utils.extractAttributionData(
          baseEventParams.txHash,
          orderKind,
          { orderId }
        );
        if (attributionData.taker) {
          taker = attributionData.taker;
        }

        // beneficiary should be available for these events, however, check to ensure a valid address is included
        if (!_.isEmpty(parsedLog.args["beneficiary"])) {
          if (isBuyOrder) {
            maker = parsedLog.args["beneficiary"].toLowerCase();
          } else {
            taker = parsedLog.args["beneficiary"].toLowerCase();
          }
        }

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
          contract: tokenAddress,
          tokenId,
          amount: tokenAmountOfEvent,
          orderSourceId: attributionData.orderSource?.id,
          aggregatorSourceId: attributionData.aggregatorSource?.id,
          fillSourceId: attributionData.fillSource?.id,
          baseEventParams,
        });

        onChainData.fillInfos.push({
          context: `${orderId}-${baseEventParams.txHash}`,
          orderId: orderId,
          orderSide,
          contract: tokenAddress,
          tokenId,
          amount: tokenAmountOfEvent,
          price: priceData.nativePrice,
          timestamp: baseEventParams.timestamp,
          maker,
          taker,
        });

        onChainData.orderInfos.push({
          context: `filled-${orderId}-${baseEventParams.txHash}`,
          id: orderId,
          trigger: {
            kind: "sale",
            txHash: baseEventParams.txHash,
            txTimestamp: baseEventParams.timestamp,
          },
        });

        // If an ERC20 transfer occured in the same transaction as a sale
        // then we need resync the maker's ERC20 approval to the exchange
        const erc20 = getERC20Transfer(currentTxLogs);
        if (erc20) {
          onChainData.makerInfos.push({
            context: `${baseEventParams.txHash}-buy-approval`,
            maker,
            trigger: {
              kind: "approval-change",
              txHash: baseEventParams.txHash,
              txTimestamp: baseEventParams.timestamp,
            },
            data: {
              kind: "buy-approval",
              contract: erc20,
              orderKind,
            },
          });
        }
        break;
      }

      case "payment-processor-v2-updated-token-level-pricing-boundaries":
      case "payment-processor-v2-updated-collection-level-pricing-boundaries":
      case "payment-processor-v2-updated-collection-payment-settings": {
        const parsedLog = eventData.abi.parseLog(log);
        const tokenAddress = parsedLog.args["tokenAddress"].toLowerCase();

        // Refresh
        const ppConfig = await paymentProcessorV2Utils.getConfigByContract(tokenAddress, true);
        if (ppConfig) {
          // Update backfilled royalties
          await paymentProcessorV2Utils.saveBackfilledRoyalties(tokenAddress, [
            {
              recipient: ppConfig.royaltyBackfillReceiver,
              bps: ppConfig.royaltyBackfillNumerator,
            },
          ]);
        }

        break;
      }

      case "payment-processor-v2-trusted-channel-removed-for-collection":
      case "payment-processor-v2-trusted-channel-added-for-collection": {
        const parsedLog = eventData.abi.parseLog(log);
        const tokenAddress = parsedLog.args["tokenAddress"].toLowerCase();

        // Refresh
        await paymentProcessorV2Utils.getTrustedChannels(tokenAddress, true);

        break;
      }

      case "payment-processor-v2-banned-account-added-for-collection":
      case "payment-processor-v2-banned-account-removed-for-collection": {
        const parsedLog = eventData.abi.parseLog(log);
        const tokenAddress = parsedLog.args["tokenAddress"].toLowerCase();

        // Refresh
        await paymentProcessorV2Utils.getBannedAccounts(tokenAddress, true);

        break;
      }

      case "payment-processor-v2-payment-method-added-to-whitelist":
      case "payment-processor-v2-payment-method-removed-from-whitelist": {
        const parsedLog = eventData.abi.parseLog(log);
        const paymentMethodWhitelistId = parsedLog.args["paymentMethodWhitelistId"];

        // Refresh
        await paymentProcessorV2Utils.getPaymentMethods(paymentMethodWhitelistId, true);

        break;
      }
    }
  }
};
