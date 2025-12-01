import { Interface } from "@ethersproject/abi";
import { Contract } from "@ethersproject/contracts";
import axios from "axios";

import { idb } from "@/common/db";
import { logger } from "@/common/logger";
import { baseProvider } from "@/common/provider";
import { redis } from "@/common/redis";
import { sanitizeText, toBuffer } from "@/common/utils";
import { getCoingeckoNetworkId, getNetworkSettings } from "@/config/network";
import { currenciesFetchJob } from "@/jobs/currencies/currencies-fetch-job";
import { CurrencyMetadata } from "@/models/currencies";
import { config } from "@/config/index";

export type Currency = {
  contract: string;
  name?: string;
  symbol?: string;
  decimals?: number;
  totalSupply?: number;
  metadata?: CurrencyMetadata;
};

export enum CurrenciesPriceProvider {
  COINGECKO = "coingecko",
  UNISWAP_V3 = "uniswap-v3",
  UNISWAP_V2 = "uniswap-v2",
}

const CURRENCY_MEMORY_CACHE: Map<string, Currency> = new Map<string, Currency>();

export const clearCache = (currencyAddress: string) => {
  CURRENCY_MEMORY_CACHE.delete(currencyAddress);
};

export const getCurrency = async (
  currencyAddress: string,
  getCurrencyDetails = true
): Promise<Currency> => {
  if (!CURRENCY_MEMORY_CACHE.has(currencyAddress)) {
    const result = await idb.oneOrNone(
      `
        SELECT
          currencies.name,
          currencies.symbol,
          currencies.decimals,
          currencies.total_supply,
          currencies.metadata
        FROM currencies
        WHERE currencies.contract = $/contract/
      `,
      {
        contract: toBuffer(currencyAddress),
      }
    );

    if (result && result.name && result.symbol && result.decimals !== undefined) {
      CURRENCY_MEMORY_CACHE.set(currencyAddress, {
        contract: currencyAddress,
        name: result.name,
        symbol: result.symbol,
        decimals: result.decimals,
        totalSupply: result.total_supply,
        metadata: result.metadata,
      });
    } else if (getCurrencyDetails) {
      let name: string | undefined;
      let symbol: string | undefined;
      let decimals: number | undefined;
      let totalSupply: number | undefined;
      let metadata: CurrencyMetadata | undefined;

      // If the currency or important fields are not available, then we try to retrieve its details
      try {
        // At most 1 attempt per minute
        const lockKey = `try-get-currency-details-lock:${currencyAddress}`;
        if (await redis.get(lockKey)) {
          throw new Error("Locked");
        } else {
          await redis.set(lockKey, "locked", "EX", 60);
        }

        ({ name, symbol, decimals, totalSupply, metadata } = await tryGetCurrencyDetails(
          currencyAddress
        ));
      } catch (error) {
        const isWhitelisted = getNetworkSettings().whitelistedCurrencies.has(
          currencyAddress.toLowerCase()
        );

        // Only log error if not whitelisted and not locked
        if (error instanceof Error && error.message !== "Locked" && !isWhitelisted) {
          logger.error(
            "currencies",
            `Failed to initially fetch ${currencyAddress} currency details: ${error}`
          );
        }

        if (isWhitelisted) {
          ({ name, symbol, decimals, metadata } = getNetworkSettings().whitelistedCurrencies.get(
            currencyAddress.toLowerCase()
          )!);
        } else {
          // TODO: Although an edge case, we should ensure that when the job
          // finally succeeds fetching the details of a currency, we also do
          // update the memory cache (otherwise the cache will be stale).

          // Retry fetching the currency details
          await currenciesFetchJob.addToQueue({ currency: currencyAddress });
        }
      }

      metadata = metadata || {};

      if (!result) {
        await idb.none(
          `
            INSERT INTO currencies (
              contract,
              name,
              symbol,
              decimals,
              total_supply,
              metadata
            ) VALUES (
              $/contract/,
              $/name/,
              $/symbol/,
              $/decimals/,
              $/totalSupply/,
              $/metadata:json/
            ) ON CONFLICT DO NOTHING
          `,
          {
            contract: toBuffer(currencyAddress),
            name: sanitizeText(name) || null,
            symbol: sanitizeText(symbol) || null,
            decimals,
            totalSupply,
            metadata,
          }
        );
      } else {
        await idb.none(
          `
            UPDATE currencies SET
              name = $/name/,
              symbol = $/symbol/,
              decimals = $/decimals/,
              total_supply = $/totalSupply/,
              metadata = currencies.metadata || $/metadata:json/,
              updated_at = NOW()
            WHERE contract = $/contract/
          `,
          {
            contract: toBuffer(currencyAddress),
            name,
            symbol,
            decimals,
            totalSupply,
            metadata,
          }
        );
      }

      // Update the in-memory cache
      CURRENCY_MEMORY_CACHE.set(currencyAddress, {
        contract: currencyAddress,
        name,
        symbol,
        decimals,
        totalSupply,
        metadata,
      });
    }
  }

  return CURRENCY_MEMORY_CACHE.get(currencyAddress)!;
};

export const tryGetCurrencyDetails = async (
  currencyAddress: string
): Promise<{
  name?: string;
  symbol: string;
  decimals: number;
  totalSupply?: number;
  metadata: CurrencyMetadata;
}> => {
  // `name`, `symbol` and `decimals` are fetched from on-chain
  const iface = new Interface([
    "function name() view returns (string)",
    "function symbol() view returns (string)",
    "function decimals() view returns (uint8)",
    "function totalSupply() view returns (uint256)",
    "function balanceOf(address owner) view returns (uint256)",
    "function allowance(address owner, address spender) public view returns (uint256)",
    "function contractURI() view returns (string)",
  ]);

  const contract = new Contract(currencyAddress, iface, baseProvider);

  // Try to fetch the standard ERC20 fields with error handling
  // Some contracts don't implement these methods properly or cheap RPCs may fail
  let name: string | undefined;
  let symbol: string | undefined;
  let decimals: number | undefined;
  let totalSupply: number | undefined;

  try {
    name = await contract.name();
  } catch (error) {
    logger.debug("currencies", `Failed to fetch name for ${currencyAddress}: ${error}`);
  }

  try {
    symbol = await contract.symbol();
  } catch (error) {
    logger.debug("currencies", `Failed to fetch symbol for ${currencyAddress}: ${error}`);
  }

  try {
    decimals = await contract.decimals();
  } catch (error) {
    logger.debug("currencies", `Failed to fetch decimals for ${currencyAddress}: ${error}`);
  }

  try {
    const totalSupplyBigNumber = await contract.totalSupply();
    if (totalSupplyBigNumber) {
      totalSupply = Number(totalSupplyBigNumber.toString());
    }
  } catch (error) {
    logger.debug("currencies", `Failed to fetch totalSupply for ${currencyAddress}: ${error}`);
  }

  // If we couldn't get the essential fields, throw an error to trigger retry or fallback
  if (!symbol || decimals === undefined) {
    throw new Error(
      `Contract ${currencyAddress} is missing required ERC20 fields (symbol: ${
        symbol !== undefined
      }, decimals: ${decimals !== undefined})`
    );
  }

  // Detect if the currency follows the ERC20 standard
  let erc20Incompatible: boolean | undefined;
  try {
    const randomAddress1 = "0xb5cec8cf2cfe69b949a4d3221cff19c5c94233be";
    const randomAddress2 = "0x270a8ad54fed804f4bac1118dabfa2df4f41089c";
    await contract.balanceOf(randomAddress1);
    await contract.allowance(randomAddress1, randomAddress2);
  } catch {
    // As an example, the MATIC ERC20 token on Polygon is not ERC20-compatible
    // since it's missing some standard methods that we depend on:
    // https://polygonscan.com/address/0x0000000000000000000000000000000000001010
    erc20Incompatible = true;
  }

  const metadata: CurrencyMetadata = {
    erc20Incompatible,
  };

  const coingeckoNetworkId = getCoingeckoNetworkId();
  if (coingeckoNetworkId) {
    const result: { id?: string; image?: { large?: string } } = await axios
      .get(
        `https://api.coingecko.com/api/v3/coins/${coingeckoNetworkId}/contract/${currencyAddress}`,
        { timeout: 10 * 1000 }
      )
      .then((response) => response.data);
    if (result.id) {
      metadata.coingeckoCurrencyId = result.id;
    }
    if (result.image?.large) {
      metadata.image = result.image.large;
    }
  }

  try {
    const contractUri = await contract.contractURI();

    if (contractUri) {
      const currencyMetadata = await axios.get(contractUri, {
        timeout: 5000,
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (currencyMetadata.data) {
        logger.info(
          "currencies",
          `contractUri ${contractUri} for currency ${currencyAddress} contractUriMetadata ${JSON.stringify(
            currencyMetadata.data
          )}`
        );

        const contractUriMetadata = currencyMetadata.data;
        if (contractUriMetadata?.name) {
          name = contractUriMetadata.name;
        }

        if (contractUriMetadata?.image) {
          metadata.image = contractUriMetadata.image;
        }

        if (contractUriMetadata?.description) {
          metadata.description = contractUriMetadata.description;
        }

        if (contractUriMetadata?.external_link) {
          metadata.externalLink = contractUriMetadata.external_link;
        }

        if (contractUriMetadata?.twitter_url) {
          metadata.twitterUrl = contractUriMetadata.twitter_url;
        }

        if (contractUriMetadata?.twitter_username) {
          metadata.twitterUsername = contractUriMetadata.twitter_username;
        }

        if (contractUriMetadata?.discord_url) {
          metadata.discordUrl = contractUriMetadata.discord_url;
        }

        if (contractUriMetadata?.telegram_url) {
          metadata.telegramUrl = contractUriMetadata.telegram_url;
        }

        if (contractUriMetadata?.reddit_url) {
          metadata.redditUrl = contractUriMetadata.reddit_url;
        }

        if (contractUriMetadata?.github_url) {
          metadata.githubUrl = contractUriMetadata.github_url;
        }
      }
    }
  } catch {
    // Ignore errors
  }

  if (!metadata.image && config.enableUpdateTopCurrencies) {
    try {
      const dexscreenerResponse = await axios.get(
        `https://api.dexscreener.com/token-pairs/v1/${config.chainName}/${currencyAddress}`,
        {
          timeout: 5000,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      if (dexscreenerResponse.data) {
        const dexscreenerData = dexscreenerResponse.data.filter(
          (data: { baseToken: { address: string }; info: { imageUrl: string } }) =>
            data.baseToken?.address.toLowerCase() === currencyAddress && data.info?.imageUrl
        );

        if (dexscreenerData.length) {
          metadata.image = dexscreenerData[0].info.imageUrl;

          logger.debug(
            "currencies",
            JSON.stringify({
              message: `got image from dexscreener for currency ${currencyAddress}. imageUrl=${dexscreenerData[0].info.imageUrl}`,
              dexscreenerResponseData: dexscreenerResponse.data,
              dexscreenerData,
              dexscreenerData0: dexscreenerData[0],
            })
          );
        }
      }
    } catch (error) {
      logger.error(
        "currencies",
        JSON.stringify({
          message: `error getting image from dexscreener for currency ${currencyAddress}.`,
          error,
        })
      );
    }
  }

  // Make sure to update the in-memory cache
  CURRENCY_MEMORY_CACHE.set(currencyAddress, {
    contract: currencyAddress,
    name,
    symbol,
    decimals,
    totalSupply,
    metadata,
  });

  return {
    name,
    symbol,
    decimals,
    totalSupply,
    metadata,
  };
};
