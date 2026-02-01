import { now, toTime } from "@/common/utils";

import { OpenseaOrderParams } from "@/orderbook/orders/seaport-v1.1";
import { TraitOfferEventPayload } from "@opensea/stream-js";
import { getNetworkSettings } from "@/config/network";

export const handleEvent = (payload: TraitOfferEventPayload): OpenseaOrderParams | null => {
  if (!getNetworkSettings().supportedBidCurrencies[payload.payment_token.address]) {
    return null;
  }

  const contract = (payload.asset_contract_criteria as { address: string }).address;

  const payloadWithList = payload as TraitOfferEventPayload & {
    trait_criteria?: { trait_type?: string; trait_name?: string };
    trait_criteria_list?: { trait_type?: string; trait_name?: string }[];
  };

  if (
    payloadWithList.trait_criteria &&
    payloadWithList.trait_criteria_list &&
    payloadWithList.trait_criteria_list.length
  ) {
    const single = payloadWithList.trait_criteria;
    const list = payloadWithList.trait_criteria_list;
    const listIsSingleMatch =
      list.length === 1 &&
      list[0]?.trait_type === single.trait_type &&
      list[0]?.trait_name === single.trait_name;

    if (!listIsSingleMatch) {
      throw new Error("Trait offer payload has conflicting trait_criteria and trait_criteria_list");
    }
  }

  const rawCriteria = payloadWithList.trait_criteria
    ? [payloadWithList.trait_criteria]
    : payloadWithList.trait_criteria_list ?? [];

  const attributes: { key: string; value: string }[] = [];
  const seen = new Set<string>();
  for (const entry of rawCriteria) {
    if (!entry?.trait_type || !entry?.trait_name) {
      continue;
    }
    const signature = `${entry.trait_type}:${entry.trait_name}`;
    if (!seen.has(signature)) {
      seen.add(signature);
      attributes.push({ key: entry.trait_type, value: entry.trait_name });
    }
  }

  if (!attributes.length) {
    return null;
  }

  attributes.sort((a, b) =>
    a.key === b.key ? a.value.localeCompare(b.value) : a.key.localeCompare(b.key)
  );

  return {
    kind: "token-list",
    side: "buy",
    hash: payload.order_hash,
    price: payload.base_price,
    paymentToken: payload.payment_token.address,
    amount: payload.quantity,
    startTime: now(),
    endTime: toTime(payload.expiration_date),
    contract,
    offerer: payload.maker.address,
    collectionSlug: payload.collection.slug,
    attributes,
    attributeKey: attributes.length === 1 ? attributes[0].key : undefined,
    attributeValue: attributes.length === 1 ? attributes[0].value : undefined,
  };
};
