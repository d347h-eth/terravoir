import { config as dotEnvConfig } from "dotenv";
dotEnvConfig();

import * as es from "@/events-sync/storage";
import { jest, describe, it, expect } from "@jest/globals";
import { assignMintCommentToFillEvents } from "@/events-sync/handlers/utils/fills";
import { BigNumber } from "ethers";

jest.setTimeout(1000 * 1000);

const zeroAddress = "0x0000000000000000000000000000000000000000";
const zeroValue = BigNumber.from(0);

type BaseEventParams = es.fills.Event["baseEventParams"];
type BaseEventInput = Omit<BaseEventParams, "from" | "to" | "value"> &
  Partial<Pick<BaseEventParams, "from" | "to" | "value">>;

const buildBaseEvent = (params: BaseEventInput): BaseEventParams => ({
  ...params,
  from: params.from ?? zeroAddress,
  to: params.to ?? zeroAddress,
  value: params.value ?? zeroValue,
});

describe("Mint Comment", () => {
  it("merge-custom-mint-comment", async () => {
    const fillEvents: es.fills.Event[] = [
      {
        orderKind: "mint",
        orderSide: "sell",
        taker: "0xf6f0cc35c1ad0af84576464a1de1c7d00b220ff2",
        maker: "0x0000000000000000000000000000000000000000",
        amount: "1",
        currency: "0x0000000000000000000000000000000000000000",
        price: "10777000000000000",
        currencyPrice: "10777000000000000",
        contract: "0xc0774e7a41eda0cecd2cb8872df3c047fb03fb2a",
        tokenId: "1",
        isPrimary: true,
        baseEventParams: buildBaseEvent({
          address: "0xc0774e7a41eda0cecd2cb8872df3c047fb03fb2a",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 109,
          block: 17146520,
          blockHash: "0x3bc35a54cce29f015c9674eeef5e7354c021f2e45e00970dc6db3c6ee651f5ed",
          logIndex: 0,
          timestamp: 1682707859,
          batchIndex: 1,
        }),
      },
      {
        orderKind: "mint",
        orderSide: "sell",
        taker: "0xf6f0cc35c1ad0af84576464a1de1c7d00b220ff2",
        maker: "0x0000000000000000000000000000000000000000",
        amount: "1",
        currency: "0x0000000000000000000000000000000000000000",
        price: "10777000000000000",
        currencyPrice: "10777000000000000",
        contract: "0xc0774e7a41eda0cecd2cb8872df3c047fb03fb2a",
        tokenId: "2",
        isPrimary: true,
        baseEventParams: buildBaseEvent({
          address: "0xc0774e7a41eda0cecd2cb8872df3c047fb03fb2a",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 109,
          block: 17146520,
          blockHash: "0x3bc35a54cce29f015c9674eeef5e7354c021f2e45e00970dc6db3c6ee651f5ed",
          logIndex: 1,
          timestamp: 1682707859,
          batchIndex: 1,
        }),
      },
      {
        orderKind: "mint",
        orderSide: "sell",
        taker: "0xf6f0cc35c1ad0af84576464a1de1c7d00b220ff2",
        maker: "0x0000000000000000000000000000000000000000",
        amount: "1",
        currency: "0x0000000000000000000000000000000000000000",
        price: "10777000000000000",
        currencyPrice: "10777000000000000",
        contract: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
        tokenId: "3",
        isPrimary: true,
        baseEventParams: buildBaseEvent({
          address: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 109,
          block: 17146520,
          blockHash: "0x3bc35a54cce29f015c9674eeef5e7354c021f2e45e00970dc6db3c6ee651f5ed",
          logIndex: 3,
          timestamp: 1682707859,
          batchIndex: 1,
        }),
      },
      {
        orderKind: "mint",
        orderSide: "sell",
        taker: "0xf6f0cc35c1ad0af84576464a1de1c7d00b220ff2",
        maker: "0x0000000000000000000000000000000000000000",
        amount: "1",
        currency: "0x0000000000000000000000000000000000000000",
        price: "10777000000000000",
        currencyPrice: "10777000000000000",
        contract: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
        tokenId: "3",
        isPrimary: true,
        baseEventParams: buildBaseEvent({
          address: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 109,
          block: 17146520,
          blockHash: "0x3bc35a54cce29f015c9674eeef5e7354c021f2e45e00970dc6db3c6ee651f5ed",
          logIndex: 5,
          timestamp: 1682707859,
          batchIndex: 1,
        }),
      },
      {
        orderKind: "mint",
        orderSide: "sell",
        taker: "0xf6f0cc35c1ad0af84576464a1de1c7d00b220ff2",
        maker: "0x0000000000000000000000000000000000000000",
        amount: "1",
        currency: "0x0000000000000000000000000000000000000000",
        price: "10777000000000000",
        currencyPrice: "10777000000000000",
        contract: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
        tokenId: "3",
        isPrimary: true,
        baseEventParams: buildBaseEvent({
          address: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 109,
          block: 17146520,
          blockHash: "0x3bc35a54cce29f015c9674eeef5e7354c021f2e45e00970dc6db3c6ee651f5ed",
          logIndex: 6,
          timestamp: 1682707859,
          batchIndex: 1,
        }),
      },
    ];

    const rawMintComments = [
      {
        tokenContract: "0xc0774e7a41eda0cecd2cb8872df3c047fb03fb2a",
        comment: "mint comment1",
        baseEventParams: buildBaseEvent({
          address: "0xde1fea3b048a5f0f318483f3bf2b1392a479cd0c",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 0,
          block: 17783770,
          blockHash: "0x0dc75265e1d1aefba28f6e3a6fb2d0f69b6007457c95903ce67070bbcee1472d",
          logIndex: 2,
          timestamp: 1690450588,
          batchIndex: 1,
        }),
      },
      {
        tokenContract: "0xc0774e7a41eda0cecd2cb8872df3c047fb03fb2a",
        comment: "mint comment1",
        baseEventParams: buildBaseEvent({
          address: "0xde1fea3b048a5f0f318483f3bf2b1392a479cd0c",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 0,
          block: 17783770,
          blockHash: "0x0dc75265e1d1aefba28f6e3a6fb2d0f69b6007457c95903ce67070bbcee1472d",
          logIndex: 2,
          timestamp: 1690450588,
          batchIndex: 1,
        }),
      },
      {
        tokenContract: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
        comment: "mint comment2",
        baseEventParams: buildBaseEvent({
          address: "0xde1fea3b048a5f0f318483f3bf2b1392a479cd0c",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 0,
          block: 17783770,
          blockHash: "0x0dc75265e1d1aefba28f6e3a6fb2d0f69b6007457c95903ce67070bbcee1472d",
          logIndex: 4,
          timestamp: 1690450588,
          batchIndex: 1,
        }),
      },
      {
        tokenContract: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
        comment: "mint comment3",
        baseEventParams: buildBaseEvent({
          address: "0xde1fea3b048a5f0f318483f3bf2b1392a479cd0c",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 0,
          block: 17783770,
          blockHash: "0x0dc75265e1d1aefba28f6e3a6fb2d0f69b6007457c95903ce67070bbcee1472d",
          logIndex: 7,
          timestamp: 1690450588,
          batchIndex: 1,
        }),
      },
      {
        tokenContract: "0x25d1799ad5c025f170bfacb41def9e21e3930616",
        comment: "mint comment3",
        baseEventParams: buildBaseEvent({
          address: "0xde1fea3b048a5f0f318483f3bf2b1392a479cd0c",
          txHash: "0xbda021fab5830fa99ca3e0d78aacfc279832c2cb05632b97e2169c859cc565cd",
          txIndex: 0,
          block: 17783770,
          blockHash: "0x0dc75265e1d1aefba28f6e3a6fb2d0f69b6007457c95903ce67070bbcee1472d",
          logIndex: 7,
          timestamp: 1690450588,
          batchIndex: 1,
        }),
      },
    ];

    const mintComments: Array<Parameters<typeof assignMintCommentToFillEvents>[1][number]> =
      rawMintComments.map((comment) => ({
        token: comment.tokenContract,
        quantity: 1,
        comment: comment.comment,
        baseEventParams: comment.baseEventParams,
      }));

    await assignMintCommentToFillEvents(fillEvents, mintComments);

    expect(fillEvents[4]?.comment).toEqual("mint comment3");
    expect(fillEvents[0]?.comment).toEqual("mint comment1");
    expect(fillEvents[2]?.comment).toEqual("mint comment2");
  });
});
