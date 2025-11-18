import * as Boom from "@hapi/boom";
import { Request, RouteOptions } from "@hapi/hapi";
import Joi from "joi";

import { logger } from "@/common/logger";
import { config } from "@/config/index";
import { focusOwnerSnapshotJob } from "@/jobs/focus/focus-owner-snapshot-job";

export const postFocusSnapshotOwnershipOptions: RouteOptions = {
  description: "Queue focus-owner snapshot jobs that call ownerOf(tokenId) and persist snapshots.",
  tags: ["api", "admin"],
  plugins: {
    "hapi-swagger": {
      id: "post-focus-snapshot-ownership",
    },
  },
  validate: {
    headers: Joi.object({
      "x-admin-api-key": Joi.string().required(),
    }).options({ allowUnknown: true }),
    payload: Joi.object({
      tokenIds: Joi.array()
        .items(Joi.string().pattern(/^[0-9]+$/))
        .min(1)
        .max(5000),
      range: Joi.object({
        start: Joi.number().integer().min(0).required(),
        end: Joi.number().integer().min(0).required(),
      }).custom((value, helpers) => {
        if (value.end < value.start) {
          return helpers.error("any.invalid");
        }
        if (value.end - value.start > 20000) {
          return helpers.error("any.max");
        }
        return value;
      }),
      blockNumber: Joi.number().integer().min(0),
      chunkSize: Joi.number().integer().min(1).max(500).default(100),
      source: Joi.string().max(64).default("ownerOf"),
    })
      .xor("tokenIds", "range")
      .options({ stripUnknown: true }),
  },
  response: {
    schema: Joi.object({
      enqueued: Joi.number().integer().required(),
    }),
  },
  handler: async (request: Request) => {
    if (!config.focusCollectionAddress) {
      throw new Error("Focus mode must be enabled to use the snapshot endpoint");
    }

    if (request.headers["x-admin-api-key"] !== config.adminApiKey) {
      throw Boom.unauthorized("Wrong or missing admin API key");
    }

    const payload = request.payload as {
      tokenIds?: string[];
      range?: { start: number; end: number };
      blockNumber?: number;
      chunkSize: number;
      source: string;
    };

    const tokenIds = payload.tokenIds
      ? payload.tokenIds
      : Array.from({ length: payload.range!.end - payload.range!.start + 1 }, (_, i) =>
          (payload.range!.start + i).toString()
        );

    const chunks = [] as { tokenId: string; blockNumber?: number; source: string }[][];
    for (let i = 0; i < tokenIds.length; i += payload.chunkSize) {
      const slice = tokenIds.slice(i, i + payload.chunkSize).map((tokenId) => ({
        tokenId,
        blockNumber: payload.blockNumber,
        source: payload.source,
      }));
      chunks.push(slice);
    }

    for (const chunk of chunks) {
      await focusOwnerSnapshotJob.addToQueue(chunk);
    }

    logger.info(
      "post-focus-snapshot-ownership",
      JSON.stringify({
        tokenCount: tokenIds.length,
        blockNumber: payload.blockNumber,
      })
    );

    return {
      enqueued: tokenIds.length,
    };
  },
};
