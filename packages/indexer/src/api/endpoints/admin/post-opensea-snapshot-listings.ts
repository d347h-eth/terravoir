/* eslint-disable @typescript-eslint/no-explicit-any */

import { Request, RouteOptions } from "@hapi/hapi";
import Joi from "joi";

import { logger } from "@/common/logger";
import { toBuffer } from "@/common/utils";
import { Collections } from "@/models/collections";
import { openseaListingsProcessJob } from "@/jobs/opensea-listings/opensea-listings-process-job";
import { idb } from "@/common/db";
import { config } from "@/config/index";

const version = "v1";

export const postOpenseaSnapshotListingsV1Options: RouteOptions = {
  description: "Snapshot OpenSea Listings (by collection)",
  notes:
    "Fetch best/active OpenSea listings across a collection via OS REST and save them like WS path. Use to seed a new indexer instance.",
  tags: ["api", "admin", "opensea"],
  plugins: {
    "hapi-swagger": {
      order: 14,
    },
  },
  validate: {
    headers: Joi.object({
      "x-admin-api-key": Joi.string().required(),
    }).options({ allowUnknown: true }),
    payload: Joi.object({
      // Accept either contract or slug; resolve missing field from DB if possible
      collection: Joi.string().required().description("Collection id (contract) or slug"),
      prioritize: Joi.boolean().default(false),
    }),
  },
  response: {
    schema: Joi.object({ message: Joi.string() }).label(
      `postOpenseaSnapshotListings${version.toUpperCase()}Response`
    ),
    failAction: (_request, _h, error) => {
      logger.error(
        `post-opensea-snapshot-listings-${version}-handler`,
        `Wrong response schema: ${error}`
      );
      throw error;
    },
  },
  handler: async (request: Request) => {
    if (request.headers["x-admin-api-key"] !== config.adminApiKey) {
      throw new Error("Unauthorized");
    }
    const payload = request.payload as any;
    let slug = payload.collection;
    let contract: string | undefined;
    let collectionId: string | undefined;

    // Try to resolve from collections table
    const bySlug = await idb.oneOrNone(
      `SELECT id, contract, slug FROM collections WHERE slug = $/slug/ LIMIT 1`,
      { slug }
    );
    if (bySlug) {
      collectionId = bySlug.id;
      contract = bySlug.contract ? `0x${Buffer.from(bySlug.contract).toString("hex")}` : undefined;
    } else {
      // Fallback: treat input as contract address
      const byContract = await Collections.getById(payload.collection);
      if (!byContract) {
        throw new Error(`Collection not found for input=${payload.collection}`);
      }
      collectionId = byContract.id;
      contract = byContract.contract;
      slug = byContract.slug || slug;
    }

    if (!slug || !contract) {
      throw new Error("Both slug and contract are required to snapshot listings");
    }

    // Focus gate: if focus is enabled, enforce the same contract
    if (config.focusCollectionAddress) {
      if (config.focusCollectionAddress.toLowerCase() !== contract.toLowerCase()) {
        throw new Error("Focus mode is enabled; snapshot is restricted to the focus collection");
      }
    }

    await openseaListingsProcessJob.addToQueue([
      {
        contract,
        collectionId: collectionId!,
        collectionSlug: slug,
        prioritized: Boolean(payload.prioritize),
      },
    ]);

    return { message: "enqueued" } as any;
  },
};
