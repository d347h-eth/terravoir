# syntax=docker/dockerfile:1.4
FROM node:24-bookworm-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential python3 git && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace root configuration
COPY package.json yarn.lock .yarnrc.yml turbo.json ./

# Copy all workspace package.json files for dependency resolution
COPY packages/indexer/package.json ./packages/indexer/
COPY packages/mint-interface/package.json ./packages/mint-interface/
COPY packages/sdk/package.json ./packages/sdk/
COPY packages/contracts/package.json ./packages/contracts/

# Install all dependencies (monorepo-aware)
RUN --mount=type=cache,target=/root/.cache/yarn \
    corepack enable && yarn install --immutable

# Copy all source code for all workspaces
COPY packages/ ./packages/

# Build all workspaces from root (respects workspace links)
# Persist Turborepo local cache across Docker builds for faster no-op builds
RUN --mount=type=cache,target=/app/.turbo,id=turbo-cache,sharing=locked \
    yarn build

# Production image
FROM node:24-bookworm-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy root package.json (needed for module-alias configuration)
COPY --from=builder /app/package.json ./package.json

# Copy built artifacts maintaining monorepo structure
COPY --from=builder /app/packages/indexer/dist ./packages/indexer/dist
COPY --from=builder /app/packages/indexer/package.json ./packages/indexer/package.json
## Migrations are required at runtime by node-pg-migrate
COPY --from=builder /app/packages/indexer/src/migrations ./packages/indexer/src/migrations
## Also copy local workspace packages required at runtime. Yarn links these in node_modules
## to their workspace folders (e.g., node_modules/@reservoir0x/sdk -> ../../packages/sdk).
## Without copying the workspace dirs, require('@reservoir0x/sdk') fails at runtime.
COPY --from=builder /app/packages/sdk/dist ./packages/sdk/dist
COPY --from=builder /app/packages/sdk/package.json ./packages/sdk/package.json
COPY --from=builder /app/packages/mint-interface/dist ./packages/mint-interface/dist
COPY --from=builder /app/packages/mint-interface/package.json ./packages/mint-interface/package.json

# Copy node_modules from root and indexer workspace
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/indexer/node_modules ./packages/indexer/node_modules

ENV NODE_ENV=production

# Start the indexer (must run from root for module-alias to work)
CMD ["node", "-r", "module-alias/register", "packages/indexer/dist/index.js"]
