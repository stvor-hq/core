# Stvor API. Runtime MUST be Bun — the API uses bun:sqlite (native to Bun), and
# @stvor/core resolves to TypeScript source via the "bun" export condition, so
# there is no separate build step. One process, one machine, one volume.
FROM oven/bun:1.3 AS deps
WORKDIR /app

# Install against the workspace manifests first for layer caching.
COPY package.json bun.lock ./
COPY stvor-core/package.json ./stvor-core/
COPY stvor-sdk/package.json ./stvor-sdk/
COPY stvor-api/package.json ./stvor-api/
COPY stvor-verify/package.json ./stvor-verify/
COPY examples/orbserv/package.json ./examples/orbserv/
RUN bun install --frozen-lockfile

FROM oven/bun:1.3 AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Persistent state lives on the mounted volume, never in the image.
ENV STVOR_DB=/data/stvor.db
ENV STVOR_KEYS_FILE=/data/keys.json
ENV PORT=3000
ENV HOST=0.0.0.0

COPY --from=deps /app/node_modules ./node_modules
COPY . .

EXPOSE 3000
CMD ["bun", "run", "stvor-api/src/index.ts"]
