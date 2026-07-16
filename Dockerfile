# Stvor API. Runtime MUST be Bun — the API uses bun:sqlite (native to Bun), and
# @stvor/core resolves to TypeScript source via the "bun" export condition, so
# there is no separate build step.
#
# Single stage on purpose: Bun's isolated linker lays out per-package
# node_modules (a workspace dep like fastify lives under stvor-api/node_modules,
# symlinked into the root node_modules/.bun store). A multi-stage build that
# copies only the ROOT node_modules loses those per-package dirs, and the app
# crashes at boot with "Cannot find package 'fastify'". Installing against the
# real, full source tree lays every node_modules out correctly.
FROM oven/bun:1.3
WORKDIR /app

# .dockerignore excludes node_modules/.stvor/dist, so this brings clean source.
COPY . .
RUN bun install --frozen-lockfile

ENV NODE_ENV=production
ENV STVOR_DB=/data/stvor.db
ENV STVOR_KEYS_FILE=/data/keys.json
ENV PORT=3000
ENV HOST=0.0.0.0

EXPOSE 3000
CMD ["bun", "run", "stvor-api/src/index.ts"]
