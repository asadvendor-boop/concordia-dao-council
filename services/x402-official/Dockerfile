# Concordia official x402 settlement service (WP5).
# Build is fully offline-reproducible from the committed exact-pin lockfile.

FROM node:22.12.0-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22.12.0-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# The settle-journal migration is read at runtime (dist/../migrations).
COPY migrations ./migrations
# Durable fulfillment ledger volume (compose: x402_official_data:/data).
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
ENV X402_OFFICIAL_PORT=8787
EXPOSE 8787
USER node
CMD ["node", "dist/index.js"]
