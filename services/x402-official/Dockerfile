# Concordia official x402 settlement service (WP5).
# Build is fully offline-reproducible from the committed exact-pin lockfile.

FROM node:22.12.0-bookworm-slim AS build
WORKDIR /app

ARG CONCORDIA_IMAGE_REVISION
ARG CONCORDIA_IMAGE_DEPLOYMENT
ARG CONCORDIA_IMAGE_SOURCE

COPY scripts/validate_oci_image_identity.sh /usr/local/bin/validate-oci-image-identity
RUN /bin/sh /usr/local/bin/validate-oci-image-identity \
    "${CONCORDIA_IMAGE_REVISION}" \
    "${CONCORDIA_IMAGE_DEPLOYMENT}" \
    "${CONCORDIA_IMAGE_SOURCE}"

COPY services/x402-official/package.json services/x402-official/package-lock.json services/x402-official/tsconfig.json ./
RUN npm ci
COPY services/x402-official/src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22.12.0-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app

ARG CONCORDIA_IMAGE_REVISION
ARG CONCORDIA_IMAGE_DEPLOYMENT
ARG CONCORDIA_IMAGE_SOURCE

COPY scripts/validate_oci_image_identity.sh /usr/local/bin/validate-oci-image-identity
RUN /bin/sh /usr/local/bin/validate-oci-image-identity \
    "${CONCORDIA_IMAGE_REVISION}" \
    "${CONCORDIA_IMAGE_DEPLOYMENT}" \
    "${CONCORDIA_IMAGE_SOURCE}"

LABEL org.opencontainers.image.revision="${CONCORDIA_IMAGE_REVISION}" \
      org.opencontainers.image.source="${CONCORDIA_IMAGE_SOURCE}" \
      io.concordia.deployment-commit="${CONCORDIA_IMAGE_DEPLOYMENT}"

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY services/x402-official/package.json ./
# The settle-journal migration is read at runtime (dist/../migrations).
COPY services/x402-official/migrations ./migrations
# Durable fulfillment ledger volume (compose: x402_official_data:/data).
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
ENV X402_OFFICIAL_PORT=8787
EXPOSE 8787
USER node
CMD ["node", "dist/index.js"]
