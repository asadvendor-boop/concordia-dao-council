FROM node:20-bookworm-slim

WORKDIR /app

ARG CONCORDIA_IMAGE_REVISION
ARG CONCORDIA_IMAGE_DEPLOYMENT
ARG CONCORDIA_IMAGE_SOURCE
ARG NEXT_PUBLIC_GATEWAY_URL=""
ARG NEXT_PUBLIC_CONCORDIA_MODE="reviewer"
ARG NEXT_PUBLIC_CSPR_CLICK_APP_ID

COPY scripts/validate_oci_image_identity.sh /usr/local/bin/validate-oci-image-identity
RUN /bin/sh /usr/local/bin/validate-oci-image-identity \
    "${CONCORDIA_IMAGE_REVISION}" \
    "${CONCORDIA_IMAGE_DEPLOYMENT}" \
    "${CONCORDIA_IMAGE_SOURCE}"

LABEL org.opencontainers.image.revision="${CONCORDIA_IMAGE_REVISION}" \
      org.opencontainers.image.source="${CONCORDIA_IMAGE_SOURCE}" \
      io.concordia.deployment-commit="${CONCORDIA_IMAGE_DEPLOYMENT}"

ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_GATEWAY_URL="${NEXT_PUBLIC_GATEWAY_URL}" \
    NEXT_PUBLIC_CONCORDIA_MODE="${NEXT_PUBLIC_CONCORDIA_MODE}" \
    NEXT_PUBLIC_CSPR_CLICK_APP_ID="${NEXT_PUBLIC_CSPR_CLICK_APP_ID}"

COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci

COPY dashboard/ ./
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start", "--", "-H", "0.0.0.0", "-p", "3000"]
