FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

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

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock README.md ./
COPY shared ./shared
COPY config ./config
COPY gateway ./gateway
COPY x402_provider ./x402_provider
COPY agents ./agents
COPY proposal-simulator ./proposal-simulator
COPY integrations ./integrations
COPY scripts ./scripts
COPY docs ./docs
COPY dashboard/app/proof ./dashboard/app/proof
COPY dashboard/app/judge ./dashboard/app/judge
COPY docker/entrypoint.sh /usr/local/bin/concordia-entrypoint

RUN uv sync --locked --no-dev \
    && chmod 0755 /usr/local/bin/concordia-entrypoint

EXPOSE 8000 9000

ENTRYPOINT ["concordia-entrypoint"]
CMD ["gateway"]
