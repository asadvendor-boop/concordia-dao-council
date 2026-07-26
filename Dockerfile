FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

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
COPY artifacts/live ./artifacts/live
COPY artifacts/rwa ./artifacts/rwa
COPY docs ./docs
COPY dashboard/app/proof ./dashboard/app/proof
COPY dashboard/app/judge ./dashboard/app/judge
COPY docker/entrypoint.sh /usr/local/bin/concordia-entrypoint

RUN uv sync --locked --no-dev \
    && chmod 0755 /usr/local/bin/concordia-entrypoint

EXPOSE 8000 9000

ENTRYPOINT ["concordia-entrypoint"]
CMD ["gateway"]
