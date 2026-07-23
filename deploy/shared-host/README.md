# Concordia Shared Host Deployment

This profile runs Concordia DAO Council beside the other public demo services on one shared Docker host. It keeps Concordia on its own internal network and exposes only the dashboard and gateway through the shared reverse proxy.

## Public URL

Use:

```text
https://concordia.47.84.232.193.sslip.io
```

## Host layout

```text
/opt/apps/concordia/
  compose.prod.yml
  concordia.env
  releases/
    <exact-release-commit>/
      src/                       # clean immutable checkout of this commit
        artifacts/              # never copied into a Docker image
      config/
        x402-official/
          x402-governance-v3.json
          x402-resources.json
          protected-report.bin
      registries/
        official-staging/
          registry.json
  secrets/
    llm_api_key
    gateway_secret
    recorder_submission_key
    triage_submission_key
    diagnosis_submission_key
    safety_reviewer_submission_key
    commander_submission_key
    operator_submission_key
    proposal_room_api_key
    approval_proxy_secret
    approval_ui_bcrypt_hash
    approval_ui_csrf_secret
    safepay_proxy_secret
    concordia_operator_token
    casper_secret_key.pem
    casper_public_key.pem
```

Secret files should be owned by root and readable only by the deployment group.
The release directory is write-once. Never update `src/` in place: a successor
commit gets a successor directory. The Python image excludes the entire
`artifacts/` tree, so an artifact-only release commit cannot change the image
content ID. Gateway receives the exact release artifact tree and exactly one
selected proof registry through separate read-only binds.

The `x402-governance-v3.json` file is public release configuration, while the
protected report is not public. Both stay in the release-private config
directory, mode `0600`, and are mounted read-only. The release collector records
a tree digest without serializing those bytes.

## Mandatory runtime proof mounts

Before rendering Compose, export all three paths. There are no defaults:

```bash
RELEASE_COMMIT="$(git rev-parse HEAD)"
RELEASE_ROOT="/opt/apps/concordia/releases/${RELEASE_COMMIT}"
RELEASE_SOURCE="${RELEASE_ROOT}/src"

test "$(git -C "${RELEASE_SOURCE}" rev-parse HEAD)" = "${RELEASE_COMMIT}"
test -z "$(git -C "${RELEASE_SOURCE}" status --porcelain=v1)"

export CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR="${RELEASE_SOURCE}/artifacts"
export CONCORDIA_PROOF_REGISTRY_HOST_DIR="${RELEASE_SOURCE}/artifacts/live/proof-registry"
export X402_OFFICIAL_CONFIG_DIR="${RELEASE_ROOT}/config/x402-official"
```

Each bind uses `read_only: true` and `create_host_path: false`; a missing source
therefore blocks container creation. Gateway additionally validates before
Uvicorn starts that:

- the artifact root, its historical proof inputs, and the RWA sample are
  regular non-symlink files;
- the selected registry is a separate non-symlink directory containing exactly
  `registry.json`;
- the complete registry passes the strict Python validator; and
- its card-chain and public artifact digests equal the bytes in the mounted
  release tree.

Run the same check in a one-shot container before every selection:

```bash
docker compose --env-file concordia.env -f compose.prod.yml \
  run --rm --no-deps --entrypoint python gateway \
  -m shared.runtime_release_mounts
```

Do not start or recreate Gateway if this command does not return
`{"status":"ready",...}`.

## Stage the official-x402 governance binding

Do this only after the `OfficialX402SettlementV1` exact-envelope proof is
finalized and independently verified. The generator accepts no package,
contract, network, or deployment-domain arguments: it extracts those identities
from the proof after running `scripts.verify_v3_proof.verify_v3_proof_document`.
It performs no network requests and reads no key or token.

From the exact release checkout, generate into a new release-scoped directory:

```bash
umask 077
RELEASE_COMMIT="$(git rev-parse HEAD)"
RELEASE_ROOT="/opt/apps/concordia/releases/${RELEASE_COMMIT}"
RELEASE_SOURCE="${RELEASE_ROOT}/src"
export X402_OFFICIAL_CONFIG_DIR="${RELEASE_ROOT}/config/x402-official"
install -d -m 0700 "${X402_OFFICIAL_CONFIG_DIR}"

uv run python scripts/generate_x402_governance_v3_config.py \
  --proof /absolute/path/to/finalized-official-x402-v3-proof.json \
  --out "${X402_OFFICIAL_CONFIG_DIR}/x402-governance-v3.json"

CONFIG_SHA256="$(
  sha256sum "${X402_OFFICIAL_CONFIG_DIR}/x402-governance-v3.json" |
  awk '{print $1}'
)"
test -n "${CONFIG_SHA256}"
test "$(stat -c '%a' "${X402_OFFICIAL_CONFIG_DIR}/x402-governance-v3.json")" = "600"
```

These commands target the Linux deployment host. If generation occurs in the
verified local release checkout and the bytes are transferred to the host,
transfer them into a newly created release-scoped directory, set mode `0600`,
and require the host SHA-256 to equal the generator's recorded
`config_sha256`. Never replace an existing config path. A collision or
mismatched digest stops the release.

Pin Compose to that exact directory in `concordia.env`:

```text
X402_OFFICIAL_CONFIG_DIR=/opt/apps/concordia/releases/<release-commit>/config/x402-official
```

Keep `X402_OFFICIAL_CONFIG_DIR` exported in the release shell. Before starting
`x402-official`, verify both the host bytes and the bytes seen through the
read-only container mount:

```bash
HOST_SHA256="$(
  sha256sum "${X402_OFFICIAL_CONFIG_DIR}/x402-governance-v3.json" |
  awk '{print $1}'
)"
CONTAINER_SHA256="$(
  docker compose --env-file concordia.env -f compose.prod.yml \
    run --rm --no-deps --entrypoint node x402-official \
    -e "const fs=require('node:fs');const c=require('node:crypto');process.stdout.write(c.createHash('sha256').update(fs.readFileSync('/run/config/x402-governance-v3.json')).digest('hex'))"
)"
test "${HOST_SHA256}" = "${CONFIG_SHA256}"
test "${CONTAINER_SHA256}" = "${CONFIG_SHA256}"
```

Only after both comparisons pass may the service start. After startup,
`/health` must report the expected blocked or live state without a governance
configuration error; missing, malformed, stale, or WCSPR-reused governance
identity is a release refusal.

## Isolated official-x402 registry switch

The official service needs its finalized action and signed-payment binding
before `/verify` or `/settle`, but the final public settlement proof does not
exist yet. Never put the staging and final registry documents in one loaded
directory.

Generate the complete combined staging document into the release-scoped
directory:

```bash
STAGING_REGISTRY_DIR="${RELEASE_ROOT}/registries/official-staging"
install -d -m 0700 "${STAGING_REGISTRY_DIR}"

uv run python scripts/stage_official_x402_governance.py \
  --base-registry "${RELEASE_SOURCE}/artifacts/live/proof-registry/registry.json" \
  --v3-proof /absolute/path/exact-envelope-v3-official.json \
  --payment-envelope /absolute/path/official-x402-payment-envelope.json \
  --signed-payment-payload /absolute/path/payment-payload.json \
  --out "${STAGING_REGISTRY_DIR}/registry.json"
```

Create a new release env file rather than editing the active one in place. It
must keep `CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR` fixed and set only:

```text
CONCORDIA_PROOF_REGISTRY_HOST_DIR=/opt/apps/concordia/releases/<release-commit>/registries/official-staging
```

Run the one-shot mount validator with that env file. Then select it with one
Gateway-only configuration replacement:

```bash
docker compose --env-file concordia-staging.env -f compose.prod.yml \
  up -d --no-deps --force-recreate gateway
curl -fsS "https://${CONCORDIA_HOSTNAME}/health"
```

This is the atomic configuration switch: one immutable env file selects one
immutable directory for the newly created Gateway container. Do not restart
Caddy, the dashboard, the provider, or the official-x402 service for this
selection.

After settlement capture, assemble and commit the final registry, create a new
immutable checkout for that exact final commit, and set:

```text
CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR=/opt/apps/concordia/releases/<final-commit>/src/artifacts
CONCORDIA_PROOF_REGISTRY_HOST_DIR=/opt/apps/concordia/releases/<final-commit>/src/artifacts/live/proof-registry
X402_OFFICIAL_CONFIG_DIR=/opt/apps/concordia/releases/<final-commit>/config/x402-official
```

Copy the already verified config directory into the final release root, compare
its recorded tree/file digests, run the one-shot validator, recreate Gateway
only, and recheck health plus the public and internal registry routes. G12 is
run only after this final selection; it rejects the staging path.

## Shared proxy integration

1. Create the public edge network:

```bash
docker network create concordia-edge
```

2. Copy `Caddyfile.snippet` into the shared proxy Caddyfile.
3. Add `CONCORDIA_HOSTNAME=concordia.47.84.232.193.sslip.io` to the shared proxy environment.
4. Attach the proxy container to `concordia-edge`.
5. Mount the same SafePay proxy-attestation file read-only at
   `/run/secrets/safepay_proxy_secret` inside the independently managed shared
   Caddy container. Concordia Compose does not own or imply this mount.
6. Run the runtime mount check before every Caddy adapt/reload; it reads no
   secret value into host output and verifies that the external Caddy mount is
   byte-identical to the application secret source:

```bash
CADDY_CONTAINER=<shared-caddy-container> \
  SAFEPAY_APP_SECRET_PATH=/opt/apps/concordia/secrets/safepay_proxy_secret \
  ./scripts/preflight_shared_caddy_safepay_secret.sh
```

Do not adapt or reload the shared Caddy configuration unless this preflight
passes.

## Start

```bash
docker compose --env-file concordia.env -f compose.prod.yml up -d --build
```

## Verify

```bash
docker compose --env-file concordia.env -f compose.prod.yml ps
curl -fsS https://concordia.47.84.232.193.sslip.io/health
curl -fsS https://concordia.47.84.232.193.sslip.io/ready
docker compose --env-file concordia.env -f compose.prod.yml exec gateway python scripts/casper_preflight.py --network
```

`/ready` must fail closed if the live LLM key or endpoint is absent in production mode.

## Final chain proof

The qualification proof is not complete until Locke submits a real Casper Testnet receipt transaction and the demo shows:

```text
contract hash
transaction hash
proposal ID
evidence URL
```
