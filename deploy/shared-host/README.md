# Concordia Shared Host Deployment

This profile runs Concordia DAO Council beside the other public demo services on one shared Docker host. It keeps Concordia on its own internal network and exposes only the dashboard and gateway through the shared reverse proxy.

## Public URL

Use:

```text
https://concordiadao.xyz
```

## Host layout

```text
/opt/apps/concordia/
  releases/
    <exact-release-commit>/
      src/                       # clean immutable checkout of this commit
        artifacts/              # never copied into a Docker image
        deploy/shared-host/
          compose.prod.yml
          otel-collector-config.yml
      env/
        concordia.env
        concordia-staging.env
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
The release directory is owner-controlled and write-once. Never update `src/`
in place: a successor commit gets a successor directory. Read-only container
binds prevent a Concordia process from changing it; host-root remains inside the
deployment trust boundary. The Python image excludes the entire `artifacts/`
tree, so an artifact-only release commit cannot change the image content ID.
Gateway receives the exact release artifact tree and exactly one selected proof
registry through separate read-only binds.

The `x402-governance-v3.json` file is public release configuration, while the
protected report is not public. Both stay in the release-private config
directory, mode `0600`, and are mounted read-only. The release collector records
a tree digest without serializing those bytes.

## Mandatory runtime proof mounts

Before rendering Compose, export all three paths. There are no defaults:

```bash
RELEASE_COMMIT="${RELEASE_COMMIT:?Set RELEASE_COMMIT to the approved 40-character commit}"
case "${RELEASE_COMMIT}" in
  *[!0-9a-f]*|"") echo "RELEASE_COMMIT must be lowercase hexadecimal" >&2; exit 64 ;;
esac
test "${#RELEASE_COMMIT}" -eq 40

RELEASE_ROOT="/opt/apps/concordia/releases/${RELEASE_COMMIT}"
RELEASE_SOURCE="${RELEASE_ROOT}/src"
COMPOSE_FILE="${RELEASE_SOURCE}/deploy/shared-host/compose.prod.yml"
ENV_FILE="${RELEASE_ROOT}/env/concordia.env"
STAGING_ENV_FILE="${RELEASE_ROOT}/env/concordia-staging.env"

test "$(git -C "${RELEASE_SOURCE}" rev-parse HEAD)" = "${RELEASE_COMMIT}"
test -z "$(git -C "${RELEASE_SOURCE}" status --porcelain=v1 --untracked-files=all)"
test -f "${COMPOSE_FILE}"
test -f "${ENV_FILE}"

export CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR="${RELEASE_SOURCE}/artifacts"
export CONCORDIA_PROOF_REGISTRY_HOST_DIR="${RELEASE_SOURCE}/artifacts/live/proof-registry"
export X402_OFFICIAL_CONFIG_DIR="${RELEASE_ROOT}/config/x402-official"
export CONCORDIA_DEPLOYMENT_COMMIT="${RELEASE_COMMIT}"
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
docker compose --project-name concordia \
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" \
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
: "${RELEASE_COMMIT:?Run the mandatory release-anchor block first}"
: "${RELEASE_SOURCE:?Run the mandatory release-anchor block first}"
: "${ENV_FILE:?Run the mandatory release-anchor block first}"
export X402_OFFICIAL_CONFIG_DIR="${RELEASE_ROOT}/config/x402-official"
install -d -m 0700 "${X402_OFFICIAL_CONFIG_DIR}"

(
  cd "${RELEASE_SOURCE}"
  uv run python "${RELEASE_SOURCE}/scripts/generate_x402_governance_v3_config.py" \
    --proof /absolute/path/to/finalized-official-x402-v3-proof.json \
    --out "${X402_OFFICIAL_CONFIG_DIR}/x402-governance-v3.json"
)

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

Pin Compose to that exact directory in the immutable `${ENV_FILE}`:

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
  docker compose --project-name concordia \
    --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" \
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

(
  cd "${RELEASE_SOURCE}"
  uv run python "${RELEASE_SOURCE}/scripts/stage_official_x402_governance.py" \
    --base-registry "${RELEASE_SOURCE}/artifacts/live/proof-registry/registry.json" \
    --v3-proof /absolute/path/exact-envelope-v3-official.json \
    --payment-envelope /absolute/path/official-x402-payment-envelope.json \
    --signed-payment-payload /absolute/path/payment-payload.json \
    --out "${STAGING_REGISTRY_DIR}/registry.json"
)
```

Create `${STAGING_ENV_FILE}` as a new mode-`0600` copy of `${ENV_FILE}` rather
than editing the active file in place. Its only semantic difference is:

```text
CONCORDIA_PROOF_REGISTRY_HOST_DIR=/opt/apps/concordia/releases/<release-commit>/registries/official-staging
```

Run the one-shot mount validator with that env file. Then select it with one
Gateway-only configuration replacement:

```bash
test -f "${STAGING_ENV_FILE}"
docker compose --project-name concordia \
  --env-file "${STAGING_ENV_FILE}" -f "${COMPOSE_FILE}" \
  run --rm --no-deps --entrypoint python gateway \
  -m shared.runtime_release_mounts
docker compose --project-name concordia \
  --env-file "${STAGING_ENV_FILE}" -f "${COMPOSE_FILE}" \
  up -d --no-deps --no-build --force-recreate gateway
curl -fsS "https://${CONCORDIA_HOSTNAME}/health"
```

This is the atomic configuration switch: one immutable env file selects one
immutable directory for the newly created Gateway container. Do not restart
the shared proxy, its networks, the dashboard, the provider, or the
official-x402 service for this selection.

After settlement capture, assemble and commit the final registry, create a new
immutable checkout for that exact final commit, repeat the mandatory
release-anchor block with the new `RELEASE_COMMIT`, and set:

```text
CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR=/opt/apps/concordia/releases/<final-commit>/src/artifacts
CONCORDIA_PROOF_REGISTRY_HOST_DIR=/opt/apps/concordia/releases/<final-commit>/src/artifacts/live/proof-registry
X402_OFFICIAL_CONFIG_DIR=/opt/apps/concordia/releases/<final-commit>/config/x402-official
```

Copy the already verified config directory into the final release root, compare
its recorded tree/file digests, run the one-shot validator, recreate Gateway
only, and recheck health plus the public and internal registry routes. G12 is
run only after this final selection; it rejects the staging path.

```bash
docker compose --project-name concordia \
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" \
  run --rm --no-deps --entrypoint python gateway \
  -m shared.runtime_release_mounts
docker compose --project-name concordia \
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" \
  up -d --no-deps --no-build --force-recreate gateway
```

## One-time shared proxy bootstrap (not a release step)

Skip this entire section for normal releases and every artifact or registry
selection. Those operations are Concordia-Gateway-only and must not change the
shared proxy, shared networks, or any cohost application.

1. Create the public edge network:

```bash
docker network create concordia-edge
```

2. Copy `Caddyfile.snippet` into the shared proxy Caddyfile.
3. Add `CONCORDIA_HOSTNAME=concordiadao.xyz`, `CONCORDIA_WWW_HOSTNAME=www.concordiadao.xyz`, `X402_PROVIDER_HOSTNAME=safepay.concordiadao.xyz`, and `CONCORDIA_X402_HOSTNAME=x402.concordiadao.xyz` to the shared proxy environment.
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
  "${RELEASE_SOURCE}/scripts/preflight_shared_caddy_safepay_secret.sh"
```

Do not adapt or reload the shared Caddy configuration unless this preflight
passes.

## Validate image identity

Every project-owned image must carry the same reviewed deployment commit in
`org.opencontainers.image.revision` and
`io.concordia.deployment-commit`; `org.opencontainers.image.source` is fixed to
the public Concordia repository. Validate these inputs before accepting the
rendered Compose configuration; the Dockerfiles repeat the same check before
installing dependencies or compiling application code.

```bash
"${RELEASE_SOURCE}/scripts/validate_oci_image_identity.sh" \
  "${CONCORDIA_DEPLOYMENT_COMMIT}" \
  "${CONCORDIA_DEPLOYMENT_COMMIT}" \
  "https://github.com/asadvendor-boop/concordia-dao-council"

docker compose --project-name concordia \
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" config --quiet
```

Missing, uppercase, non-40-character, divergent, or wrong-source identities
stop here. The immutable third-party index digests and their Linux platform
manifests are recorded in
[`OCI_IMAGE_PINS.md`](./OCI_IMAGE_PINS.md).

## Start

Build one image at a time. Before the first build and after every cutover,
perform the established GET-only health inventory for Concordia and all three
cohost judged applications. Stop immediately on any regression. Never reboot
the host, reload the shared proxy, or combine service cutovers.

```bash
COMPOSE=(
  docker compose --project-name concordia
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}"
)

"${COMPOSE[@]}" build gateway
"${COMPOSE[@]}" build x402-official
"${COMPOSE[@]}" build dashboard

"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate simulator
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate x402-provider
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate rowan
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate mercer
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate verity
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate alden
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate locke
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate wells
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate recorder-heartbeat
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate gateway
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate x402-official
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate dashboard
```

## Verify

```bash
docker compose --project-name concordia \
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" ps
curl -fsS https://concordiadao.xyz/health
curl -fsS https://concordiadao.xyz/ready
docker compose --project-name concordia \
  --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" \
  exec gateway python /app/scripts/casper_preflight.py --network
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
