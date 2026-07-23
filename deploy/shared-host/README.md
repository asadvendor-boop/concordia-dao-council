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
  config/
    x402-official-<release-commit>/
      x402-governance-v3.json
      x402-resources.json
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
The `x402-governance-v3.json` file is public release configuration, not a
secret, but it is still mode `0600`, write-once, and mounted read-only so a
runtime process cannot redirect the governance identity.

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
export X402_OFFICIAL_CONFIG_DIR="/opt/apps/concordia/config/x402-official-${RELEASE_COMMIT}"
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
X402_OFFICIAL_CONFIG_DIR=/opt/apps/concordia/config/x402-official-<release-commit>
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
