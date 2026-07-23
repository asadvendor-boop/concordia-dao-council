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
