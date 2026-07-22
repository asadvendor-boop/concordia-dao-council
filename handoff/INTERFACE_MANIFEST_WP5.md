# INTERFACE MANIFEST — WP5 (official CSPR.cloud x402 settlement service)

- Producer branch: `claude/finals-product-security`
- Producer commit: `f5cf748`
- Rooted at freeze: `concordia-g1-freeze-v2.0-a` (`b24c0409`)
- Spec authority: `handoff/G1_INTERFACE_SPEC.md` §6, §11, §12 "Official x402 local service v1", §13
- Lane status: `npm ci` + typecheck clean; 128/128 vitest green (offline, all upstreams mocked/loopback). Golden vectors cross-checked against an INDEPENDENT Python `hashlib.blake2b(digest_size=32)` reference (I re-verified two anchor vectors myself).

Greenfield, isolated in `services/x402-official/`. It starts and remains
`blocked_fail_closed` until Codex injects live chain access — exactly §11's
required start state. Items below are Codex-owned for integration + the live canary.

## compose.prod.yml service entry (Codex / WP10)
Service `x402-official` (alias `concordia-x402-official`), build `services/x402-official/Dockerfile`, `restart: unless-stopped`, networks concordia-internal (+ edge vhost net), volume `x402_official_data:/data`. Env EXACTLY:
`NODE_ENV=production`, `X402_OFFICIAL_PORT=8787`, `X402_FACILITATOR_URL=https://x402-facilitator.cspr.cloud`, `X402_NETWORK=casper:casper-test`, `X402_SCHEME=exact`, `X402_WCSPR_PACKAGE_HASH=3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e`, `X402_WCSPR_CONTRACT_HASH=032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a`, `X402_WCSPR_CONTRACT_VERSION=8`, `X402_TOKEN_NAME='Wrapped CSPR'`, `X402_TOKEN_SYMBOL=WCSPR`, `X402_TOKEN_DECIMALS=9`, `X402_TOKEN_DOMAIN_VERSION=1`, **`X402_LEDGER_PATH=/data/x402-official.db`** (frozen name in G1_CROSS_LANE_SCHEMAS.json — distinct from the SafePay provider's ledger env), `X402_GATEWAY_INTERNAL_URL=http://gateway:8000`, `X402_RESOURCES_FILE=/run/config/x402-resources.json`.
Secrets: `X402_CSPR_CLOUD_TOKEN_FILE=/run/secrets/x402_official_cspr_cloud_token`, `X402_SIGNER_FILE=/run/secrets/x402_official_signer`, `X402_GATEWAY_TOKEN_FILE=/run/secrets/x402_official_gateway_token`.
Healthcheck: `node -e "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`.

## Caddy vhost (Codex / WP10)
`{$CONCORDIA_X402_HOSTNAME}` reverse_proxy `concordia-x402-official:8787` for `GET /health`, `GET /supported`, `GET /resource/*`, `POST /verify`, `POST /settle`. (This is the `x402.concordiadao.xyz` record — DNS only after the vhost is staged, per C3.)

## Gateway internal registry endpoint (Codex)
`GET /internal/proof-registry/v1/x402/{signed_payment_payload_hash}` per §13 EXACTLY. This service authenticates with `X-Concordia-Service-Token` from `/run/secrets/x402_official_gateway_token` and validates the 22-field record with **unknown-fields-REJECT** — so any extra field Codex adds will fail closed. Bodies: 404 `{error:'action_not_found'}`, 409 `{error:'ambiguous_governance_binding'}`. (Codex's WP4 registry commit `96312f0` already provides `/internal/proof-registry/...` — confirm the x402 sub-path + exact 22 fields match.)

## Live ChainTransport wiring (Codex, canary-time)
Implement/inject the Casper RPC observer for the frozen interface in `services/x402-official/src/chain.ts`, at deps construction in `src/index.ts`:
- `resolveActivePackage(packageHashHex) -> {lockStatus, enabledVersion, enabledContractHash}`
- `getFinalizedTransaction(txHashHex) -> {finalized, executionSuccess, targetContractHash, contractVersion, entryPoint, argNames[, args]}`
Until injected, the service is structurally `blocked_fail_closed` (drift guards refuse, zero credentialed calls).

## Resource config + report bytes (Codex / WP10)
Mount JSON per `services/x402-official/config/resources.example.json` (`{resources:[{id,url,description,mimeType,amount,payTo,maxTimeoutSeconds,reportFile|reportBase64}]}`) + the protected report bytes file. URLs must already be canonical per §6 — the loader **rejects, never normalizes**.

## Deviations / notes for Codex
- Local `GET /supported` returns THIS service's own frozen capability doc computed from config (no credentialed upstream). The §12 facilitator-`/supported` parser (kinds/extensions/signers) is implemented + tested in `src/facilitator.ts` for the Codex-run probe.
- No live Casper RPC readback client in-lane (Codex-owned live ops); default ChainTransport fails closed = §11 start state.
- `settlement_state → official_hosted_verified_live` only when a settlement row reaches `finalized` with post-settle v8 readback passed; production-reachable only via the real hosted canary.
- Dev deps: `vitest@3.2.7` (clears GHSA-5xrq-8626-4rwp), `better-sqlite3@12.4.1`, `blakejs@1.2.1` are the extra exact pins; the four §12 runtime pins are exact and untouched.
- EIP-712 verify reuses the pinned `@make-software/casper-x402` `ExactCasperScheme.verify()` offline (stub signer, `getNetworkConfig` only) — strict §12 canonical/shape validation runs FIRST because the official verify alone is looser.

## Open issues / live-gate flags
- **The `amount`-vs-`value` ABI trap is real:** the published 1.0.0 settlement builder uses runtime arg `amount` while live v8 requires `value`. If the hosted facilitator runs that builder, this service's post-settle readback correctly fails closed (argNames containing `amount` is a hard, test-covered failure). Codex must confirm the facilitator path before the canary.
- Production `/verify` + `/settle` cannot reach the credentialed facilitator until Codex injects the live ChainTransport — intended §11 behavior; make it an explicit gate in the WP10 rollout.
- `X402_SETTLEMENT_COMPATIBILITY_STATE` env from the schemas is informational; authoritative state is persisted in the ledger `service_state` table (starts blocked_fail_closed, survives restart) and reported by `/health`.
