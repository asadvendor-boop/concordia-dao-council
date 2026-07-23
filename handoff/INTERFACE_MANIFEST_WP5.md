# INTERFACE MANIFEST — WP5 (official CSPR.cloud x402 settlement service)

- Producer branch: `claude/finals-product-security`
- Producer commit: `2179eb0` (correction lineage: `f5cf748` → `929f4a2` → `1c832f7` → `2179eb0` resource-route transport invariant)
- Rooted at freeze: `concordia-g1-freeze-v2.0-a` (`b24c0409`)
- Spec authority: `handoff/G1_INTERFACE_SPEC.md` §6, §11, §12 "Official x402 local service v1", §13
- Lane status: `npm ci` + typecheck clean; 291/291 vitest green x3 consecutive at `2179eb0` (incl. adversarial concurrency, stored-response-tampering, terminal-invariant, and resource-transport suites); `npm audit --audit-level=high` clean. Golden vectors cross-checked against an INDEPENDENT Python `hashlib.blake2b(digest_size=32)` reference.

## Resource-route transport invariant (HTTP-surface blocker) — at `2179eb0`
`GET /resource/:resourceId` can return a 2xx ONLY when the exact protected report bytes are released from a finalized, integrity-verified fulfillment row with a valid PAYMENT-RESPONSE header — true success and the exact idempotent retry are the only 200 report responses. Every non-release outcome maps non-2xx at the resource boundary: 402 payment/governance/settlement refusals (including protocol-shaped `ServiceRefusal(200)` codes such as `ungoverned_payload`, `blocked_upgrade_drift`, `settlement_execution_failed`, `post_settle_readback_failed` when surfaced via the resource route), 409 terminal binding conflicts, 429 throttled paid attempts, 503 pending/retryable, 500 ledger-integrity; residual sub-400 statuses are hard-coerced. The `/verify` + `/settle` wire semantics (protocol-shaped 200 refusal bodies) are UNCHANGED — the fix is the resource route's mapping layer. Paid resource attempts draw from the SAME per-client fixed-window settlement budget as `POST /settle` (throttle bypass closed). Pinned by ten HTTP-level tests (`test/server.test.ts` "protected resource transport invariant"): seven non-release outcomes each asserting non-2xx + no bytes + no PAYMENT-RESPONSE + no false release audit code, two positive release controls, one throttle test.

## Correction pass (post NO-GO review) — what changed at `929f4a2`
- Readback fail-closed: `TransactionReadback.args` is mandatory; all EIGHT `transfer_with_authorization` args verified (exact CL type/ABI order, account-only Key variant, U256 value, validity window, nonce, public key, signature) + exact package/contract/transaction identity; `finalized:false` = resumable PENDING; lockStatus must be `Unlocked`.
- Lost `/settle` recovery via **ChainTransport method `locateSettlementByAuthorization(payer, package, contract, nonce)`** — **Codex: the live ChainTransport you inject must implement this third method** (in addition to `resolveActivePackage` / `getFinalizedTransaction`, and `getFinalizedTransaction` must return all 8 typed args + `transactionHash`). **CONTRACT CHANGE (security addendum at `1c832f7`): a negative result MUST be `{found:false, observed:{finalized:true, blockHeight:<finalized height>, stateRootHash:<64-hex state root actually queried>}}` and may only be returned when the absence was proven against a FINALIZED state snapshot. An indexer miss, mempool/non-finalized-head read, or unknown outcome must THROW instead. The service treats any boundary-less or malformed negative as indeterminate (stays pending, never resubmits). Resubmission after a proven-unconsumed result additionally requires winning a durable per-row recovery lease (single SQLite CAS, 120s expiry), so no two callers/processes can resubmit concurrently — the invariant "exactly one facilitator settlement per fulfillment, under N concurrent retries and across processes" is now enforced and proven by `test/concurrency.test.ts`.**
- Production config frozen (any env differing from a G1 constant is rejected at startup); credentialed fetches: exact HTTPS origins, raw Authorization, `redirect:"error"`, bounded timeout/body.
- Exact terminal/idempotent retries resolve from the ledger BEFORE volatile registry/expiry/liveness gates.
- `src/settlement-item.ts` is a pure VALIDATING builder for the official §13 registry item — **Codex emits it at canary time with operator-supplied trusted RPC endpoints** (the service never chooses verifier observation URLs). **API CHANGE (security addendum at `1c832f7`): `checkObservedAt` is gone; the input now requires `checks: [{name, passed, source, observed_at, evidence}]` — one independently captured receipt per required check. The builder validates the complete set (all 15 required names exactly once, no extras, `passed:true`, per-check artifact source, strict UTC-Z chronology vs `captured_at`, non-empty evidence) and REFUSES otherwise — it can no longer mint `verification_status:"verified"` from identity fields. Codex's canary tooling must capture each check receipt from the actual artifacts.**
- Ledger schema gained `valid_after`/`valid_before`/`public_key`/`signature` columns (restart reconciliation) and, at `1c832f7`, `recovery_lease_id`/`recovery_lease_expires_at` (durable exclusive submission/recovery ownership; additive `ALTER TABLE` auto-migration for existing volumes); state machine + unique keys unchanged. Terminal rows are invariant-checked on write (violations roll back) AND on read: a finalized row requires a 64-hex transaction, stored response bytes with a matching SHA-256 digest, `settled_at`, and no failure reason; a failed row requires its bounded failure code and matching stored failure response. Corrupt terminal rows fail closed and are never replayed as success — **WP10 rollout note: terminal rows written before this addendum without stored response bytes/digest will refuse replay instead of resynthesizing.**

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
