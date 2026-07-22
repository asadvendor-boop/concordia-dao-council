# INTERFACE MANIFEST — WP2 (SafePay v2 durable atomic consumption)

- Producer branch: `claude/finals-product-security`
- Producer commit: `9a4d66f`
- Rooted at freeze: `concordia-g1-freeze-v2.0-a` (`b24c0409`)
- Spec authority: `handoff/G1_INTERFACE_SPEC.md` §12 "SafePay Lite supplemental v2", §2 (encoding)
- Lane status: 66 new SP tests green (36 ledger + 30 verifier) + freeze 16/16. Golden vectors (`correlation_id`, `quote_hash`) verified byte-for-byte against an INDEPENDENT reference computed from the spec formulas.

The **no-shortcuts core**: `duplicate_proof_rejected` is now derivable as genuinely
TRUE from durable single-use consumption — the claim is never removed or renamed.
Items below are Codex-owned changes required for full integration.

## shared/proof_runtime.py + shared/proof_pack.py (Codex / WP4) — THE truth-gate rewire
Derive `duplicate_proof_rejected` ONLY from ledger evidence, never from artifact booleans:
- The provider persists append-only `safepay_redemption_observations` (kinds `first_consumption` / `idempotent_replay` / `cross_binding_rejected`, each with `http_status`).
- The provider exposes `SafePayLedger.summarize_quote_evidence(quote_id)` whose rule is: **`consumption_recorded` AND a `cross_binding_rejected` (http 409) observation exists for the consumed payment.**
- `build_safepay_lite` (`:641-644`) and the invariant (`:403-408`) must consume that summary / the new artifact `artifacts/live/safepay-lite-replaysafe-v2.json`, NOT `artifact.get('duplicate_proof_rejected')` or the 4-status handshake. SP-13 proves the provider side already ignores forged booleans.
- Frozen artifact shape for `safepay-lite-replaysafe-v2.json`: `quote{...13 immutable fields}` · `consumption{network, payment_hash, quote_id, consumed_at, response_hash}` · `redemption_observations[]` · `verification{observed recipient, amount_motes, transfer_id, deploy_status, error_message, block_height}`.

## gateway/app.py (Codex / WP4) — v2 client flow + status mapping
- Client flow: `POST /x402/v2/quotes` → echo `quote.correlation_id` as the EXACT native transfer id in the wallet intent (never reconstruct a quote) → `POST /x402/v2/redemptions` with the exact quote + lowercase deploy hash.
- Map the new helper statuses from `shared/x402_payments.py`: `idempotent_replay` → HTTP 200 + idempotent marker; `duplicate_conflict` → 409 passthrough terminal; `provider_rejected` / `invalid_provider_response` → honest non-paid states.
- NEVER retry 400/404/409/410/422 (the async helpers already enforce this and now all accept a `transport=` param for testing).

## deploy compose (Codex / WP10)
- `x402-provider` service: named volume `x402_provider_data:/data`, env **`X402_LEDGER=/data/safepay.db`** (NOTE: I used `X402_LEDGER`; recon draft said `X402_LEDGER_PATH` — freeze ONE name).
- Provision `/run/secrets/safepay_proxy_secret` and `/run/secrets/safepay_client_key_hmac_secret` (≥32 bytes each) with envs `SAFEPAY_PROXY_SECRET_FILE` + `SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE`. **⚠ The provider now FAILS STARTUP without these outside `CONCORDIA_TEST_MODE` — deploy the secrets BEFORE this branch ships or the container crash-loops.**
- `SAFEPAY_TRUSTED_PROXY_CIDRS` (invalid CIDR fails startup), `SAFEPAY_PAYEE_ACCOUNT_HASH` (64 lowercase hex) + `SAFEPAY_AMOUNT_MOTES` for the immutable quote terms.
- Add the ledger file to the §20 backup set.

## Caddy (Codex / WP10)
- Per §12: DELETE any caller-supplied `X-Concordia-Client-IP` / `X-Concordia-SafePay-Proxy`, then overwrite with the real remote peer and the server-side proxy secret. Provider verifies peer ∈ CIDR + constant-time attestation.

## tests/test_concordia_core.py (Codex owns migration, per Sol's WP2 rulings)
- `test_x402_transfer_proof_parser_requires_processed_transfer` pins the OLD false behavior (amount 1,200,000 accepted vs expected 1,000,000 via `>=`, no transfer-id check) and now fails BY DESIGN. Migrate to exact-equality fixtures (exact amount, exactly one matching transfer, transfer id required when resource-bound). This is the only WP2-caused break.

## Deviations from spec I made (for Codex review)
- Startup-secret gate: a set `*_FILE` env is always hard-validated; when BOTH are unset AND `CONCORDIA_TEST_MODE` is active, an ephemeral in-process random secret is generated so the root conftest + legacy tests can build the app. Production with unset envs fails startup as frozen.
- Quote already consumed by a DIFFERENT payment_hash, then redeemed with a new payment: spec defines no outcome → terminal 409 `payment_already_consumed_for_other_binding` / `cross_binding_rejected` (closest frozen enum).
- Internal integrity failures → endpoint 503 `provider_unavailable` fail-closed (content-addressed report hash conflict at issuance; stored bytes no longer hashing to `quote.report_hash` at redemption, SP-12). Spec fixes fail-closed but not the exact code; no consumption recorded.
- Missing/expired reservation at final issue tx → 503 `quote_capacity_exhausted` (spec silent; grouped with capacity family).
- Added ONE table beyond the frozen minimum: append-only `safepay_redemption_observations` `UNIQUE(kind,network,payment_hash,quote_id)` — required to honestly evidence the registry checks and SP-13. All frozen tables/columns implemented exactly.
- Legacy `GET /x402/risk-report` verifier now also requires transfer id == `x402_payment_correlation_id(resource)` when resource-bound (plus exact payee/amount, exactly one matching transfer). §12 keeps legacy for continuity; item-5 exactness applies. The historical June-29 deploy carries this id (gateway wallet intent embedded it).

## Open issues for Codex / live-gate
- `observe_safepay_v2_payment` maps CSPR.live `processed` → `finalized`; the live-gate should confirm the finality source before capturing live SafePay v2 evidence. All redemption acceptance logic is exact per the frozen predicate.
- SP-15 (dashboard honest-unavailable render + removal of hardcoded `duplicate_proof_rejected`/all-passed fallbacks) is a WP7 deliverable, NOT here (dashboard/** outside WP2 whitelist).
- Re-baseline the full suite after both lanes land: my run showed 11 pre-existing `pycspr` env failures + failures from concurrent sibling-agent edits in the shared worktree — none from WP2 files.
