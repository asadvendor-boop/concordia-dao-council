# x402 Governance Report Adapter

The core proof for Concordia remains the Casper Testnet governance receipt transaction. The x402 path is implemented as a paid specialist-report boundary with two generations:

- **SafePay Lite supplemental v2** (current, G1-frozen): a durable, replay-safe quote/redemption contract served by `x402_provider/`.
- **Legacy v1** (`GET /x402/risk-report` + `X-Payment`): retained for historical continuity only. It can never generate or substantiate new supplemental-v2 evidence.

The normative contract is `handoff/G1_INTERFACE_SPEC.md` §12 plus the `safepay_v2` machine schema in `handoff/G1_CROSS_LANE_SCHEMAS.json`. On any conflict, those documents win over this README.

## SafePay v2 wire contract

- `POST /x402/v2/quotes` with exactly `{schema_version:"safepay-quote-request-v2", proposal_id, resource_id}` (unknown fields rejected). The provider persists the complete immutable quote **before** returning HTTP 402 with `{schema_version:"safepay-v2", error:{code:"payment_required",retryable:false}, quote, payment_requirements}`. Every `payment_requirements` value equals the corresponding immutable quote field.
- `POST /x402/v2/redemptions` with exactly `{schema_version:"safepay-redemption-v2", quote, payment_hash}` where `quote` is the complete issued quote and `payment_hash` is 64 lowercase hex. `X-Payment` is not an accepted transport for v2.
- Both endpoints always send `Cache-Control: no-store` and `X-Concordia-SafePay-Version: safepay-v2`.

### Immutable quote

Fields (exact order): `schema_version` (`safepay-v2`), `quote_id`, `proposal_id`, `resource_id`, `network` (exactly `casper:casper-test`; aliases rejected before any ledger lookup and never normalized), `payee_account_hash`, `amount_motes`, `correlation_id`, `report_version` (`safepay-report-v2`), `report_hash`, `expires_at` (`issued_at + 900` exactly), `quote_nonce`, `quote_hash`.

`correlation_id` is per quote — the first 8 big-endian bytes of `BLAKE2b-256("CONCORDIA_SAFEPAY_QUOTE_V2\0" || lp(quote_id) || lp(proposal_id) || lp(resource_id) || quote_nonce)` — and is also the exact Casper native-transfer id. `quote_hash` uses the `CONCORDIA_SAFEPAY_QUOTE_HASH_V2\0` domain with `amount_motes` encoded as U512 fixed 64 bytes big-endian. Derivations live in `shared/x402_payments.py` (`safepay_v2_correlation_id`, `safepay_v2_quote_hash`, `safepay_v2_response_hash`) with golden vectors in `tests/test_safepay_verifier.py`.

### Durable ledger

SQLite at `X402_LEDGER` (default `/data/safepay.db`, named volume `x402_provider_data:/data`), WAL + `busy_timeout`, `BEGIN IMMEDIATE` writes, applied from `x402_provider/migrations/0001_safepay_v2.sql`:

- `safepay_quotes` — immutable issued quotes (restart-safe; redemption revalidates every submitted field plus the recomputed `quote_hash` against this row; a caller-computed but unissued quote is 404 `quote_not_issued`).
- `safepay_reports` — content-addressed protected report bytes (SHA-256 key, ≤1,024 rows, ≤67,108,864 decoded bytes total, per-report ≤262,144 bytes; hash conflicts fail issuance closed). Fulfillments serve `content_base64` only from these persisted bytes; the protected bytes never appear in the public quote.
- `payment_consumptions` — the consumption authority with `UNIQUE(network, payment_hash)`. Exactly one redemption wins; the stored fulfillment and `response_hash` are immutable.
- `safepay_quote_rate_limits` + `safepay_quote_issue_reservations` — durable fixed-window counters (12 per client / 120 global per 60s, window start `floor(now/60)*60`, global sentinel row `(global, global)`) and the 32-in-flight reservation cap for the two-phase issuance.
- `safepay_redemption_observations` — append-only provider observations (`first_consumption`, `idempotent_replay`, `cross_binding_rejected`) powering honest evidence derivation.

Quote issuance is two-phase: a preflight `BEGIN IMMEDIATE` (bounded GC ≤100 rows, rate/in-flight admission, both counters charged with no refund, 60s pending reservation) commits **before** report resolution, which runs with a hard 10s timeout outside every write transaction; a second `BEGIN IMMEDIATE` samples the single `issued_at`, rechecks all caps (10,000 outstanding active, 20,000 retained unconsumed including expired, report row/byte caps), inserts or exactly revalidates the report, inserts the quote, and completes the reservation before the 402 is returned. A rejected preflight never calls the report source.

### Redemption semantics

Order: canonical-network validation → load persisted quote (`404 quote_not_issued`, no payment lookup) → exact field + recomputed `quote_hash` match (`422 quote_binding_invalid`) → read-only consumption lookup (same binding → stored idempotent 200, different binding → terminal `409`, neither needs a chain call, including after expiry) → unconsumed expired quote → terminal `410` before chain observation → exact Casper observation outside any write lock → `BEGIN IMMEDIATE` revalidate + atomic claim.

Payment acceptance is exact-only: finalized/processed status, an execution result with no execution error, exactly one native transfer, exact payee equality (never substring), exact amount equality (never `>=`, overpay refused), exact transfer id equal to `correlation_id`, exact network. An exact retry returns the identical fulfillment and `response_hash` with `delivery.replay_disposition="idempotent_replay"`; the gateway never retries 400/404/409/410/422 and `shared/x402_payments.py` no longer treats HTTP 409 as retryable indexer lag anywhere (it surfaces terminal `duplicate_conflict`).

### Truth constraint

Duplicate rejection is proven only by recorded ledger observations — a persisted consumption plus a recorded terminal 409 cross-binding observation. Artifact booleans (for example a claimed `duplicate_proof_rejected`) are never trusted or copied; `x402_provider/ledger.py::summarize_quote_evidence` recomputes everything from rows.

## Provider configuration

```bash
X402_LEDGER=/data/safepay.db                     # SQLite ledger path (volume x402_provider_data:/data)
SAFEPAY_PAYEE_ACCOUNT_HASH=<64 lowercase hex>    # v2 payee (falls back to X402_PAYMENT_ACCOUNT_HASH)
SAFEPAY_AMOUNT_MOTES=2500000000                  # v2 amount (falls back to X402_PAYMENT_AMOUNT)
SAFEPAY_TRUSTED_PROXY_CIDRS=<comma-separated>    # invalid CIDRs fail startup; unset = headers never trusted
SAFEPAY_PROXY_SECRET_FILE=/run/secrets/safepay_proxy_secret
SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE=/run/secrets/safepay_client_key_hmac_secret
```

Both secret files must exist and hold at least 32 bytes or the process fails startup. `X-Concordia-Client-IP` / `X-Concordia-SafePay-Proxy` are honored only when the socket peer is inside `SAFEPAY_TRUSTED_PROXY_CIDRS` **and** the attestation matches in constant time; otherwise the socket peer is used. Only HMAC-SHA-256 client keys are persisted — raw addresses never touch the ledger. The simulated indexer-lag switch for v2 is a test-only constructor parameter that defaults off; no environment variable can enable it.

## Legacy v1 (historical continuity)

- `shared/x402_payments.py` builds HTTP payment-request headers.
- `/x402/governance-report` returns HTTP `402` until an `X-Payment` proof is supplied.
- Demo mode validates a deterministic local HMAC-style proof.
- Real mode is enabled with `X402_SETTLEMENT_MODE=real` and `X402_FACILITATOR_URL`, calling facilitator `/verify` and `/settle`.
- Verification/settlement retries are bounded to absorb Casper provider indexer lag; the legacy verifier now also requires exact payee/amount/transfer-id matches.

```bash
X402_SETTLEMENT_MODE=real
X402_FACILITATOR_URL=https://your-facilitator.example
X402_FACILITATOR_TOKEN=optional-token
X402_PAYMENT_ADDRESS=your-casper-payment-address
X402_PAYMENT_AMOUNT=1000000
X402_PAYMENT_NETWORK=casper-testnet
X402_MAX_ATTEMPTS=4
X402_RETRY_DELAY_SECONDS=5
```

No production payment private key is embedded in the repository.
