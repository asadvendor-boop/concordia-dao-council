# Settle-Journal Correction — `claude/official-settle-journal-correction`

Base: executable product head `7ef9ca1` (immutable). One commit implements
the durable upstream-settle journal required by the frozen official-x402
release evidence. No VM, secrets, chain, DNS, npm, or live-artifact action
occurred; no Codex-owned schema/adapter/release file was altered.

## Files

Added:
- `services/x402-official/migrations/0002_upstream_settle_journal.sql`
- `services/x402-official/src/settle-journal.ts`
- `services/x402-official/test/settle-journal.test.ts`

Modified (exactly the permitted set):
- `src/types.ts` — `SettleCallBinding`; `FacilitatorTransport.settle(body,
  binding)`.
- `src/facilitator.ts` — journaled settle flow (below); journal supplied
  via `FacilitatorTransportTestOptions.settleJournal`.
- `src/http.ts` — `readBoundedText` extracted; `readBoundedJson` now wraps
  it (behaviour unchanged for verify/supported).
- `src/pipeline.ts` — the single `/settle` call site passes the binding
  from the reserved fulfillment row.
- `src/index.ts` — constructs `SettleJournal(config.ledgerPath)` (same
  durable volume/file as the ledger), passes it to the transport, closes it
  on shutdown.
- `test/helpers.ts` — `MockFacilitator.settle` accepts + records bindings.
- `Dockerfile` — `COPY migrations ./migrations` into the runtime image
  (read at runtime as `dist/../migrations`).

## Contract implemented

- Table `x402_upstream_settle_calls`, columns in the ordered shape:
  `sequence, event_type, call_id, network, wcspr_contract,
  signed_payment_payload_hash, payer_account_hash, authorization_nonce,
  resource_id, action_id, envelope_hash, request_method, request_url,
  request_headers_json, request_body, request_body_sha256, response_status,
  response_headers_json, response_body, response_body_sha256, failure_code,
  observed_at`. Event types exactly `request_started`, `response_observed`,
  `request_failed`.
- Append-only: BEFORE UPDATE and BEFORE DELETE triggers always `RAISE(ABORT)`.
- Partial unique indexes: one start per `call_id`; one terminal per
  `call_id`; one start per authorization identity `(network, wcspr_contract,
  payer_account_hash, authorization_nonce)`; one start per payload
  `(network, signed_payment_payload_hash)`.
- Terminal insertion aborts unless a `request_started` row exists with the
  SAME call_id AND identical binding/request fields (trigger
  `x402_settle_terminal_matches_start`).
- `call_id = SHA256("CONCORDIA_X402_SETTLE_CALL_V1\0" || lp(field)…)` over
  length-prefixed (u32-BE, matching `hashes.lp`) UTF-8 fields in order:
  network, WCSPR contract, signed-payload hash, payer, nonce, resource ID,
  action ID, envelope hash, request-body SHA256.
- `HttpFacilitatorTransport.settle`: serializes ONCE; journals those exact
  bytes durably (`synchronous=FULL` connection) BEFORE any credentialed
  I/O; sends the same bytes. Start-append failure ⇒ no network call.
  2xx ⇒ raw bytes read bounded and journaled as `response_observed` BEFORE
  parsing; if that append fails, success is never returned (throw; the
  ledger's reserved `submission_started` row keeps recovery fail-closed).
  Non-2xx/transport failure ⇒ bounded `request_failed` with status +
  allowlisted headers only — credentialed non-2xx bodies are never read or
  stored. Journaled request headers are exactly
  `{"content-type":"application/json"}`; response headers pass the
  allowlist {content-type, content-length, date, retry-after, server,
  x-request-id}; Authorization/tokens/cookies never enter a row.
- Retry/reconcile/cross-binding paths never reach `settle()` (the ledger's
  exclusive-submission CAS is its only caller); the journal's unique start
  indexes are a second, independent enforcement of at-most-one-settle.
- A transport constructed without a journal refuses `settle()` outright
  (`settle_journal_not_configured`) before any I/O — required because the
  journal parameter rides in the options object: the pre-existing
  credential-discipline tests (`test/facilitator.test.ts`,
  `test/server.test.ts`) construct the transport positionally and are
  outside this correction's permitted file set, so the constructor
  signature could not change; the fail-closed guard makes an unjournaled
  settle structurally impossible anyway.

## Tests (12 new, in `test/settle-journal.test.ts`)

Append-only UPDATE/DELETE abort · duplicate start per call/authorization/
payload refuses · terminal-without-matching-start and drifted-binding
terminal abort · second terminal refuses · call_id derivation pinned
(domain NUL, field sensitivity) · start journaled BEFORE fetch with
byte-identical sent/journaled body · start-append failure ⇒ zero network
calls · no credential in any row (constant request-header record, response
allowlist, token absent from full dump) · raw 2xx bytes journaled BEFORE
parse (unparseable body preserved) · bounded non-2xx failure (status +
headers, body null) · bounded transport-error failure · restart
persistence on the same file · pipeline-level: idempotent `runSettle`
retry re-serves the stored response with exactly one journaled
start+response pair and one upstream `/settle` fetch.

Failing-first evidence: the entire feature is absent at `7ef9ca1` — this
test file does not even import there (`src/settle-journal.ts` missing;
`settle()` had no binding parameter), so every test fails at the base by
construction.

## Gate results (all at the correction commit)

- `npm ci`: clean, 0 vulnerabilities reported at install.
- `npm run typecheck` (`tsc --noEmit`): clean.
- `npm test` (vitest): **21 files, 409/409 passed — three consecutive
  runs** (397 pre-existing + 12 new).
- `npm audit --omit=dev`: **0 vulnerabilities**.

No live or release mutation occurred; all work is local code and tests on
this branch only.

---

# Correction round — frozen-contract conformance (on top of immutable `9c349be`)

Sol's review found my 409 tests validated a schema of my own design, not
the frozen release contract. This correction replaces the migration with
the EXACT frozen bytes and makes the TypeScript producer conform.

- `migrations/0002_upstream_settle_journal.sql` is now byte-for-byte the
  `UPSTREAM_SETTLE_JOURNAL_MIGRATION` constant from
  `tests/test_release_official_x402_adapter.py`: **5,206 bytes, SHA-256
  `c660abcc…fb51c5f`** — pinned by test.
- Producer conformance:
  - `request_headers_canonical_json` / `response_headers_canonical_json`
    BLOB columns; canonical JSON = lowercase keys, sorted, compact
    (byte-compatible with the adapter's Python `_canonical`).
  - Request/response bodies stored as exact BLOBs — the transport
    serializes once to a Buffer, journals it, sends the same Buffer; the
    response is read as raw bounded bytes and journaled before parsing.
  - Terminal rows set every request field to NULL (schema-enforced and
    producer-enforced; pinned by test).
  - Failure rows carry ONLY the bounded failure code plus an optional
    4xx/5xx status — no headers, no body, ever.
  - Frozen call ID:
    `SHA256("CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\0" ||
    payload_hash_bytes || nonce_bytes)` — parity with the frozen Python
    derivation pinned by vector
    (`05f10a9c738a161b6e7e15fd4b955ba93ac462e7f9dcd89a8d67cb8cd1c729dc`
    for payload `bb`×32 / nonce `ee`×32).
  - Frozen index/trigger names verified against `sqlite_master` by test.
  - Upstream success must be EXACTLY 200; any other status fails closed
    without reading or storing the body (2xx≠200 →
    `unexpected_success_status`, status NULL; 4xx/5xx → bounded
    `facilitator_http_<n>` with status).
  - The frozen start-row CHECK pins `request_url` to the production
    `/settle` endpoint — a transport pointed anywhere else cannot even
    journal a start, and therefore cannot settle. Journal tests exercise
    the real transport against the frozen origin with a stubbed global
    fetch (no network I/O occurs).
- Tests: 12 → **17** journal tests (migration byte-exactness, SQLite
  object names/types, byte identity of journaled request/response, NULL
  terminal request fields, call-ID parity vector, non-200 fail-closed,
  plus all prior coverage re-proven against the frozen schema).
- Gates at the correction commit: `npm ci` clean; typecheck clean;
  **414/414 vitest ×3 consecutive runs**; `npm audit --omit=dev` 0
  vulnerabilities. `9c349be` untouched (no amend/rebase); no live system
  touched.
