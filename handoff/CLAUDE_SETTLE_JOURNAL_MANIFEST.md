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

## Superseded first draft

Commit `9c349be` established the durable-journal implementation shape, but its
schema was not the already-frozen release contract. It is retained only as
immutable review history. Its column names, call-ID derivation, response
status semantics, and 409-test count are not release requirements and must
not be used by an operator or artifact generator.

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
