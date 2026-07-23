# Release registry adapter contract

This is the fail-closed handoff required to make the G12 registry complete.
`scripts/assemble_proof_registry.py` currently verifies historical Odra, exact
envelope v3, and native treasury artifacts. It must not manufacture SafePay or
official-x402 checks from `verified`, `passed`, `status`, or other producer
booleans.

The final release registry is accepted only with these five public proof types
and two artifact-derived internal action records:

1. `historical_odra_receipt_v2`
2. `exact_envelope_v3`
3. `native_treasury_execution_v1`
4. `safepay_v2`
5. `official_x402_settlement_v1`

The internal records are the exact `NativeTransferV1` and
`OfficialX402SettlementV1` projections. The release validator in
`shared/release_manifest.py` compares every field to the bound source artifact.

The normative wire contracts are closed Draft 2020-12 JSON Schemas:

- `handoff/schemas/safepay-v2-live-artifact.schema.json`
- `handoff/schemas/safepay-v2-adapter-result.schema.json`
- `handoff/schemas/official-x402-live-artifact.schema.json`
- `handoff/schemas/official-x402-adapter-result.schema.json`

Their paths and SHA-256 digests are pinned in
`handoff/RELEASE_REGISTRY_ADAPTER_SCHEMAS.json`. The prose below explains the
verification semantics; it does not loosen any schema field, type, cardinality,
encoding, or `additionalProperties: false` boundary.

## SafePay v2 adapter

Input is the canonical `artifacts/live/safepay-lite-replaysafe-v2.json`. The
adapter must independently recompute all eleven checks in
`REQUIRED_CHECKS_BY_PROOF_TYPE["safepay_v2"]` from raw evidence.

The exact artifact contains:

- release identity: `schema_version`, `captured_at`, `source_commit`, and
  `deployment_commit`;
- capture-tool identity bound to `source_commit`, plus deterministic runtime
  identities for the provider instance before and after restart. Each identity
  binds the container ID, deployment ID, image digest, start time, observation
  time, and restart count; quote, consumption, and SQLite observations must
  fall inside the matching runtime interval;
- the complete persisted immutable quote and its issued-row readback;
- the exact quote-hash and correlation-ID preimages, not only their digests;
- the exact Casper `info_get_deploy`, `chain_get_block`, and
  `info_get_status` request/response transcripts from two named providers,
  including deploy hash, execution result, transfer source, payee, amount,
  transfer ID, block hash, height, state root, timestamps, chainspec, and a
  tip at least eight blocks beyond the payment block;
- the committed payment-consumption row before and after provider restart;
- the exact repository migration plus three SQLite online backups of the
  authoritative provider ledger after first consumption, exact retry, and
  rejected cross-binding reuse;
- the first fulfillment, exact retry fulfillment, and cross-binding request and
  terminal `409` response;
- exact persisted protected-report bytes (base64 is acceptable), media type,
  report hash, response hash, quote/resource/proposal binding, and observation
  timestamps.

WP2's provider-native summary uses one configured CSPR.live REST observer and
is useful operational evidence, but it is not sufficient for the release
adapter. The Codex-owned capture step must enrich the committed artifact with
the two independently named raw Casper JSON-RPC observations required by the
pinned artifact schema. If either transcript is missing, unavailable, or
disagrees, the adapter remains unavailable; it must not collapse the summary
into a two-node claim.

The adapter must:

- recompute the canonical network as exactly `casper:casper-test`;
- recompute quote hash and per-quote correlation ID from the G1 frozen binary
  formulas;
- parse one structured native transfer and require exact payee, amount, and
  transfer ID; substring matching and `amount >= expected` are forbidden;
- require processed execution with no execution error, corroborate the
  canonical block facts, and derive finality from two distinct nodes whose
  `casper-test` tips are each at least eight blocks beyond that block;
- validate SQLite integrity, require the exact repository schema and unique
  `(network, payment_hash)` key, and independently query all three backups to
  prove one immutable consumption. A second row sharing the payment hash,
  quote ID, quote hash, or correlation ID is also forbidden, even under a
  different network spelling. The ordered 1→2→3 redemption-observation
  progression across first consumption, exact retry, and rejected reuse must
  agree with the chronological HTTP transcripts;
- prove a changed quote/resource binding returned terminal `409` before any
  second consumption;
- recompute the report hash from exact persisted bytes.

Only those recomputed facts may create the `safepay_v2` public item. Its
`proposal_id`, `report_hash`, artifact digest, commits, and capture time must
come from the verified artifact.

## Official x402 adapter

Input is the canonical
`artifacts/live/official-x402-settlement-v1.json`. The adapter must
independently recompute all twenty-two checks in
`REQUIRED_CHECKS_BY_PROOF_TYPE["official_x402_settlement_v1"]`.

The exact artifact contains:

- release identity: `schema_version`, `captured_at`, `source_commit`, and
  `deployment_commit`;
- one complete `governance_binding` containing the exact internal-record
  fields: `proposal_id`, `proposal_hash`, `proposal_nonce`, `action_id`,
  `action_kind`, `action_version`, `envelope_hash`, `deployment_domain`,
  `network`, `package_hash`, `contract_hash`, `v3_finalized_exact`,
  `finalization_transaction`, `finalized_at`, `observed_at`,
  `resource_url_hash`, and the exact-envelope check evidence;
- the exact bytes and SHA-256 of the separate v3 proof whose action kind is
  `OfficialX402SettlementV1`; the native-transfer v3 proof cannot be reused or
  relabeled for this binding;
- configured resource bytes and the accepted/payment-requirements objects;
- exact EIP-712 authorization preimage, Ed25519 signature and tagged Ed25519
  public key, recovered payer, payee, value, nonce, validity window, and
  signed-payload bytes;
- raw sanitized `/verify` and `/settle` request/response transcripts;
- active WCSPR v8 package, contract, entry-point, and argument readbacks before
  verify, before settle, and after settle. Each observation includes
  `info_get_status`, reads the package and contract at that provider's exact
  latest block/state root, proves that v8 is the latest enabled version, and
  records the real Casper CLValue types and bytes;
- finalized settlement `info_get_transaction`, `chain_get_block`, and
  `info_get_status` RPC transcripts from the two release-pinned provider
  origins, with no execution error, valid unique Casper block-proof signers,
  distinct node signing identities, and at least eight confirmations;
- the first paid-resource release, exact retry, and cross-binding reuse as
  exact `GET /resource/:resourceId` exchanges. Each exchange carries the
  canonical sanitized request/response header maps and their SHA-256 values,
  the exact `PAYMENT-SIGNATURE` raw value and decoded signed-payload bytes,
  and exact response bytes. Successful releases additionally carry the exact
  `PAYMENT-RESPONSE` raw value and decoded settlement bytes. The terminal
  `409` exchange carries an empty canonical response-header map, so the
  absence of `PAYMENT-RESPONSE` is parsed from evidence rather than accepted
  from a producer boolean;
- durable fulfillment rows before/after restart and three SQLite online
  backups of the authoritative upstream-settle-call journal: after first
  release, after exact retry, and after rejected cross-binding reuse;
- exact protected-report bytes and release-order evidence.

The adapter must recompute the payment-requirements hash, signed-payment-payload
hash, report hash, resource URL hash, payer account hash, EIP-712 signature,
finalized transfer arguments, and every v3 governance identity. It must require
`isValid === true`, `success === true`, the active WCSPR v8 drift guards, one
unique authorization/nonce binding, idempotent restart reconciliation, and a
terminal pre-submission cross-binding rejection.

The paid-resource header maps are canonical ASCII JSON objects containing only
lowercase payment header names. The request map is exactly
`{"payment-signature":"<raw value>"}`. A successful response map is exactly
`{"payment-response":"<raw value>"}`. The rejected-reuse response map is
exactly `{}`. `Authorization`, cookies, proxy credentials, access tokens, and
all other headers are forbidden from the artifact. The adapter hashes and
decodes the dedicated raw-value fields and requires them to equal the values
parsed from those maps.

The journal migration bytes must equal the repository migration
`services/x402-official/migrations/0002_upstream_settle_journal.sql`; an
artifact-supplied migration is never accepted as its own authority. Every
snapshot is an actual SQLite online-backup image. The adapter opens each image
read-only with an immutable URI, requires `PRAGMA integrity_check` to return
exactly `ok`, validates the table and indexes installed by that migration, and
queries the append-only `x402_upstream_settle_calls` rows in ascending sequence
order. It serializes those rows as ASCII JSON using sorted keys, separators
`,` and `:`, `ensure_ascii=true`, and no non-finite numbers, then requires the
exact `rows_canonical_json_base64` and SHA-256 in the snapshot.

The table is an immutable event journal. A `request_started` row is committed
with `synchronous=FULL` after the fulfillment CAS reaches
`submission_started` and before any credentialed network I/O. It contains the
exact serialized request bytes and the complete non-secret settlement
binding. A successful bounded HTTP 200 response appends one
`response_observed` row
before JSON parsing or returning to the pipeline. A timeout, transport error,
or any non-200 response appends one `request_failed` row containing only the
bounded local failure code and an optional 4xx/5xx HTTP status;
credential-reflecting response headers and bytes are never stored. Terminal
rows carry no request fields. Update and delete triggers make all three event
classes append-only. Partial unique indexes permit exactly one
`request_started` and at most one terminal event per call ID, and exactly one
request-start event per WCSPR authorization identity. The call ID is
independently recomputed as SHA-256 over the frozen domain separator followed
by the raw signed-payload hash and authorization nonce bytes.

The independently derived journal root is:

```text
SHA256(
  "CONCORDIA_X402_SETTLE_CALL_JOURNAL_V1\0"
  || u64be(row_count)
  || SHA256(canonical_row_1)
  || ...
  || SHA256(canonical_row_n)
)
```

For the successful finals flow, the adapter requires one request-start row and
one response-observed row sharing the same call ID and exact binding; no
`request_failed` row is allowed. The request and response bytes must equal the
facilitator `/settle` transcript. The common network, WCSPR contract,
signed-payload hash, payer, authorization nonce, resource, action, and envelope
must equal the finalized fulfillment row; the transaction and response hash
are parsed from the observed response and must also equal that fulfillment.
The same two canonical rows and root must survive all three snapshots even
though the latter two service observations occur after retry and rejection.
Producer-supplied call counts, success booleans, and claimed roots are never
verification inputs; counts and roots are recomputed from the SQLite images.

Only those recomputed facts may create the official public item and its
`OfficialX402SettlementV1` internal record. The internal record must equal the
artifact projection byte-for-byte after canonical JSON normalization; public
and internal action/envelope/payment/report/settlement identities must match.

## Adapter API and release behavior

Each product handoff must provide a deterministic Python verifier callable by
the assembler:

```text
verify_safepay_v2_artifact(document, raw_bytes) -> verified facts + check evidence
verify_official_x402_artifact(document, raw_bytes) -> verified facts + check evidence
```

The result may contain derived facts, but no input truth boolean can authorize
a check. Each result check contains the exact source artifact path, an
evidence-derived `observed_at`, one or more JSON Pointers into the frozen input,
and the SHA-256 of the canonical evidence projection. The result schemas pin
check order and cardinality (11 SafePay, 22 official). Duplicate, missing,
future-dated, failed, reordered, or unrecognized required checks fail assembly.

The assembler then:

1. reads each artifact once with no symlink and a stable inode/stat identity;
2. runs the independent adapter;
3. constructs public/internal projections from adapter results;
4. runs Python registry validation and the packaged
   `@concordia-dao/verify` CLI;
5. rechecks every input inode and digest before atomic output;
6. emits no unavailable item as green.

Until both adapters and their mutation tests exist, G12 remains blocked. A
manual registry edit, copied producer status, or reduced five-item/two-record
cardinality is not an allowed fallback.
