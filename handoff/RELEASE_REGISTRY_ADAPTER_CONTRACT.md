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
- the complete persisted immutable quote and its issued-row readback;
- the exact quote-hash and correlation-ID preimages, not only their digests;
- the exact finalized Casper RPC request/response transcripts from two named
  providers, including deploy hash, execution result, transfer source, payee,
  amount, transfer ID, block hash, height, state root, and timestamps;
- the committed payment-consumption row before and after provider restart;
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
- require processed/finalized execution with no execution error and corroborate
  the canonical block facts;
- prove one `(network, payment_hash)` consumption, identical fulfillment and
  response hash after restart, and no second consumption;
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
- exact EIP-712 authorization preimage, signature, public key, recovered payer,
  payee, value, nonce, validity window, and signed-payload bytes;
- raw sanitized `/verify` and `/settle` request/response transcripts;
- active WCSPR v8 package, contract, entry-point, and argument readbacks before
  verify, before settle, and after settle;
- finalized settlement RPC transcripts from two named providers with no
  execution error;
- durable fulfillment rows before/after restart, exact retry evidence, and
  cross-binding/authorization reuse rejection evidence;
- exact protected-report bytes and release-order evidence.

The adapter must recompute the payment-requirements hash, signed-payment-payload
hash, report hash, resource URL hash, payer account hash, EIP-712 signature,
finalized transfer arguments, and every v3 governance identity. It must require
`isValid === true`, `success === true`, the active WCSPR v8 drift guards, one
unique authorization/nonce binding, idempotent restart reconciliation, and a
terminal pre-submission cross-binding rejection.

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
