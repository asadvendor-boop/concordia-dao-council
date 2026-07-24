# Concordia G1 Interface Freeze v2.0-A

Status: **normative and ready** when paired with `G1_FREEZE_MANIFEST.json` at the
annotated tag `concordia-g1-freeze-v2.0-a`.

This document resolves the remaining contradictions in the approved v2.0 plan
and v2.0-A addendum. Where either planning document differs from this freeze,
this freeze is authoritative. It freezes interfaces and proof semantics; it is
not evidence that the implementation or any live proof already exists.

## 1. Non-negotiable boundaries

- Historical v1/v2 source, Wasm, artifacts, receipts, package hashes, and the
  frozen canonical 12-card chain are read-only.
- v3 is a new sibling crate and a new Testnet package.
- Claude owns only its assigned product/security paths. Codex owns all shared
  integration files and every VM, Caddy, Compose, DNS-publication, Testnet,
  artifact-generation, and npm-publish operation.
- Both implementation branches must start at the exact annotated G1 tag.
- No secret value may appear in a command line, log, response dump, artifact,
  handoff file, commit, or chat.
- The current production stack remains available until a replacement has
  passed its own health gate. Rollback restores availability; it never counts
  as completing an item.

## 2. Canonical scalar encoding

All hashed encodings are concatenations in the field order defined below.
There is no JSON canonicalization and no delimiter-concatenated text.

Every reference to `BLAKE2b-256` means RFC 7693 BLAKE2b configured directly
with `digest_size=32`, an empty key, empty salt, and empty personalization. It is
not a truncation of a 64-byte BLAKE2b digest. Every domain separator is exact
ASCII followed by one `0x00` byte; the authoritative separator hex and byte
lengths are recorded in the machine manifest and golden-vector tests.

| Type | Canonical bytes |
|---|---|
| `u8` | one unsigned byte |
| `u32` | four unsigned big-endian bytes |
| `u64` | eight unsigned big-endian bytes |
| `U256` | exactly 32 unsigned big-endian bytes, including leading zeroes |
| `U512` | exactly 64 unsigned big-endian bytes, including leading zeroes |
| `Bytes32` | exactly 32 raw bytes |
| `AccountHash` | semantic account identity, exactly 32 raw account-hash bytes |
| `String` | `u32_be(byte_length) || exact ASCII bytes` |
| `Bytes` | `u32_be(byte_length) || raw bytes` |
| `bool` | `0x00` false or `0x01` true |

Every hashed string is ASCII. Length limits are byte limits. Encoders reject
non-ASCII input, embedded NUL, invalid grammar, overlong input, or a supplied
display string that is not byte-for-byte equal to the validated source. There
is no trimming, Unicode normalization, case folding, or implicit URL rewrite.

`proposal_id` grammar: `[A-Z0-9-]{1,64}`.

Machine field names: `[a-z][a-z0-9_]{0,63}`.

Free display/config strings: printable ASCII `0x20..0x7e`, with the per-field
maximum below.

Authoritative separator bytes:

| Purpose | Bytes | Length |
|---|---|---:|
| deployment domain | `434f4e434f524449415f444f4d41494e5f563300` | 20 |
| envelope | `434f4e434f524449415f474f5645524e414e43455f454e56454c4f50455f563300` | 33 |
| action ID | `434f4e434f524449415f414354494f4e5f49445f563300` | 23 |
| transfer ID | `434f4e434f524449415f5452414e534645525f49445f563300` | 25 |
| resource URL | `434f4e434f524449415f5245534f555243455f55524c5f563100` | 26 |
| preauth evidence | `434f4e434f524449415f505245415554485f45564944454e43455f563100` | 30 |
| authorized metadata | `434f4e434f524449415f415554484f52495a45445f4d455441444154415f563100` | 33 |
| execution args | `434f4e434f524449415f455845435f415247535f563100` | 23 |
| payment requirements | `434f4e434f524449415f5041594d454e545f524551554952454d454e54535f563100` | 34 |
| signed payment payload | `434f4e434f524449415f5349474e45445f5041594d454e545f5041594c4f41445f563100` | 36 |
| x402 report | `434f4e434f524449415f583430325f5245504f52545f563100` | 25 |
| SafePay correlation | `434f4e434f524449415f534146455041595f51554f54455f563200` | 27 |
| SafePay quote hash | `434f4e434f524449415f534146455041595f51554f54455f484153485f563200` | 32 |

The final byte of every separator above is `00`, not the two printable bytes
`5c30` (backslash plus zero).

## 3. Deployment domain and toolchain

The v3 toolchain is pinned to:

- Rust `nightly-2025-02-01`
- Odra and Odra build/test dependencies exactly `=2.8.2`
- `cargo --locked`
- package key name `concordia_governance_receipt_v3`
- `odra_cfg_is_upgradable=false`
- `odra_cfg_allow_key_override=false`
- `odra_cfg_is_upgrade=false`

The date-derived formula in the planning document is superseded because it
cannot distinguish two installations on the same day. The final formula is:

```text
deployment_domain = BLAKE2b-256(
  "CONCORDIA_DOMAIN_V3\0"
  || lp("casper-test")
  || lp("concordia_governance_receipt_v3")
  || installation_nonce
)
```

`installation_nonce` is a cryptographically random, non-zero `Bytes32`
generated before installation, passed once to the constructor, recorded in the
deployment manifest, and never reused. The contract recomputes and stores the
domain. The finalizer cannot supply the schema version, chain name, installation
nonce, or deployment domain.

## 4. Common exact-envelope header

The header order is fixed:

1. `schema_version: u32` — contract-injected, exactly `3`
2. `deployment_domain: Bytes32` — contract-injected
3. `casper_chain_name: String[1..32]` — contract-injected, `casper-test`
4. `proposal_id: String[1..64]`
5. `proposal_nonce: Bytes32`
6. `decision_code: u8`
7. `requested_allocation_bps: u32`, `0..10000`
8. `approved_allocation_bps: u32`, `0..10000`
9. `action_kind: u8`
10. `action_version: u32`, exactly `1`
11. `action_id: Bytes32`
12. `proposal_hash: Bytes32`
13. `policy_hash: Bytes32`
14. `plan_hash: Bytes32`
15. `final_card_hash: Bytes32`
16. `dissent_hash: Bytes32`
17. `agent_action_hash: Bytes32`
18. `preauth_evidence_root: Bytes32`
19. `authorized_metadata_root: Bytes32`

`decision_code`: `0 REJECTED`, `1 APPROVED`, `2 APPROVED_WITH_LIMITS`,
`3 SUPPRESSED`, `4 ESCALATED`.

`action_kind`: `1 NativeTransferV1`, `2 OfficialX402SettlementV1`.
Discriminant `0` is reserved for a future AttestationOnly schema and is rejected
by v3 finalization with `InvalidActionField`. It has no body and cannot be
finalized or authorized. `propose_envelope` stores an opaque commitment and
therefore cannot inspect its action kind. This resolves the earlier undefined-
body ambiguity without inventing an unaudited third action schema.

Executable finalization is permitted only for `APPROVED` and
`APPROVED_WITH_LIMITS`. `REJECTED`, `SUPPRESSED`, or `ESCALATED` paired with an
executable action is `InvalidEnvelopeField`. Native actions require
`0 < approved_allocation_bps <= requested_allocation_bps <= 10000`;
`APPROVED` requires approved equals requested, while `APPROVED_WITH_LIMITS`
requires approved strictly below requested. Official x402 actions require
`APPROVED` and both allocation fields exactly zero.

## 5. NativeTransferV1 body

Body order is fixed:

1. `asset_kind: u8`, exactly `0` (native CSPR)
2. `source_account: AccountHash`
3. `recipient_account: AccountHash`
4. `amount_motes: U512`
5. `treasury_snapshot_balance_motes: U512`
6. `snapshot_block_hash: Bytes32`
7. `snapshot_block_height: u64`
8. `transfer_id: u64`
9. `action_nonce: Bytes32`, non-zero
10. `execution_target: String[1..64]`, exactly `native-transfer`
11. `execution_version: u32`, exactly `1`

`source_account` and `recipient_account` are account identities, never generic
`Key` values. Contract/package variants are rejected. The executor may convert
them to Casper `Key::Account` only after validation.

Native finalization additionally enforces, with checked wide-integer
arithmetic:

```text
amount_motes = floor(
  treasury_snapshot_balance_motes * approved_allocation_bps / 10000
)
```

`amount_motes` and the snapshot balance must be non-zero; multiplication may not
overflow U512; `source_account != recipient_account`; header `action_kind` must
be `1`; and the native entry point may not accept an x402 action. Failure is
`InvalidActionField`, before any state mutation. For the finals proof, a snapshot
of exactly `625000000000` motes and `800` bps yields exactly `50000000000` motes.

Native action core order is exactly fields `1,2,3,4,5,6,7,10,11`. It excludes
the supplied header `action_id`, the explicit `action_nonce`, and the derived
`transfer_id`.

## 6. OfficialX402SettlementV1 body

Body order is fixed:

1. `x402_version: u32`, exactly `2`
2. `scheme: String[1..16]`, exactly `exact`
3. `caip2_network: String[1..32]`, exactly `casper:casper-test`
4. `wcspr_package: Bytes32`, Testnet package below
5. `wcspr_contract: Bytes32`, exact enabled contract below
6. `token_name: String[1..32]`, exactly `Wrapped CSPR`
7. `token_symbol: String[1..16]`, exactly `WCSPR`
8. `eip712_domain_version: String[1..16]`, exactly `1`
9. `token_decimals: u8`, exactly `9`
10. `payer: AccountHash`
11. `payee: AccountHash`
12. `value: U256`, exact atomic WCSPR value
13. `resource_url_hash: Bytes32`
14. `report_hash: Bytes32`
15. `payment_requirements_hash: Bytes32`
16. `signed_payment_payload_hash: Bytes32`
17. `eip712_auth_nonce: Bytes32`
18. `valid_after: u64`
19. `valid_before: u64`, strictly greater than `valid_after`
20. `action_nonce: Bytes32`, non-zero
21. `settlement_target: String[1..64]`, exactly `cspr-cloud-facilitator`
22. `settlement_version: u32`, exactly `1`

`value` must be greater than zero. A zero U256 remains a scalar-encoding test
case but is never a valid settlement action. The package must equal
`3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e`
and the active contract must equal
`032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a`.
`payer != payee`; the authorization nonce, action nonce, and all four bound
hashes must be non-zero. Violations return `InvalidActionField`.

X402 action core order is exactly fields `1..19,21,22`. It excludes the
supplied header `action_id` and the explicit `action_nonce`. No x402 body field
is proposal-derived.

The exact protected resource URL is a configured, validated absolute ASCII
HTTPS URL. It must already be canonical: lowercase `https` scheme and lowercase
ASCII DNS host; no userinfo, fragment, explicit port, backslash, control, NUL,
empty path, or dot segment; percent escapes use uppercase hex and unreserved
characters are not percent-encoded. Query byte order and trailing slash are
significant. It is never normalized at hash time. Every producer and verifier
hashes the exact configured bytes:

```text
resource_url_hash = BLAKE2b-256(
  "CONCORDIA_RESOURCE_URL_V1\0" || lp(exact_resource_url_ascii)
)
```

The other three x402-bound hashes use typed binary preimages, never JSON.

```text
payment_requirements_hash = BLAKE2b-256(
  "CONCORDIA_PAYMENT_REQUIREMENTS_V1\0"
  || lp(scheme)
  || lp(caip2_network)
  || wcspr_package
  || value_u256_fixed_32_be
  || payee_account_hash
  || u32_be(max_timeout_seconds)
  || lp(token_name)
  || lp(eip712_domain_version)
  || u8(token_decimals)
  || lp(token_symbol)
)
```

`paymentRequirements.amount` is parsed as an unsigned canonical decimal string
with no sign, whitespace, leading zero (except `0`), decimal point, or exponent,
then encoded as U256. `payTo` must be `00` plus the same 32-byte payee account
hash. The full `paymentPayload.accepted` requirements object must be field-for-
field equal to the outer `paymentRequirements`, including extras.

For the finals integration, `paymentPayload.resource` is required and has exact
ASCII fields `url`, `description`, and `mimeType`; extensions must be absent or
an empty object. The payload hash is:

```text
signed_payment_payload_hash = BLAKE2b-256(
  "CONCORDIA_SIGNED_PAYMENT_PAYLOAD_V1\0"
  || u32_be(paymentPayload.x402Version)
  || lp(resource.url)
  || lp(resource.description)
  || lp(resource.mimeType)
  || payment_requirements_hash
  || lp(signature_raw_bytes)
  || canonical_public_key
  || payer_account_hash
  || payee_account_hash
  || value_u256_fixed_32_be
  || u64_be(valid_after)
  || u64_be(valid_before)
  || eip712_auth_nonce
  || u32_be(0)
)
```

The final `u32_be(0)` commits to an empty extensions map. Signature is exactly
65 raw bytes decoded from 130 bare hexadecimal characters. Public key uses the
canonical Casper `PublicKey` encoding defined below. Authorization `from`, `to`,
`value`, `validAfter`, `validBefore`, and `nonce` must exactly equal the typed
action fields.

The service parses the public key with the pinned Casper SDK and requires
`PublicKey.accountHash()` to equal the typed `payer`/authorization `from`
account hash. The signature's leading algorithm byte must equal the public-key
algorithm tag, and the remaining 64 bytes must verify the exact EIP-712 digest.
These checks occur before any ledger claim or facilitator request.

The cross-language account-hash derivation is exactly Casper's
`AccountHash::from_public_key`: `BLAKE2b-256(algorithm_name_ascii ||
0x00 || raw_public_key_bytes)`, where the algorithm-name bytes are ASCII
`ed25519` or `secp256k1` and the raw key excludes the canonical PublicKey tag.
There is no numeric length prefix. Implementations must cross-check this result with
the pinned Casper SDK rather than hashing `tag || key`.

The protected report is a byte artifact with an independently verified media
type. Its bound hash is:

```text
report_hash = BLAKE2b-256(
  "CONCORDIA_X402_REPORT_V1\0" || lp(exact_report_bytes)
)
```

## 7. Action and envelope derivation

`action_nonce` appears exactly once in the action-ID preimage:

```text
action_id = BLAKE2b-256(
  "CONCORDIA_ACTION_ID_V3\0"
  || u8(action_kind)
  || action_nonce
  || action_core_bytes
)
```

For NativeTransferV1 only:

```text
transfer_id = first_8_bytes_big_endian(
  BLAKE2b-256(
    "CONCORDIA_TRANSFER_ID_V3\0"
    || lp(proposal_id)
    || proposal_nonce
    || action_id
  )
)
```

The header and full action body, including `action_id`, `action_nonce`, and the
Native `transfer_id`, are then encoded in their frozen orders:

```text
envelope_hash = BLAKE2b-256(
  "CONCORDIA_GOVERNANCE_ENVELOPE_V3\0"
  || header_bytes
  || action_body_bytes
)
```

The contract must preserve four relationships in golden vectors: same semantic
action plus same nonce under another proposal gives the same `action_id`;
another proposal gives a different native `transfer_id`; changed semantic
contents give a different `action_id`; a new nonce gives a different
`action_id`.

## 8. Role and contract ABI

Constructor role arguments are semantic account hashes exposed in the generated
Casper schema as `ByteArray(32)`, never unrestricted `Key`. The contract derives
the caller's account hash from `env().caller()` and rejects a non-account caller.

Constructor arguments, in order:

1. `proposer: AccountHash/ByteArray(32)`
2. `finalizer: AccountHash/ByteArray(32)`
3. `signer_a: AccountHash/ByteArray(32)`
4. `signer_b: AccountHash/ByteArray(32)`
5. `signer_c: AccountHash/ByteArray(32)`
6. `threshold: u8`, exactly `2` or `3`
7. `casper_chain_name: String`, exactly `casper-test`
8. `installation_nonce: Bytes32`, non-zero

The proposer, finalizer, and three signers are pairwise distinct. The owner is
installation provenance only and has no callable governance power.

Entry points:

- `propose_envelope(proposal_id: String, envelope_hash: ByteArray(32)) -> Unit`
  — proposer only; stores the exact commitment once.
- `approve_envelope(proposal_id: String, envelope_hash: ByteArray(32)) -> Unit`
  — signer only; approval key is `(proposal_id, envelope_hash, signer)`.

Both finalizers use flattened Casper runtime arguments in exactly the following
order; no generated composite, tuple, map, JSON, or opaque bytes argument is
permitted.

```text
finalize_native_transfer(
  proposal_id:String,
  proposal_nonce:ByteArray(32),
  decision_code:U8,
  requested_allocation_bps:U32,
  approved_allocation_bps:U32,
  action_kind:U8,
  action_version:U32,
  action_id:ByteArray(32),
  proposal_hash:ByteArray(32),
  policy_hash:ByteArray(32),
  plan_hash:ByteArray(32),
  final_card_hash:ByteArray(32),
  dissent_hash:ByteArray(32),
  agent_action_hash:ByteArray(32),
  preauth_evidence_root:ByteArray(32),
  authorized_metadata_root:ByteArray(32),
  asset_kind:U8,
  source_account:ByteArray(32),
  recipient_account:ByteArray(32),
  amount_motes:U512,
  treasury_snapshot_balance_motes:U512,
  snapshot_block_hash:ByteArray(32),
  snapshot_block_height:U64,
  transfer_id:U64,
  action_nonce:ByteArray(32),
  execution_target:String,
  execution_version:U32
) -> ByteArray(32)
```

```text
finalize_official_x402(
  proposal_id:String,
  proposal_nonce:ByteArray(32),
  decision_code:U8,
  requested_allocation_bps:U32,
  approved_allocation_bps:U32,
  action_kind:U8,
  action_version:U32,
  action_id:ByteArray(32),
  proposal_hash:ByteArray(32),
  policy_hash:ByteArray(32),
  plan_hash:ByteArray(32),
  final_card_hash:ByteArray(32),
  dissent_hash:ByteArray(32),
  agent_action_hash:ByteArray(32),
  preauth_evidence_root:ByteArray(32),
  authorized_metadata_root:ByteArray(32),
  x402_version:U32,
  scheme:String,
  caip2_network:String,
  wcspr_package:ByteArray(32),
  wcspr_contract:ByteArray(32),
  token_name:String,
  token_symbol:String,
  eip712_domain_version:String,
  token_decimals:U8,
  payer:ByteArray(32),
  payee:ByteArray(32),
  value:U256,
  resource_url_hash:ByteArray(32),
  report_hash:ByteArray(32),
  payment_requirements_hash:ByteArray(32),
  signed_payment_payload_hash:ByteArray(32),
  eip712_auth_nonce:ByteArray(32),
  valid_after:U64,
  valid_before:U64,
  action_nonce:ByteArray(32),
  settlement_target:String,
  settlement_version:U32
) -> ByteArray(32)
```

Public read-only queries and exact return types:

```text
schema_version() -> U32
deployment_domain() -> ByteArray(32)
casper_chain_name() -> String
proposer() -> ByteArray(32)
finalizer() -> ByteArray(32)
signer_a() -> ByteArray(32)
signer_b() -> ByteArray(32)
signer_c() -> ByteArray(32)
threshold() -> U8
proposed_envelope(proposal_id:String) -> Option<ByteArray(32)>
approval_count(proposal_id:String) -> U8
has_approved(proposal_id:String, signer:ByteArray(32)) -> Bool
quorum_met(proposal_id:String) -> Bool
finalized(proposal_id:String) -> Bool
finalized_envelope(proposal_id:String) -> Option<ByteArray(32)>
action_authorized(action_id:ByteArray(32)) -> Bool
```

Event fields are emitted in this exact order:

```text
V3Initialized(schema_version:U32, deployment_domain:ByteArray(32),
  proposer:ByteArray(32), finalizer:ByteArray(32), signer_a:ByteArray(32),
  signer_b:ByteArray(32), signer_c:ByteArray(32), threshold:U8)
EnvelopeProposed(proposal_id:String, envelope_hash:ByteArray(32),
  proposer:ByteArray(32))
EnvelopeApproved(proposal_id:String, envelope_hash:ByteArray(32),
  signer:ByteArray(32), approval_count:U8)
EnvelopeFinalized(proposal_id:String, envelope_hash:ByteArray(32),
  action_id:ByteArray(32), finalizer:ByteArray(32), approval_count:U8,
  schema_version:U32, action_kind:U8)
```

The finalizer supplies header fields `4..19`; fields `1..3` are injected from
state. There is no generic opaque `finalize(bytes)` and no caller-supplied
precomputed hash accepted as proof of recomputation.

## 9. Authoritative validation and error precedence

Stable error codes:

1. `InvalidSignerSet`
2. `InvalidThreshold`
3. `InvalidRoleAddress`
4. `UnauthorizedProposer`
5. `UnauthorizedSigner`
6. `UnauthorizedFinalizer`
7. `ProposalAlreadyExists`
8. `QuorumNotMet`
9. `ProposalMissing`
10. `EnvelopeHashMismatch`
11. `AlreadyApproved`
12. `AlreadyFinalized`
13. `ActionAlreadyAuthorized`
14. `InvalidProposalId`
15. `InvalidEnvelopeField`
16. `InvalidActionField`

Finalization order is authoritative and supersedes the contradictory C1 order
in the addendum:

1. Authenticate finalizer; otherwise `UnauthorizedFinalizer`.
2. Validate `proposal_id` grammar; otherwise `InvalidProposalId`.
3. Load proposal; otherwise `ProposalMissing`.
4. If proposal is finalized, return `AlreadyFinalized`.
5. Require quorum; otherwise `QuorumNotMet`.
6. Validate grammar, individual scalar bounds, account-only wire identities,
   string encodability, and the presence/shape needed to encode. Do not yet
   apply cross-field decision, allocation, amount, package, or settlement
   policy invariants. Invalid common fields return `InvalidEnvelopeField` and
   invalid action fields return `InvalidActionField`.
7. Recompute `action_id` from the exact core and compare to the header;
   mismatch returns `InvalidActionField`.
8. For NativeTransferV1, recompute and compare `transfer_id`; mismatch returns
   `InvalidActionField`.
9. Inject immutable fields, encode the supplied full envelope, recompute its
   hash, and compare to the committed hash; self-consistent-but-uncommitted
   fields return `EnvelopeHashMismatch`.
10. Enforce decision/action compatibility and every cross-field semantic
    invariant from sections 4–6. Common decision/allocation violations return
    `InvalidEnvelopeField`; native/x402 action violations return
    `InvalidActionField`.
11. If the recomputed `action_id` is globally authorized, return
    `ActionAlreadyAuthorized`.
12. Atomically persist finalization and global action authorization, then emit
    exactly one success event.

This ordering deliberately preserves the judge-facing mutation result: after
quorum, changing the header's `approved_allocation_bps` from `800` to `3000`
returns `EnvelopeHashMismatch`. Changing an action field while retaining the
old derived IDs returns `InvalidActionField`; recomputing those IDs consistently
then returns `EnvelopeHashMismatch`. Every failure is pre-mutation and emits no
success event.

Approval order: authenticate signer; validate ID; require proposal; if finalized
return `AlreadyFinalized`; compare supplied hash to committed hash; then check
duplicate approval; then mutate. A wrong hash never changes approval state.

## 10. Subordinate binary manifests

### Generic ancillary arguments v1

```text
u32_be(entry_count)
|| entries sorted by ascending raw ASCII name bytes
```

Each entry is `lp(name) || u8(type_tag) || canonical_value`. Duplicate names,
unknown tags, unsorted input, invalid names, and duplicate canonical encodings
are rejected. Tags are fixed:

1 `bool`; 2 `u8`; 3 `u32`; 4 `u64`; 5 `U256`; 6 `U512`;
7 `Bytes32`; 8 `AccountHash`; 9 `Key`; 10 `String`; 11 `Bytes`;
12 `List<Key>`; 13 `PublicKey`; 14 `Option<u64>`. `Key` is a one-byte variant
(`0x00` Account, `0x01` Hash) followed by 32 bytes; `List<Key>` is
`u32_be(count)` followed by canonical keys. `PublicKey` is Casper's algorithm
tag `0x01` plus 32 Ed25519 bytes or `0x02` plus 33 compressed Secp256k1 bytes.
`Option<u64>` is `0x00` for None or `0x01 || u64_be(value)` for Some.

### Pre-authorization evidence manifest v1

Root:

```text
BLAKE2b-256("CONCORDIA_PREAUTH_EVIDENCE_V1\0" || manifest_bytes)
```

Manifest bytes: `u32(version=1) || u32(entry_count) || entries`, sorted by
ascending `artifact_id` ASCII bytes. Entry order:

1. `artifact_id: String[1..64]`, machine-name grammar
2. `artifact_kind: u8` — 1 proposal, 2 policy evaluation, 3 council card,
   4 dissent, 5 approval, 6 payment quote, 7 external observation, 255 other
3. `content_sha256: Bytes32` — SHA-256 of exact artifact bytes
4. `byte_length: u64`
5. `media_type: String[1..64]` — lowercase printable ASCII
6. `provenance_class: u8` — 0 historical v1/v2, 1 current v3 authorization,
   2 native treasury execution, 3 SafePay Lite native CSPR, 4 official x402
   WCSPR, 5 post-execution, 6 live, 7 snapshot, 8 unavailable, 9 unknown
7. `captured_at_unix_seconds: u64`

### Authorized metadata manifest v1

Root:

```text
BLAKE2b-256("CONCORDIA_AUTHORIZED_METADATA_V1\0" || manifest_bytes)
```

Manifest bytes: `u32(version=1) || ancillary_argument_encoding`. Metadata names
are unique and sorted. Metadata is display/evidence context only; no financial
parameter that belongs in a typed action body may be moved here.

### Execution-argument manifest v1

Root:

```text
BLAKE2b-256("CONCORDIA_EXEC_ARGS_V1\0" || manifest_bytes)
```

Manifest bytes are `u32(version=1) || lp(target) || lp(entry_point) ||
u32(arg_count) || args`. Arguments preserve the target ABI order; each is
`lp(name) || u8(type_tag) || canonical_value`. Duplicate or reordered names are
rejected. Native Casper transfer args are exactly `target: Key` (account
variant), `amount: U512`, `id: Option<u64>` with `Some(transfer_id)`. WCSPR
`transfer_with_authorization` args are exactly `from: Key` (account variant),
`to: Key` (account variant), `value: U256`, `valid_after: u64`, `valid_before:
u64`, `nonce: Bytes`, `public_key: PublicKey`, `signature: Bytes`. The runtime
argument is **`value`**, never `amount`.

## 11. Live WCSPR and facilitator freeze

Read-only public Testnet RPC observation:

- observation block `55e5c5715d9c6fd17d01b5de758fa1274d7360fcac56adfc12c0af80ee1f27c2`
- height `8590556`, timestamp `2026-07-22T18:34:15.635Z`
- state root `ab8e7bf40bcf17d83b2bc1cdcdede8363485d277373089eafe411f2af96f8d93`
- protocol `2.2.2`
- package `3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e`
- enabled/latest contract v8
  `032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a`
- previous package versions 1..7 are disabled; package is unlocked
- on-chain metadata: `Wrapped CSPR`, `WCSPR`, decimals `9`, chain name
  `casper:casper-test`
- live `transfer_with_authorization` ABI: `from: Key`, `to: Key`, `value: U256`,
  `valid_after: U64`, `valid_before: U64`, `nonce: List<U8>`, `public_key:
  PublicKey`, `signature: List<U8>`, return `Unit`

The official facilitator base is `https://x402-facilitator.cspr.cloud` with raw
`Authorization: <token>`—never `Bearer`. Its 401 response reflects the supplied
authorization value, so production probes must never print response bodies,
exceptions containing bodies, curl verbose output, or traces.

The existing credential passed an authenticated, redacted `GET /supported`
probe and advertised x402 v2 `exact` for `casper:casper-test`. This proves only
capability discovery. It does not prove `/verify` or settlement.

The pinned public JS and Go implementations currently build the WCSPR runtime
argument as `amount`, while the live v8 ABI requires `value`. The Go domain path
also appears to use `casper-test` where the live/EIP-712 domain is
`casper:casper-test`. Therefore official settlement starts in `blocked_fail_closed`
state. It may become `verified_live` only after a real Testnet canary produces a
successful finalized v8 `transfer_with_authorization` using the exact envelope.
`/supported`, HTTP 200, or `/verify isValid:true` can never lift this gate.

Implementation must use the official protocol shapes and pin dependencies, but
must not silently try both `amount` and `value`. The committed official item is
complete only when the hosted CSPR.cloud facilitator produces the required live
proof and the state becomes `official_hosted_verified_live`. A patched,
self-hosted compatibility experiment is separately labeled
`self_hosted_compatibility_proof` and can never satisfy or be marketed as the
official facilitator deliverable.

Because the package is unlocked, every verify attempt and every settlement
attempt must independently resolve the package's currently enabled contract and
require version `8` plus hash
`032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a`.
A mismatch returns `blocked_upgrade_drift`. The check is repeated immediately
before settlement; a prior cached read is insufficient. The finalized
transaction is then read back and must prove the exact v8 target, entry point,
arguments, execution success, and no contract-version drift before any protected
report is released. If the hosted facilitator cannot guarantee the exact
versioned target, hosted settlement remains blocked. Required tests cover a
pre-verify upgrade, a pre-settle upgrade, a post-settle/TOCTOU mismatch, and a
wrong-contract transaction.

## 12. Cross-lane service contracts

### SafePay Lite supplemental v2

Provider is the only consumption authority. Immutable quote fields are:

`schema_version`, `quote_id`, `proposal_id`, `resource_id`, `network`,
`payee_account_hash`, `amount_motes`, `correlation_id`, `report_version`,
`report_hash`, `expires_at`, `quote_nonce`, `quote_hash`. `schema_version` is
exactly `safepay-v2`; `expires_at` is unsigned Unix seconds.

The only wire contract permitted for new supplemental-v2 evidence is:

- `POST /x402/v2/quotes` with the exact JSON object
  `{schema_version:"safepay-quote-request-v2", proposal_id, resource_id}`.
  Unknown fields are rejected. The provider persists the issued quote before
  returning HTTP 402 and the exact object
  `{schema_version:"safepay-v2",
  error:{code:"payment_required",retryable:false}, quote,
  payment_requirements}`. `payment_requirements` contains `network`,
  `payee_account_hash`, `amount_motes`, `correlation_id`, and `expires_at`, each
  exactly equal to the corresponding immutable quote field.
- `POST /x402/v2/redemptions` with the exact JSON object
  `{schema_version:"safepay-redemption-v2", quote, payment_hash}`.
  `quote` is the complete issued immutable quote and `payment_hash` is exactly
  32 lowercase hex bytes. New v2 redemption does not accept `X-Payment` as an
  alternate transport.
- Both responses carry `Cache-Control: no-store` and
  `X-Concordia-SafePay-Version: safepay-v2`.

On redemption, canonical-network validation precedes all ledger access. The
provider loads `quote_id` next; an absent issued quote returns terminal HTTP
404 `quote_not_issued` without looking up or observing the payment. Any mismatch
between submitted and persisted quote fields or a recomputed `quote_hash`
returns terminal HTTP 422 `quote_binding_invalid`. Only then may the provider
enter the atomic validation/claim transaction. Gateway obtains and echoes the
provider-issued quote; it never reconstructs one. Its wallet intent uses that
quote's `correlation_id` as the exact transfer ID, then submits the exact quote
plus lowercase deploy hash to the redemption endpoint. The legacy
`GET /x402/risk-report` / `X-Payment` flow may remain for historical continuity
but can never generate or substantiate new supplemental-v2 evidence.

Anonymous quote issuance is bounded to 12 requests per normalized client per
60 seconds and 120 requests globally per 60 seconds, with at most 10,000
outstanding quotes, where outstanding means unconsumed and `expires_at > now`.
The provider samples one integer Unix `issued_at` exactly once at the start of
the final issue transaction, after report resolution, and fixes `expires_at` to
exactly `issued_at + 900`; clients cannot supply or extend it. Limits use a
durable SQLite fixed window whose start is `floor(now / 60) * 60`. In the same
fixed window, the one global counter row uses `(scope="global",
client_key="global")`. Issuance is deliberately two-phase. A short preflight
`BEGIN IMMEDIATE` deletes at most 100 stale rate/reservation rows, checks the
client/global attempt limits and a hard 32-reservation in-flight cap, charges
both counters without future refund, inserts a pending reservation expiring in
60 seconds, and commits. A rejected preflight never calls the report source.
Only a committed reservation may resolve/render report bytes, with a hard
10-second timeout, outside every SQLite write transaction. A report-source
failure still consumes the attempt and is marked failed in a short transaction.
Finally, a second `BEGIN IMMEDIATE` samples the single `issued_at`, reloads the
exact unexpired pending reservation, performs bounded quote/report GC, rechecks all active, retained,
row, and byte capacities, inserts or exactly revalidates the content-addressed
report, inserts the quote, marks the reservation completed, and commits before
returning 402. Capacity failure marks the reservation failed and commits no
quote. Concurrent attempts therefore cannot bypass limits, and expensive
report work cannot occur before rate admission or while holding the write lock.

The 10,000 active-quote cap is supplemented by a hard 20,000 retained
unconsumed-quote cap that includes expired rows. Exact report bytes are stored
once in `safepay_reports` by SHA-256, with at most 1,024 rows and 67,108,864
decoded bytes total. A hash conflict must match media type, bytes, and decoded
length exactly or issuance fails closed. This prevents expired quote metadata
or unique large reports from exhausting the provider disk before the 24-hour
GC threshold. Report GC removes at most 100 unreferenced rows per transaction.

Caddy removes any caller `X-Concordia-Client-IP` and
`X-Concordia-SafePay-Proxy`, then overwrites them with the actual remote peer
and server-side proxy attestation respectively. The provider trusts the client
IP header only when its immediate socket peer belongs to explicitly configured
`SAFEPAY_TRUSTED_PROXY_CIDRS` and the attestation matches in constant time;
otherwise it ignores both headers and uses the socket peer. The proxy secret is
loaded through `SAFEPAY_PROXY_SECRET_FILE` from
`/run/secrets/safepay_proxy_secret` and is at least 32 bytes. IPs are parsed,
zone-free, IPv4-mapped addresses collapse to IPv4, and all other addresses use
lowercase compressed form. Only an HMAC-SHA-256 client key is persisted, under
the runtime secret loaded by `SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE` from
`/run/secrets/safepay_client_key_hmac_secret` (minimum 32 bytes); raw addresses
are never stored. Missing, unreadable, or shorter-than-32-byte HMAC or proxy
secrets fail process startup. Limit and capacity failures are 429 `quote_rate_limited` and
503 `quote_capacity_exhausted`. Bounded maintenance may delete at most 100
expired, unconsumed, unreferenced quotes per transaction only after they have
been expired for 86,400 seconds; consumed or referenced quote rows are never
removed by this garbage collector.

`network` is exactly `casper:casper-test`; aliases are rejected before ledger
lookup and never normalized. Each re-quote has a new quote ID and non-zero
`quote_nonce`. The native transfer/correlation ID is per quote:

```text
correlation_id = first_8_bytes_big_endian(BLAKE2b-256(
  "CONCORDIA_SAFEPAY_QUOTE_V2\0"
  || lp(quote_id)
  || lp(proposal_id)
  || lp(resource_id)
  || quote_nonce
))
```

`correlation_id` is the unsigned big-endian `u64` above and is also the exact
Casper native-transfer ID. There is no independent resource-derived transfer
ID and no second full-digest correlation identifier.

The immutable quote hash is:

```text
quote_hash = BLAKE2b-256(
  "CONCORDIA_SAFEPAY_QUOTE_HASH_V2\0"
  || lp(quote_id) || lp(proposal_id) || lp(resource_id) || lp(network)
  || payee_account_hash || amount_motes_fixed_64_be || u64_be(correlation_id)
  || lp(report_version) || report_hash || u64_be(expires_at_unix_seconds)
  || quote_nonce
)
```

The report transport is `{report_version, proposal_id, resource_id,
correlation_id, media_type, content_base64, report_hash}`. `media_type` is
exactly `application/json`; canonical padded RFC 4648 `content_base64` decodes
to at most 262,144 exact protected-report bytes, and `report_hash` is lowercase
SHA-256 of those bytes. Before returning the quote, the provider stores the
exact bytes once in content-addressed `safepay_reports` and makes the quote
reference that hash; `content_base64` is derived canonically from the persisted
bytes on fulfillment. Redemption and retries use only that persisted content,
so report mutation or restart cannot change what the payer bought. The
protected bytes are never sent in the public quote. Parsing the report into JSON or another media
representation never changes the bytes that are hashed.

Consumption key is `(network, payment_hash)`. Exact retry of the same quote and
resource returns the same immutable fulfillment content and `response_hash`
with `replay_disposition=idempotent_replay` and does not consume twice. The
outer retry response need not be byte-identical because its disposition differs
from the first response. Reuse for a different quote/resource returns
terminal HTTP 409 with `replay_disposition=cross_binding_rejected`. Gateway does
not retry 409 and does not keep a second consumption ledger.

The unkeyed `quote_hash` is a content commitment, not authentication. Every
issued quote is first persisted immutably in `safepay_quotes`; redemption loads
that row by `quote_id` and requires every quote field plus the recomputed hash to
match it exactly. A caller-computed but unissued quote is rejected. Both quote
and consumption rows survive provider restart.

After initial persisted-quote validation, the provider first performs a
read-only consumption lookup by canonical network and payment hash. A matching
binding immediately returns the stored idempotent result and a different
binding immediately returns terminal 409; neither path depends on a fresh
indexer call, including after quote expiry. An unconsumed expired quote returns
410 before chain observation. Only an unconsumed, unexpired payment reaches the
slow Casper observation, still outside any SQLite write transaction. After
successful exact chain verification, the provider enters `BEGIN IMMEDIATE`,
reloads and revalidates the quote, its expiry, and any newly committed
consumption, and then atomically claims the unique payment key and persists the
fulfillment (or returns the concurrently stored idempotent result /
cross-binding 409). No network I/O occurs while holding the SQLite write lock;
concurrent observations are harmless because only one final claim can commit.

An unconsumed expired quote returns terminal 410 and is never consumed. A quote
consumed before expiry retains its stored idempotent response after expiry.
Final payment observation requires a finalized/processed Casper transaction, an
execution result, no execution error, and exact payee, exact amount, exact
correlation/transfer ID, and exact network. The simulated indexer-lag switch is
test-only and defaults off. Provider persistence is the named volume
`x402_provider_data` mounted at `/data`, with SQLite path `/data/safepay.db`.

Every successful provider response is exactly
`{schema_version:"safepay-v2", fulfillment, delivery}`. Immutable
`fulfillment` contains `quote`, `payment_observation`, `consumption`, `report`,
`binding_checks`, `observed_at`, and `response_hash`. Per-request `delivery`
contains only `replay_disposition`, either `first_consumption` or
`idempotent_replay`. An exact retry returns identical fulfillment and hash; only
the delivery disposition changes. No top-level boolean is authoritative; Codex
recomputes registry status from the nested observations.

Every non-402 error on either v2 endpoint is exactly
`{schema_version:"safepay-v2",
error:{code,retryable}, delivery:{replay_disposition}}`, with no message or
extra boolean. Status, code, retryability, and disposition are the exact values
in the machine schema. The quote-issue 402 is the sole shape exception and
includes its persisted quote and payment requirements. The successful response
has literal `schema_version:"safepay-v2"`.

Malformed JSON, unknown/missing fields, and type/canonical-encoding failures are
HTTP 400 `invalid_request`. Quote issuance additionally permits the frozen 429
rate and 503 capacity/report-source outcomes; redemption permits the frozen
404/409/410/422/425 and 503 observer-unavailable outcomes. The Gateway never
retries 400, 404, 409, 410, or 422. Bounded retries are allowed only for the
machine-schema outcomes explicitly marked retryable. Provider validation and
catch-all exception handlers sanitize every response: an uncaught storage,
timeout, or internal failure becomes the endpoint-specific 503
`provider_unavailable` body. Neither response nor logs may include exception
text, request bodies/headers, secrets, or upstream bodies; stable logs contain
only event ID, endpoint ID, exception class, and timestamp.

### Approval boundary v1

Runtime secrets use `_FILE` loading. Caddy performs Basic Auth and overwrites
`X-Proxy-Secret` from a server-side secret; it never forwards a caller-supplied
value. Gateway separately verifies proxy secret, Basic credentials with bcrypt,
approver allowlist, CSRF token, and nonce. Public direct Gateway access is not
routable. Success is a trusted human message and consumed nonce, not a generic
room message.

Frozen configuration names are `APPROVAL_PROXY_SECRET_FILE`,
`APPROVAL_UI_USER_FILE`, `APPROVAL_UI_APPROVER_ID_FILE`,
`APPROVAL_UI_BCRYPT_HASH_FILE`, and `APPROVAL_UI_CSRF_SECRET_FILE`; each points
to a `/run/secrets/...` file and direct value variables are ignored in
production. Caddy's independent Basic-Auth user/hash and proxy-secret injection
are provisioned by Codex's release layer. The Gateway trusts only the overwritten
`X-Proxy-Secret` header name with exact casing-insensitive HTTP semantics.

### Demo capability v1

The public browser receives a signed opaque capability containing:
`capability_id`, `scenario_id`, `issued_at`, `expires_at`, `client_binding_hash`,
and `nonce`. It is short-lived, scenario-scoped, one-use/idempotent, and never
contains the operator token. `POST /api/demo/activate` may activate only the
capability's scenario. Public reset does not exist. Each created record carries
`demo_run_id` and `is_demo=true`. Cleanup accepts one exact `demo_run_id` and
must exclude every canonical/historical proposal ID even if provenance is
corrupt.

The token is
`unpadded_base64url(payload_bytes).unpadded_base64url(HMAC-SHA256(tag_input))`.
Payload bytes are `u32_be(1) || uuid_16_raw(capability_id) || lp(scenario_id) ||
u64_be(issued_at) || u64_be(expires_at) || client_binding_hash || nonce`;
`tag_input` is `"CONCORDIA_DEMO_CAPABILITY_V1\0" || payload_bytes`. Verification
is constant-time. The dedicated secret is at
`DEMO_CAPABILITY_HMAC_SECRET_FILE=/run/secrets/demo_capability_hmac_secret`, is
at least 32 random bytes, and may not reuse the operator or approval secrets.

Client binding uses a server-generated random 32-byte
`__Host-concordia-demo-client` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`,
`Path=/`, `Max-Age=600`). The bound value is
`SHA-256("CONCORDIA_DEMO_CLIENT_V1\0" || raw_cookie_nonce)`. IP address and user
agent are never used as stable fingerprints.

Gateway is the sole issuer, HMAC validator, operator-token holder, durable
capability ledger, and activation authority. The public Next routes are thin
same-origin proxies and manage only the ephemeral client cookie. They forward
to `POST /internal/demo/capability` and `POST /internal/demo/activate` over the
internal network using `X-Concordia-Dashboard-Token`, loaded from
`DASHBOARD_DEMO_GATEWAY_TOKEN_FILE=/run/secrets/dashboard_demo_gateway_token`.
They forward the decoded 32-byte client nonce in
`X-Concordia-Demo-Client`; neither internal endpoint is public through Caddy.
The issue response is exactly `{schema_version:"demo-capability-v1",
capability, scenario_id, expires_at}`. The Dashboard never holds the operator
token or HMAC secret.

### Room identity v1

Authenticated key mapping is authoritative for `sender_id`, `sender_role`, and
`sender_type`; caller-supplied identity fields are ignored/rejected. Agent keys
cannot emit User or System. Human approval enters only through the approval
boundary. Create/join/list/read/post operations enforce membership and a frozen
role-operation matrix. Production agent traffic cannot use the full Gateway
secret fallback.

### Official x402 local service v1

Local endpoints: `GET /health`, `GET /supported`, `GET /resource/:resourceId`,
`POST /verify`, `POST /settle`. The service emits `PAYMENT-REQUIRED` on 402 and
accepts `PAYMENT-SIGNATURE`. It stores a durable fulfillment ledger with primary
uniqueness key `(network, signed_payment_payload_hash)` and stores the resource,
action, envelope, payer, and EIP-712 nonce binding in that row. Exact same-binding
retry is idempotent; any changed binding is terminal 409 before chain submission.
Settlement computes `signed_payment_payload_hash` from the validated request
and queries the unique proof-registry record indexed by that hash; it does not
accept a caller-supplied `action_id` or envelope hash. The record must have
`v3_finalized_exact=true`, `verification_status=verified`, and every required
exact-envelope check present and passed. HTTP 200 is never success unless the response has
`success=true` and the resulting transfer is finalized on chain.

Service contract: listen on `0.0.0.0:8787`; ledger volume
`x402_official_data:/data`; SQLite path `/data/x402-official.db`. Frozen
non-secret variables are `X402_OFFICIAL_PORT=8787`,
`X402_FACILITATOR_URL=https://x402-facilitator.cspr.cloud`,
`X402_NETWORK=casper:casper-test`, `X402_WCSPR_PACKAGE_HASH`,
`X402_WCSPR_CONTRACT_HASH`, `X402_WCSPR_CONTRACT_VERSION=8`, and
`X402_GATEWAY_INTERNAL_URL=http://gateway:8000`. Secrets are loaded only from
`X402_CSPR_CLOUD_TOKEN_FILE=/run/secrets/x402_official_cspr_cloud_token`,
`X402_SIGNER_FILE=/run/secrets/x402_official_signer`, and
`X402_GATEWAY_TOKEN_FILE=/run/secrets/x402_official_gateway_token`.
Dependencies are pinned to `@make-software/casper-x402@1.0.0`,
`@x402/core@2.15.0`, `casper-js-sdk@5.0.12`, and
`@casper-ecosystem/casper-eip-712@1.2.1`; source audit commit is
`14c364bb30838003302074423b7500b4360df889`.

Both `/verify` and `/settle` apply local shape, canonical-number, account, and
signature validation, compute the signed-payload hash, and require the unique
verified v3 registry binding before any credentialed facilitator call. An
ungoverned, ambiguous, stale, or invalid payload causes zero upstream calls.
Only then do both endpoints send outer `x402Version: 2`,
`paymentPayload.x402Version: 2`, `paymentPayload`, and `paymentRequirements`.
`paymentRequirements` is exactly: `scheme="exact"`,
`network="casper:casper-test"`, the bare package hash as `asset`, decimal-string
`amount`, account-tagged `payTo` (`00` plus 64 hex), `maxTimeoutSeconds`, and
`extra={name:"Wrapped CSPR",version:"1",decimals:"9",symbol:"WCSPR"}`.
The nested Casper authorization is `from`, `to`, decimal-string `value`,
`validAfter`, `validBefore`, and 64-hex `nonce`, plus the signature and
algorithm-prefixed Casper public key. The signed authorization and requirements
must agree exactly after decimal parsing.

`/verify` response is `{isValid:boolean, invalidReason?:string,
invalidMessage?:string, payer?:string, extensions?:object, extra?:object}`.
`/settle` response is `{success:boolean, errorReason?:string,
errorMessage?:string, payer?:string, transaction:string, network:string,
amount?:string, extensions?:object, extra?:object}`. Unknown response fields are
ignored; required fields and types are validated. A malformed 2xx response is a
terminal safe failure.

`GET /supported` is parsed as `kinds`, `extensions`, and `signers`. A supported
kind requires `x402Version=2`, `scheme="exact"`, and
`network="casper:casper-test"`. Unknown extra keys are preserved. Fee-payer and
signer strings are opaque facilitator identities and must not be reused as
`payTo`. Token metadata is never inferred from `/supported`; it comes from the
pinned live contract readback.

## 13. Provenance-aware proof registry v1

Public transport is `GET /proof-registry/v1/{proposal_id}` and returns
`{schema_version:1, generated_at, proposal_id, items:[...]}`. Every item has
these dimensions separately; they are never collapsed into one provenance or
status string:

- `proof_id`, `proof_type`, and `generation` (`v1`, `v2`, `v3`, `none`)
- `lineage`: `canonical` or `supplemental`
- `observation_mode`: `live`, `snapshot`, or `unavailable`
- `temporal_scope`: `historical` or `current`
- `verification_status`: `verified`, `pending`, `stale`, `unavailable`, or
  `invalid`
- `execution_outcome`: `accepted`, `expected_rejection`, `not_applicable`,
  `unexpected_rejection`, `not_attempted`, `unknown`
- `claim_scope` and `enforcement_scope`
- `proposal_id`, `action_id`, and `envelope_hash`, each nullable only when the
  proof type genuinely has no such identity
- `artifact_path`, `artifact_sha256`, `source_commit`, `deployment_commit`,
  `network`, `package_hash`, `contract_hash`, `schema_version`, and `captured_at`
- x402 binding fields `payment_requirements_hash`,
  `signed_payment_payload_hash`, `report_hash`, and `settlement_transaction`,
  nullable for non-x402 types
- `checks`: named observed checks with `required`, `passed`, `source`,
  `observed_at`, and optional `detail_code`
- typed `links`

An expected rejection such as `QuorumNotMet` is represented as
`verification_status=verified` plus `execution_outcome=expected_rejection`; it
is not an invalid proof. Only `verification_status=verified` may use a green
verification cue, and only when every mapped required check occurs exactly once
with `required=true, passed=true`, every extra required check passes,
observation is available, and the outcome is `accepted`, `expected_rejection`,
or `not_applicable`. Duplicate check names make the item invalid. Unknown,
missing, failed, stale, unexpected, not-attempted, or top-level asserted
booleans never become green.

The exact `proof_type` enum is `historical_odra_receipt_v2`,
`exact_envelope_v3`, `native_treasury_execution_v1`, `safepay_v2`,
`official_x402_settlement_v1`, `approval_boundary_v1`, `demo_capability_v1`,
`room_identity_v1`, and `snapshot`. Required check sets are fixed:

- `historical_odra_receipt_v2`: artifact hash, deploy finality, execution success,
  package/contract match, receipt-field readback, historical-lineage match.
- `exact_envelope_v3`: source/Wasm/schema hashes, package/contract/deployment
  domain match, pre-quorum code 8, post-quorum mutation code 10, exact
  acceptance, repeat code 12, final state readback, `action_authorized=true`.
- `native_treasury_execution_v1`: verified v3 finalization, executor journal claim,
  canonical snapshot block/hash/state root, source balance at that state equal to
  the envelope snapshot, snapshot before finalization/execution, exact
  target/amount/transfer ID, finalized execution, post-state balances, no second
  transaction.
- `safepay_v2`: persisted issued quote plus quote hash, restart survival, exact
  Casper finality/payee/amount/transfer ID, provider atomic consumption, report
  hash, same fulfillment hash on exact idempotent retry, cross-binding terminal
  409.
- `official_x402_settlement_v1`: requirements/payload/report hashes, exact v3 finalization,
  public-key-to-payer binding, pre-verify and pre-settle v8 drift checks,
  `isValid=true`, `success=true`, finalized v8 transfer with exact args,
  post-settle v8 readback, authorization-nonce uniqueness, restart
  reconciliation, fulfillment idempotency, cross-binding rejection.
- `snapshot`: artifact SHA-256, capture time, source URL, and staleness check.

The official service consumes an internal, authenticated read model:

```text
GET /internal/proof-registry/v1/actions/{action_id_hex}
GET /internal/proof-registry/v1/x402/{signed_payment_payload_hash}
X-Concordia-Service-Token: <file-loaded token>
```

The first endpoint is the general action lookup used by Codex-owned execution
and verification clients. The second is the only lookup used by the official
x402 settlement service. Both require 64 lowercase hexadecimal path values and
share the response below. Zero matches return 404. More than one current,
verified x402 record for one signed-payload hash returns 409
`ambiguous_governance_binding`; no caller or service may choose one arbitrarily.

The token comes only from `/run/secrets/x402_official_gateway_token`; missing or
wrong auth returns 403 without disclosing whether an action exists. Success is:

```json
{
  "schema_version": 1,
  "proposal_id": "...",
  "proposal_hash": "64 lowercase hex",
  "proposal_nonce": "64 lowercase hex",
  "action_id": "64 lowercase hex",
  "action_kind": "OfficialX402SettlementV1",
  "action_version": 1,
  "envelope_hash": "64 lowercase hex",
  "deployment_domain": "64 lowercase hex",
  "network": "casper:casper-test",
  "v3_finalized_exact": true,
  "verification_status": "verified",
  "package_hash": "64 lowercase hex",
  "contract_hash": "64 lowercase hex",
  "resource_url_hash": "64 lowercase hex",
  "payment_requirements_hash": "64 lowercase hex",
  "signed_payment_payload_hash": "64 lowercase hex",
  "report_hash": "64 lowercase hex",
  "finalization_transaction": "64 lowercase hex",
  "finalized_at": "RFC3339 UTC",
  "observed_at": "RFC3339 UTC",
  "checks": []
}
```

The service requires exact equality for every identity/hash and every required
check passed; it never trusts the top-level boolean alone. Historical v1/v2
entries stay historical. New v3, treasury execution, SafePay v2, and official
x402 remain separate supplemental/current items until their own proofs pass and
are never presented as retroactive protection of the canonical run.

## 14. Handoff and branch protocol

The annotated tag is `concordia-g1-freeze-v2.0-a`. Claude must:

1. Resolve the tag's exact commit.
2. validate `handoff/G1_FREEZE_MANIFEST.json` from that commit;
3. require `status == "ready"`;
4. create `claude/finals-product-security` from that exact commit; and
5. work only in Claude-owned paths.

Claude-to-Codex shared integration requests are committed as:

- `handoff/INTERFACE_MANIFEST_WP2.md`
- `handoff/INTERFACE_MANIFEST_WP3.md`
- `handoff/INTERFACE_MANIFEST_WP5.md`
- `handoff/INTERFACE_MANIFEST_WP7.md`

Each handoff contains the producer commit, required shared-file change, exact
request/response or env shape, tests already passed, and proposed diff. Claude
does not edit `gateway/app.py`, `shared/proof_runtime.py`, `shared/proof_pack.py`,
Compose, Caddy, live artifacts, or release manifests.

WP3 changes needed in `gateway/auth.py`, `gateway/database.py`,
`shared/proposal_room.py`, or `shared/local_room_runtime.py` are also handoffs
that Codex applies. Codex owns migration of `tests/test_concordia_core.py`.
Claude owns the release-hygiene edits to `docs/LLM_PROVIDER.md` and
`.github/SECURITY.md`; these paths do not move the security integration
boundary.

## 15. Freeze acceptance

The G1 tag is valid only when:

- the JSON manifest parses and reports `status: ready`;
- its recorded specification SHA-256 matches this file;
- all field orders and action-core lists are unique and exact;
- `action_nonce` is absent from both action cores and appears once in the
  action-ID preimage;
- WCSPR action field `value` is U256/fixed-32 and runtime arg is `value`;
- the official settlement gate starts fail-closed;
- historical contract tracked-file hashes match the recorded baseline;
- baseline Python tests, a fresh dashboard production build, and Playwright
  tests pass; and
- both implementation branches can be rooted at the annotated tag without
  modifying `main`.

Implementation tests and golden vectors are then written first in each owned
work package and must pass before any live claim or deployment.
