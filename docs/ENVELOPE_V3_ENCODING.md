# Concordia typed exact-envelope v3

Status: frozen by `concordia-g1-freeze-v2.0-a`. This document describes the
bytes enforced by the sibling Odra 2.8.2 contract and the independent Python,
Rust, and JavaScript verifiers. It does not change historical v1/v2 receipts.

## Trust boundary

V3 authorizes an exact action; it does not custody assets or execute transfers.
The contract stores one envelope commitment, accepts votes only from three
configured account identities, requires a 2-of-3 or 3-of-3 threshold, recomputes
the complete typed envelope during finalization, and globally consumes its
proposal-independent `action_id`. The native executor and official-x402 service
must independently verify the finalized readback before moving value.

The installer account is installation provenance only. It must differ from the
proposer, finalizer, and all signers and has no governance entry point.

## Scalar encoding

Canonical hash preimages use these encodings (not Casper CLValue bytes):

| Type | Canonical bytes |
|---|---|
| `bool` | `00` or `01` |
| `u8` | one byte |
| `u32`, `u64` | fixed-width big-endian |
| `U256` | exactly 32-byte big-endian |
| `U512` | exactly 64-byte big-endian |
| `Bytes32`, `AccountHash` | 32 raw bytes |
| `String` | `u32_be(length) || printable ASCII bytes` |

`AccountHash` is semantic as well as binary: deployment and service boundaries
must prove the source identity was an account, not a contract or package, before
passing its 32 bytes. Finalization has flattened Casper ABI arguments; the
generated schema is authoritative for the CLValue types and order.

## Deployment domain

The package key and chain name are fixed:

```text
package_key_name = "concordia_governance_receipt_v3"
casper_chain_name = "casper-test"
deployment_domain = BLAKE2b-256(
  "CONCORDIA_DOMAIN_V3\0"
  || lp(casper_chain_name)
  || lp(package_key_name)
  || installation_nonce_bytes32
)
```

`installation_nonce` is non-zero and recorded in the deployment manifest. The
contract injects schema version `3`, deployment domain, and chain name into each
finalization; a finalizer cannot resupply them.

## Common header

The common header is encoded in this exact order:

1. `schema_version: u32` (contract-injected, exactly 3)
2. `deployment_domain: Bytes32` (contract-injected)
3. `casper_chain_name: String` (contract-injected, `casper-test`)
4. `proposal_id: String` (`[A-Z0-9-]{1,64}`)
5. `proposal_nonce: Bytes32`
6. `decision_code: u8`
7. `requested_allocation_bps: u32`
8. `approved_allocation_bps: u32`
9. `action_kind: u8`
10. `action_version: u32` (exactly 1)
11. `action_id: Bytes32`
12. `proposal_hash: Bytes32`
13. `policy_hash: Bytes32`
14. `plan_hash: Bytes32`
15. `final_card_hash: Bytes32`
16. `dissent_hash: Bytes32`
17. `agent_action_hash: Bytes32`
18. `preauth_evidence_root: Bytes32`
19. `authorized_metadata_root: Bytes32`

Executable decisions are `APPROVED` (1) and `APPROVED_WITH_LIMITS` (2).
Native `APPROVED` requires requested and approved basis points to be equal;
`APPROVED_WITH_LIMITS` requires a strict reduction. Official x402 requires
`APPROVED` and both basis-point fields equal to zero.

## NativeTransferV1

The body order is:

1. `asset_kind: u8` = 0
2. `source_account: AccountHash`
3. `recipient_account: AccountHash`
4. `amount_motes: U512`
5. `treasury_snapshot_balance_motes: U512`
6. `snapshot_block_hash: Bytes32`
7. `snapshot_block_height: u64`
8. `transfer_id: u64`
9. `action_nonce: Bytes32` (non-zero)
10. `execution_target: String` = `native-transfer`
11. `execution_version: u32` = 1

The action core is fields 1-7, 10, and 11. It excludes the proposal-derived
`transfer_id` and encodes `action_nonce` only in the outer action-ID preimage.

```text
action_id = BLAKE2b-256(
  "CONCORDIA_ACTION_ID_V3\0" || u8(1) || action_nonce || action_core
)
transfer_id = first_u64_be(BLAKE2b-256(
  "CONCORDIA_TRANSFER_ID_V3\0"
  || lp(proposal_id) || proposal_nonce || action_id
))
```

The contract checks `source != recipient`, non-zero values, checked U512
multiplication, and:

```text
amount_motes = floor(treasury_snapshot_balance_motes * approved_bps / 10000)
```

## OfficialX402SettlementV1

The body order is:

1. `x402_version: u32` = 2
2. `scheme: String` = `exact`
3. `caip2_network: String` = `casper:casper-test`
4. `wcspr_package: Bytes32`
5. `wcspr_contract: Bytes32`
6. `token_name: String` = `Wrapped CSPR`
7. `token_symbol: String` = `WCSPR`
8. `eip712_domain_version: String` = `1`
9. `token_decimals: u8` = 9
10. `payer: AccountHash`
11. `payee: AccountHash`
12. `value: U256`
13. `resource_url_hash: Bytes32`
14. `report_hash: Bytes32`
15. `payment_requirements_hash: Bytes32`
16. `signed_payment_payload_hash: Bytes32`
17. `eip712_auth_nonce: Bytes32`
18. `valid_after: u64`
19. `valid_before: u64`
20. `action_nonce: Bytes32` (non-zero)
21. `settlement_target: String` = `cspr-cloud-facilitator`
22. `settlement_version: u32` = 1

The core is every field except `action_nonce`; the outer action-ID formula uses
kind byte `2`. The contract checks the frozen Testnet WCSPR package and exact
enabled contract, a non-zero value and bound hashes, distinct payer/payee, and
`valid_before > valid_after`.

## Envelope and state transition

```text
envelope_hash = BLAKE2b-256(
  "CONCORDIA_GOVERNANCE_ENVELOPE_V3\0" || header_bytes || body_bytes
)
```

`propose_envelope` stores that commitment. `approve_envelope` authenticates the
signer and compares the supplied hash before changing count or emitting an
event. Finalization requires the configured finalizer, an existing proposal,
quorum, a non-finalized proposal, exact action/body derivations, and an exact
commitment match. A globally authorized action ID cannot be finalized under a
second proposal. Reverts change no state and emit no success event.

Stable errors are codes 1-16 in the generated schema; notably
`QuorumNotMet=8`, `EnvelopeHashMismatch=10`, `AlreadyFinalized=12`, and
`ActionAlreadyAuthorized=13`.

## Locked deployment

Release installs must be built by `scripts/install_governance_receipt_v3.py`.
It validates account provenance and the generated call schema before signing:

```text
odra_cfg_package_hash_key_name = concordia_governance_receipt_v3
odra_cfg_is_upgradable = false
odra_cfg_allow_key_override = false
odra_cfg_is_upgrade = false
```

The authoritative Wasm filename is read from generated schema
`call.wasm_file_name`. The source, Wasm, schema, install deploy, exact package
hash, exact contract hash, and locked flags belong in `deployment.manifest.json`.

## Proven state readback

`scripts/read_v3_state.py` does not accept deploy arguments or booleans as
readback. It captures a hash-pinned `chain_get_block`, an exact-contract
`query_global_state`, and fourteen `state_get_dictionary_item` calls pinned to
the same state root, contract hash, `state` dictionary, and Odra 2.8.2-derived
item keys. The persisted artifact includes every raw request/response and a
canonical transcript digest. Reopening it reparses the raw CLValue bytes,
cross-checks parsed values, verifies package-to-contract ownership, and creates
an opaque process-sealed runtime object.

The read surfaces are schema/domain/chain, proposer/finalizer/signers/threshold,
proposed envelope, approval count, finalized flag/envelope, and global action
authorization. `scripts/verify_v3_proof.py` recomputes the full typed envelope
and requires these observed facts; fields named `passed` or `verified` are never
used as evidence.

## Gates

```bash
uv run pytest tests/test_envelope_v3_encoder.py \
  tests/test_actions_v3_encoder.py tests/test_clvalue_roundtrip.py
cd contracts/odra-governance-receipt-v3
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Golden vectors under `tests/golden/envelope_v3/` are the cross-language byte
contract. Historical `contracts/odra-governance-receipt/` and frozen live
artifacts must remain byte-identical before and after every v3 build.
