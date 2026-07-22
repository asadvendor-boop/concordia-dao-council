# Historical Odra receipt artifact v1

Status: mandatory post-G1 correction for the independent verifier. This
artifact replaces trust in the humanized
`artifacts/live/casper-final-receipt-proof.json`; it does not modify any
historical receipt or card.

## Publication identity

- Schema: `concordia.historical_odra_receipt.v1`
- Repository artifact path:
  `artifacts/live/historical-odra-receipt-v2.json`
- Public route:
  `GET /proof-artifacts/v1/{proposal_id}/historical-odra-receipt`
- Network: exactly `casper-test`
- Schema-capable generations: exactly `v1` or `v2`, with distinct frozen
  session variants and argument orders.
- Currently publishable combined generation: exactly `v1`. A `v2` combined
  artifact remains unavailable until an independently exported card chain
  terminates at its different signed `final_card_hash`.
- Frozen inventory asset:
  `handoff/HISTORICAL_ODRA_RECEIPTS_V1.json`
- Frozen inventory SHA-256 (including its terminal LF):
  `3c73db58180d19e3d91e360d650c6765023487e3c5b11b3a266d40e85dc26e4d`

## Exact top-level shape

No missing or additional keys are accepted:

```json
{
  "schema_version": "concordia.historical_odra_receipt.v1",
  "proposal_id": "DAO-PROP-...",
  "generation": "v1",
  "captured_at": "RFC3339 UTC-Z",
  "source_commit": "lowercase git40",
  "deployment_commit": "lowercase git40",
  "source_url": "https://.../proof-artifacts/v1/{proposal_id}/historical-odra-receipt",
  "network": "casper-test",
  "lineage_inventory": {},
  "contract_identity": {},
  "card_chain": {},
  "raw_rpc": {}
}
```

`source_url` must be credential-free HTTPS with no query or fragment and the
exact path above. Redirected, artifact-selected, loopback, private, link-local,
or credential-bearing URLs are never verifier observation sources.

## Lineage inventory

Exact keys:

```json
{
  "schema_version": "concordia.historical_odra_inventory.v1",
  "sha256": "hex32",
  "canonical_json": "verbatim UTF-8 contents of the frozen inventory asset"
}
```

The verifier packages its own copy of the inventory asset. It requires exact
byte equality between `canonical_json` and that packaged file, including the
terminal LF, and recomputes `sha256`. The bundle cannot select or self-assert
another inventory.

The inventory deliberately separates:

- `chain_identity`: exact package, contract, on-chain Wasm state hash,
  contract/protocol version, install deploy/block, entry point, and receipt
  deploy identities; and
- `preserved_repo_source`: byte-preservation hashes for the historical repo
  tree at the baseline commit.

`preserved_repo_source.source_deployment_equivalence` is exactly `unproven`.
The local historical source/Wasm bytes are not byte-identical to the deployed
v1/v2 Wasm state identities. Neither the artifact nor public copy may claim
that the preserved repo source reproduces those deployments.

## Contract identity

Exact keys:

```json
{
  "package_hash": "hex32",
  "contract_hash": "hex32",
  "contract_wasm_state_hash": "hex32",
  "contract_version": 1,
  "protocol_version_major": 2,
  "entry_point": "store_governance_receipt",
  "session_variant": "StoredContractByHash",
  "session_target_kind": "contract",
  "session_target_hash": "hex32",
  "session_version": null
}
```

Every value must equal the selected generation in the packaged frozen
inventory. No `hash-`, `contract-`, or `contract-package-` prefixes appear in
the artifact values. For `v1`, the session target is the frozen contract and
`session_version` is null. For `v2`, the session target is the frozen package,
the variant is `StoredVersionedContractByHash`, and `session_version` is `1`.
The two forms are not interchangeable.

## Card chain

`card_chain` is the complete exact `concordia.card_chain.v1` object. Its first
card is `ProposalCard` with `signal_id == proposal_id`; no later card may be a
`ProposalCard`; every later frozen card type carries
`proposal_id == artifact.proposal_id`. The terminal recomputed `card_hash`
must equal the selected generation's signed `final_card_hash` runtime argument
and the frozen inventory value.

The canonical exported chain terminates at the `v1` root
`710b406d7b960d03c633e110fb2edda890b12594967b5db9dba533198a25d622`.
The accepted `v2` receipt signed the different root
`710b9ad9885458fe4a381be50b1c0f7c077189774f150ef9110cb4de1ed7ad66`.
Those roots must never be spliced together. Until a separate exact v2 chain is
exported, v2 remains valid supplemental quorum evidence but is unavailable as
this combined receipt-and-card-chain artifact.

## Raw RPC transcripts

`raw_rpc` has exactly five keys:

```json
{
  "deploy": {"request": {}, "response": {}},
  "canonical_block": {"request": {}, "response": {}},
  "state_root": {"request": {}, "response": {}},
  "package": {"request": {}, "response": {}},
  "contract": {"request": {}, "response": {}}
}
```

Each transcript is duplicate-key-free JSON and has exactly `request` and
`response`. Requests and responses use matching JSON-RPC `id` values and the
following exact method/parameter binding:

1. `deploy`: `info_get_deploy` for the selected frozen receipt deploy.
2. `canonical_block`: `chain_get_block` identified by the deploy execution's
   returned block hash.
3. `state_root`: `chain_get_state_root_hash` identified by that same block
   hash.
4. `package`: `query_global_state` for `hash-{package_hash}` at that exact
   state root with an empty path.
5. `contract`: `query_global_state` for `hash-{contract_hash}` at that same
   state root with an empty path.

The adapter derives facts from these raw values. It never consumes a
`passed`, `processed`, `chain_valid`, CSPR.live summary, or legacy
`casper-final-receipt-proof.json` assertion.

## Fail-closed verification

The independent adapter must:

1. Recompute the deploy body hash and deploy hash from header/body bytes and
   verify every approval signature against the recomputed deploy hash.
2. Require one finalized execution observation with no execution error.
3. Bind its block hash/height to the returned canonical block and state root.
4. Require the selected generation's exact frozen session form: v1 uses
   `StoredContractByHash` targeting the contract; v2 uses
   `StoredVersionedContractByHash` targeting the package at version `1`.
   Both call `store_governance_receipt`.
5. Decode exactly the selected generation's frozen 17 receipt runtime
   arguments, order, and types. The v1 and v2 orders differ. Missing,
   duplicate, additional, reordered, or mismatched arguments are invalid; the
   verifier must not normalize into a shared presentation order before deploy
   hash or receipt-argument-digest verification.
6. Bind `proposal_id` and `final_card_hash` to the artifact/card chain and the
   selected generation's frozen inventory value.
7. Prove the package state contains the exact selected version/contract and
   on-chain Wasm state hash, and the contract state points back to that exact
   package.
8. Match all chain identities to the packaged frozen inventory while reporting
   source/deployment equivalence as unproven.

Missing any raw transcript makes the proof unavailable at registry loading.
A present but malformed, contradictory, ambiguous, or noncanonical transcript
makes it invalid.

`receiptArgumentDigest` is SHA-256 over the exact ordered Casper bytesrepr
argument-list bytes: `u32_le(argument_count)` followed by each `NamedArg` in
signed order. A `NamedArg` is bytesrepr `String(name)` concatenated with
bytesrepr `CLValue(value)`. The digest is emitted as 64 lowercase hexadecimal
characters. Implementations must not hash parsed JSON, sort by name, omit the
list count, or encode a presentation schema. The generation-specific v1 and v2
orders therefore produce distinct digests even when field names overlap.

## Derived verifier result

Only after every check passes may the adapter return:

- `proposalId`, `generation`;
- `deployHash`, `blockHash`, `blockHeight`, `stateRootHash`;
- `packageHash`, `contractHash`, `contractWasmStateHash`, `sessionVariant`,
  `sessionTargetKind`, `sessionTargetHash`, `sessionVersion`;
- `finalCardHash`, `receiptArgumentDigest`;
- `sourceCommit`, `deploymentCommit`, `capturedAt`;
- `sourceDeploymentEquivalence: "unproven"`;
- explicit `verificationScope` and `observationSources`.

The historical public registry item remains historical. Passing this adapter
does not retroactively prove v3 exact-envelope enforcement. A valid v2 receipt
without its separately matching card-chain export must be reported as
supplemental raw on-chain evidence, never as a passing combined artifact.
