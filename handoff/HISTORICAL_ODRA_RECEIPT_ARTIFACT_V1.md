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
- Supported generation: exactly `v1` or `v2`
- Frozen inventory asset:
  `handoff/HISTORICAL_ODRA_RECEIPTS_V1.json`
- Frozen inventory SHA-256 (including its terminal LF):
  `2d5010e71f3dcea9c706c3d2ae00fbc604507e97e58241f2b0ea772815e5d13a`

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
  "entry_point": "store_governance_receipt"
}
```

Every value must equal the selected generation in the packaged frozen
inventory. No `hash-`, `contract-`, or `contract-package-` prefixes appear in
the artifact values.

## Card chain

`card_chain` is the complete exact `concordia.card_chain.v1` object. Its first
card is `ProposalCard` with `signal_id == proposal_id`; no later card may be a
`ProposalCard`; every later frozen card type carries
`proposal_id == artifact.proposal_id`. The terminal recomputed `card_hash`
must equal the signed receipt's exact `final_card_hash` runtime argument.

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
4. Require a stored-contract-by-hash session targeting the exact frozen
   contract and `store_governance_receipt`.
5. Decode exactly the frozen 17 receipt runtime arguments and types; missing,
   duplicate, additional, reordered-where-order-is-semantic, or mismatched
   arguments are invalid.
6. Bind `proposal_id` and `final_card_hash` to the artifact/card chain.
7. Prove the package state contains the exact selected version/contract and
   on-chain Wasm state hash, and the contract state points back to that exact
   package.
8. Match all chain identities to the packaged frozen inventory while reporting
   source/deployment equivalence as unproven.

Missing any raw transcript makes the proof unavailable at registry loading.
A present but malformed, contradictory, ambiguous, or noncanonical transcript
makes it invalid.

## Derived verifier result

Only after every check passes may the adapter return:

- `proposalId`, `generation`;
- `deployHash`, `blockHash`, `blockHeight`, `stateRootHash`;
- `packageHash`, `contractHash`, `contractWasmStateHash`;
- `finalCardHash`, `receiptArgumentDigest`;
- `sourceCommit`, `deploymentCommit`, `capturedAt`;
- `sourceDeploymentEquivalence: "unproven"`;
- explicit `verificationScope` and `observationSources`.

The historical public registry item remains historical. Passing this adapter
does not retroactively prove v3 exact-envelope enforcement.
