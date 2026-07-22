# Historical Odra accepted-session live audit

Status: release-blocking correction input for G1-C13 and
`HISTORICAL_ODRA_RECEIPT_ARTIFACT_V1.md`.

Observed read-only from the public Casper Testnet RPC
`https://node.testnet.casper.network/rpc` at
`2026-07-22T22:40:44Z`. No credential, transaction, or mutation was used.
Each deploy identity below is independently pinned in
`HISTORICAL_ODRA_RECEIPTS_V1.json`.

## v1 accepted receipt

- deploy: `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`
- execution block: `2719fe52e26e5e9b6ffb95338db0ce80962dfd49af2789c8bacdd68864ab8367`
- execution height: `8340490`
- session variant: `StoredContractByHash`
- session target: contract
  `a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`
- entry point: `store_governance_receipt`
- signed `final_card_hash`:
  `710b406d7b960d03c633e110fb2edda890b12594967b5db9dba533198a25d622`
- initiator public key:
  `019aeeb6276a9bfe8534a1b51cc7c1e0b72b63cd307566f08d91223bee9e610151`
- approvals: exactly one
- raw response size: 7,444 bytes
- raw response SHA-256 for this observation:
  `38c1af87f4bc5fa3642887c7d9197316df2d34a74feed9fb68ce5368016f1440`

Exact signed argument order and CL types:

1. `proposal_id: String`
2. `proposal_type: String`
3. `proposal_hash: ByteArray(32)`
4. `final_card_hash: ByteArray(32)`
5. `plan_hash: ByteArray(32)`
6. `decision: String`
7. `risk_level: String`
8. `risk_score: U32`
9. `treasury_action: String`
10. `policy_hash: ByteArray(32)`
11. `policy_version: String`
12. `dissent_hash: ByteArray(32)`
13. `approved_allocation_bps: U32`
14. `casper_network: String`
15. `agent_council_version: String`
16. `evidence_uri: String`
17. `agent_action_hash: ByteArray(32)`

This is the generation that matches the existing exported historical card
root `710b406d...d622`.

## v2 accepted receipt

- deploy: `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`
- execution block: `994d3baff4c9ef2ff047465796ac8448b069abdf4aff4fdc0d822b7d8e6f8808`
- execution height: `8350034`
- session variant: `StoredVersionedContractByHash`
- session target: package
  `1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`
- explicit contract version: `1`
- entry point: `store_governance_receipt`
- signed `final_card_hash`:
  `710b9ad9885458fe4a381be50b1c0f7c077189774f150ef9110cb4de1ed7ad66`
- initiator public key:
  `02033c3b4d6eddae1be00f87e635aebe26a1cb5125ec8d09be1e95297208c5754ce1`
- approvals: exactly one
- raw response size: 7,796 bytes
- raw response SHA-256 for this observation:
  `052f9dbcd276b35fa72d206817b7b519aceba333e5447ce237e93b582cf0fbad`

Exact signed argument order and CL types:

1. `proposal_id: String`
2. `proposal_type: String`
3. `proposal_hash: ByteArray(32)`
4. `policy_hash: ByteArray(32)`
5. `dissent_hash: ByteArray(32)`
6. `final_card_hash: ByteArray(32)`
7. `plan_hash: ByteArray(32)`
8. `agent_action_hash: ByteArray(32)`
9. `approved_allocation_bps: U32`
10. `risk_score: U32`
11. `risk_level: String`
12. `decision: String`
13. `treasury_action: String`
14. `policy_version: String`
15. `casper_network: String`
16. `agent_council_version: String`
17. `evidence_uri: String`

## Required schema correction

The pre-correction handoff incorrectly requires `StoredContractByHash` and the
v1 argument order for both generations. It cannot validate the frozen v2
accepted deploy without falsifying its signed body.

The corrected verifier contract must be generation-specific:

- v1: direct-contract variant and v1 order above;
- v2: versioned-package variant, version `1`, and v2 order above;
- both: recompute the deploy body/hash/signature from the exact signed order;
- never reorder arguments into a shared presentation schema before computing
  the deploy body or receipt-argument digest;
- card-chain verification must use an independently exported chain whose
  terminal hash equals the selected generation's signed `final_card_hash`.

Until a second card chain rooted at `710b9ad9...ad66` is independently
exported, the coherent public combined historical artifact is the v1 accepted
receipt. The v2 quorum pair remains valid separate historical evidence, but
must not be spliced onto the v1-rooted card chain.
