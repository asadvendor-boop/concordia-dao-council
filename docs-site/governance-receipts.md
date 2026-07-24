# On-Chain Governance Receipts

Concordia anchors approved governance decisions to Casper Testnet through a
lineage of receipt contracts. This page separates what is **live, historical
proof** from what is **current work in progress** — the two are never mixed.

## v1 — GovernanceReceipt receipt anchor (historical, live)

The v1 Odra `GovernanceReceipt` contract, deployed **June 29**, is the
canonical receipt anchor:

- Contract: `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`
- Package: `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`

Receipts written through the v1 anchor:

| Receipt | Deploy hash |
|---|---|
| Canonical reviewer receipt (`DAO-PROP-6CB25C`) | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Browser-wallet custody receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| Supplemental dynamic lifecycle proof (`DAO-PROP-DYN-002`) | `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Supplemental RWA invoice-pool receipt (`DAO-PROP-RWA-001`) | `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc` |

The entry point is `store_governance_receipt`, with typed Casper CLValues:
`ByteArray(32)` for decision/evidence roots and `U32` for numeric risk and
allocation fields.

## v2 — quorum-enabled GovernanceReceipt (historical, live)

The v2 quorum-enabled `GovernanceReceipt` package, deployed **June 30**, adds
an M-of-N approval gate in front of the store call:

- Package: `hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`

The quorum exercise proved the gate both ways on-chain:

| Step | Evidence |
|---|---|
| Pre-quorum store attempt **rejected** | Deploy `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431` — `User error: 8` (`QuorumNotMet`) at block **8,349,116** |
| Store **accepted** after 2-of-3 approval (including a browser-wallet approval) | Deploy `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` at block **8,350,034** |

This is the demo's climax proof: the *same* action is reverted before quorum
and accepted after quorum, on the public chain, with no trust in the demo
narration required.

Auxiliary Odra modules (`CouncilRegistry`, `TreasuryPolicy`,
`CardIndexLedger`) were each independently exercised on Testnet as a
supplemental topology-genesis proof. That shows they install and execute; it
does **not** claim the canonical receipt cross-calls them in a fully
productized four-contract suite — that remains roadmap.

## v3 — exact-envelope receipt contract (current work, **not yet live**)

!!! warning "Work in progress — no live v3 proof exists yet"
    Everything in this section describes the v3 design currently being
    implemented. v3 is a **new sibling contract crate and a new Testnet
    package**; it does not modify or retroactively re-protect the historical
    v1/v2 receipts above, and an old receipt never proves a v3 property. No v3
    package hash, contract hash, or receipt exists to cite yet — when v3 goes
    live, its proofs are written to the generated release manifest and published
    with their own on-chain references. `PENDING_PROOF`: v3 install (package /
    contract hash + install deploy) and the four-outcome live proof
    (`QuorumNotMet`, `EnvelopeHashMismatch`, exact acceptance, `AlreadyFinalized`
    deploy hashes + block heights + `action_authorized=true` readback), plus the
    native-transfer treasury execution (625 → 50 CSPR, bound transfer ID).

v3 moves the exact-envelope guarantee from Gateway code into the contract
itself. Key properties of the frozen v3 interface:

- **Common exact-envelope header.** Every v3 envelope commits, in a fixed
  field order, to the proposal identity (`proposal_id`, `proposal_nonce`,
  `proposal_hash`), the decision (`decision_code`, requested vs approved
  allocation in basis points), the action identity (`action_kind`,
  `action_version`, `action_id`), and the full evidence root set
  (`policy_hash`, `plan_hash`, `final_card_hash`, `dissent_hash`,
  `agent_action_hash`, `preauth_evidence_root`, `authorized_metadata_root`).
- **Deployment-domain binding.** The contract derives and stores a unique
  deployment domain from the chain name, package key name, and a one-time
  installation nonce, so envelopes cannot be replayed across installations.
- **Typed action bodies.** v3 defines two executable action schemas:
  `NativeTransferV1` (native CSPR treasury execution) and
  `OfficialX402SettlementV1` (WCSPR settlement through the official x402
  facilitator flow, see [Official x402](official-x402.md)).
- **Decision-code discipline.** Executable finalization is permitted only for
  `APPROVED` and `APPROVED_WITH_LIMITS`; rejected, suppressed, or escalated
  decisions can never carry an executable action.
- **Quorum semantics carried forward.** As in v2, a pre-quorum store attempt
  fails closed on-chain; mutation after proposal and repeat finalization are
  likewise contract-rejected with distinct error codes.

Until v3's own on-chain proofs are published, the canonical reviewer proof
remains the v1 receipt `e926582f...d852`, and the quorum proof remains the v2
pair at blocks 8,349,116 / 8,350,034.

## How receipts are judged

Concordia's proof surfaces report receipts with separate, honest dimensions —
generation (`v1`/`v2`/`v3`), lineage (canonical vs supplemental), temporal
scope (historical vs current), verification status, and execution outcome —
rather than one collapsed "verified" flag. An expected on-chain rejection such
as `QuorumNotMet` is a *verified* proof with outcome `expected_rejection`, not
a failure. Only a fully verified item with every required check passed may
render green; unknown, missing, stale, or failed observations never do.

See [Proof & Verification](proof-verification.md) for how to check any of
these receipts yourself.
