# v3 Envelope Specification

!!! warning "Design specification — v3 is not yet live"
    This page specifies the **design** of the GovernanceReceipt v3 exact-envelope
    contract, which is finals work in progress. No v3 package hash, contract
    hash, deploy, or state readback exists to cite yet. Every concrete value,
    hash, height, and status for v3 is sourced from the generated release
    manifest after live capture. `PENDING_PROOF`: v3 install + four-outcome live
    proof + `action_authorized=true` readback. See
    [On-Chain Governance Receipts](governance-receipts.md) for the v1/v2/v3
    lineage and what is live today.

v3 moves the exact-envelope guarantee from Gateway code into the contract
itself. It is a **new sibling contract crate and a new Testnet package**; it
does not modify or retroactively re-protect the historical v1/v2 receipts.

## Common exact-envelope header

Every v3 envelope commits, in a fixed field order, to:

- **Proposal identity** — `proposal_id`, `proposal_nonce`, `proposal_hash`.
- **Decision** — `decision_code`, requested vs approved allocation in basis
  points.
- **Action identity** — `action_kind`, `action_version`, `action_id`.
- **Evidence root set** — `policy_hash`, `plan_hash`, `final_card_hash`,
  `dissent_hash`, `agent_action_hash`, `preauth_evidence_root`,
  `authorized_metadata_root`.

## Deployment-domain binding

The contract derives and stores a unique deployment domain from the chain name,
package key name, and a one-time installation nonce, so an envelope cannot be
replayed across installations.

## Typed action bodies

v3 defines two executable action schemas:

- **`NativeTransferV1`** — native CSPR treasury execution (see
  [Treasury Execution](treasury-execution.md)).
- **`OfficialX402SettlementV1`** — WCSPR settlement through the official x402
  facilitator flow (see [Official x402](official-x402.md)).

## Decision-code discipline

Executable finalization is permitted only for `APPROVED` and
`APPROVED_WITH_LIMITS`. Rejected, suppressed, or escalated decisions can never
carry an executable action.

## Four on-chain outcomes (design)

The finals proof extends the two-outcome quorum story into four contract
outcomes for one proposal and one envelope. Each is `PENDING_PROOF` until its
live deploy hash, block height, and readback are captured:

1. **Before quorum** → the contract reverts with `QuorumNotMet` (error code 8).
2. **Post-approval mutation** → a mutated envelope (for example 3000 bps against
   an approved 800 bps) reverts with `EnvelopeHashMismatch` (error code 10). The
   contract does not re-evaluate the DAO's policy; that check stays with the
   deterministic core off-chain. The contract rejects any envelope that is not
   byte-exactly the one quorum approved.
3. **The exact approved envelope** → accepted, with `action_authorized=true`
   readable from contract state.
4. **The same envelope again** → the contract reverts with `AlreadyFinalized`
   (error code 12).

One-time v3 finalization is **authorization**, not execution; the executor's
durable journal is the replay lock that prevents a second transfer for the same
authorization.
