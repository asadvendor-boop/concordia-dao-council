# DAO Adoption Pack

Concordia DAO Council is intended as a policy-governed execution firewall for Casper DAOs. It does not give models direct treasury control. Agents deliberate, challenge, revise, and prepare exact envelopes; humans approve; Locke anchors the approved decision root to Casper Testnet.

## Who Uses It

- DAO treasury committees reviewing DeFi allocation proposals.
- RWA committees onboarding receivable or collateral pools.
- Grant and risk councils that need auditable dissent, not just final votes.
- Casper ecosystem builders who want agent-assisted governance without opaque autonomous execution.

## What A DAO Configures

- `config/dao_constitution.cas.json`
- maximum single-strategy allocation
- RWA evidence requirements
- allowed Casper network
- required receipt entry point
- multisig approval requirement
- risk thresholds

## What Agents May Do

- Rowan routes material proposals into a Council Chamber.
- Mercer gathers treasury, policy, Casper node, and optional CSPR/Casper context.
- Verity enforces the DAO Constitution and records structured dissent.
- Alden converts a revised decision into an exact action envelope.
- Locke submits only an approved, hash-bound receipt to Casper Testnet.
- Wells summarizes the sealed evidence trail.

## What Agents May Not Do

- Move real treasury funds in the qualification build.
- Bypass multisig approval.
- Execute altered parameters.
- Ignore a Constitution violation.
- Claim CSPR.cloud, MCP, x402, or Odra paths are production-deep unless they are configured and proven.

## Final Proof Artifacts

- Casper Testnet contract hash.
- Casper Testnet deploy/transaction hash.
- Entry point: `store_governance_receipt`.
- `proposal_id`.
- `final_card_hash`.
- `plan_hash`.
- `policy_hash`.
- `dissent_hash`.
- `approved_allocation_bps`.
- public evidence URL.

## 30/60/90-Day Roadmap

- 30 days: Casper Testnet pilot with receipt contract, policy templates, and CSPR.cloud status reads.
- 60 days: Odra contract upgrade, proposal registry, richer query endpoints, and x402 specialist report endpoint.
- 90 days: DAO pilot, agent reputation scoring, RWA policy templates, and production wallet policy.
