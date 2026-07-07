# Policy Templates

The active demo policy is in `config/dao_constitution.cas.json`.

## Core Constitution Fields

```json
{
  "dao_name": "Concordia Treasury DAO",
  "policy_version": "2026.06.cas-v1",
  "max_single_allocation_bps": 800,
  "max_high_risk_allocation_bps": 300,
  "requires_risk_challenge_above_bps": 1000,
  "requires_rwa_evidence_hash": true,
  "requires_multisig_for_execution": true,
  "allowed_execution_network": "casper-test",
  "allowed_receipt_entry_point": "store_governance_receipt"
}
```

## Rule Meaning

- `max_single_allocation_bps`: largest allowed strategy allocation without revision.
- `requires_risk_challenge_above_bps`: forces Verity to challenge high-allocation proposals.
- `requires_rwa_evidence_hash`: blocks RWA onboarding without an evidence hash.
- `allowed_execution_network`: Locke refuses receipts outside the configured network.
- `allowed_receipt_entry_point`: binds the execution target to the known Casper contract entry point.

## Dissent Receipts

When a rule is violated, Verity creates a Dissent Receipt containing:

- dissenting agent
- violated rule
- policy hash
- proposal hash
- challenged plan hash
- reason hash
- severity
- timestamp

The final approved Casper receipt carries the `dissent_hash` so auditors can verify that objections were not lost.
