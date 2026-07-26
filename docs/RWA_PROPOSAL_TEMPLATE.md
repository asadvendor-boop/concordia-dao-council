# RWA Proposal Template

## Input

```json
{
  "proposal_id": "DAO-RWA-001",
  "proposal_type": "RWA_INVOICE_POOL_ONBOARDING",
  "asset_class": "invoice_receivables",
  "face_value_usd": 125000,
  "maturity_days": 60,
  "debtor_risk_score": 58,
  "issuer_reputation_score": 72,
  "evidence_hash": "sha256:...",
  "requested_action": "Approve invoice pool as eligible collateral"
}
```

## Expected Concordia Behavior

- Rowan classifies the RWA onboarding proposal.
- Mercer reviews issuer, maturity, face value, and Casper context.
- Verity verifies that required evidence is hash-bound.
- Alden prepares a capped approval plan.
- Locke anchors the approved RWA governance receipt to Casper Testnet.

## Evidence Required

- evidence hash
- issuer or debtor risk fields
- maturity
- face value
- final card hash
- plan hash
- Casper transaction hash after execution
