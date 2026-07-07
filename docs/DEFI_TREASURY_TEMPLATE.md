# DeFi Treasury Proposal Template

Hero demo scenario:

> A DAO proposal requests moving 30% of treasury into a high-yield liquidity strategy. Verity blocks it, Alden revises it to 8%, and Locke anchors the approved capped decision to Casper Testnet.

## Input

```json
{
  "proposal_id": "DAO-TREASURY-001",
  "proposal_type": "DEFI_TREASURY_REALLOCATION",
  "requested_action": "Move 30% of treasury into high-yield liquidity strategy",
  "treasury_allocation_bps": 3000,
  "target_protocol": "Simulated Casper Liquidity Pool",
  "expected_apy": 18.4,
  "liquidity_depth_score": 42,
  "impermanent_loss_risk": "HIGH"
}
```

## Expected Concordia Behavior

- Rowan routes the proposal.
- Mercer performs treasury, policy, and Casper node reads.
- Verity challenges `MAX_SINGLE_ALLOCATION_BPS`.
- Alden revises the plan to `approved_allocation_bps=800`.
- A human approver approves the exact envelope.
- Locke anchors the final receipt with `policy_hash` and `dissent_hash`.

## Truth Boundary

The qualification build stores a governance receipt. It does not transfer treasury funds.
