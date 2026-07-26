# Governance Receipt Contract

This Casper Wasm contract stores the final Concordia governance receipt for a proposal.

Entry point:

```text
store_governance_receipt
```

Runtime arguments:

```text
proposal_id: String
proposal_type: String
proposal_hash: ByteArray(32)
final_card_hash: ByteArray(32)
plan_hash: ByteArray(32)
decision: String
risk_level: String
risk_score: U32
treasury_action: String
policy_hash: ByteArray(32)
policy_version: String
dissent_hash: ByteArray(32)
approved_allocation_bps: U32
casper_network: String
agent_council_version: String
evidence_uri: String
agent_action_hash: ByteArray(32)
```

Deploy this contract to Casper Testnet and copy the resulting contract hash into `.env` as:

```bash
CASPER_RECEIPT_CONTRACT_HASH=hash-your-testnet-contract
```
