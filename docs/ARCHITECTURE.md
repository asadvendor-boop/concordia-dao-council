# Architecture

Concordia DAO Council is an off-chain multi-agent governance council with an on-chain Casper receipt anchor.

```text
Proposal simulator / DAO feed
        |
        v
FastAPI Gateway / Concordia Core
  - proposal state machine
  - Council Chamber messages
  - card sealing
  - nonce lifecycle
  - authorization lifecycle
        |
        +--> Rowan  / Proposal Sentinel
        +--> Mercer / Treasury Intelligence Agent
        +--> Verity / Risk & Legal Agent
        +--> Alden  / Protocol Strategy Agent
        +--> Locke  / Casper Execution Agent
        +--> Wells  / Governance Archivist
        |
        v
Casper Testnet governance receipt contract
```

## Trust boundaries

The LLM layer is advisory. It can explain routing, assess evidence, and draft a plan, but it cannot authorize or execute. The Gateway owns proposal state transitions, card hashes, action hashes, and nonce consumption. Locke executes only a consumed authorization whose exact action envelope matches the approved hash.

## On-chain anchor

The final on-chain receipt stores or emits:

```text
proposal_id
proposal_hash
final_card_hash
plan_hash
decision
risk_level
treasury_action
evidence_uri
agent_action_hash
```

This lets reviewers compare the local evidence chain with the Casper Testnet transaction.

## Casper services

Concordia uses the Casper stack as follows:

- **Casper Testnet** for the transaction-producing receipt.
- **Wasm contract** in `contracts/governance-receipt/`.
- **Odra multi-contract migration package** in `contracts/odra-governance-receipt/`, with manifest and verifier.
- **Python-native Casper JSON-RPC execution** through `shared/casper_executor.py`.
- **CSPR.cloud** via credential-gated adapters in `shared/cspr_cloud.py`; local mode is explicitly labeled mock.
- **MCP adapters** via `shared/casper_mcp.py`; external MCP calls require configured server URLs, while node status can call live JSON-RPC.
- **x402** via `shared/x402_payments.py`, `/x402/payment-intent`, and `/x402/governance-report` for demo proofs, real Casper transfer-hash verification, and provider/facilitator retry paths.
- **CSPR.click skill path** documented for wallet creation, signing, and event handling.
