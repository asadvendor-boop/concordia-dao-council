# Casper Tooling Map

Concordia deliberately separates the production proof path from optional ecosystem adapters. This avoids overstating scaffolds while keeping the long-term architecture visible.

| Component | Status | Concordia implementation |
|---|---|---|
| Casper Testnet | Core proof | Locke submits the final governance receipt transaction after exact-envelope approval. |
| Casper receipt contract | Core proof | `contracts/governance-receipt/` stores proposal type, approved proposal hash, final card hash, plan hash, decision, risk level, risk score, treasury action, policy hash, dissent hash, approved allocation, evidence URI, and action hash. Hash roots are `ByteArray(32)` and risk/allocation are `U32`. |
| DAO Constitution | Core guardrail | `config/dao_constitution.cas.json` and `shared/dao_policy.py` deterministically block the 30% treasury request and produce the 8% capped approval. |
| Python-native Casper JSON-RPC execution | Core proof path | `shared/casper_executor.py` uses `pycspr` to construct typed CLValues, signs the deploy in Python, serializes it to Casper JSON, and broadcasts through `account_put_deploy` over HTTPS JSON-RPC. The backend image does not install or call `casper-client` or Node.js for Locke execution. |
| Casper Node JSON-RPC | Live read boundary | `shared/casper_mcp.py:get_casper_node_status()` performs a live `info_get_status` call and `get_casper_public_status()` performs a public HTTPS GET unless `CASPER_MCP_OFFLINE_MOCK=1`. |
| CSPR.cloud REST API | Credential-gated adapter | `shared/cspr_cloud.py` includes account, deploy, and rate helpers. Without `CSPR_CLOUD_ACCESS_TOKEN`, these return deterministic local context and are not claimed as final proof. |
| CSPR.cloud Streaming API | Credential-gated adapter | `streaming_subscription_context()` exposes stream connection metadata for V2 event listeners. |
| Casper Node API via CSPR.cloud | Configured endpoint | `CSPR_NODE_RPC_URL` and `CASPER_NODE_ADDRESS` point the execution and MCP adapters at the selected node RPC endpoint. |
| Casper MCP Server | External-service adapter | `shared/casper_mcp.py` calls `CASPER_MCP_URL` if configured; otherwise balance/deploy tools are explicit mocks. |
| CSPR.trade MCP | External-service adapter | `shared/casper_mcp.py` calls `CSPR_TRADE_MCP_URL` if configured; otherwise quote data is deterministic demo context. |
| Odra | Live receipt proof + live quorum exercise + supplemental topology genesis | The canonical live proof uses the Jun 29 v1 Odra `GovernanceReceipt` receipt anchor. The supplemental quorum exercise uses the Jun 30 v2 quorum-enabled package and is live-complete with configure/propose/approve/pre-quorum-failure/final-receipt hashes. `CouncilRegistry` is exercised through a representative `register_agent` call, while `TreasuryPolicy` and `CardIndexLedger` are independently called through `validate_allocation` and `seal_card_root` in `artifacts/live/odra-topology-genesis-proof.json`; this proves auxiliary module execution without replacing the canonical receipt. |
| SafePay Lite | Recorded V1 native-CSPR evidence | The public proof preserves payment hash `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` for independent CSPR.live comparison. Official x402 and a live provider/facilitator service are not shipped. |
| IPFS | Live Kubo evidence pinning + optional Pinata | `shared/ipfs_client.py` can add the governance archive to a Concordia-hosted Kubo node and serve it through `/api/ipfs/{cid}`. Pinata can also be used when configured. Web3.Storage/NFT.Storage paths are legacy/experimental until their current UCAN/w3up-style auth flows are implemented. |
| CSPR.click AI Agent Skill | Browser-wallet signing intent | `integrations/cspr-click/` and `/cspr-click/unsigned-receipt/{proposal_id}` expose the exact unsigned envelope for wallet custody. |
| Proof Center | Judge-facing proof layer | `shared/proof_pack.py`, `/proof-center/{proposal_id}`, and `/proof-pack/{proposal_id}` package compact proof, blocked-action demo, outcome gallery, and downloadable archive. |

Before recording the final proof, run:

```bash
make casper-preflight
```

The preflight fails if the real execution driver is missing, the key path is unreadable, or `CASPER_RECEIPT_CONTRACT_HASH` is not copied with its required `hash-` prefix.
