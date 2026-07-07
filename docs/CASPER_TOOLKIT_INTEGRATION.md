# Casper Toolkit Integration

Concordia DAO Council uses the Casper agent/developer stack in a layered way.

## Required proof path

| Casper product/service | Concordia use |
|---|---|
| Casper Testnet | Settlement layer for the final governance receipt transaction. |
| Casper smart contracts | Minimal `store_governance_receipt` contract stores the approved decision root. |
| Python-native Casper JSON-RPC | Locke submits the approved receipt through `shared/casper_executor.py`, which uses `pycspr` typed CLValues and `httpx` JSON-RPC instead of host CLI subprocesses. |

## Optional live-read and V2 paths

| Casper product/service | Concordia use | Honesty note |
|---|---|---|
| CSPR.cloud REST API | Mercer can read account, deploy, and rate context through `shared/cspr_cloud.py`. | Requires `CSPR_CLOUD_ACCESS_TOKEN`; otherwise returns deterministic local context labeled as mock. |
| CSPR.cloud Streaming API | Runtime metadata is present for deploy/contract event subscriptions. | Subscription listener is V2. |
| Casper Node API via CSPR.cloud/direct node | `get_casper_node_status()` performs JSON-RPC `info_get_status`. | Live read available for MCP/preflight proof. |
| Casper MCP Server | `shared/casper_mcp.py` exposes account balance and deploy-status tool boundaries. | External server URL required for live tool calls. |
| CSPR.trade MCP | Mercer can request DeFi quote context for treasury proposals. | External server URL required for live quotes. |
| x402 | `shared/x402_payments.py`, `/x402/payment-intent`, `/x402/governance-report`, and `x402_provider/` support real CSPR transfer-hash verification through CSPR.live plus bounded retry for indexer lag. | The hosted proof configures a separate same-VM Concordia Risk Oracle provider at `x402-provider.47.84.232.193.sslip.io`; external marketplace providers remain adapter-compatible but are not claimed unless separately configured. |
| IPFS | `shared/ipfs_client.py`, `/ipfs/evidence/{proposal_id}`, and `/api/ipfs/{cid}` can pin and serve the governance archive through a Concordia-hosted Kubo node; Pinata remains an optional external pinner. | Requires a governance admin token for pinning. Web3.Storage/NFT.Storage paths are compatibility/experimental until current auth flows are implemented. |
| Odra | `contracts/odra-governance-receipt/` is a Wasm-build-checked multi-contract package with `Odra.toml`, build binaries, and `migration.manifest.json`: council registry, card index, treasury policy, typed receipt, and quorum entrypoints. | The live proof uses the Jun 29 v1 Odra `GovernanceReceipt`; the supplemental quorum path uses the Jun 30 v2 quorum-enabled package and is live-complete in `artifacts/live/odra-quorum-exercise-plan.json`. The auxiliary registry/policy/index modules are also captured as supplemental topology genesis proof in `artifacts/live/odra-topology-genesis-proof.json`: representative CouncilRegistry `register_agent`, TreasuryPolicy `validate_allocation`, and CardIndexLedger `seal_card_root`. |
| Casper Wallet custody path | `integrations/cspr-click/`, `/cspr-click/unsigned-receipt/{proposal_id}`, `/cspr-click/quorum-approval/{proposal_id}`, and `/cspr-click/quorum-receipt/{proposal_id}` expose wallet-ready unsigned deploys for the receipt envelope and Odra quorum path. The route names are compatibility names; the current dashboard signs with the active Casper Wallet account directly. | Browser-wallet signing is verified for the receipt and quorum exercise; the UI still fails closed for unsupported proposals or missing package configuration. |

For reviewer-facing MCP instructions, see `docs/MCP_JUDGE_TOOL.md`.

Final submission mode must use real Casper Testnet credentials and record the transaction hash produced by Locke.
