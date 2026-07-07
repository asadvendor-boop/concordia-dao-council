# Verification Notes

This note records the submission-risk fixes made after reviewing the final integration checklist.

## Confirmed and fixed

1. **Ecosystem-tooling honesty**
   - `README.md` now includes an integration truth table.
   - The required proof path is explicitly limited to Casper Testnet receipt anchoring through Locke, the receipt contract, and the Casper execution adapter.
   - Odra, x402, IPFS, CSPR.cloud, external MCP, CSPR.trade MCP, and CSPR.click are documented by their actual status: implemented where credential-gated code exists, and roadmap only where the current build intentionally stops.

2. **MCP live network boundary**
   - `shared/cspr_cloud.py:get_node_status()` performs a real Casper Node JSON-RPC `info_get_status` call unless `CASPER_MCP_OFFLINE_MOCK=1`.
   - `shared/casper_mcp.py:get_casper_node_status()` exposes that call to Concordia.
   - `integrations/mcp/concordia_casper_mcp.py` exposes `casper_node_status()` as a FastMCP tool.

3. **Casper execution preflight**
   - `shared/casper_executor.py:casper_execution_preflight()` validates `CASPER_EXECUTION_MODE=real`, key-path existence, contract-hash prefix/shape, and selected driver availability before the demo.
   - `make casper-preflight` runs the check.
   - The required backend driver is `pycspr`; unsupported drivers fail closed.
   - The runtime path builds, signs, serializes, and broadcasts Casper deploys in Python through JSON-RPC without `casper-client`, Node, or shell subprocess execution.

4. **Contract-hash prefix guard**
   - `CASPER_RECEIPT_CONTRACT_HASH` must be in the `hash-` plus 64 hex format copied from Testnet.
   - Placeholder all-zero hashes fail before real execution.

5. **Typed Casper runtime values**
   - The deployed Odra `GovernanceReceipt` contract accepts SHA/evidence roots as `ByteArray(32)` and governance numbers as `U32`.
   - The `pycspr` driver emits native CLValues instead of stringifying every value.
   - Runtime-arg validation rejects control characters, oversized strings, and non-numeric U32 values. Apostrophes remain valid in JSON-RPC/CLString metadata.

6. **Dashboard/API naming contract**
   - The dashboard and gateway use `proposal_id` consistently.
   - A test prevents regression to `incident_id` in dashboard/gateway/database code.

## Verified live proof

The qualification blocker has been closed with a real Casper Testnet deploy and a reconciled public evidence chain.

- Contract hash: `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`
- Final deploy hash: `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`
- Entry point: `store_governance_receipt`
- Block height: `8340490`
- Hero proposal ID: `DAO-PROP-6CB25C`
- Evidence URL: `https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C`
- Explorer URL: `https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`
- API proof URL: `https://api.testnet.cspr.live/deploys/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`

Contract lineage: the canonical deploy writes to the Jun 29 v1 GovernanceReceipt receipt anchor. Link that hash in CSPR.live as `https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`. The supplemental quorum receipt `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` writes through the Jun 30 v2 quorum-enabled GovernanceReceipt package after 2-of-3 approval.

The public evidence endpoint now reports `RESOLVED`, 12 sealed cards, one human decision, exact planned-vs-executed action match, and a valid evidence chain. The chain preserves an earlier raw-receipt card as historical evidence, but the canonical current receipt is the Odra deploy above. The CSPR.live API response confirms typed Casper arguments including `ByteArray(32)` hashes and `U32` allocation/risk fields.
