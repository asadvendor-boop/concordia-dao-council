# Submission Checklist

Before publishing Concordia DAO Council, complete this list.

## Required proof

- [ ] Public GitHub/GitLab/Bitbucket repository is created.
- [ ] README contains setup instructions and the integration truth table.
- [x] Governance receipt contract is deployed on Casper Testnet.
- [ ] `scripts/finalize_casper_shared_host.py` has produced `artifacts/casper-contract-setup.json` on the shared host.
- [x] `CASPER_RECEIPT_CONTRACT_HASH` includes the `hash-` prefix.
- [x] `make casper-preflight` passes in `CASPER_EXECUTION_MODE=real`.
- [x] Locke has produced a real Casper Testnet transaction hash.
- [ ] Demo video is public.
- [ ] `docs/SUBMISSION_PACKET.md` contains contract hash, transaction hash, hero proposal ID, repo URL, and video URL.
  Casper fields are complete; repository and video URLs remain human/publication tasks.

## Demo path

- [ ] Start Gateway.
- [ ] Start proposal simulator.
- [ ] Start Rowan, Mercer, Verity, Alden, Locke, and the Concordia Core heartbeat.
- [ ] Trigger the Risky Treasury Allocation Proposal.
- [ ] Show Verity issuing a challenge.
- [ ] Show Alden producing a revised ResponsePlan.
- [ ] Approve the exact multisig envelope.
- [ ] Show Locke anchoring the CasperExecutionReceipt.
- [ ] Open `/evidence/{proposal_id}` and show `chain_valid: true`.
- [ ] Show the Casper Testnet transaction hash and explorer page.

## Repository hygiene

- [ ] Run `make smoke`.
- [ ] Confirm no legacy model/vendor branding remains.
- [ ] Confirm no private key, `.env`, database, local cache, or dependency directory is committed.
- [ ] Confirm optional CSPR.cloud, MCP, and Odra areas are scoped accurately, and that official x402 is explicitly excluded.
