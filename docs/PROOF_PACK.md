# Concordia Proof Pack

Concordia's live proof is designed so judges can verify the whole governance loop without trusting the demo narration.

## Live Proof Items

1. Open the live dashboard and select `DAO-PROP-6CB25C`.
2. Open `https://concordia.47.84.232.193.sslip.io/dashboard/judge` for the Judge Walkthrough.
3. Open `https://concordia.47.84.232.193.sslip.io/dashboard/proof?proposal=DAO-PROP-6CB25C` for the Proof Center.
4. Open `https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C` for the public evidence chain.
5. Open `https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C/download` for the downloadable governance archive.
6. Open `https://concordia.47.84.232.193.sslip.io/technical-jury-note` for the canonical-proof and production-scope boundary.
7. Open `https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C` for the HTML certificate.
8. Download `https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C/pdf` for the PDF certificate with QR links.
9. Open the CSPR.live deploy link shown in the Proof Center.
10. Verify the real x402 paid-report proof:

```bash
curl -H 'X-Payment: dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c' \
  'https://x402-provider.47.84.232.193.sslip.io/x402/risk-report?proposal_id=DAO-PROP-6CB25C'
```

11. Run the local verifier:

```bash
python scripts/verify_concordia_receipt.py --base-url "$CONCORDIA_PUBLIC_URL" --proposal-id DAO-PROP-6CB25C
```

12. Run the live-chain verifier mode when network access is available:

```bash
python scripts/verify_concordia_receipt.py \
  --base-url "$CONCORDIA_PUBLIC_URL" \
  --proposal-id DAO-PROP-6CB25C \
  --live-chain
```

## What The Verifier Checks

- evidence chain validity
- Casper Testnet deploy hash
- receipt contract hash
- entry point `store_governance_receipt`
- `policy_hash`, `dissent_hash`, `final_card_hash`, and `plan_hash`
- typed Casper arguments, including `ByteArray(32)` roots and `U32` numeric fields
- blocked rogue execution proof
- deterministic firewall statement that LLMs cannot execute unapproved actions

With `--live-chain`, the verifier also queries Casper Testnet/CSPR.live, confirms the deploy finalized successfully, and diffs the live contract hash, entry point, and typed runtime arguments against the local proof pack.

## Hero Run

The primary live run is a DeFi treasury reallocation scenario:

> A DAO proposal requests moving 30% of treasury into a high-yield liquidity strategy. Verity blocks it, Alden revises it to the DAO Constitution cap of 8%, a human multisig approves the exact revised envelope, and Locke anchors the approved capped decision to Casper Testnet.

The proof packet must show:

- `decision`: `APPROVED_WITH_LIMITS`
- requested allocation: `3000 bps`
- approved allocation: `800 bps`
- policy event: `max_single_allocation_bps`
- `dissent_hash`
- `policy_hash`
- `final_card_hash`
- Casper deploy hash
- CSPR.live explorer URL
- x402 paid-report transfer hash: `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`
- IPFS archive CID: `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`

## Canonical Proof Hierarchy

| Proof item | Canonical value |
|---|---|
| Proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Quorum proof | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Supplemental dynamic lifecycle proof | `DAO-PROP-DYN-002` -> `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Supplemental RWA receipt | `DAO-PROP-RWA-001` -> `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| x402 SafePay Lite payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

Contract lineage: v1 GovernanceReceipt, deployed Jun 29, is the receipt anchor at `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` under package `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`; canonical `e926...`, browser-wallet `56b6...`, and supplemental dynamic `68fd...` receipts use that anchor. The v2 quorum-enabled GovernanceReceipt package, deployed Jun 30, is `hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`; the final quorum receipt `9d631...` is the store call that succeeds only after the 2-of-3 gate passes. CSPR.live contract links for the v1 anchor must use `/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`.

SafePay Lite demonstrates conditional paid specialist-report settlement: Concordia verifies Casper payment, validates the provider report hash, shows deterministic duplicate-proof replay, records provider reputation delta, and includes the result in the governance proof. It is not described as full escrow, a refund contract, or a marketplace.

## Integration Boundaries

Implemented for final submission:

- native Python `pycspr` Casper deploy construction
- typed Casper runtime arguments
- direct JSON-RPC broadcast
- deploy/transaction finality polling fallback
- Proof Center
- downloadable audit packet
- verifier script
- Casper Wallet unsigned receipt intent endpoint
- x402 payment intent endpoint
- x402 real Casper transfer-hash verification with indexer-lag retry
- live Kubo IPFS evidence pinning with public `/api/ipfs/{cid}` gateway route
- Wasm-build-checked multi-contract Odra migration package
- local Odra module exercise packet in `artifacts/live/odra-module-exercise-plan.json`
- live-complete M-of-N quorum exercise in `artifacts/live/odra-quorum-exercise-plan.json`, including `configure_quorum`, `propose_envelope`, pre-quorum blocked `store_governance_receipt`, server signer approval, browser-wallet approval, and final receipt after threshold.
- live-complete supplemental Odra topology genesis proof in `artifacts/live/odra-topology-genesis-proof.json`, including a representative CouncilRegistry `register_agent` call plus independent TreasuryPolicy `validate_allocation` and CardIndexLedger `seal_card_root` calls.

Odra wording boundary:

- The canonical reviewer proof is the Odra `GovernanceReceipt` deploy `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`.
- The quorum exercise is supplemental proof, with final receipt `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`.
- The RWA invoice-pool receipt is supplemental proof, with receipt `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc`.
- `CouncilRegistry`, `TreasuryPolicy`, and `CardIndexLedger` are independently exercised as supplemental Odra topology genesis proof. CouncilRegistry is represented by a live `register_agent` call for Locke; TreasuryPolicy and CardIndexLedger are represented by live `validate_allocation` and `seal_card_root` calls. This proves the auxiliary modules can be installed and called on Casper Testnet; it does not replace the canonical reviewer receipt or claim a fully productized four-contract DAO suite.

Explicit roadmap-only items:

- full Enterprise IAM and durable queues
- full Event Streaming / SSE finality pipeline

Those roadmap items are intentionally not required for the final proof packet.

## Technical Jury Scope Note

Concordia's canonical reviewer proof is frozen for reproducibility. Dynamic proposals are preview/execution-ready unless their own evidence chain, signature, finality record, and proof artifact exist. The Odra topology genesis proves `CouncilRegistry`, `TreasuryPolicy`, and `CardIndexLedger` as independently exercised supplemental modules; full cross-contract production enforcement is roadmap, not overclaimed. See `docs/TECHNICAL_JURY_NOTE.md` and `https://concordia.47.84.232.193.sslip.io/technical-jury-note`.
