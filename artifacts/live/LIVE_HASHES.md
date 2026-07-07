# Concordia Live Hash Manifest

Captured UTC: 2026-06-30T14:02:59.585345+00:00
Live app: https://concordia.47.84.232.193.sslip.io/dashboard/proof
Judge Walkthrough: https://concordia.47.84.232.193.sslip.io/dashboard/judge
Proof pack: https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C
Evidence: https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C
HTML Certificate: https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C
PDF Certificate: https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C/pdf

## Canonical Casper Receipt
- proposal_id: DAO-PROP-6CB25C
- deploy_hash: e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
- explorer_url: https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
- contract_hash: hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
- contract_url: https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
- package_hash: hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a
- entry_point: store_governance_receipt

## Browser Wallet / Quorum Exercise
- wallet_receipt_hash: 56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf
- pre_quorum_blocked_hash: 6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431
- server_signer_approval_hash: dd7c68fc3be3295261ed8ca41f51e5dd0840923dc83c1e67ca23ad6f5d6a31c5
- browser_wallet_approval_hash: 7ee77b11b8373fa55976b047e5613d391dd2ece5b6c2f0671c7232183cc875da
- final_quorum_receipt_hash: 9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928
- quorum_package_hash: hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96
- quorum_note: Jun 30 v2 quorum-enabled GovernanceReceipt package; the final receipt succeeds only after 2-of-3 approval.

## Supplemental Dynamic Lifecycle Proof
- proposal_id: DAO-PROP-DYN-002
- deploy_hash: 68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0
- explorer_url: https://testnet.cspr.live/deploy/68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0
- contract_hash: hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
- entry_point: store_governance_receipt
- artifact: artifacts/live/dynamic-proposal-execution-proof.json

## Supplemental RWA Invoice-Pool Receipt
- proposal_id: DAO-PROP-RWA-001
- deploy_hash: 3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc
- explorer_url: https://testnet.cspr.live/deploy/3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc
- contract_hash: hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
- entry_point: store_governance_receipt
- artifact: artifacts/live/dynamic-proposal-execution-proof-DAO-PROP-RWA-001.json
- note: Supplemental RWA proof only; not the canonical reviewer receipt.

## GovernanceReceipt Contract Lineage
- v1_receipt_anchor: Jun 29 GovernanceReceipt contract `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`, package `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`; canonical `e926...`, browser-wallet `56b6...`, supplemental dynamic `68fd...`, and supplemental RWA `3803...` receipts write here.
- v2_quorum_package: Jun 30 quorum-enabled GovernanceReceipt package `hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`; supplemental quorum receipt `9d631...` writes here after the 2-of-3 gate passes.
- cspr_live_note: use `/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` for the v1 contract hash.

## x402 / IPFS
- x402_payment_hash: dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c
- x402_provider_url: https://x402-provider.47.84.232.193.sslip.io/x402/risk-report
- ipfs_status: verified
- ipfs_cid: bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq
