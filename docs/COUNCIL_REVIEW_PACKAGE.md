# Concordia Council Review Package

This source package is a clean review archive for Concordia DAO Council.

The archive intentionally includes source code, documentation, contracts, dashboard code, deployment descriptors, tests, and live proof artifacts. It intentionally excludes local dependencies, build outputs, caches, secrets, private keys, VM backups, and generated runtime folders.

## Live Review URLs

- Dashboard Proof Center: https://concordiadao.xyz/dashboard/proof
- Judge Walkthrough: https://concordiadao.xyz/dashboard/judge
- Evidence chain: https://concordiadao.xyz/evidence/DAO-PROP-6CB25C
- Proof pack: https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C
- Technical jury note: https://concordiadao.xyz/technical-jury-note
- HTML certificate: https://concordiadao.xyz/certificate/DAO-PROP-6CB25C
- PDF certificate: https://concordiadao.xyz/certificate/DAO-PROP-6CB25C/pdf

## Canonical Proof Hashes

- Proposal: `DAO-PROP-6CB25C`
- Canonical contract: `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`
- Canonical receipt deploy: `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`
- Browser wallet receipt: `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf`
- Pre-quorum blocked deploy: `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431`
- Server signer approval: `dd7c68fc3be3295261ed8ca41f51e5dd0840923dc83c1e67ca23ad6f5d6a31c5`
- Browser wallet quorum approval: `7ee77b11b8373fa55976b047e5613d391dd2ece5b6c2f0671c7232183cc875da`
- Final quorum receipt: `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`
- x402 payment hash: `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`
- IPFS evidence CID: `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`

The same values are also recorded in `artifacts/live/LIVE_HASHES.md` and `artifacts/live/live-proof-pack-current.json`.

Contract lineage note: the canonical reviewer receipt uses the Jun 29 v1 GovernanceReceipt receipt anchor (`hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`, CSPR.live `/contract/` URL). The final quorum receipt uses the Jun 30 v2 quorum-enabled GovernanceReceipt package `hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`; it is the demo-climax receipt because it succeeds only after the 2-of-3 gate passes.

SafePay Lite demonstrates conditional paid specialist-report settlement: Concordia verifies Casper payment, validates the provider report hash, shows deterministic duplicate-proof replay, records provider reputation delta, and includes the result in the governance proof. It is not a claim of full escrow, refund-contract custody, or a marketplace.

Technical jury note: the canonical reviewer proof is frozen for reproducibility. Dynamic proposals are preview/execution-ready unless fully evidenced and signed; the Odra topology genesis proves auxiliary modules independently; and full cross-contract production enforcement is roadmap, not overclaimed. See `docs/TECHNICAL_JURY_NOTE.md`.

## Verification

Run the focused local check:

```bash
python3 -m py_compile shared/approval.py shared/casper_executor.py agents/alden/__init__.py agents/locke/__init__.py gateway/routes/submission.py gateway/routes/authorization.py tests/test_concordia_core.py
pytest -q tests/ -q
```

The current full local verification collects and passes 100 tests, including the core authorization, invariant, SafePay Lite, redaction, dashboard, certificate-PDF, and proof-consistency checks.
