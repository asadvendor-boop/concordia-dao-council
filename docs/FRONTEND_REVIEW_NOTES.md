# Concordia Frontend Review Notes

## Scope

This pass reworks Concordia's dashboard into a judge-first proof cockpit. It does not change the canonical Casper proof, backend proof state, contract hashes, or supplemental proof hierarchy.

Canonical reviewer proof remains:

- Proposal: `DAO-PROP-6CB25C`
- Canonical receipt: `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`
- Canonical contract: `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`
- Browser wallet receipt: `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf`
- Final quorum receipt: `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`
- x402 payment: `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`
- IPFS CID: `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`

## What Changed

- Added a shared `ProofActionRegistry`, `ProofActionBar`, `HashChip`, and `CodePreview` so proof links and long hashes are rendered consistently.
- Proof Center now defaults to the canonical reviewer proof and separates `Summary`, `Safety`, `On-chain`, `Data`, and `Exports`.
- Suppressed/non-canonical proposals show an evidence-only banner instead of scary missing canonical receipt states.
- Verified receipts are shown separately from advanced wallet/quorum re-run actions.
- Judge Walkthrough now has a clean recording path at `/dashboard/judge?recording=1` and `/dashboard/record`.
- Added a preview-only Judge Sandbox for safe testnet intent inspection without mutating `DAO-PROP-6CB25C`.
- Technical Jury Note now renders inside the dashboard shell at `/dashboard/technical-jury-note`.
- Certificate HTML now uses responsive QR cards with short labels instead of long raw URLs.
- Global CSS now wraps brand text, hash chips, proof buttons, and code previews to reduce horizontal overflow risk.
- App shell now supports the requested 280px desktop sidebar, 88px collapsed desktop sidebar, and mobile drawer behavior.
- Overview now leads with the judge-first CTA hierarchy: Judge Walkthrough, Proof Center, and the canonical CSPR.live receipt.
- The first KPI now reports the selected canonical proof run instead of showing an alarming `0` active-proposal state during replay.
- The front page now introduces Rowan, Mercer, Verity, Alden, Locke, and Wells with larger persona portraits and bounded-authority personality cues.
- Headless Playwright browser checks generate a screenshot set in `artifacts/frontend-review/screenshots/` and a review contact sheet at `artifacts/frontend-review/contact-sheet.png`.

## Known Boundaries

- The canonical proof is intentionally frozen for reproducibility.
- Supplemental dynamic and quorum receipts are labeled as supplemental, not replacements for the canonical receipt.
- Judge Sandbox defaults to preview-only. Any wallet signing remains an advanced testnet action and is not required for review.
- Playwright is included as a dashboard dev dependency. The e2e suite verifies no horizontal overflow, button health, canonical Proof Center defaults, recording mode chrome suppression, Technical Jury Note styling, responsive certificate layout, visible keyboard focus, accessible control names, and core text contrast.

## Verification Commands

```bash
npm --prefix dashboard run build
pytest -q tests/test_dashboard_contract.py -q
npm --prefix dashboard run test:e2e
```
