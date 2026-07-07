# Concordia Launch Roadmap

Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

This roadmap separates the live Buildathon proof from the production hardening path.

Community & socials: Live community presence: X @ConcordiaDAO (https://x.com/ConcordiaDAO), launch post https://x.com/ConcordiaDAO/status/2074438324769689653; community channel expansion (Telegram/Discord) on the roadmap.

## Live Buildathon Proof

- Canonical reviewer proof: `DAO-PROP-6CB25C`
- Canonical Casper receipt: `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`
- Canonical contract: `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`
- Supplemental quorum proof: `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`
- Browser-wallet receipt: `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf`
- SafePay Lite x402 payment: `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`
- IPFS archive CID: `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`

Contract lineage: the canonical receipt is on the Jun 29 v1 GovernanceReceipt receipt anchor, while the supplemental quorum receipt is on the Jun 30 v2 quorum-enabled GovernanceReceipt package. The final quorum receipt `9d631...` is the demo climax because it succeeds only after 2-of-3 approval; it does not replace the canonical reviewer receipt `e926...`.

DAO-PROP-6CB25C is the canonical executed reviewer proof. Non-canonical proposals use the dynamic preview path unless they are separately signed and anchored on Casper.

## Target Users

- Casper DAOs that need policy-governed execution rather than advisory-only AI summaries.
- Treasury committees that need dissent, evidence, and exact-envelope approval before on-chain action.
- RWA protocols that need reviewer-readable evidence packets before governance decisions.
- Compliance teams that need a public proof pack, trace API, certificate, and verifier script.

## Deployment Model

Concordia is packaged as a governance middleware layer:

1. A FastAPI gateway owns deterministic policy, proof-pack generation, SafePay Lite verification, and Casper receipt packaging.
2. The dashboard exposes Judge Walkthrough, Proof Center, downloadable archive, and certificate surfaces.
3. Casper Testnet/Mainnet contracts anchor approved receipts and, over time, more governance state.
4. Optional adapters connect CSPR.cloud, CSPR.trade, CSPR.click/Casper Wallet, IPFS pinning, and x402 providers.

## 30-Day Plan

- Harden the supplemental dynamic proposal path from the processed `DAO-PROP-DYN-002` receipt into a reusable proposal intake path.
- Add more DAO policy templates for treasury allocation, RWA onboarding, and protocol-parameter changes.
- Expand invariant coverage with named proof artifacts for replay, nonce, hash mismatch, and duplicate-payment rejection.
- Add hosted demo video, launch post, and public issue/milestone tracking.

## 60-Day Plan

- Promote the supplemental auxiliary Odra module calls into live cross-contract dependencies after audit: CouncilRegistry authority checks, TreasuryPolicy cap enforcement, and CardIndexLedger canonical card-root state.
- Add governance-admin UX for configuring DAO Constitution caps and quorum thresholds.
- Add more RWA evidence examples with document hashes, issuer scores, maturity bands, and paid specialist reports.
- Pilot SafePay Lite with a second provider service while keeping the claim limited to conditional paid specialist-report settlement.

## 90-Day Plan

- Generalize the `DAO-PROP-DYN-002` signed execution pattern for non-canonical proposals after evidence sealing and quorum approval.
- Add DAO-specific reputation deltas for agents and paid providers.
- Add organization-level deployment templates and a CSPR.click/Casper Wallet custody guide.
- Add production monitoring around Casper submit/finality/x402/IPFS with Jaeger or Tempo traces.

## Six-Month Plan

- Package Concordia as an enterprise governance SDK for Casper DAOs and RWA protocols.
- Add independent Odra module deployments for registry, policy, card ledger, and receipt anchoring.
- Add enterprise IAM, durable queues, and event-stream finality as production infrastructure.
- Explore Casper grant/pilot partnerships with DAOs that need AI-assisted but policy-bound governance execution.

## Monetization Direction

SafePay Lite is the first monetization primitive. Concordia can charge:

- per verified governance archive,
- per SafePay specialist-report settlement,
- per DAO policy pack,
- per hosted compliance dashboard,
- or per enterprise deployment.

SafePay Lite is not a full escrow, refund contract, or marketplace in the current proof. It demonstrates conditional paid specialist-report settlement: Concordia verifies Casper payment, validates the provider report hash, shows deterministic duplicate-proof replay, records provider reputation delta, and includes the result in the governance proof.

## Security Hardening

- Keep deterministic authorization stronger than advisory LLM output.
- Preserve redaction gates for trace APIs, CSV exports, certificates, and proof packs.
- Add deeper tests for every replay/hash/quorum invariant.
- Move more policy state on-chain only after each contract path is independently tested.

## UI Roadmap

- Split the dashboard into a dedicated Judge Mode for the 90-second proof story and a Technical Mode for raw proof tables, trace data, JSON payloads, and verifier outputs.
- Add a progressive-disclosure front door where the first screen shows the blocked action, quorum enforcement, and receipt proof, with a clear "View technical proof" reveal for deeper inspection.
- Replace the remaining dashboard density with a guided proof story that keeps the sequence readable: unsafe proposal, dissent, mandate cap, pre-quorum rejection, quorum approval, final receipt, and certificate.
- Treat the current Proof Center as the expert drill-down surface while the Judge Walkthrough becomes the primary public entry point after the Buildathon.
- Add persona detail drawers on the Overview council cards: each drawer opens the persona's bounded authority, dissent/receipt history, and proof links. Keep the LLM layer provider-agnostic, with deployed models documented in docs/LLM_PROVIDER.md — drawers surface authority and receipts, not model branding.
