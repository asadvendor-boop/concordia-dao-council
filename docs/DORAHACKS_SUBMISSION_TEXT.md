# DoraHacks Submission Text

## Project Title

Concordia DAO Council

## Short Description

Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

## Submission Pitch

Concordia turns AI governance from advisory chat into proof-bound execution. In the live proof, a risky treasury proposal tries to allocate 30% of DAO capital. The DAO Constitution allows only 8%, so Concordia's invariant runner catches the violation, Verity preserves dissent as Dissent Receipts, Alden creates the approved DAO Mandate, Locke is constrained to the exact approved hash, and the supplemental browser-wallet quorum path proves the contract is reverted before quorum and accepted after quorum.

The judge can verify the result through CSPR.live, Concordia's `/api/ipfs/{cid}` IPFS gateway, SafePay Lite x402 proof, downloadable proof pack, trace API, verifier script, and QR certificate.

## Live Links

- Live Judge Walkthrough: https://concordia.47.84.232.193.sslip.io/dashboard/judge
- Proof Center: https://concordia.47.84.232.193.sslip.io/dashboard/proof
- Evidence Chain: https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C
- Proof Pack: https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C
- Technical Jury Note: https://concordia.47.84.232.193.sslip.io/technical-jury-note
- Certificate: https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C
- Canonical CSPR.live Receipt: https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
- Supplemental Dynamic Receipt: https://testnet.cspr.live/deploy/68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0
- Supplemental Quorum Receipt: https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928

## Published Repository And Video

- Public repository URL: https://github.com/asadvendor-boop/concordia-dao-council
- Public demo video URL: https://www.youtube.com/watch?v=GU01V83Jrko

## What Is Live

- Canonical Odra `GovernanceReceipt` reviewer proof on Casper Testnet.
- Supplemental dynamic lifecycle proof for `DAO-PROP-DYN-002`.
- Supplemental quorum proof with browser-wallet participation.
- SafePay Lite x402 specialist-report settlement proof.
- IPFS/Kubo evidence archive.
- Machine-verifiable invariant runner.
- DAO Mandate artifact and QR certificate.
- Public trace API and downloadable audit packet.

## Honest Scope

Concordia is a canonical, reproducible Casper governance proof system with supplemental dynamic execution evidence. It is not claiming a fully generic enterprise DAO SaaS, full escrow marketplace, or fully productized four-contract DAO suite. The Jun 29 v1 GovernanceReceipt anchor holds the canonical reviewer receipt `e926...d852`; the Jun 30 v2 quorum-enabled package holds the supplemental quorum receipt `9d631...e2928`. `CouncilRegistry`, `TreasuryPolicy`, and `CardIndexLedger` are captured as supplemental Odra topology genesis proof with CouncilRegistry exercised through a representative `register_agent` call and the policy/index modules exercised through `validate_allocation` and `seal_card_root`.
