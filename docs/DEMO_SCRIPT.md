# Concordia Demo Script

Target length: 3 minutes or less.

## One-line submission pitch

Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

## Demo hook

A malicious AI tries to push an unsafe 30% treasury allocation. Concordia catches the violation, Verity challenges it with Dissent Receipts, the DAO Mandate caps it to 8%, Locke can execute only the exact approved hash, and browser-wallet quorum proves the same action is reverted before quorum and accepted after quorum.

## Recording Sequence

1. Concordia is the policy-governed council layer for Casper DAO execution.
2. A risky/malicious treasury proposal requests 30%.
3. DAO Constitution allows only 8%.
4. Invariant runner catches the violation.
5. Verity challenges and preserves dissent.
6. Alden produces the approved DAO Mandate.
7. Quorum approves only the safe envelope.
8. Locke refuses unsafe payloads and executes only the mandate.
9. CSPR.live verifies the typed Casper receipt.
10. QR certificate links to Casper, IPFS, proof pack, and audit trail.

## Suggested voiceover

Start on `https://concordiadao.xyz/dashboard/judge`.

Say: "Concordia is not another AI chatbot. It is the Casper governance firewall for AI-run DAOs. Dissent Receipts preserve objections, Locke can only execute the exact approved hash, and the browser-wallet quorum proof shows the contract rejecting execution before quorum and accepting it after quorum."

Show the risky proposal and policy leash meter.

Say: "The malicious or unsafe suggestion asks for 30% treasury allocation. The DAO Constitution allows only 8%. The invariant runner catches that mismatch before execution."

Show Verity, the Dissent Receipt, and Alden's DAO Mandate.

Say: "Verity preserves dissent, Alden converts the safe 8% action into a DAO Mandate, and the mandate binds the exact approved hash, action, network, entry point, and expiry."

Show SafePay Lite.

Say: "When specialist evidence is needed, SafePay Lite verifies Casper payment and report hash before the report becomes proof. If payment, report hash, deterministic duplicate-proof replay, or provider response validation fails, Concordia does not mark it verified."

Show the quorum receipts and CSPR.live.

Say: "The canonical reviewer receipt is `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` on the Jun 29 v1 receipt anchor. For the demo climax, open the supplemental quorum final receipt `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`: that store call runs on the Jun 30 quorum-enabled GovernanceReceipt package and only succeeds after the 2-of-3 gate passes."

Close on the certificate.

Say: "The certificate links to CSPR.live, the IPFS archive, the proof pack, evidence chain, verifier instructions, SafePay Lite proof, and quorum proof."

## Canonical proof hierarchy

| Proof item | Canonical value |
|---|---|
| Proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Quorum proof | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Supplemental dynamic lifecycle proof | `DAO-PROP-DYN-002` -> `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| SafePay Lite recorded native-CSPR payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

Contract lineage note: v1 GovernanceReceipt is the Jun 29 receipt anchor (`hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`, package `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`); v2 is the Jun 30 quorum-enabled package (`hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`). Use the CSPR.live `/contract/` page for the v1 contract hash.

## Links to open during recording

- Judge Walkthrough: <https://concordiadao.xyz/dashboard/judge>
- Proof Center: <https://concordiadao.xyz/dashboard/proof>
- Evidence chain: <https://concordiadao.xyz/evidence/DAO-PROP-6CB25C>
- Proof pack: <https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C>
- HTML certificate: <https://concordiadao.xyz/certificate/DAO-PROP-6CB25C>
- PDF certificate: <https://concordiadao.xyz/certificate/DAO-PROP-6CB25C/pdf>
- Canonical CSPR.live receipt: <https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852>
