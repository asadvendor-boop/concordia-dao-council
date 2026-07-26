# Concordia DAO Council — Finals Stable Copy

## One-line description

Concordia is an evidence-first governance council that lets AI agents advise
while deterministic policy, human approval, and Casper Testnet receipts keep
execution accountable.

## What it does

A proposal moves through named council roles for triage, treasury analysis,
constitutional challenge, bounded planning, execution preparation, and
archiving. Model output remains advisory. Deterministic code owns allocation
caps, card-chain integrity, plan/action hashes, approval nonces, and proof
classification.

The canonical V1 flow preserves the original 30% request and Verity's dissent,
reduces the approved allocation to the 800-bps policy cap, binds human approval
to the exact action, and exposes a receipt, transcript, proof pack, certificate,
downloads, and replay.

## Recorded proof

| Evidence | Identity |
| --- | --- |
| Proposal | `DAO-PROP-6CB25C` |
| Canonical receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| V1 contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Pre-quorum rejection | `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431` — `QuorumNotMet` |
| Quorum acceptance | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| SafePay Lite recorded native-CSPR payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

## Why it matters

AI governance fails when model output is mistaken for authorization. Concordia
turns recommendations into reviewable cards, makes dissent durable, requires a
human at the execution boundary, and gives reviewers independent Testnet
identities instead of a success screenshot.

## Judge flow

1. Open <https://concordiadao.xyz/dashboard/judge>.
2. Select `DAO-PROP-6CB25C`.
3. Inspect <https://concordiadao.xyz/dashboard/proof?proposal=DAO-PROP-6CB25C>.
4. Compare the canonical receipt on
   <https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852>.
5. Compare the pre-quorum rejection and post-quorum acceptance.
6. Open the SafePay Lite record and verify the recorded native-CSPR deploy.
7. Download the governance archive and certificate.

## Truth boundary

Official x402 is not shipped. Mainnet has not been executed. Governance v3 is
excluded from V1.5. SafePay Lite is recorded native-CSPR V1 evidence under the
apex, not a live official-x402 service, escrow, refund contract, or marketplace.

Historical V2/V3 parsers retained by `@concordia-dao/verify` exist for
compatibility and fail-closed refusal behavior only. They are not product
surfaces in this release.

## Links

- App: <https://concordiadao.xyz>
- Docs: <https://docs.concordiadao.xyz>
- Source: <https://github.com/asadvendor-boop/concordia-dao-council>
- npm 0.1.2 target:
  <https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.2>
- X: <https://x.com/ConcordiaDAO>
