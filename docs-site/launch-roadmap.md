# Launch Roadmap

Concordia is a working, reproducible Casper governance proof system today, with a
clear line between what is live and what is planned. This page is the planned
trajectory; nothing here is presented as already shipped.

## Shipping inside the final round

Each of these is `PENDING_PROOF` until its publication gate passes (see
[Links](links.md) and [Deployment & Security](deployment-security.md)):

- **Production domain** — `concordiadao.xyz` (+ `www`, `x402` subdomain), with
  the existing `*.sslip.io` links kept as working aliases.
- **Hosted documentation portal** — `docs.concordiadao.xyz`.
- **Published verifier** — `@concordia-dao/verify` on npm, clean-room installable
  (see [Verifier SDK / CLI](verifier-cli.md)).
- **GovernanceReceipt v3** — on-chain exact-envelope enforcement, with its
  four-outcome live proof (see [v3 Envelope Specification](v3-envelope.md)).
- **Native treasury execution** and the **two corrected payment rails** —
  [Treasury Execution](treasury-execution.md), [SafePay Lite](safepay-lite.md),
  and [Official x402](official-x402.md).

## Beyond the final round

- A DAO adoption pack and policy templates for DeFi treasuries and tokenized-RWA
  proposals (see [Policy Matrix](policy-matrix.md)).
- Productizing the quorum-enforced, exact-envelope execution path toward Casper
  mainnet, with the mainnet build first replacing the build-time dependencies
  dismissed in the security register.

## What is already live

The canonical reviewer receipt, the two-way quorum proof (reverted before
quorum, accepted after), the historical SafePay Lite payment, and the IPFS
evidence archive are live on Casper Testnet today and are cited with their frozen
values throughout this site. See [On-Chain Governance Receipts](governance-receipts.md)
and [Proof & Verification](proof-verification.md).
