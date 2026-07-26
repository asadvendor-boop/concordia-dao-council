# Judge Quickstart

This path is read-only and uses the canonical V1 proposal.

## 1. Council decision

Open the [Judge Walkthrough](https://concordiadao.xyz/dashboard/judge) and select
`DAO-PROP-6CB25C`. Confirm that the council transcript preserves the original
30% request, Verity's dissent, and the deterministic reduction to the 800-bps
policy cap.

## 2. Proof Center

Open the
[Proof Center](https://concordiadao.xyz/dashboard/proof?proposal=DAO-PROP-6CB25C).
The Council, Timeline, Metrics, and Raw Cards views should refer to the same
proposal and receipt.

## 3. Independent Casper checks

Compare the displayed identities with:

- [canonical reviewer receipt](https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852);
- [pre-quorum rejection](https://testnet.cspr.live/deploy/6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431),
  recorded as `User error: 8` / `QuorumNotMet` at block 8,349,116; and
- [post-quorum acceptance](https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928)
  at block 8,350,034.

This rejection/acceptance pair is the quorum proof. It is recorded evidence,
not a request to submit a new transaction.

## 4. Evidence and downloads

- [Evidence chain](https://concordiadao.xyz/evidence/DAO-PROP-6CB25C)
- [Proof pack](https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C)
- [Governance archive](https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C/download)
- [HTML certificate](https://concordiadao.xyz/certificate/DAO-PROP-6CB25C)
- [PDF certificate](https://concordiadao.xyz/certificate/DAO-PROP-6CB25C/pdf)

## 5. SafePay Lite boundary

Open the [SafePay Lite record](https://concordiadao.xyz/safepay-lite/DAO-PROP-6CB25C)
and compare its recorded native-CSPR payment with
[CSPR.live](https://testnet.cspr.live/deploy/dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c).

Official x402 is not shipped. The record does not prove an official
facilitator, escrow, refunds, or a live payment marketplace.

## 6. Stop conditions

Stop and report the release as unverified if proposal IDs conflict, a receipt
hash differs, a download is absent, the pre-quorum failure is presented as
success, or SafePay Lite is labelled as official x402.
