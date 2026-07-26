# SafePay Lite Record

SafePay Lite is recorded V1 native-CSPR evidence associated with the canonical
proposal. The archive preserves a historical native-CSPR payment/report
relation under the Concordia apex; it is not promoted as a continuously
available payment service.

## Recorded identity

| Field | Value |
| --- | --- |
| Proposal | `DAO-PROP-6CB25C` |
| Network | Casper Testnet |
| Payment deploy | [`dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`](https://testnet.cspr.live/deploy/dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c) |
| Public record | [SafePay Lite evidence](https://concordiadao.xyz/safepay-lite/DAO-PROP-6CB25C) |

The record can bind a proposal, payment identity, and report evidence. Reviewers
should verify the deploy independently and treat unavailable fields as
unavailable, not as success.

## Explicit boundary

!!! warning "Not official x402"
    Official x402 is not shipped. SafePay Lite is not an official facilitator,
    escrow contract, refund contract, marketplace, WCSPR settlement claim, or
    promise of a live external provider.

The npm verifier retains `safepay_v2` and
`official_x402_settlement_v1` compatibility parsers. Without independently
verifiable semantic evidence those adapters report unsupported capability and
fail closed. Parser presence does not upgrade this recorded V1 payment.

Mainnet has not been executed. Governance v3 is excluded from V1.5.
