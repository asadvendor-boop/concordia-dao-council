# Concordia DAO Council V1.5

Concordia is an evidence-first governance council for AI-assisted DAOs on
Casper Testnet. Named agents deliberate, challenge, and explain. Deterministic
code evaluates policy, seals the transcript, binds approval to exact hashes,
and prepares the receipt path. A human remains the final authority for
execution.

## What V1.5 proves

The canonical proposal `DAO-PROP-6CB25C` records:

- a complete V1 council and policy transcript;
- a canonical Testnet reviewer receipt
  `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`;
- an on-chain rejection before quorum and acceptance after 2-of-3 approval;
- downloadable JSON, CSV, HTML, PDF, certificate, and IPFS evidence; and
- SafePay Lite as recorded native-CSPR evidence under the Concordia apex.

Start with the [90-second judge path](judge-walkthrough.md), then inspect the
[receipt and quorum lineage](governance-receipts.md) and
[verification limits](proof-verification.md).

## Scope is intentionally narrow

!!! warning "V1.5 boundary"
    Casper-native x402 v2 is implemented as an HTTP 402 payment request,
    payment intent, and native-transfer verification on Testnet. A later
    official facilitator service and successful external-provider settlement
    are not shipped or claimed in V1.5. SafePay Lite remains recorded Testnet
    native-CSPR evidence.

The npm verifier retains historical V2/V3 parser and refusal compatibility.
That compatibility does not promote those paths into the V1.5 product.

## Core invariants

1. Advisory output cannot directly mutate governance state.
2. Policy and allocation arithmetic are deterministic.
3. Human approval binds the exact proposal, plan revision, and action hash.
4. Nonces are single-use.
5. Missing, contradictory, unknown, or unavailable evidence never becomes
   success.
6. Every public claim should resolve to source, a transcript, or a recorded
   Testnet artifact.

## Public surfaces

- [App](https://concordiadao.xyz)
- [Judge Walkthrough](https://concordiadao.xyz/dashboard/judge)
- [Proof Center](https://concordiadao.xyz/dashboard/proof?proposal=DAO-PROP-6CB25C)
- [Source](https://github.com/asadvendor-boop/concordia-dao-council)
- [Verifier 0.1.4](https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.4)

Publication and hosted-state claims remain subject to the release gates in
[V1.5 Release Scope](release-scope.md).
