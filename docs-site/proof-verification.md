# Proof Verification

Concordia separates recorded facts, recomputed facts, and unsupported claims.

## Canonical identities

| Item | Identity |
| --- | --- |
| Proposal | `DAO-PROP-6CB25C` |
| Canonical receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| V1 contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Pre-quorum rejection | `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431` |
| Quorum acceptance | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| SafePay Lite recorded native-CSPR payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

## Manual verification

1. Load the
   [evidence chain](https://concordiadao.xyz/evidence/DAO-PROP-6CB25C).
2. Load the [proof pack](https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C)
   and confirm every cited item belongs to the same proposal.
3. Compare the
   [canonical receipt](https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852)
   and [V1 contract](https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1)
   with CSPR.live.
4. Confirm the
   [pre-quorum deploy](https://testnet.cspr.live/deploy/6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431)
   failed and the
   [post-quorum deploy](https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928)
   succeeded.
5. Compare the SafePay Lite record with its
   [native-CSPR deploy](https://testnet.cspr.live/deploy/dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c).

## Verifier outcomes

| Status | Meaning |
| --- | --- |
| `verified` | Every required supported check passed |
| `invalid` | Evidence exists but is malformed, contradictory, or tampered |
| `unavailable` | Required bytes or a read-only observation cannot be obtained |
| `unknown` | No supported terminal observation establishes the claim |

Only `verified` is success. Boolean fields inside an artifact are assertions;
they do not replace recomputation.

## Limits

Offline artifact verification can establish byte identity, signature validity,
and transcript consistency. It does not by itself prove canonical-chain
membership. Live RPC corroboration can increase observation strength but does
not prove independent administration merely because hostnames differ.

Official x402 is not shipped. Mainnet has not been executed. Governance v3 is
excluded from V1.5. Historical compatibility adapters remain fail-closed.

See [Verifier SDK / CLI](verifier-cli.md) for the package boundary.
