# V1 Receipts and Quorum

## Canonical V1 anchor

The canonical reviewer proof is proposal `DAO-PROP-6CB25C`:

- receipt:
  [`e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`](https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852);
- contract:
  [`hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`](https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1);
  and
- package:
  `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`.

The browser-wallet receipt
[`56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf`](https://testnet.cspr.live/deploy/56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf)
and supplemental dynamic receipt
[`68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0`](https://testnet.cspr.live/deploy/68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0)
belong to the same preserved V1 receipt lineage.

## Recorded quorum sequence

The later quorum-enabled **contract generation** used package
`hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`.
The generation label is contract lineage, not a Concordia V2 product claim.

| Step | Recorded result |
| --- | --- |
| Store attempted before quorum | [`6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431`](https://testnet.cspr.live/deploy/6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431) failed with `User error: 8` / `QuorumNotMet` at block 8,349,116 |
| 2-of-3 approval reached | server signer plus browser-wallet approval recorded |
| Store attempted after quorum | [`9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`](https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928) accepted at block 8,350,034 |

The failed deploy is important evidence: it shows the gate refusing the same
class of action before quorum. It must never be relabelled as a successful
execution.

## Supplemental receipts

- `DAO-PROP-DYN-002`:
  [`68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0`](https://testnet.cspr.live/deploy/68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0)
- `DAO-PROP-RWA-001`:
  [`3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc`](https://testnet.cspr.live/deploy/3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc)

These are supplemental and do not replace the canonical reviewer receipt.

## Scope boundary

All identities above are Casper Testnet records. Mainnet has not been executed.
Governance v3 is excluded from V1.5.
