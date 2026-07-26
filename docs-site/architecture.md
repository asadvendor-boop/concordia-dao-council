# Architecture and Trust Boundaries

Concordia separates advisory reasoning from authoritative state changes.

```text
Proposal input
  -> Rowan triage
  -> Mercer treasury analysis
  -> Verity policy challenge
  -> Alden bounded plan
  -> deterministic policy and integrity core
  -> human approval bound to exact hashes
  -> Locke receipt preparation
  -> Wells evidence summary
  -> Casper Testnet record and public proof surfaces
```

## Advisory plane

The named council agents produce typed cards and explanations. Their model
output is untrusted input. It cannot approve itself, consume an approval nonce,
sign a deploy, or declare evidence valid.

## Deterministic control plane

Python code owns:

- basis-point parsing and policy caps;
- card hashing and previous-card linkage;
- proposal, plan, and action identity;
- approval nonce issue, validation, expiry, revision binding, and consumption;
- redaction and proof-pack assembly; and
- fail-closed outcome classification.

## Human boundary

Casper execution actions require a human approval path. Approval is valid only
for the exact proposal, plan revision, and action hash. A replayed, expired, or
mismatched nonce is rejected before execution.

## Evidence plane

The V1 release exposes read-only evidence, proof-pack, certificate, replay, and
download routes. CSPR.live links provide an independent view of recorded
Testnet deploys. IPFS provides a content-addressed archive reference.

The proof layers must not be conflated:

| Layer | Establishes | Does not establish |
| --- | --- | --- |
| Card chain | exact transcript bytes and linkage | canonical-chain inclusion |
| Signed deploy | deploy bytes and approval validity | successful execution |
| RPC transcript | observed block/state response | independent node administration |
| CSPR.live record | explorer view of Testnet deploy | Mainnet execution |
| SafePay Lite record | one historical native-CSPR payment relation | official x402 semantics |

## Excluded architectures

Governance v3 is excluded from V1.5. Official x402 is not shipped. Mainnet has
not been executed. Compatibility code retained by the verifier is not connected
to the V1 runtime and is not a public product surface.
