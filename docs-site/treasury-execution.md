# Treasury Execution

Treasury execution is the first of Concordia's three separate financial claims,
each with its own mechanism, asset, and proof (see also
[SafePay Lite](safepay-lite.md) and [Official x402](official-x402.md)). They are
never conflated.

!!! warning "Finals work in progress — no live native-transfer evidence yet"
    The native-CSPR treasury transfer described here depends on the v3
    exact-envelope contract (see [v3 Envelope Specification](v3-envelope.md)),
    which is not yet live. No finalized native-transfer deploy exists to cite.
    `PENDING_PROOF`: treasury execution — finalized native-transfer deploy
    (625 CSPR snapshot → 50 CSPR transfer, bound transfer ID) + execution
    artifact.

## What the claim is

A real treasury transfer: **authorized by on-chain quorum, bound to the approved
envelope hash, executed as a native CSPR transfer.** In the finals scenario, a
treasury snapshot of 625 CSPR produces a 50 CSPR native transfer whose Casper
transfer ID is bound to the authorized envelope.

## Authorization vs execution

One-time v3 finalization is **authorization**, not execution. The contract
authorizes exactly one envelope, once. The executor then performs the native
transfer and records it in a **durable execution journal**, which is the replay
lock: a second transfer for the same authorization is refused because the
journal already shows it consumed.

## Documented boundary

Stated plainly, and not overclaimed:

> Concordia prevents duplicate execution through its trusted executor. It cannot
> prevent an independently compromised treasury key from bypassing that executor.

## What will be verifiable

When the live capture completes, the release manifest will carry the finalized
native-transfer deploy hash, the exact source/recipient/amount/transfer-ID
fields, the snapshot balance and block height, and finality/gas — each checkable
on CSPR.live and reconciled against the v3 authorization. Until then this claim
is `PENDING_PROOF` and never renders as verified.
