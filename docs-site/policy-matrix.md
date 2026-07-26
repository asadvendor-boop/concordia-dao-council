# Policy Matrix

The matrix describes V1 behavior.

| Condition | Deterministic result | Human action |
| --- | --- | --- |
| Allocation within policy and no execution action | Continue council review | Optional |
| Requested allocation above 800 bps | Reduce or refuse; preserve dissent | Review revised plan |
| High or critical risk | Approval required | Approve or reject exact hashes |
| Casper receipt or transfer action | Approval required | Approve exact plan/action |
| Approval nonce expired, replayed, or mismatched | Refuse before execution | Issue a new bound approval if appropriate |
| Required evidence missing or unavailable | Do not claim success | Investigate evidence |
| Pre-quorum store attempt | Contract rejects with `QuorumNotMet` | Reach configured quorum |
| 2-of-3 quorum reached | Recorded store may proceed | Verify signers and receipt |

## Evidence rule

`passed`, `verified`, and similar fields inside an artifact are untrusted
summaries. The proof layer must recompute supported identities or return a
non-success outcome.

## Release boundary

Official x402 is not shipped. Mainnet has not been executed. Governance v3 is
excluded from V1.5. SafePay Lite is recorded native-CSPR evidence, not an
additional live policy or settlement system.
