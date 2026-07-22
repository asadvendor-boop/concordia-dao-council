# Concordia Finals Execution State

This is the durable cross-compaction ledger. Update it at every gate and before
every handoff or live mutation. Claims require the evidence listed here.

## Immutable coordination rules

- Freeze tag: `concordia-g1-freeze-v2.0-a`.
- Codex branch: `codex/finals-core-v3`.
- Claude branch: `claude/finals-product-security`, created only from the peeled
  freeze tag after manifest validation.
- Integration branch: `codex/finals-integration`, created from the same tag.
- Codex owns WP1/WP4/WP6/WP8/WP10 and is the only live/release operator.
- Claude owns WP2/WP3/WP5/WP7/WP9/WP11 and never edits Codex-owned shared paths.
- Historical v1/v2 and the canonical 12-card chain are read-only.
- No secret values in output, files, commits, artifacts, or chat.
- Never invoke the current public demo reset or activation during read-only QA.
- Keep sslip submission links live; protect the other judged apps on the VM.

## Gate ledger

| Gate | Status | Evidence / next action |
|---|---|---|
| Baseline Git | PASS | main/origin `b79b42c`, tree `c82655a…`, clean at kickoff |
| Baseline pytest | PASS | 113 passed, 1 warning |
| Baseline npm ci | PASS_WITH_OBSERVATION | install passed; npm reported 3 low + 3 high vulnerabilities |
| Baseline Next production build | PASS | Next 16.2.9 fresh build, 14 routes generated |
| Baseline Playwright | PASS | 19 passed |
| Facilitator auth semantics | PASS | raw Authorization; authenticated redacted `/supported` returned 200 |
| WCSPR live readback | PASS | package `3d80…47c1e`, active v8 `032706…35f4a`, value:U256, metadata pinned |
| Official settlement compatibility | BLOCKED_FAIL_CLOSED | public JS/Go use runtime `amount`; live v8 requires `value`; only a real finalized canary can lift |
| G1 interface freeze | PASS | annotated tag `concordia-g1-freeze-v2.0-a` peels to `b24c040`; manifest status is `ready` |
| G0-R fallback verification | PASS | `handoff/G0R_FALLBACK_EVIDENCE.json`: bundle/history, clean tree, archive, SQLite, 77/77 images, completed ECS snapshot, 16/16 routes, 32/32 anchors, four screenshots; restore runbook written |
| WP1 v3 | PASS_LOCAL | exact-envelope contract/tooling committed through `588507d`; cross-language temporal correction G1-C6 is locally green; 554 Python + 29 Rust tests, fmt/clippy, reproducible Wasm/schema, mixed-custody checkpoints, and historical hash inventory all green; live deployment remains WP10 |
| WP4 registry | PASS_LOCAL_PENDING_PRODUCERS | fail-closed registry/API and legacy SafePay truth rewire committed; live v3/SafePay/x402 registry artifacts wait on the corresponding verified executions |
| WP6 executor | PASS_LOCAL | `ac03cec` + ordering hardening `fd66e67`; independent audit GO, 285 focused tests |
| WP8 verifier | IN_PROGRESS | package implementation and cross-language semantic audit in progress; its independent adapter found and now enforces post-freeze corrections G1-C6/C7 |
| WP10 live/release | PENDING | no mutations before local/integration gates |
| Claude integration | BLOCKED_ON_CORRECTIONS | WP2 `9a4d66f` and WP3 `d096403` independently reviewed NO-GO; exact blockers in `handoff/CODEX_REVIEW_CLAUDE_WP2_WP3.md`; no cherry-pick performed |
| Final release | PENDING | no claim until hosted/live gates pass |

## Upstream x402 blocker details

- Facilitator: `https://x402-facilitator.cspr.cloud`.
- Never add `Bearer` to its token.
- Never print an error body: 401 responses can reflect the submitted credential.
- `/supported` and `/verify` are not settlement proof.
- Wire requirements use `amount`; signed authorization and live runtime use
  `value`; automatic fallback between runtime names is forbidden.
- CAIP/EIP-712 domain is `casper:casper-test`, not `casper-test`.

## Latest checkpoint

At the current Codex checkpoint, WP1 and WP6 are committed and independently
cleared for integration. WP1's typed exact-envelope sibling contract rejects
pre-quorum finalization, post-quorum mutation, repeat authorization, invalid
roles, and zero financial endpoints; its host tooling binds raw Casper state
and install transcripts, supports mixed browser/server custody, and reproduces
the pinned Wasm byte-for-byte. The full Python gate passed 550 tests, the Rust
contract gate passed 29 tests, and the historical v1/v2 inventory remained
byte-identical.

WP6's durable journal persists signed bytes before broadcast,
reconciles uncertain submission by deploy hash, reparses two independent RPC
finality observations, binds exact historical balance evidence, and proves one
matching transfer over a contiguous time-bounded scan. The public artifact
serializer reparses every emitted raw transcript and equality-binds it to the
sealed parser-issued proofs. The focused WP6 gate passed 285 tests; the final
capture-time ordering hardening passed 15 artifact tests and Ruff.

Claude's WP2/WP3 focused suite passed, but independent source review found
release-blocking invariants not covered by those tests. Those commits remain
isolated and unmerged. WP8 continues concurrently; Claude WP5 is undergoing an
independent read-only release audit before any cherry-pick.

The WP8 cross-language adapter found two omissions after the immutable G1 tag:
the Python v3 verifier did not compare readback height with exact-finalization
height, and public registry items lacked the v3 deployment domain needed for
exact/treasury parity. Both are now mandatory deltas in
`handoff/G1_POST_FREEZE_CORRECTIONS.json`; 554 Python tests pass with the new
adversarial cases. The original tag remains the common branch root and is not
silently rewritten.

No VM, Caddy, DNS, Compose, Testnet, npm, live artifact, or `main` mutation has
occurred since G1.

### Earlier G0-R checkpoint

At 2026-07-22T19:58:59Z Codex had independently completed G0-R without a live
mutation: the bundle and archive are readable, SQLite integrity is `ok`, all 77
recorded image IDs remain available, the ECS snapshot is complete, 16/16
submission routes and 32/32 discovered anchors return 200, and four visual
baselines were captured and inspected. The authoritative project environment
passes 129 Python tests with one deprecation warning; the G1-specific suite
passes 16 tests and all 21 vectors regenerate deterministically.
`READY_FOR_ANNOTATED_TAG` means the
committed freeze is the candidate the tag will publish; it is not itself a
claim that the tag exists. Actual G1 publication is proven only when the tag is
an annotated Git tag that peels to this commit and tagged-tree tests pass. No
VM, Caddy, DNS, Compose, Testnet, npm, live artifact, or `main` mutation has
occurred.
