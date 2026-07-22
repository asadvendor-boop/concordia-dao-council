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
| WP1 v3 | PASS_LOCAL | exact-envelope contract/tooling plus canonical-block corrections committed through `b6b2c98`; G1-C6/C8 enforce raw temporal and fork identity; 172 affected Python tests and the prior full/Rust/Wasm gates are green; live deployment remains WP10 |
| WP4 registry/artifacts | PASS_LOCAL_PENDING_CAPTURE | fail-closed registry/API, provenance/chronology binding, exact card-chain export bound to a trusted external terminal root, and frozen raw historical-receipt contract are committed; no canonical card/root or combined receipt artifact is fabricated locally, and live capture/registry publication remain WP10 |
| WP6 executor | PASS_LOCAL | `ac03cec` + ordering hardening `fd66e67`; independent audit GO, 285 focused tests |
| WP8 verifier | IN_PROGRESS_BLOCKED_ON_PRODUCERS | package implementation and cross-language audit found G1-C6 through C13, missing independent adapters, unusable/unsafe live scope, provenance relabelling and attacker-controlled chronology; card/historical/live-observer work is active, while SafePay/x402 completion waits on corrected producer schemas |
| WP10 live/release | PENDING | no mutations before local/integration gates |
| Claude integration | BLOCKED_ON_CORRECTIONS | WP2 `9a4d66f` and WP3 `d096403` independently reviewed NO-GO; exact blockers in `handoff/CODEX_REVIEW_CLAUDE_WP2_WP3.md`; no cherry-pick performed |
| Claude WP5 | BLOCKED_ON_CORRECTIONS | `f5cf748` independently reviewed NO-GO: fail-open optional/partial settlement args plus five durability/config/readiness blockers; exact corrections in `handoff/CODEX_REVIEW_CLAUDE_WP5.md` |
| Claude WP7 | BLOCKED_ON_CORRECTIONS | `dfa3cd2` visual direction approved, implementation NO-GO: stale cross-proposal state, wrong demo protocol/reset, fail-open evidence/approval states, false SafePay fallback, hardcoded proof, role and accessibility defects; exact corrections in `handoff/CODEX_REVIEW_CLAUDE_WP7.md` |
| Claude WP9/WP11 | BLOCKED_ON_CORRECTIONS | `abd46d1` docs foundation builds strictly, but current copy overstates unmerged/live behavior and the cited Python verifier; `f199062` is an incomplete WP11 copy pass with incorrect role/archive wording. Exact corrections in `handoff/CODEX_REVIEW_CLAUDE_WP9_WP11.md` |
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

The WP8 cross-language adapter found additional omissions after the immutable
G1 tag. Python now rejects contract steps at/before installation, competing
block hashes at an equal step/readback height, and treasury scans whose starting
block hash differs from the exact-v3 finalization block. Those fixes are
committed at `b6b2c98`; 172 affected tests pass. G1-C10 also freezes a new exact
sealed-card publication because the existing humanized evidence view is not a
cryptographic hash preimage. The original tag remains the common branch root
and is not silently rewritten.

Subsequent independent review added G1-C11 through C13. The public registry now
binds each proof type to its allowed generation/lineage/observation/temporal/
outcome semantics and rejects impossible observation chronology. Exact card
preimages are exported only when a strict immutable release-root mapping binds
the terminal hash; no Host header or self-asserted card root is accepted. The
historical v1/v2 receipt verifier contract consumes raw Casper RPC transcripts
and a packaged chain-identity inventory, while explicitly reporting that the
preserved repo source is not proven byte-equivalent to either deployed Wasm.
No fake root or combined historical artifact has been created; those remain
live capture outputs.

Claude WP5 also remains isolated. Its existing 128 tests pass, but independent
review proved that omitted/partial WCSPR argument values can pass post-settle
readback, pending finality is made terminal, lost responses cannot be recovered
without a transaction hash, frozen credential-bearing origins are overridable,
and terminal retries rerun expiring/live gates. The complete rework gate is in
`handoff/CODEX_REVIEW_CLAUDE_WP5.md`.

Claude WP7 also remains isolated. A real browser audit confirmed that its
control-room redesign, quorum centerpiece, responsive Judge route, and exact
authorization composition are visually strong. Source/runtime verification
nevertheless found stale cross-proposal data races, the obsolete public demo
protocol/reset, green fallbacks from card presence, rejected approvals rendered
as authorized, false SafePay narration in recording mode, hardcoded accessible
proof summaries, incorrect Wells/agent taxonomy, and incomplete tab/ledger
accessibility. The correction gate is recorded in
`handoff/CODEX_REVIEW_CLAUDE_WP7.md`.

Claude WP9/WP11 also remain isolated. The curated MkDocs tree, locked
dependencies, strict build, and Pages workflow are a sound foundation, but the
site currently describes unmerged SafePay/x402/security behavior as
implemented, assigns Wells deterministic archive work it does not perform,
calls Locke a fifth advisory/reasoning agent, and overstates the legacy Python
verifier. WP11 has not yet produced the required BUIDL copy or video materials.
The correction and publication gate is recorded in
`handoff/CODEX_REVIEW_CLAUDE_WP9_WP11.md`.

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
