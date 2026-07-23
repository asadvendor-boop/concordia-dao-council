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
| WP1 v3 | PASS_LOCAL | exact-envelope contract/tooling plus canonical-block corrections committed through `83972a8`; the strict independent audit found no contract defect, and Python now matches the frozen Rust `InvalidActionField` precedence with both action ABIs regression-checked. Fresh gates: 688 Python and 29 Rust tests; live deployment remains WP10 |
| WP4 registry/artifacts | PASS_LOCAL_PENDING_CAPTURE | fail-closed registry/API, provenance/chronology binding, bounded exact card-chain export, and offline historical receipt verification are committed. Independent C10 review passed the 64 MiB/RSS and nested credential-bypass probes. Only v1 currently has a matching canonical card chain; no root or combined artifact is fabricated locally, and live capture/registry publication remain WP10 |
| WP6 executor | PASS_LOCAL | `ac03cec` + ordering hardening `fd66e67`; independent audit GO, 285 focused tests |
| WP8 verifier | PASS_LOCAL_PENDING_PRODUCERS | `8f5ac4a` + truth correction `7aadeca`; independent audit found no P0/P1/P2. Serialized npm gate passes 142/142, lint, audit 0, 132-file pack, temp install/import/bin. Historical v1, exact-v3, native treasury and two-node live corroboration fail closed; WP2/WP3/WP5 adapters await corrected producer schemas. No npm publication yet |
| WP10 live/release | PASS_LOCAL_PENDING_FINAL_BATCH_REVIEW | no live mutation. The correction tree now has secure create-once readback output, file-only signer custody, exact install success, explicit journal resume modes, two-node treasury-snapshot lineage, exhaustive CLI mode rejection, and source-to-deployment ancestry. After additional cross-runtime URL/DNS parity fixes, fresh gates are 895 Python and 149 verifier tests plus lint/Ruff/diff checks. The corrected snapshot-specific independent review is GO with zero P0/P1/P2; the whole-batch independent review remains the commit gate |
| Release manifest | BLOCKED_ON_FINAL_COLLECTOR_REVIEW | first assembler `7507684` remains superseded and NO-GO. Its three-file replacement now derives Compose/runtime/Caddy/HTTP/TLS/Pages/npm/two-RPC observations, reloads and reruns producer-verifier receipts, binds registry metadata and lineage, scans known secret canaries, requires stable observations, and removes arbitrary ready-payload writing. The new 22-test suite is green, but DNS projection, deep route predicates, Pages deployment status, npm offline self-test, and an independent adversarial review still gate commit |
| Compose secret scope | PASS_LOCAL_PENDING_REREVIEW | isolated branch `codex/finals-compose-secrets`; CSPR.cloud is file-only in production and mounted only into Mercer, Casper signing is limited to Gateway/Locke, legacy x402 credentials are absent, and SafePay config is limited to Gateway/provider. Raw CSPR.cloud authorization is chain-bound to exact API and Node `/rpc` origins; Association/lookalike hosts receive no token; redirects and environment proxies are disabled. Fresh gate: 883 Python tests, Ruff, rendered Compose, and diff check pass; independent re-review of the final P1/P2 corrections is pending |
| Integration branch | PASS_LOCAL_PENDING_CORRECTIONS | core history through `77bedb9` is integrated. Fresh integration evidence: 831 Python tests excluding the separately run manifest suite, 25/25 manifest tests, 29 Rust v3 tests, 147 npm verifier tests, TypeScript lint, and Python Ruff all pass. These passing tests do not override the two independent NO-GO code reviews above |
| Claude integration | BLOCKED_ON_CORRECTIONS | WP2 `9a4d66f` and WP3 `d096403` independently reviewed NO-GO; exact blockers in `handoff/CODEX_REVIEW_CLAUDE_WP2_WP3.md`; no cherry-pick performed |
| Claude WP5 | BLOCKED_ON_CORRECTIONS | `f5cf748` independently reviewed NO-GO: fail-open optional/partial settlement args plus five durability/config/readiness blockers; exact corrections in `handoff/CODEX_REVIEW_CLAUDE_WP5.md` |
| Claude WP7 | BLOCKED_ON_CORRECTIONS | `dfa3cd2` visual direction approved, implementation NO-GO: stale cross-proposal state, wrong demo protocol/reset, fail-open evidence/approval states, false SafePay fallback, hardcoded proof, role and accessibility defects; exact corrections in `handoff/CODEX_REVIEW_CLAUDE_WP7.md` |
| Claude WP9/WP11 | BLOCKED_ON_CORRECTIONS | `abd46d1` docs foundation builds strictly, but current copy overstates unmerged/live behavior and the cited Python verifier; `f199062` is an incomplete WP11 copy pass with incorrect role/archive wording. Exact corrections in `handoff/CODEX_REVIEW_CLAUDE_WP9_WP11.md` |
| Final release | PENDING | no claim until corrected local gates, hosted/live gates, and release receipts pass; no VM, Caddy, DNS, Testnet, npm, canonical-artifact, or production mutation has occurred since G1 |

## Upstream x402 blocker details

- Facilitator: `https://x402-facilitator.cspr.cloud`.
- Never add `Bearer` to its token.
- Never print an error body: 401 responses can reflect the submitted credential.
- `/supported` and `/verify` are not settlement proof.
- Wire requirements use `amount`; signed authorization and live runtime use
  `value`; automatic fallback between runtime names is forbidden.
- CAIP/EIP-712 domain is `casper:casper-test`, not `casper-test`.

## Latest checkpoint

The latest active local gate has not mutated production, Testnet, DNS, npm,
GitHub Pages, Caddy, canonical evidence, or `main`. The WP10 correction tree
passes 895 Python and 149 verifier tests; its snapshot/URL review is GO and its
whole-batch review is active. The isolated Compose least-privilege tree passes
883 Python tests after correcting exact raw-auth routing and Testnet/Mainnet
host binding; final re-review is pending. A local Caddy 2.10.2 probe proved
that mounted-file placeholders work for both the approval bcrypt hash and the
overwritten upstream proxy header: unauthenticated access returned 401 and an
authenticated spoofed-header request reached the test upstream only with the
mounted value. All temporary containers and files were removed.

Claude's producer branch is still at `9839032`; no correction commit newer than
the recorded WP2/WP3/WP5/WP7/WP9/WP11 NO-GO reviews has been presented, so
none of those commits has been integrated.

At the current integration checkpoint, Codex is the sole merge and release
operator. The full committed core range through `1aa856b` was cherry-picked
onto `codex/finals-integration`; the first release-safety batch `ea087cc` maps
to integration `5ebec77`, and strict DNS/JSON follow-up `0803ab2` maps to
`77bedb9`. The post-hoc release-manifest assembler is present at `7507684` but
is explicitly **NO-GO**, not approved merely because its 25 tests pass.

Fresh local integration gates at this boundary are: 831 Python tests plus the
separate 25-test manifest suite, 29 Rust v3 tests, 147 npm verifier tests,
TypeScript lint, and Ruff. Independent red-team review then found release
truth and privileged-file gaps that those tests missed. Corrections are active
in isolated worktrees and will be re-reviewed before another cherry-pick.

Claude's branch remains isolated at `9839032`; none of WP2/WP3/WP5/WP7/WP9/
WP11 has been cherry-picked because the recorded correction gates have not yet
been satisfied by newer commits. The historical v1/v2 contract tree,
`artifacts/live`, canonical database chain, production VM, Caddy, DNS, npm,
GitHub Pages, and Casper Testnet remain untouched by this integration work.

WP8 is independently GO at `8f5ac4a` plus `7aadeca`. The package recomputes
historical-v1, exact-v3, card-chain and native-treasury evidence, upgrades live
scope only through two explicit corroborating Casper RPC endpoints, and keeps
unsupported producer proof types unavailable. A fresh serialized run passed
142 tests, lint and npm audit; the 132-file public tarball installed and ran in
a clean consumer. The first release deliberately makes no provenance claim and
remains an interactive public publish by the npm owner; future releases may use
trusted publishing after the package exists.

The full Python suite now passes 688 tests after the final WP1 parity fix, and
the v3 crate passes 29 Rust tests. The integration worktree has been created
from the exact G1 tag but remains empty until all producer branches pass their
own review. A first read-only WP10 audit is intentionally NO-GO: the existing
live runner does not yet durably persist every signed deploy before network I/O
or independently corroborate each step's block inclusion. Remediation is local
and active; production and Testnet remain untouched.

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
A later independent public-RPC audit found that the accepted v1 and v2 deploys
use different session variants, target kinds, signed argument orders, and
terminal card roots. The frozen correction is now generation-specific. Only
v1 currently has a matching canonical card-chain export; v2 remains separate
supplemental quorum evidence until its different exact chain is exported. No
fake root or cross-generation combined historical artifact has been created.

The final C10 adversarial re-review is GO. A separate-process 64 MiB hostile
SQLite row failed closed while increasing `ru_maxrss` by only 655,360 bytes;
the connection length limit and transaction state were restored. Exact and
nested `authorization_id` / `token_usage` attempts carrying both `ghp_` and
`github_pat_` credentials were rejected. The historical offline adapter now
labels its scope `artifact_transcript_consistency` and exposes no observation
sources; only explicit independent live RPC corroboration may upgrade that
scope. Future archive attribution is also corrected in code: Core builds,
Locke seals, and Wells is a non-reasoning presentation heartbeat. The current
full Python gate passes 684 tests with one known Starlette deprecation warning.

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
