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

## Current operational checkpoint

- `handoff/FINALS_SCOPE_CONTROL.json` is the machine-checked authority for the
  approved plan hashes, every G0-G13 gate, every human prerequisite, and the
  normative A2-A5 truth contract. A work-package summary below cannot override
  or complete a formal gate in that file.
- Core correction commit
  `3d51406873ec89e73aabe22a6fc1bfa842422c30`, Compose secret-scope commit
  `7a8b9e1`, and Caddy staging commit `8956f97` are independently reviewed and
  accepted locally, but remain isolated until the release-collector worktree is
  clean and Codex cherry-picks them.
- The replacement release collector is intentionally uncommitted and red until
  its second independent adversarial review clears it.
- Claude-owned WP2/WP3/WP5/WP7/WP9/WP11 remain correction-gated; the required
  official-x402 live runner/verifier, 15-section docs IA, exact frontend/file
  map, final BUIDL copy, and 11-beat video script are not silently waived.
- Production, Testnet, DNS, npm, GitHub Pages, Caddy, canonical artifacts, and
  `main` remain unmodified since G1. The fallback checkout remains clean at
  `b79b42c` and equals `origin/main`.

## Formal release-gate index

The detailed acceptance predicates, evidence, and next actions live in
`handoff/FINALS_SCOPE_CONTROL.json`.

| Gate | Current status | Blocking boundary |
|---|---|---|
| G0 | BLOCKED | distinct proposer/finalizer/treasury/recipient/WCSPR identities, exact funding, and remaining live authorities |
| G1 | PASS | annotated freeze tag and ready manifest are immutable |
| G2 | IN_PROGRESS | corrected Claude packages and one integrated fresh component matrix |
| G3 | PENDING | locked Wasm plus supported live state readback |
| G4 | PENDING | integrated backend and frozen schemas |
| G5 | PENDING | hosted approval/demo/room adversarial security |
| G6 | PENDING | fresh SafePay Lite native-CSPR proof |
| G7a | PENDING | v3 four outcomes plus exact 625-to-50 CSPR transfer |
| G7b | BLOCKED | corrected official-x402 service, at least 25 WCSPR, and finalized compatibility canary |
| G8 | PENDING | generation-specific proof lineage and registry publication |
| G9 | PENDING | full frontend build, behavior, viewports, accessibility, console, and degraded QA |
| G9n | PENDING | first npm publish with registry-visible provenance |
| G9d | PENDING | strict 15-section MkDocs build and Pages-before-CNAME deployment |
| G10 | PENDING | hosted RC, runtime/Caddy/DNS/TLS identity, and sslip continuity |
| G11 | PENDING | complete claim-to-artifact content mapping |
| G12 | PENDING | local Git equals GitHub, deployed images/source, proof, docs, and package manifests |
| G13 | PENDING | new 11-beat video and incognito DoraHacks/submission verification |

## Human-prerequisite index

The evidence-safe details and owner actions are recorded in
`handoff/FINALS_SCOPE_CONTROL.json`; no secret value belongs in this ledger.

| Area | Current status | Owner |
|---|---|---|
| Existing three signer identities and 1,952-CSPR funding source | PARTIAL_READY | Asad + Codex |
| Distinct proposer and finalizer | BLOCKED | Asad |
| Dedicated treasury at exactly 625.000000000 CSPR and native recipient | BLOCKED | Asad |
| Treasury gas allowance and 100-CSPR rerun reserve | PARTIAL | Asad + Codex; funding source exists, allocation receipt pending |
| WCSPR payer/payee, supported signer, and at least 25 WCSPR | BLOCKED | Asad |
| Facilitator supported/verify/settle | PARTIAL | Asad + Codex; supported passed, finalized canary missing |
| Namecheap, VM/Caddy, YouTube, DoraHacks | AUTHORITY_CONFIRMED | Asad + Codex |
| GitHub Pages | PARTIAL | admin confirmed; Pages workflow/domain not live |
| npm org/login/2FA/provenance | PARTIAL | org and 2FA confirmed; provenance-bearing first publish pending |

## Work-package gate ledger

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
| WP1 v3 | PASS_LOCAL_PENDING_INTEGRATION | final correction commit `3d51406873ec89e73aabe22a6fc1bfa842422c30`; independent review found P0/P1/P2=0. Fresh post-commit gates: 897 Python, 149 verifier, TypeScript lint, Ruff, diff checks, and clean-archive verification; live deployment remains G3/G7a |
| WP4 registry/artifacts | PASS_LOCAL_PENDING_CAPTURE | fail-closed registry/API, provenance/chronology binding, bounded exact card-chain export, and offline historical receipt verification are committed. Independent C10 review passed the 64 MiB/RSS and nested credential-bypass probes. Only v1 currently has a matching canonical card chain; no root or combined artifact is fabricated locally, and live capture/registry publication remain WP10 |
| WP6 executor | PASS_LOCAL | `ac03cec` + ordering hardening `fd66e67`; independent audit GO, 285 focused tests |
| WP8 verifier | PASS_LOCAL_PENDING_PRODUCERS | `8f5ac4a` + truth correction `7aadeca`; independent audit found no P0/P1/P2. Serialized npm gate passes 142/142, lint, audit 0, 132-file pack, temp install/import/bin. Historical v1, exact-v3, native treasury and two-node live corroboration fail closed; WP2/WP3/WP5 adapters await corrected producer schemas. No npm publication yet |
| WP10 live/release | PASS_LOCAL_PENDING_INTEGRATION_AND_COLLECTOR | core release tooling is included in `3d51406873ec89e73aabe22a6fc1bfa842422c30` and independently cleared with P0/P1/P2=0. No live mutation. The separate three-file release collector remains intentionally uncommitted until its second adversarial review |
| Release manifest | BLOCKED_ON_FINAL_COLLECTOR_REVIEW | first assembler `7507684` remains superseded and NO-GO. Its three-file replacement now derives Compose/runtime/Caddy/HTTP/TLS/Pages/npm/two-RPC observations, reloads and reruns producer-verifier receipts, binds registry metadata and lineage, scans known secret canaries, requires stable observations, and removes arbitrary ready-payload writing. The new 22-test suite is green, but DNS projection, deep route predicates, Pages deployment status, npm offline self-test, and an independent adversarial review still gate commit |
| Compose secret scope | PASS_LOCAL_PENDING_INTEGRATION | commit `7a8b9e1`; CSPR.cloud is file-only in production and mounted only into Mercer, Casper signing is limited to Gateway/Locke, legacy x402 credentials are absent, and SafePay config is limited to Gateway/provider. Raw authorization is chain-bound and invalid config is redacted. Independent review P0/P1/P2=0; fresh gate: 895 Python tests, Ruff, rendered Compose, and diff check |
| Caddy staging | PASS_LOCAL_PENDING_INTEGRATION | commit `8956f97`; caddy:2.8-alpine validation and runtime probe prove Basic Auth before proxy, spoofed proxy-secret overwrite, exact x402 method/path allowlist, real 308 root redirect, apex/www mapping, and direct demo-route removal. Independent review found no P0/P1; release requires byte-exact no-newline secret files and runtime-image/full-config binding |
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

## Historical checkpoint narrative (non-operative)

The text below is preserved as an append-only audit trail. It contains older
snapshots and must not be used to decide the next action; the operational
tables and `handoff/FINALS_SCOPE_CONTROL.json` above always win.

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
a clean consumer. The first public release remains blocked until the registry
shows provenance whose subject digest and source commit bind the exact tarball;
a provenance-free bootstrap does not satisfy G9n.

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
