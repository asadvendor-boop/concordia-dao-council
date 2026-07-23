# Interface Manifest — Mainnet Canary Hardening (`claude/mainnet-canary-hardening`)

Producer: Claude lane, branch `claude/mainnet-canary-hardening`.
Base: `d5d7582` (immutable rejected prototype/reference — preserved unmerged).
Hardening commit: `93724c6de44f900197c8f26f5188b449d1882639`.
Runtime-wiring commit: see §4b (the reviewer's "unit-tested but unwired"
finding); the module attestations in §2 are unchanged by it — it moved no
contract source, only Python enforcement paths and tests.

**No-mutation statement.** This branch performed local code, tests, fixtures,
and this manifest only. No VM, Caddy, DNS, npm, Testnet, Mainnet, wallet,
canonical artifact, or `artifacts/live/**` mutation. No secret access, no
signing, no broadcast. Historical Testnet v1/v2 proofs and the frozen
canonical 12-card chain are byte-for-byte untouched. Nothing here claims live
Mainnet completion; every live-proof field remains `BLOCKED_PENDING_LIVE_PROOF`.

---

## 1. Network-specific contract build (the B1 resolution)

The Testnet RC Wasm hard-codes `casper-test` in constructor validation and
cannot initialise on Mainnet. This branch introduces a **compile-time network
profile** in `contracts/odra-governance-receipt-v3`:

- `build.rs` reads `CONCORDIA_V3_NETWORK_PROFILE` (`testnet` |
  `mainnet-native`) and emits `network_profile_*` cfgs. **Unset or any other
  value panics the build** — a profile-less governance contract cannot exist.
- `src/encoding.rs` carries `compile_error!` guards for the both-set and
  neither-set cfg states, plus per-profile constants:

  | constant | `testnet` | `mainnet-native` |
  |---|---|---|
  | `CASPER_CHAIN_NAME` | `casper-test` | `casper` |
  | `CAIP2_NETWORK` | `casper:casper-test` | `casper:casper` |
  | `DOMAIN_SEPARATOR` | `CONCORDIA_DOMAIN_V3\0` (frozen) | `CONCORDIA_DOMAIN_V3_MAINNET\0` |
  | `OFFICIAL_X402_SUPPORTED` | `true` | `false` |

- Mainnet-native **never lies with `casper-test`**: the constructor accepts
  exactly `casper` and refuses everything else (`InvalidEnvelopeField`/15).
- Mainnet-native **x402 is fail-closed at two independent levels** until a
  live Mainnet `/supported` observation pins asset constants:
  `CommonHeader::validate_basic` refuses the x402 action kind AND
  `OfficialX402SettlementV1::validate_semantics` refuses outright — both with
  `InvalidActionField` (16), pinned as `User error: 16`.
- Caller-supplied chain values remain forbidden; identity comes only from the
  compiled profile constants.

### Deviation record (for Codex's ruling)

The prompt asked for a Cargo **feature**-selected profile. `cargo-odra 0.1.7`
forwards **no** cargo flags through the accepted release command
(`cargo --locked odra build -c GovernanceReceiptV3` — verified:
`cargo odra build --help` exposes only `-c/-v/-q`), so a feature cannot ride
the accepted pipeline without changing the release command itself. The
profile therefore rides a **build-script environment variable with no
default** — same compile-time guarantees (mutual exclusion, fail-on-absent,
`compile_error!` backstops), zero change to the accepted release command.
The single allowlisted build-input delta between network artifacts is that
one environment variable; the source trees are byte-identical.

### Exact contract diff (d5d7582 → 93724c6, `contracts/` only)

```
build.rs                |  29 +   (env → cfg emission, panic on absent/invalid)
src/encoding.rs         |  50 +-  (profile constants, compile_error! guards,
                                   x402 double gate, CAIP-2 comparison via const)
src/lib.rs              |   3 +-  (re-export CAIP2_NETWORK, CASPER_CHAIN_NAME,
                                   OFFICIAL_X402_SUPPORTED)
tests/{adversarial,deployment,encoding}.rs | +4 each (#![cfg(network_profile_testnet)])
tests/network_profile.rs | 410 +  (new dual-profile suite)
```

No other semantic difference exists between the profiles: the governance
state machine, error codes 1–16, envelope/action/transfer derivations, and
the frozen Testnet domain separator are untouched (Testnet suites pass
byte-frozen goldens — see §5).

### Build commands (both profiles, accepted pipeline)

```
cd contracts/odra-governance-receipt-v3
CONCORDIA_V3_NETWORK_PROFILE=testnet        cargo --locked odra build -c GovernanceReceiptV3
CONCORDIA_V3_NETWORK_PROFILE=mainnet-native cargo --locked odra build -c GovernanceReceiptV3
```

## 2. Reproducible artifact attestation (local, double-built)

Each profile was built **twice from independently exported clean trees** of
peeled commit `93724c6de44f900197c8f26f5188b449d1882639` (git archive → fresh
directory → accepted release command). Both builds per profile were
byte-identical; hashes recomputed from the actual artifacts:

| profile | wasm SHA-256 (both builds byte-identical) |
|---|---|
| `testnet` | `6605611e9649e513fe343e176d5427b317c5214c41fef340fcbb76180baa5564` |
| `mainnet-native` | `0bc50e2444569d8c8f728ea46fe7a6c83eac82a5df0f28098e83553f1df2383d` |

Toolchain (pinned by the tree's `rust-toolchain.toml`, resolved during the
builds): `nightly-2025-02-01`, `cargo-odra 0.1.7`; `Cargo.lock` SHA-256
`ec91d86526c54cde44954583c27124a5186f100b0f712420e76cdf0de9c4b187`
(unchanged from the base — `--locked` builds).

**The Testnet-profile artifact at `93724c6` byte-reproduces the accepted
Testnet RC hash `6605611e…` EXACTLY.** The profile plumbing compiles out to
the identical Testnet Wasm: under `network_profile_testnet` the selected
constants equal the frozen literals, so codegen is unchanged — the strongest
possible no-other-semantic-difference proof for the Testnet side, and it
simultaneously re-proves local reproducibility of the accepted pipeline.
The Mainnet-native artifact is disjoint, as required. Codex independently
decides cherry-pick vs reproduce and republishes authoritative hashes under
its own annotated tag.

`tools/mainnet_canary/attestation.py` encodes the same discipline for the
future live gate: annotated-tag-only resolution (tag object + peeled commit;
missing/lightweight/moved refuse), pristine worktree including untracked,
fresh private exports, double builds byte-identical, actual-artifact hashing
(declared hashes never trusted — `ARTIFACT_HASH_UNBACKED`), Testnet ≠
Mainnet hash required, pinned toolchain facts required
(`TOOLCHAIN_UNPINNED`), env-var-only allowlisted delta
(`SOURCE_DELTA_NOT_ALLOWLISTED`).

## 3. Cross-language domain-separator goldens

Nonce `0xa5 × 32`, package `concordia_governance_receipt_v3` — pinned
byte-for-byte in BOTH `tests/network_profile.rs` (Rust) and
`tests/mainnet_canary/test_mc_hardening_plan_encoding.py` (Python):

```
testnet  40804e79504df011ccbe7326898a9d7e489e01b445f483a199467584ddfb5726
mainnet  738f08998497f41853bacfa94833f5b301cbe3f3530e70f663f147255b27fcfd
```

The Python mirror (`tools/mainnet_canary/encoding.py`) previously derived
Mainnet domains with the **Testnet** separator — a genuine cross-language
mismatch, caught failing-first and fixed: the separator now switches on the
chain name.

## 4. Spend model v2 — dry-run cost report format

`tools/mainnet_canary/economic_manifest.py`
(`concordia.mainnet-canary.economic-manifest.v1`), derived from the plan:

- **Lines 1:1 with the plan's economic steps** — install, propose, each
  approval, pre-quorum refusal (E, `User error: 8`), wrong-envelope refusal
  (F9, `User error: 10`), finalize, duplicate-finalize refusal (H,
  `User error: 12`), native transfer. Refusal proofs are never free.
- Per-line binding: entry point, typed-args SHA-256, signer role + account,
  max payment, basis, RC tag, source commit, wasm hash (install line).
- Immutable integers with **checked arithmetic**:
  `transfer_principal_motes`, `max_install_payment_motes`,
  `max_governance_payment_motes`, `max_transfer_payment_motes`,
  `max_fees_motes` (= Σ line maxima), and
  `max_total_outlay_motes = transfer_principal_motes + max_fees_motes`.
  Any recompute mismatch → `CEILING_ARITHMETIC_INVALID`. Zero/placeholder
  fees refuse.
- Every fee maximum requires a **finalized Testnet calibration receipt**.
  *(Superseded in the §4d correction round: the calibration schema is now
  `testnet-calibration.v2` — plan-bound, line-set-exact, dually observed —
  and the operator-ceiling substitute was REMOVED; supplying any refuses
  with `OPERATOR_CEILING_NOT_PERMITTED`.)* **No costs are guessed anywhere;
  no Testnet calibration receipts exist yet** (blocker §8).
- Human authorization (`concordia.mainnet-canary.human-authorization.v1`)
  binds plan hash, chain `casper`, treasury/recipient account hashes,
  principal, `max_fees_motes`, `max_total_outlay_motes`, trusted-clock
  `expiry_unix` (zero/past → `AUTHORIZATION_EXPIRED`), 32-byte nonce,
  approvers. `require_within_authorization` makes spending above the signed
  ceiling impossible.
- `required_funding_motes()` outputs **exactly** the maximum required
  funding (`max_total_outlay_motes`) and nothing else. No purchase,
  transfer, bridge, swap, or exchange recommendation exists anywhere.

**Amount is an exact human confirmation.** The frozen v3 envelope semantics
pin `amount == floor(balance × approved_bps / 10000)`; the plan refuses
unless `human_authorized_amount_motes` equals that exact value (and the tiny
cap). The implementation cannot choose an amount silently.

## 4b. Runtime wiring (reviewer finding on `38866fd`)

The reviewer's early audit reproduced 235/235 but found the decisive gap:
the new safety modules were **unit-tested in isolation and not imported by
the CLI/stage/verify path**, so at runtime they enforced nothing. Confirmed
exactly — only `path_policy` was wired. A safety module off the enforcement
path is documentation, not a control.

Every module is now ON the path, and each has a CLI-level test that drives
the binary and asserts the refusal only the wired module can produce:

| module | where it now runs | CLI refusal proven |
|---|---|---|
| `attestation` | `stage` → `require_build_attestation`: the RC-declared Mainnet hash must be backed by a double-built, two-profile, disjoint attestation | `ARTIFACT_HASH_UNBACKED` |
| `economic_manifest` | `stage` → plan-derived manifest + signed human authorization + `require_within_authorization`; new `funding` mode | `CALIBRATION_RECEIPT_ABSENT`, `AUTHORIZATION_EXPIRED` |
| `finality_v2` | `verify` → every economic step needs two agreeing disjoint providers with raw response evidence | `NODE_SET_INVALID`, `OBSERVATION_MALFORMED` (v1 bundles) |
| `proof_bundle` | new `bundle` mode → lineage + verbatim statement + forbidden-claims scan before any write | `FORBIDDEN_CLAIM`, namespace refusals |
| `path_policy` | `stage` (already) and now `bundle` writes | `CANONICAL_NAMESPACE_PROTECTED` |

`stage` gained four REQUIRED arguments (`--attestation`, `--calibration`,
`--authorization`, `--clock-unix`) so staging cannot proceed on an unattested
artifact, an ungrounded cost model, or an unsigned/expired authorization.
CLI modes are now `inventory, estimate, plan, stage, funding, verify, bundle,
broadcast`.

`funding` prints the exact maximum outlay and nothing else, and says
in-band that this lane never purchases, transfers, bridges, swaps, or
exchanges CSPR — provisioning stays a human action outside the tooling.

**Scope note, stated rather than glossed:** `supported_probe` is deliberately
NOT on the prep-lane runtime path. It is a pure redaction helper (it performs
no network I/O itself), and the preparation lane may not make authenticated
calls or hold a token, so there is nothing for it to gate here. It remains
unit-tested and is for the future live lane. That is a scope boundary, not a
wired control — do not read it as one.

## 4c. Depth findings — "wired" did not close these

The reviewer's follow-up was right that putting a module on the path is not
the same as the control being correct. Five named areas, each verified as a
real gap before fixing:

1. **Confirmation depth** — `FINALITY_CONFIRMATION_DEPTH = 8` was a constant
   **nothing read**. Providers must now report `chain_tip_height`, and
   `tip - block_height >= 8` is enforced per observation
   (`INSUFFICIENT_CONFIRMATIONS`).
2. **Authenticated human authorization** — the authorization was only
   schema-checked, so **any process able to write the file could authorize a
   real Mainnet spend**. It now requires a detached ed25519 signature over
   canonical bytes under a domain separator, verified against a **pinned**
   authorizer key set supplied out-of-band (`--authorizer-key`). Unsigned,
   tampered, unpinned, and unverifiable-backend cases all refuse
   (`AUTHORIZATION_UNSIGNED`, `AUTHORIZATION_SIGNATURE_INVALID`,
   `AUTHORIZER_NOT_PINNED`, `SIGNATURE_BACKEND_UNAVAILABLE` — an
   unverifiable signature is never treated as authentic).
3. **Independently sourced snapshot** — the transfer amount is derived from
   the treasury balance, which was a single operator file: whoever wrote it
   chose the amount. Staging now requires a corroboration document from two
   disjoint providers reporting the identical observation
   (`SNAPSHOT_NOT_CORROBORATED`). The frozen snapshot schema is untouched.
4. **Proof-bundle cross-binding** — `journal_head_hash` was a CLI argument
   the operator typed, binding nothing. The `--journal-head-hash` flag is
   **removed**; `bundle` now reads the journal, recomputes its head, and
   requires the journal, economic manifest and verification report to bind
   to the same plan (`BUNDLE_CROSS_BINDING_INVALID`).
5. **Filesystem race** — the symlink check ran against a path, leaving a
   check-then-use window before the append. Journal writes now resolve the
   parent to a descriptor once and open relative to it with `O_NOFOLLOW`, so
   the write lands in the directory that was validated.

Calibration receipts remain **operator-attested, not corroborated** — each
must be finalized and is recorded with its deploy hash, but this lane cannot
independently confirm a Testnet receipt. Stated here rather than implied;
corroborating them is a live-lane input, not something the prep lane can
manufacture.

Suite 244 → **251**. Each gate is additionally exercised against the real
CLI, including a forged authorization whose ceiling was raised after signing
(refused) beside the genuine one (accepted).

## 4d. Correction round — Sol's conditional approval, implemented

Everything in this section is on top of the accepted `2c945b3` (immutable;
no amend/rebase). Suite **259 → 299**, validation matrix **17 → 21/21**
controls, all green at this branch head.

### A — F9 redirected-recipient refusal probe (corrected construction)

The prior F9 flipped `authorized_metadata_root`. My first replacement
changed only `recipient_account` and was **rejected correctly**: the
contract recomputes `action_id`/`transfer_id` before the commitment check,
so that construction dies as `InvalidActionField` (16), never reaching
`EnvelopeHashMismatch` (10). The implemented construction mirrors
`contracts/odra-governance-receipt-v3/tests/network_profile.rs`:
copy the approved envelope → set `recipient_account` to the **finalizer**
→ recompute `action_id` from the redirected core → header carries it →
recompute `transfer_id` from it → retain the approved commitment. The
redirected envelope passes the same dual-implementation coherence gate as
the approved one; distinctness of `action_id`, `transfer_id`, and envelope
hash from G's is asserted fail-closed at plan time.

- Plan records `expected_refusal: true` + stable `refusal_scenario`
  (`pre_quorum_finalize` / `post_quorum_recipient_redirect` /
  `duplicate_finalize_replay`) for E/F9/H. **No `attack_demonstrated`
  anywhere**; `refusal_observed: true` is emitted only by `verify` from a
  dual-provider consensus on the exact finalized error.
- F9's expected outcome pins `approved_recipient`, `redirected_recipient`,
  `redirected_action_id`, `redirected_transfer_id`,
  `redirected_envelope_hash` — all independently recomputed under test.
- Tests: `tests/mainnet_canary/test_mc_refusal_probe.py` (8) proves the
  properties listed in the approval, including the error-16-class refusal
  of the naive construction; the on-chain error-10 half remains proven by
  the existing `network_profile.rs` mainnet test (contracts/ untouched —
  outside this lane's write set).
- Because expected outcomes and typed args feed the plan hash, every
  plan-bound fixture regenerates from the plan itself (no pinned plan-hash
  golden existed to update; the golden-vector gate pins the ENVELOPE
  vectors, which are unchanged).

### B — custody_model (schema v2, fail-closed, never inferred)

- `parameters.v2` + `plan.v2`: `custody_model` is a REQUIRED field; a
  v1-shaped document refuses (`PLAN_INPUT_INVALID`). Enum is exactly
  `{single_operator, independent_custodians}`; anything else →
  `CUSTODY_MODEL_INVALID`.
- Declared twice on purpose: parameters file AND `plan --custody-model`
  CLI flag must agree (mirrors the human-authorized-amount pattern).
- `independent_custodians` → `CUSTODY_EVIDENCE_ABSENT` in this release:
  distinct accounts/key mounts are not independence, and no separate
  custody-evidence mechanism exists yet.
- `proof-bundle.v2` REQUIRES `custody_model`; cross-binding refuses if it
  differs from the plan's. Concordia's canary emits `single_operator`.
- Tests: `tests/mainnet_canary/test_mc_custody_model.py` (8).

### C — calibration pipeline v2 (receipt-backed only)

New module `tools/mainnet_canary/calibration.py`
(`testnet-calibration.v2`) + CLI mode `calibration` (convert/validate):

- economic-step set DERIVED from the plan (7 fixed + one vote per
  threshold signer; threshold 3 ⇒ 10) — never hard-coded;
- exact line-set equality (`CALIBRATION_LINE_SET_MISMATCH` on missing OR
  extra);
- per-line bindings (`CALIBRATION_BINDING_INVALID` otherwise): Mainnet
  plan hash; step's typed-args digest recomputed from the plan; Testnet
  deploy-args digest which must DIFFER (byte-identical claims refuse);
  translated-field list restricted to the reviewed network-profile set;
  signer identity; `casper-test` chain identity; entry-point/RC Testnet
  Wasm/source-commit pins; positive payment extracted from the deploy;
  deploy/block hash + height; execution result matching the step's
  expected outcome (E/F9/H calibrate their exact refusals); finality depth
  ≥ 8 (`INSUFFICIENT_CONFIRMATIONS`); two disjoint RPC observations.
- converter (`--harness`) is the only sanctioned producer: digests and
  translated fields are computed/derived, never transcribed; shape drift
  or unreviewed value drift refuses.
- **Operator ceilings removed as a substitute**: any supplied ceiling →
  `OPERATOR_CEILING_NOT_PERMITTED` (finals policy). The legacy v1
  `estimate` mode remains only as the coarse pre-plan view; the
  authoritative economic path is plan → calibration → funding → stage.
- Tests: `tests/mainnet_canary/test_mc_calibration.py` (24); matrix rows
  for ceiling refusal, line-set mismatch, rebound plan hash, custody
  mismatch.
- Runbook + harness-observation template for Codex:
  `handoff/MAINNET_CANARY_OPERATOR_RUNBOOK.md` (prepare → dry-run →
  explicit `--submit` → reconcile by original deploy hash → two-node
  finalized observations → convert → validate → funding). **Do not
  calibrate against `2c945b3`** — the calibration binds the FINAL frozen
  plan hash only.

New refusal codes: `CALIBRATION_LINE_SET_MISMATCH`,
`CALIBRATION_BINDING_INVALID`, `OPERATOR_CEILING_NOT_PERMITTED`,
`CUSTODY_MODEL_INVALID`, `CUSTODY_EVIDENCE_ABSENT`.

No live or release mutation occurred: all work is local code, tests, and
handoff documents; nothing was signed, submitted, deployed, merged, or
tagged; no secret was read or printed.

## 5. Test inventory and fresh results (all at `93724c6`)

| Suite | Result |
|---|---|
| Python canary lane (`tests/mainnet_canary/`, 12 prior + 6 new hardening files) | **243/243 passed** (235 before the runtime wiring; +8 CLI-level gate tests) |
| Contract, `testnet` profile (encoding 18, adversarial 9, network_profile 3, lib 2) | **32/32 passed**, exit 0 (fresh at `93724c6`) |
| Contract, `mainnet-native` profile (network_profile mainnet module) | **5/5 passed**, exit 0 (fresh at `93724c6`) |
| Contract, profile-less | compile fails with the refusal panic (proven) |
| Repo-wide `pytest tests/` | 623 passed; 11 failures + 18 collection errors are all the **pre-existing** missing-`pycspr` environment gap (untouched files) |
| `git diff --check` | clean |

Failing-first evidence: 19 behavioral failures captured against unmodified
modules (journal SIGNED-without-evidence accepted, submit-with-different-hash
accepted, treasury==signer accepted, duplicate mounts accepted, silent
amount, missing wrong-envelope/duplicate steps, Mainnet domain derived with
the Testnet separator, prefix-matched `User error:`, untracked drift passed)
plus 4 new-module import errors — then 235/235 green.

New refusal codes: `TAG_MISSING`, `TAG_NOT_ANNOTATED`, `TAG_MOVED`,
`BUILD_COMMAND_INVALID`, `BUILD_FAILED`, `BUILD_NOT_REPRODUCIBLE`,
`ARTIFACT_HASH_UNBACKED`, `SOURCE_DELTA_NOT_ALLOWLISTED`,
`TOOLCHAIN_UNPINNED`, `PRINCIPAL_LINE_ABSENT`, `CEILING_ARITHMETIC_INVALID`,
`CALIBRATION_RECEIPT_ABSENT`, `AUTHORIZATION_EXPIRED`, `NODE_SET_INVALID`,
`NODE_DISAGREEMENT`, `READBACK_MISMATCH`, `JOURNAL_LOCK_HELD`,
`JOURNAL_PATH_UNSAFE`, `PROBE_HEADER_INVALID`, `FORBIDDEN_CLAIM`.

## 6. Executor, finality, confinement, probe, bundle (v2 summary)

- **Journal/executor**: exclusive `flock` (second process →
  `JOURNAL_LOCK_HELD`; lock dies with the fd, so no stale-lock wedge),
  symlink-safe file/dir chain (`JOURNAL_PATH_UNSAFE`), `O_EXCL` atomic
  creation + dir fsync, hash-chained records (unkeyed chain is tamper-
  EVIDENT only — the release-manifest digest signature remains a live-lane
  Codex step and is not claimed here). **SIGNED is impossible without the
  canonical signed-bytes SHA-256 and the locally computed deploy hash**;
  SUBMITTED must equal the SIGNED hash (`DUPLICATE_ECONOMIC_ACTION`
  otherwise); CONFIRMED/FAILED_FINALIZED bind the original hash; restarts
  reconcile-only. Signed evidence provably survives reload.
- **Finality v2** (`finality_v2.py`,
  `concordia.mainnet-canary.step-observation.v2`): upstream booleans alone
  are never sufficient — every observation carries provider evidence
  (provider id, endpoint host, method, request SHA-256, **raw response
  SHA-256**, retrieval time, api version, chainspec). Exactly two disjoint
  providers (`NODE_SET_INVALID`), full agreement on block identity, deploy
  hash, execution result, and state readback (`NODE_DISAGREEMENT`),
  each independently evaluated. Explicit C (install/config readback,
  `READBACK_MISMATCH`), H (`exact_refusal` `User error: 12`), and
  J (transfer readback binding source/recipient/amount/transfer-id)
  evaluations. The second disjoint Mainnet provider is still unpinned
  (blocker §8).
- **Path confinement** (`path_policy.py`, wired through `stage`): one
  policy for every output; canonical/live/secret namespaces refuse;
  absolute/`..`/component/symlink escapes refuse; exclusive fsynced
  writes with hard-link publish (identical-bytes republish is a no-op,
  any difference refuses); in-repo capture requires the
  `artifacts/mainnet-canary/<canary_id>/` namespace AND
  `live_capture_authorized=True`, which the preparation lane never sets.
- **/supported probe** (`supported_probe.py`): raw-token `Authorization`
  header value — any bearer-prefixed value refuses
  (`PROBE_HEADER_INVALID`); failed authenticated probe bodies are never
  emitted (no bytes, no hash); successful bodies reduce to SHA-256 +
  strictly allowlisted scalar fields. Telegram messages remain leads, not
  proof; `agentic.market` remains research-only, not integrated.
- **Proof bundle** (`proof_bundle.py`): lineage
  `concordia-mainnet-canary-v1`; the required statement verbatim
  ("Concordia v3 on Casper Mainnet enforced quorum and the exact approved
  native-transfer envelope; an off-chain bounded executor submitted one
  native transfer only after on-chain authorization."); mechanical
  forbidden-claims scan (`FORBIDDEN_CLAIM`) for custody/disbursal claims,
  byte-identical-wasm claims, Mainnet-x402-supported claims,
  wallet-transfer-proves-governance claims, and rewritten-history claims.

## 7. Remaining human inputs (public identifiers only)

1. Codex's annotated RC tag name + peeled commit for the hardened source.
2. Authoritative double-built wasm hashes under that tag (or a cherry-pick
   ruling on §1, then hashes).
3. A second disjoint public Mainnet RPC provider (hostname) to pin beside
   `node.mainnet.casper.network`.
4. Finalized Testnet calibration receipts (exact-equivalent deploys) or
   explicit conservative operator ceilings per economic step.
5. The dedicated Mainnet public-key inventory (public keys/account hashes
   for all seven pairwise-distinct roles) via file mount.
6. The signed human authorization document (plan hash, accounts, exact
   amount, maxima, expiry, nonce).
7. Exact maximum funding: `required_funding_motes()` of the resulting
   manifest — no purchase/transfer/bridge/swap is performed or recommended
   by this lane.

## 8. Blockers (all fail-closed today)

- No Codex RC tag for the hardened contract → RC gate refuses
  (`RC_DECLARATION_ABSENT` / `TAG_MISSING`).
- No Testnet calibration receipts → economic manifest refuses
  (`CALIBRATION_RECEIPT_ABSENT`).
- No second disjoint Mainnet provider → finality v2 refuses
  (`NODE_SET_INVALID`).
- No key inventory / human authorization mounts → keys/authorization gates
  refuse.
- Live capture unauthorized → path policy refuses in-repo writes;
  broadcast remains structurally absent
  (`SUBMISSION_NOT_IMPLEMENTED_IN_PREP`).
