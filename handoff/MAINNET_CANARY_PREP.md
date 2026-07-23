# Mainnet Canary — Preparation Lane Handoff

Producer: `claude/mainnet-canary-prep`
Base: `codex/finals-core-v3` @ `7668fa46629cca02a7eb087b9a9873c0a8479912` (exact
worktree base; branch created from this SHA and never rebased).

Statement: **NO MAINNET OR TESTNET MUTATION PERFORMED.** Nothing in this lane
signed, submitted, simulated with a funded key, or broadcast any transaction
on any network; no private key or secret was read, copied, enumerated, or
tested; no VM/Caddy/Compose/DNS/npm/Pages/DoraHacks surface was touched; no
file outside the exclusive write scope was modified.

## 1. What was built

A fail-closed, six-mode CLI under `tools/mainnet_canary/` with a durable
hash-chained journal and a failure-first test suite under
`tests/mainnet_canary/` (135 tests, three consecutive stable runs).

```
python3 -m tools.mainnet_canary inventory|estimate|plan|stage|verify|broadcast
```

Exit 0 = success JSON; exit 2 = `{"refusal": {code, detail}}` with a stable
refusal code. No mode reads environment variables; no bypass flag exists.

### File map

| Path | Purpose |
|---|---|
| `tools/mainnet_canary/__init__.py` | `PREP_LANE = True` (structurally disables submission) |
| `tools/mainnet_canary/constants.py` | pinned chain name `casper`, official RPC, error-code table, mount paths, protected namespaces |
| `tools/mainnet_canary/errors.py` | stable refusal codes + `CanaryRefusal` |
| `tools/mainnet_canary/encoding.py` | fresh from-spec G1 §2/§4/§5/§7 implementation, chain-parameterised (no shared/ imports) |
| `tools/mainnet_canary/crosscheck.py` | dual recomputation (fresh vs frozen shared primitives) + immutable golden-vector gate |
| `tools/mainnet_canary/secret_guard.py` | secret-pattern refusal (never echoes matches), secret-path read refusal |
| `tools/mainnet_canary/rc_gate.py` | Testnet-RC release dependency: tag/commit/clean-tree/Wasm/historical-drift/chain/endpoint validation |
| `tools/mainnet_canary/keys.py` | public key inventory; account hashes recomputed; role distinctness; Testnet-reuse refusal |
| `tools/mainnet_canary/cost_model.py` | refuse-while-UNKNOWN budget; ceiling gating; deterministic report |
| `tools/mainnet_canary/journal.py` | append-only hash-chained JSONL; state machine; reconcile-not-duplicate restarts |
| `tools/mainnet_canary/plan.py` | proof-sequence A..K plan; typed args; expected refusal codes; dependency graph; plan hash |
| `tools/mainnet_canary/stage.py` | content-addressed UNSIGNED intents; every gate re-run; artifact-namespace protection |
| `tools/mainnet_canary/verify.py` | fail-closed evaluators over read-only public RPC observations |
| `tools/mainnet_canary/broadcast.py` | guard surface; disabled in this lane (see §5) |
| `tools/mainnet_canary/cli.py`, `__main__.py` | argparse CLI, six modes |
| `tests/mainnet_canary/*.py` | failure-first suite (see §7) |
| `tests/mainnet_canary/fixtures/schema-only/*` | fixture-free schemas: all evidence null, no invented hashes/heights/IDs/booleans |
| `handoff/MAINNET_CANARY_INTERFACE_MANIFEST.json` | interface + blocking findings for Codex |
| `handoff/MAINNET_CANARY_COST_MODEL.json` | cost model, every line UNKNOWN/blocked |

## 2. Threat model and trust boundaries

Assets: Mainnet funds (dedicated canary accounts), the canonical/Testnet
evidence corpus, the frozen v3 encodings, and the truthfulness of every
public claim.

Trust boundaries:

- **Operator inputs are untrusted.** Every document (RC declaration, key
  inventory, parameters, observations, ceiling, authorization) is strictly
  schema-validated (exact field sets), scanned for secret-like material
  (refused without echo), and every locally checkable fact is recomputed
  (git cleanliness, HEAD equality, Wasm SHA-256, historical hashes, account
  hashes from public keys, amount formula, action/transfer/envelope IDs).
- **The chain is untrusted until finalized readback.** Verification accepts
  only finalized, proof-carrying, member-checked observations with exact
  target, entry point, typed args, and identifiers; a pre-quorum refusal is
  positive proof only as the exact finalized `QuorumNotMet` (`User error: 8`)
  message; anything ambiguous refuses.
- **This lane distrusts itself.** Identifiers must be recomputed identically
  by two independent implementations (fresh from-spec vs frozen shared
  primitives) and re-proven against the immutable G1 golden vectors before
  any plan is emitted; a single byte of drift refuses.
- **Secrets are out of scope by construction.** Only key-file mount PATHS are
  handled; paths below `/run/secrets/` are refused for reading; outputs are
  scanned; tests assert hostile inputs never leak to stdout/stderr/
  exceptions/journal/staged files.
- **Economic idempotency.** The durable journal must exist before any
  broadcast could occur; in-flight steps (SIGNED/SUBMITTED/UNKNOWN) block all
  new economic actions and can only reconcile against the original deploy
  hash. A restart can never emit a second transfer.
- **Lineage.** Mainnet evidence is supplemental
  (`provenance=mainnet_supplemental`, future
  `artifacts/mainnet-canary/v3/<canary-id>/**`); the prep lane refuses to
  write below `artifacts/` at all, and `artifacts/live/`, `artifacts/rwa/`,
  `handoff/HISTORICAL_*` are protected outright.

Blocking finding **B1** (full text in the interface manifest): the frozen
Testnet RC Wasm hard-codes chain `casper-test` in its constructor validation,
so a byte-for-byte install cannot initialise on Mainnet. The tooling refuses
(`RC_MAINNET_WASM_UNATTESTED`) until Codex's RC declaration attests a
reproducible Mainnet-chain build, and refuses reuse of the Testnet hash.

## 3. Network pins

- Chain name: exactly `casper`.
- Official RPC pinned in source: `https://node.mainnet.casper.network/rpc`
  — verified live via one credential-free `info_get_status` read
  (2026-07-23T06:45Z: `chainspec_name=casper`, protocol `2.2.2`, api `2.0.0`).
  No Authorization header was or ever is sent.
- A second disjoint-host endpoint is deliberately NOT pinned (Codex input;
  manifest finding B3).

## 4. Transaction state machine and restart semantics

Per economic step, forward-only:

```
PLANNED -> STAGED -> AUTHORIZATION_VALIDATED -> SIGNED -> SUBMITTED
SUBMITTED -> CONFIRMED_FINALIZED | FAILED_FINALIZED | SUBMISSION_UNKNOWN
SUBMISSION_UNKNOWN -> RECONCILED_CONFIRMED | RECONCILED_FAILED
```

Journal: append-only JSONL; each record hash-chains to the previous
(`prev_hash`, `record_hash` over canonical JSON); fsync before progress;
bound to one plan hash at genesis. Load verifies the whole chain
(`JOURNAL_TAMPERED` on any edit/deletion/reorder). Restart rules:

- in-flight step ⇒ `require_no_in_flight` refuses staging/broadcast
  (`RECONCILIATION_REQUIRED`);
- re-staging/re-signing an in-flight step ⇒ `DUPLICATE_ECONOMIC_ACTION`;
- reconciliation transitions require the ORIGINAL deploy hash recorded at
  submission; a different hash refuses. Unknown outcomes therefore go to
  reconciliation by the original hash — never to a second economic action.

In this lane real steps never advance beyond `AUTHORIZATION_VALIDATED`;
the later states are exercised by tests only.

## 5. Broadcast guard (disabled here)

Gate order: (1) journal exists + chain verifies + plan hash matches;
(2) Codex live authorization file at the FIXED mount
`/run/concordia/mainnet_canary/live_authorization.json` — absent ⇒ stable
refusal `BROADCAST_DISABLED_AUTHORIZATION_ABSENT` (the preparation-lane
state); (3) authorization schema/RC-tag/plan-hash/ceiling/expiry validation,
secret-scan; (4) fully-MEASURED estimate within BOTH the public ceiling and
the authorization ceiling; (5) no in-flight steps; (6) per-step interactive
TTY confirmation typing the exact step id; (7) submission itself is **not
implemented** in this lane and unconditionally refuses
(`SUBMISSION_NOT_IMPLEMENTED_IN_PREP`). There is no `--yes`, no environment
bypass (the package reads no environment variables), no development mode, no
automatic approval, and no generic retry. Tests prove a crafted authorization
file still cannot reach a submission.

## 6. Exact future human/operator inputs needed (no secrets in chat)

1. **Codex**: annotated Testnet-RC tag + `rc-declaration.v1` (all gates
   green, peeled SHA, Wasm hashes, measured `User error` rendering).
2. **Codex**: resolution of finding B1 — a reproducible Mainnet-chain v3
   Wasm attestation (`mainnet_wasm_sha256`, chain constant `casper`).
3. **Codex/Asad**: dedicated Mainnet public-key inventory via file mount
   (public keys + account hashes + key-file mount references only). Keys
   themselves stay under `/run/secrets/mainnet_canary/` and are never read
   by this tooling.
4. **Codex**: measured exact-equivalent Testnet costs
   (`testnet-measured-costs.v1.json`).
5. **Asad**: signed-off public maximum-CSPR ceiling document (no secret).
6. **Codex**: canary parameters (proposal id, nonces, governance roots,
   `max_amount_motes`) plus fresh snapshot/status observations from
   credential-free public RPC reads.
7. **Codex**: second disjoint-host public Mainnet RPC endpoint (B3).
8. **Codex only, last**: the live authorization file at the fixed mount,
   plus per-step interactive confirmation during the serialized live run.

## 7. Test inventory and results

`tests/mainnet_canary/` — **135 tests**, all passing; three consecutive
stable runs (135/135/135). Coverage (failure-first):

- Golden vectors + dual-implementation crosscheck (incl. §7 relationship
  vectors, Mainnet-chain envelope divergence, forced-disagreement refusal).
- RC gate: absent/malformed declaration, red gates, Testnet chain/endpoint
  in Mainnet mode, wrong commit, dirty tree, wrong Wasm, missing/invalid
  Mainnet-Wasm attestation, Testnet-hash reuse, historical drift (file-level
  and inventory-level), secret material refused without echo.
- Cost model: all-UNKNOWN refusal at the prep base, partial measurement
  refusal, ceiling absent/exceeded, optional-refusal approval gating,
  determinism, malformed documents.
- Inventory/keys: absent/malformed, account-hash recomputation mismatch,
  missing/duplicate/overlapping roles, source=recipient, Testnet network,
  Testnet identity reuse, secret-path read refusal, non-mount key reference.
- Plan/stage: missing inputs, stale/foreign/Testnet snapshots, tiny-cap
  violation, non-executable decision, zero nonce, tampered plan hash,
  snapshot drift at stage, content-addressed unsigned intents, idempotent
  re-stage, in-flight restart refusal.
- Journal: tamper (edit + deletion), illegal transitions, plan-hash binding,
  restart duplicate-action refusals for SIGNED/SUBMITTED/UNKNOWN,
  original-deploy-hash reconciliation, terminal-state sealing.
- Verify: pending/unsigned/malformed/non-member evidence, pre-quorum
  success refusal, wrong refusal code, exact `QuorumNotMet` acceptance,
  wrong contract/entry-point/typed-args, wrong transfer
  source/recipient/amount/id, absent/ambiguous observations, end-to-end CLI
  verify that never claims a Mainnet-verified state.
- Broadcast guard: stable absent-authorization refusal, env-bypass
  ineffectiveness, no bypass flags in the parser, journal-before-
  authorization, crafted-authorization still refused (non-TTY, wrong plan
  hash, waived confirmation, ceiling breach, in-flight block), and the
  terminal `SUBMISSION_NOT_IMPLEMENTED_IN_PREP`; static assertion that no
  signing/submission surface is imported anywhere in the package.
- Lineage: `artifacts/**` writes refused in prep, canonical prefixes
  protected, schema-only fixtures verified free of invented evidence.
- Secrets: hostile inputs never appear in stdout/stderr/exceptions/journal/
  staged bytes; all package sources and fixtures scan clean.

Static checks: `ruff check tools/mainnet_canary/ tests/mainnet_canary/`
clean. Dependency audit: stdlib + repo-internal `shared/` only; nothing new
vendored; no Authorization header anywhere.

Pre-existing repo suite: at base `7668fa4` — 901 passed, 11 errors (all in
`tests/test_assemble_proof_registry.py`, an environment-dependent module
fixture). With this branch applied the same 11 errors remain and no other
test changed state (see commit message for the fresh totals).

## 8. Clean-branch proof

Work is committed on `claude/mainnet-canary-prep` only; `git status` clean
after commit; `git diff --check` clean; no other branch touched, nothing
pushed. Stop point per assignment: local preparation only — Codex alone
audits, merges, computes the live ceiling, requests Asad's explicit spending
authorization, and performs the serialized Mainnet canary.
