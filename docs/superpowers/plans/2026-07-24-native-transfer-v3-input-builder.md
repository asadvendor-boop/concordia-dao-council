# NativeTransferV1 Production Input Builder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete `NativeTransferV1` typed input for `scripts/prepare_v3_envelope.py` exclusively from strict, mutually consistent release artifacts and a two-node Testnet treasury snapshot.

**Architecture:** A pure builder module loads each source exactly once, rejects duplicate-key or malformed JSON, and independently verifies the historical receipt, finalized v3 deployment, treasury snapshot, and operator intent before deriving any typed field. It computes subordinate evidence/metadata roots and deterministic nonces from exact source bytes, then calls `shared.actions_v3.build_native_material` as the final frozen-schema authority. A thin CLI publishes the typed input and derivation manifest together in one atomically renamed directory.

**Tech Stack:** Python 3.12, `pycspr`, existing Concordia v3 encoders/verifiers, `pytest`.

## Global Constraints

- Start from exact commit `b4115f1287056a20fd1aefef99f31c4e77ce229b`.
- Never perform network I/O, signing, secret access, VM access, or chain mutation.
- Never write to `artifacts/live`.
- Require network identity `casper-test` everywhere; reject aliases.
- Require exactly `625000000000` treasury motes, `3000` requested bps, `800` approved bps, and derive exactly `50000000000` transfer motes.
- Derive roots, nonces, action ID, transfer ID, and envelope hash; never accept them from the operator.
- Reuse `shared/envelope_v3.py`, `shared/actions_v3.py`, `shared/evidence_manifest_v3.py`, and `shared/metadata_manifest_v3.py`.

---

### Task 1: Strict Source Verification and Typed Input Derivation

**Files:**
- Create: `shared/native_transfer_input_v3.py`
- Create: `tests/native_transfer_input_fixtures.py`
- Test: `tests/test_native_transfer_input_v3.py`

**Interfaces:**
- Consumes: raw historical Odra artifact bytes, its exact frozen inventory bytes, raw canonical receipt bytes, raw finalized v3 deployment-manifest bytes, raw treasury-snapshot bytes, and raw native-transfer-intent bytes.
- Produces: `build_native_transfer_input(...) -> NativeTransferInputBuild`, whose `typed_input` is accepted unchanged by `prepare_v3_envelope`.

The intent is an exact-field JSON object. It supplies only the human-selected
accounts and the already-established 30% request; every cryptographic field is
derived:

```json
{
  "schema_id": "concordia.native-transfer-v3-intent.v1",
  "network": "casper-test",
  "intent_id": "finals_native_transfer",
  "canonical_proposal_id": "DAO-PROP-6CB25C",
  "source_account_hash": "<64 lowercase hex>",
  "recipient_account_hash": "<64 lowercase hex>",
  "requested_allocation_bps": 3000,
  "captured_at": "<RFC3339 UTC>"
}
```

- [x] **Step 1: Write failing positive and mutation tests**

Cover the exact 625 CSPR to 50 CSPR result and failure for duplicate JSON keys, wrong network, receipt-root disagreement, unfinalized deployment observations, one-node/provider disagreement, non-final snapshot status, wrong treasury balance, malformed accounts, and source/recipient equality.

- [x] **Step 2: Run the tests and observe the expected missing-module failure**

Run:

```bash
python -m pytest -q tests/test_native_transfer_input_v3.py
```

Expected: collection fails because `shared.native_transfer_input_v3` does not exist.

- [x] **Step 3: Implement minimal strict verification and derivation**

Parse the same raw bytes that are hashed into the evidence manifest. Verify the historical receipt with `verify_historical_odra_artifact`, canonical runtime arguments with `pycspr`, the install deploy and two-node finality with the v3 installer verifiers, and the treasury snapshot with `verify_treasury_snapshot_artifact`. Derive both nonces with distinct domain separators over the ordered source-digest set. Build the header/body with `build_native_material`.

- [x] **Step 4: Run focused tests to green**

Run:

```bash
python -m pytest -q tests/test_native_transfer_input_v3.py
```

Expected: all tests pass.

### Task 2: Atomic Production CLI

**Files:**
- Create: `scripts/build_native_transfer_v3_input.py`
- Create: `tests/test_build_native_transfer_v3_input.py`

**Interfaces:**
- Consumes: the five source artifact paths and a non-existing output directory.
- Produces: `<out-dir>/typed-input.json` and `<out-dir>/derivation-manifest.json`.

- [x] **Step 1: Write failing CLI tests**

Require a deterministic dry run, byte-identical repeated derivation, rejection of existing output targets, no partial directory on validation failure, and output accepted by `scripts/prepare_v3_envelope.py`.

- [x] **Step 2: Run the tests and observe the missing-CLI failure**

Run:

```bash
python -m pytest -q tests/test_build_native_transfer_v3_input.py
```

Expected: collection or subprocess failure because the CLI does not exist.

- [x] **Step 3: Implement the CLI and atomic directory publication**

Read every source once, build fully in memory, write both canonical JSON files to a sibling temporary directory, fsync files and directory, and atomically rename the directory to the requested target. Refuse existing, symlinked, relative, or `artifacts/live` output targets.

- [x] **Step 4: Run focused CLI and regression tests**

Run:

```bash
python -m pytest -q \
  tests/test_native_transfer_input_v3.py \
  tests/test_build_native_transfer_v3_input.py \
  tests/test_envelope_v3_encoder.py \
  tests/test_actions_v3_encoder.py \
  tests/test_verified_authorization_v3.py \
  tests/test_treasury_execution_operator.py
```

Expected: all tests pass.

### Task 3: Verification and Handoff

**Files:**
- Modify only files listed in Tasks 1 and 2.

- [x] **Step 1: Run syntax, diff, and relevant full regression gates**

```bash
python -m compileall -q shared/native_transfer_input_v3.py scripts/build_native_transfer_v3_input.py
git diff --check
python -m pytest -q tests/test_native_transfer_input_v3.py tests/test_build_native_transfer_v3_input.py
```

- [x] **Step 2: Review the diff against every global constraint**

Confirm there are no network clients, signer calls, secret paths, live-artifact writes, trusted verification booleans, caller-supplied roots, or changes outside the declared files.

- [x] **Step 3: Commit the isolated work package**

```bash
git add \
  docs/superpowers/plans/2026-07-24-native-transfer-v3-input-builder.md \
  shared/native_transfer_input_v3.py \
  scripts/build_native_transfer_v3_input.py \
  tests/native_transfer_input_fixtures.py \
  tests/test_native_transfer_input_v3.py \
  tests/test_build_native_transfer_v3_input.py
git commit -m "feat(release): build exact native transfer input"
```
