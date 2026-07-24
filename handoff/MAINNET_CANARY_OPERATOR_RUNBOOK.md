# Mainnet Canary — Operator Runbook (Calibration & Execution Order)

Status: PREPARATION LANE. Nothing in this runbook signs, submits, or claims a
live result. Every live claim remains `BLOCKED_PENDING_LIVE_PROOF` until the
named artifact exists. Custody disclosure: `single_operator` — one operator
holds every role key; distinct accounts and key mounts are NOT custody
independence and the tooling refuses any other declaration in this release.

Roles (fixed):
- **Codex/Sol** — sole live release operator; signs and submits automated
  Casper **Testnet** calibration deploys via the approved server-held key
  mount; owns merge/release/deployment.
- **Asad** — personally performs any Casper Wallet / CSPR.click browser
  signature; provisions funding outside this tooling.
- **Claude** — local code, tests, docs, read-only review. No keys, no
  broadcast, no VM, no live artifacts.

Hard rules:
1. **Never** print key material, tokens, mounted secret contents, or
   authorization signatures — into logs, JSON, shells, or handoff files.
2. **No operator ceilings.** `funding`/`stage` refuse
   (`OPERATOR_CEILING_NOT_PERMITTED`) if any are supplied. Every fee maximum
   comes from a finalized exact-equivalent Testnet receipt.
3. **Do not calibrate against a stale plan.** The calibration binds
   `canary_plan_sha256`; it must be generated against the FROZEN final plan
   only, after Codex reviews the final Mainnet head. A calibration produced
   against any earlier commit's plan refuses (`CALIBRATION_BINDING_INVALID`).

## 0. Freeze order (before any deploy)

1. Claude hands over the final Mainnet head (immutable; `2c945b3` remains an
   ancestor and is never amended).
2. Codex reviews that exact head and freezes the resulting plan:
   `python3 -m tools.mainnet_canary plan --rc-declaration … --key-inventory …
   --parameters … --snapshot … --status … --custody-model single_operator
   --out plan.json`
   Record `canary_plan_sha256`. This hash is what every downstream artifact
   binds.

## 1. Testnet calibration (Codex; the only signing party)

The plan derives its own economic-step set — 7 fixed steps plus one
`F-approve-*` vote per threshold signer (threshold 3 ⇒ **10** economic
steps). Calibration must cover exactly that set: no missing line, no extra
line (`CALIBRATION_LINE_SET_MISMATCH`).

Per economic step, in plan order:

1. **prepare** — build the exact-equivalent Testnet deploy: identical entry
   point, identical argument names/types/order. Values may differ ONLY on
   the reviewed network-profile fields (chain name, per-network identities,
   nonces, derived identifiers, balance-derived amounts) — the converter
   derives and checks this list; any other drift refuses.
2. **validate / dry-run** — no submission; confirm the deploy body renders
   and the argument shape matches the plan step.
3. **explicit `--submit`** — submission must be a separate, explicit flag in
   Codex's harness; never a default.
4. **reconcile by the authoritative ORIGINAL deploy hash** — the hash
   computed at signing time is the identity; never re-derive it from a
   node's echo.
5. **two-node finalized observations** — capture the finalized execution
   result from two disjoint providers (different `provider_id` AND
   different `endpoint_host`), each with the raw response's SHA-256, at
   depth ≥ 8 (`chain_tip_height − block_height ≥ 8`).

### F9 choreography (refusal probes calibrate their refusals)

The Testnet F9 deploy must use the SAME coherent redirected construction as
the Mainnet plan (mirroring
`contracts/odra-governance-receipt-v3/tests/network_profile.rs`):
copy the approved envelope, set `recipient_account` to the finalizer's
account, recompute `action_id` from the redirected action core, put it in
the header, recompute `transfer_id` from it, and KEEP the originally
approved envelope commitment on chain. Expected finalized result:
`User error: 10` (`EnvelopeHashMismatch`) exactly. A naive recipient-only
change finalizes with `User error: 16` and its receipt is refused by the
calibration checker. E expects `User error: 8`; H expects `User error: 12`.
These three deploys FAIL on purpose, still consume fees, and their receipts
carry the exact expected error or they do not count.

## 2. Generate and validate the calibration document

Write one harness observation JSON per economic step (template below), then:

```
python3 -m tools.mainnet_canary calibration --plan plan.json \
  --harness obs-B.json --harness obs-D.json … --out calibration.json
python3 -m tools.mainnet_canary calibration --plan plan.json \
  --calibration calibration.json
```

The converter computes every digest itself (plan args from the plan,
Testnet args from the harness files) and derives the translated-field list
by comparison — hand-transcribed calibration lines are not an input format.

### Harness observation template (`testnet-harness-observation.v1`)

```json
{
  "schema_id": "concordia.mainnet-canary.testnet-harness-observation.v1",
  "step_id": "D-propose-envelope",
  "testnet_chain_name": "casper-test",
  "signer_public_key_hex": "01<64 hex>",
  "entry_point": "propose_envelope",
  "wasm_sha256": null,
  "testnet_typed_args": [
    {"name": "proposal_id", "type": "String", "value": "<testnet value>"},
    {"name": "envelope_hash", "type": "ByteArray(32)", "value": "<64 hex>"}
  ],
  "deploy_payment_motes": "<amount extracted from the actual deploy>",
  "deploy_hash": "<64 hex — the ORIGINAL hash computed at signing>",
  "block_hash": "<64 hex>",
  "block_height": 123456,
  "execution": {"success": true, "error_message": null},
  "finality": {"chain_tip_height": 123464},
  "observations": [
    {"provider_id": "cspr-cloud", "endpoint_host": "node.cspr.cloud",
     "response_sha256": "<64 hex>"},
    {"provider_id": "casper-community", "endpoint_host": "node.example.org",
     "response_sha256": "<64 hex>"}
  ]
}
```

Notes:
- `wasm_sha256` is non-null ONLY for `B-install-rc-wasm` and must be the
  RC's **Testnet** Wasm hash (the Mainnet build is a disjoint artifact; the
  two are never byte-identical and the tooling refuses the claim).
- for E/F9/H set `"execution": {"success": false, "error_message":
  "User error: 8|10|12"}` respectively (exact strings from the plan).
- `deploy_payment_motes` is extracted from the deploy body, not typed from
  memory; the harness file's canonical SHA-256 becomes
  `harness_artifact_sha256`, so keep the files alongside the receipts.

## 3. Funding (exact number, no acquisition)

```
python3 -m tools.mainnet_canary funding --plan plan.json \
  --calibration calibration.json
```

Prints `required_funding_motes = principal + Σ calibrated maxima`. This
lane never purchases, transfers, bridges, or swaps; Asad provisions the
amount by hand. Run `funding` BEFORE any real CSPR is committed.

## 4. After calibration

`stage → (human authorization, signed ed25519, pinned keys) → broadcast
gate` remain exactly as manifested; nothing in this correction round opened
a signing or submission path in the preparation package (the banned-token
scan still enforces this). The proof bundle now refuses unless it discloses
`custody_model` equal to the plan's (`single_operator`).

## 5. Correction round: the live path (blockers 1–7 closed)

This round replaces every "prepared but not live" surface with a bounded,
fail-closed implementation.  Nothing below adds private-key handling to the
package; signing stays external (wallet), and the package imports signed
bytes only.

### 5.1 Executed attestation (`attest` mode) — blocker 1

```
python3 -m tools.mainnet_canary attest \
  --tag <annotated-rc-tag> --peeled-commit-sha <sha> \
  --cargo-path /absolute/path/to/cargo \
  --scratch-dir /tmp/canary-attest --out attestation.json
```

Runs the pinned cargo-odra release build TWICE per profile from independent
clean tag-tree exports and binds the result (tag object + peeled commit +
profile delta + toolchain + Cargo.lock digest + artifact path/size/bytes
hash) under canonical per-entry digests.  `stage` and `bundle` now REFUSE any
attestation that does not recompute against the repository
(`ATTESTATION_NOT_EXECUTED`) — a caller-authored summary with plausible
counters cannot pass.

### 5.2 Raw RPC evidence — blocker 2

Every calibration receipt observation and every step observation (schema
`step-observation.v3`) embeds the bounded raw `info_get_deploy` /
`chain_get_block` / `info_get_status` exchanges.  Digests recompute from the
embedded bodies; the deploy hash, block identity, membership, execution
result, and chain tip are re-derived FROM the bodies
(`RAW_EVIDENCE_ABSENT` / `RAW_EVIDENCE_MISMATCH` / `RAW_EVIDENCE_OVERSIZED`).
The read-only dual-node collector (`tools/mainnet_canary/collector.py`)
is the sanctioned producer; its output is secret-scanned.

### 5.3 Live submission boundary — blocker 3

`tools/mainnet_canary/submission.py` is the ONLY module that can broadcast:

1. import externally wallet-signed deploy bytes (never below a secret mount);
2. recompute the authoritative deploy hash from the bytes;
3. persist `SIGNED` (deploy hash + signed-bytes SHA-256) durably BEFORE any
   network call; different bytes later refuse (`SIGNED_BYTES_MISMATCH`);
4. transition `SUBMITTED` under the exclusive journal lock, then fire the
   single RPC; any failure leaves the step in flight
   (`SUBMISSION_UNKNOWN`) — reconciliation by the ORIGINAL hash is the only
   continuation.  A second broadcast is impossible across restart.

### 5.4 Testnet calibration harness — blocker 4

`tools/mainnet_canary/harness.py`: per plan-derived economic step,
prepare → validate/dry-run → explicit submit (journal-backed, exactly once)
→ reconcile by original hash → dual-node depth≥8 raw-evidence observation →
`testnet-harness-observation.v2` document → `calibration` conversion.  The
step set derives from the FINAL plan; argument names/types/order must equal
the Mainnet step's exactly.

### 5.5 Retired inputs — blocker 6

`testnet-calibration.v2` is the SOLE cost authority.  Supplying the legacy
measured-costs or spend-ceiling documents refuses
(`LEGACY_COST_INPUT_UNSUPPORTED`); operator ceilings refuse
(`OPERATOR_CEILING_NOT_PERMITTED`).  No fixed line-item list and no assumed
vote count remain on the stage/broadcast path.

### 5.6 Proof-bundle revalidation — blocker 7

`bundle` now REVALIDATES every constituent: the manifest must recompute from
plan+calibration, the attestation must verify against the repository, the
signed human authorization must re-verify against the manifest/clock/pinned
keys, the verification report's step set must equal the plan-derived
economic set EXACTLY (`PROOF_STEP_SET_MISMATCH` on empty/missing/duplicate/
extra), and every economic step must be terminally journaled.  New required
arguments: `--calibration --authorization --clock-unix --authorizer-key`.

### 5.7 Nested-schema discipline — blocker 5

All nested observation structures (block, execution, provider, finality,
raw exchanges) validate with exact key sets and types BEFORE any indexing:
malformed input returns a stable refusal code, never a traceback.
