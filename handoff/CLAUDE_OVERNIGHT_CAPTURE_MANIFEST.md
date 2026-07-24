# Capture tooling correction manifest — official x402 + SafePay v2

Correction branch `codex/capture-evidence-correction`, based on
`b05b355e7080a428dff35f1744707c62c5a18396`. The original overnight
assembler work remains in history; the correction commits replace its
evidence model without touching adapters, schemas, migrations, runtime
services, or live artifacts.

All work in this branch is local code, tests, and this manifest. No VM,
container, Caddy, DNS, wallet, secret mount, Casper RPC, facilitator,
Mainnet/Testnet transaction, npm, GitHub, or live artifact was accessed or
mutated.

## Hard boundary: assembler, not collector

`scripts/official_x402_capture.py` and `scripts/safepay_v2_capture.py` are
offline **assemblers and validators**. They do not:

- make facilitator, paid-resource, provider, or Casper RPC calls;
- read a live service database;
- perform a SQLite online backup;
- create or insert a quote, report, consumption, redemption, settlement, or
  fulfillment row;
- sign, submit, settle, redeem, restart, or deploy anything; or
- turn fixture-shaped inputs into qualifying live evidence.

The live release operator must first run a separately bound collector that
records the exact bytes returned by the real services and produces the actual
SQLite online-backup bytes. The assemblers then derive projections from those
raw bytes, self-verify the result through the accepted in-process adapters,
and perform an owner-private create-once write.

An assembled file is **not qualifying evidence by itself**. It becomes
qualifying only when the bound live collector receipt is accepted into the
`shared.release_manifest` G12 flow and appears in the G12
`proof_verifier_receipts` inventory with matching source/deployment/runtime
identity, artifact digest, capture chronology, and a successful offline
adapter replay. Fixture output, hand-built JSON, or an assembler-only success
must never flip a proof-registry item to verified.

## Shared custody and byte rules

- Control inputs are absolute, owner-owned regular files with mode `0400` or
  `0600`, read through
  `shared.secure_secret_file.read_secure_secret_file`. Descriptor-relative
  `O_NOFOLLOW` traversal and stable file-identity checks reject symlinks,
  relative paths, unsafe modes, and files that change during the read.
- Outputs require an explicit absolute path and are written once, mode `0600`,
  through `shared.atomic_private_file.write_private_file_once`.
- Canonical artifact JSON uses the accepted adapter canonicalizer and has no
  trailing newline.
- Full artifacts are never written to stdout. The official-x402 CLI emits only
  a bounded write receipt containing the artifact SHA-256; SafePay emits no
  success document.

## C2 — official x402 assembler

File: `scripts/official_x402_capture.py`

### `prepare`

Builds the browser-reviewable EIP-712 domain/message/digest from the frozen
payment requirements, resource, report, and typed v3 action. It never signs.
The original request and its canonical SHA-256 are retained so `import` can
re-derive the complete prepared record and refuse post-prepare drift.

### `import`

Verifies the tagged secp256k1 or ed25519 wallet signature offline, derives and
checks the payer account hash, builds the production-nested
`paymentPayload.payload.authorization` shape, and serializes the exact
`/verify` and `/settle` request body once. The frozen canonical request bytes
and SHA-256 are carried forward.

### `capture`

Consumes raw evidence only:

- the complete imported authorization record;
- raw `/supported`, `/verify`, and `/settle` request/response bytes, status,
  content type, URL, and observation time;
- raw WCSPR and settlement-provider RPC request/response bytes;
- raw paid-resource request and response header bytes, body bytes, status, and
  observation time;
- exact canonical fulfillment-row bytes;
- three actual upstream-settlement SQLite backup byte strings; and
- v3 proof bytes and service/runtime identity observations.

The assembler byte-matches the raw `/verify` and `/settle` request bodies to
the request frozen by `import`; it does not re-create a request and call that
observation. It parses all response projections from the supplied raw bytes.
Non-200 settlement responses refuse before response-body interpretation.

The three journal snapshots are the supplied real SQLite backup bytes. The
assembler opens in-memory read-only copies, runs integrity/schema/row
progression checks, derives the journal roots and backup hashes, and preserves
the exact bytes. It never executes the migration to manufacture a database,
never inserts a row, and never synthesizes a success, failure, HTTP status,
body, or fulfillment.

The resulting document is accepted only if
`verify_official_x402_artifact(document, canonical_bytes)` succeeds.

Correction commit:

- `c592e90` — raw facilitator/RPC/paid-resource/row/SQLite evidence,
  frozen-request byte matching, import re-derivation, absolute bounded output,
  and failure-first tests.

## C1 — SafePay v2 assembler

File: `scripts/safepay_v2_capture.py`

The capture bundle contains only:

- provider identities before and after the observed restart;
- two raw Casper RPC transcript sets;
- three exact raw `POST /x402/v2/redemptions` exchanges; and
- three actual provider-ledger SQLite online-backup byte strings with their
  observation times.

The assembler derives the target network/payment/quote binding from the first
raw redemption request. It reads the authoritative report, quote, consumption,
and redemption rows from each supplied backup, verifies SQLite integrity, and
requires the three backups to be an append-only 1/2/3-observation progression
of the same persisted fulfillment across the restart.

The quote correlation ID and quote hash are recomputed from the persisted row.
The report hash is recomputed from the persisted BLOB. The native transfer is
re-parsed from both raw RPC transcript sets. Redemption status, request,
response body, chronology, response digest, and consumption binding come from
the raw HTTP exchanges plus the persisted redemption rows. Ledger evidence
preserves and hashes the supplied backup bytes; production code performs no
SQLite insert, migration execution, or backup creation.

The resulting document is accepted only if
`verify_safepay_v2_artifact(document, canonical_bytes)` succeeds.

Correction commit:

- `bb1787b` — raw HTTP and SQLite evidence, persisted-row derivation,
  descriptor-safe bundle input, append-only restart progression, and
  failure-first tests.

## Verification

Fresh results in this correction worktree:

- official-x402 capture suite: `53 passed`;
- SafePay-v2 capture suite: `32 passed`;
- combined capture suites: `85 passed`;
- wider official-x402/SafePay capture, adapter, schema, hardening, gateway,
  ledger, runtime-truth, verifier, and governance-staging sweep:
  `471 passed, 0 failed`;
- Ruff: clean for both scripts and both focused test files;
- `compileall`: clean for both scripts;
- `git diff --check`: clean.

The focused negative cases include missing raw exchanges, altered raw
responses, altered canonical row bytes, altered SQLite backup bytes, request
drift after prepare/import, unsafe input modes, symlink input, stdin input,
relative output, and overwrite attempts. Positive controls exercise both
`0400` and `0600` descriptor-safe reads.

## Live-release handoff

At release time the sole release operator must:

1. collect raw service/RPC/HTTP bytes and actual SQLite online backups using
   the release-bound collector;
2. bind the collector output to the exact release source commit, deployment
   commit, runtime image/service identities, and capture time;
3. run these assemblers from the frozen release source;
4. replay the accepted adapters over the exact emitted bytes;
5. admit the proof only through the G12 `proof_verifier_receipts` gate; and
6. leave the proof unavailable/pending if collection, binding, adapter replay,
   or G12 receipt verification is absent.

No claim in this manifest asserts that those live steps have occurred.
