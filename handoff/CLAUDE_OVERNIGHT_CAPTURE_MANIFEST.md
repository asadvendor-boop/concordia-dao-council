# Overnight capture tooling — interface manifest (C1 + C2)

Branch `claude/overnight-capture`, base immutable `b4115f1`. All work is
local code + tests. No live system, secret, wallet, chain, DNS, npm,
GitHub, tag, `main`, or Codex worktree was mutated. Every generator is
capture/assembly (and, for C2, prepare/import) ONLY: no facilitator call,
no signing, no Casper broadcast, no service restart, no key read, no live
artifact mutation.

## Architecture — strict orchestration over frozen production helpers

Nothing here reimplements cryptography, canonicalization, or secure I/O.
Every generator imports and orchestrates the accepted production helpers,
then self-verifies the assembled artifact against the accepted in-process
adapter before an atomic mode-0600 write-once:

- Canonical ASCII JSON: `shared.official_x402_release_adapter._canonical`
  / `shared.release_proof_adapters._canonical` (json.dumps sort_keys,
  separators `(",",":")`, ensure_ascii, allow_nan=False; NO trailing
  newline — the adapters recompute and compare byte-for-byte).
- Descriptor-safe read (O_NOFOLLOW + inode/digest recheck):
  `shared.secure_secret_file.read_secure_secret_file`.
- Atomic mode-0600 write-once (O_EXCL+O_NOFOLLOW, hardlink commit, never
  overwrite): `shared.atomic_private_file.write_private_file_once`.
- x402 crypto: `_eip712_digest`, `_payment_requirements_hash`,
  `_signed_payload_hash`, `_resource_url_hash`, `_report_hash`,
  `_account_hash_from_public_key`, `_verify_casper_eip712_signature`,
  `_runtime_args_expected` from `shared.official_x402_release_adapter`.
- SafePay crypto: `safepay_v2_correlation_id`, `safepay_v2_quote_hash`,
  `safepay_v2_response_hash`, `safepay_v2_body_digest`,
  `safepay_v2_error_body` from `shared.x402_payments`.

Production modules import ONLY from `shared.*` (never from tests). Tests
may mirror the existing fixtures to construct raw inputs.

## C2 — official x402 (`scripts/official_x402_capture.py`)

Three subcommands. Frozen network `casper:casper-test`, WCSPR package
`3d80df21…847c1e`, contract `032706ae…35f4a`, facilitator origin
`https://x402-facilitator.cspr.cloud`. CSPR.cloud auth is the raw token,
never `Bearer`; the token, Authorization header, and any non-2xx body are
never printed or persisted.

### `prepare` (DONE, committed d737fd5)

```
python3 -m scripts.official_x402_capture prepare --request <req.json> --out <prepared.json>
```

Input (`concordia.official_x402_prepare_request.v1`): `accepted` payment
requirements, `resource`, `report_base64`, v3 typed action `body`,
`payer_account_hash`, `payee_account_hash`, `value`, `valid_after`,
`valid_before`, `nonce`. Output
(`concordia.official_x402_prepared_authorization.v1`): the EIP-712 domain
+ message + the 32-byte digest (validated against the frozen
cross-language golden `51aeaf3a…25dc`), the payment-requirements /
resource-URL / report bindings, and the echoed accepted/resource/report.
Emits bytes for browser signing; NEVER signs. Fails closed on
network/asset/scheme/amount/payTo/value/window/nonce/body-binding drift.

### `import` (DONE, committed d737fd5)

```
python3 -m scripts.official_x402_capture import --prepared <prepared.json> --signed <signed.json> --out <imported.json>
```

Input `signed.json` = the CSPR.click `{signatureHex, publicKeyHex}`.
Verifies the tagged secp256k1 (preferred) or ed25519 signature offline
against the prepared digest, requires the signature tag to equal the key
tag, derives the payer account hash and cross-checks it against the
prepared payer, builds the signed payload, and freezes the byte-identical
canonical `/verify` and `/settle` request bodies (serialized exactly
once). Output `concordia.official_x402_imported_authorization.v1`.

### `capture` (DONE, committed a861b5c)

```
python3 -m scripts.official_x402_capture capture --bundle <bundle.json> --out <ABS_PATH>
```

Input: a frozen raw capture bundle
(`concordia.official_x402_capture_bundle.v1`) carrying ONLY raw evidence
— the `import` subcommand's output (`imported_authorization`), the v3
proof bytes, the report bytes, the three facilitator exchanges
(`supported`/`verify`/`settle`: status + observed_at + response body; the
requests are re-derived from the signed payload so they cannot drift),
the three WCSPR readback RPC transcripts, the two settlement-provider RPC
transcripts (info_get_transaction/chain_get_block/info_get_status), and
the fulfillment/journal observation times + service instance ids.

DERIVED (never trusted): every sha256/hash, the settle `call_id`, the
`journal_root`, `parsed_verify`/`parsed_settle`/`parsed_settlement`, the
`governance_binding` (via `verify_v3_proof_document`, mirroring the
adapter's `_verify_v3` extraction), `release_order` (v3_finalized_at from
the proof, settlement_finalized_at = row.settledAt, report_released_at =
first_release.observed_at — pinned to the rest of the evidence, not a
free input), and the full chronology. The three SQLite journal snapshots
are built by executing the frozen migration
`services/x402-official/migrations/0002_upstream_settle_journal.sql`
(5206-byte / `c660abc…` pin verified before use), inserting the two
derived rows, and backing up once (byte-identical snapshots). `/settle`
status is required to be exactly 200; non-2xx bodies are refused before
decode; the CSPR.cloud token / Authorization header is never read. Self-
verifies with `verify_official_x402_artifact` in-process, then atomic
mode-0600 write-once.

Tests: **44 passed** (20 prepare/import + 24 capture) — positive
end-to-end (ed25519 + secp256k1) with fresh adapter acceptance,
journal-property + write-once guards, and 21 failure-first mutations each
refusing by the specific adapter check name.

**Honest coverage note:** six named adapter checks
(OX-02/03/04/06/08/18) are not independently reachable from a single
bundle mutation — the generator emits the configured resource, the
signed-payload resource, `accepted`, and the requirements argument from
the SAME inputs and recomputes the payer/hashes/fulfillment row, so those
fields can never disagree; mutating the underlying input trips an earlier
recomputed-hash/signature check (OX-05/07/10/11/01) instead. That the
assembler cannot emit an internally inconsistent artifact is the intended
property, demonstrated by the mutations that land on the adjacent checks.

## C1 — SafePay v2 (`scripts/safepay_v2_capture.py`) (DONE, committed 77dd1c7)

```
python3 -m scripts.safepay_v2_capture capture --bundle <bundle.json> --output <ABS_PATH>
```

Input: a frozen raw capture bundle
(`concordia.safepay_v2_capture_bundle.v1`, exact key set) carrying ONLY
raw evidence — the provider identities (before/after restart), the quote
inputs, the report bytes, the two-node Casper RPC transcripts
(info_get_deploy/chain_get_block/info_get_status ×2), the three provider
`POST /x402/v2/redemptions` exchanges (first 200 / exact-retry 200 /
cross-binding 409), the consumption/quote-row observation times, and the
three ledger-snapshot observation times. `capture_tool_commit` is bound
to `source_commit`.

DERIVED (never trusted): correlation id, quote hash, report hash,
response hash (via the frozen `shared.x402_payments` crypto); the
`parsed_transfer` by re-parsing the raw two-node RPC exactly as the
adapter's `_verify_rpc_providers` does; provider `instance_id`s; the
quote/consumption rows + canonical row digests; and the three progressive
SQLite ledger snapshots (repo migration `x402_provider/migrations/
0001_safepay_v2.sql` executed, derived rows inserted, redemption journal
appended, `connection.backup()` after each stage — first two snapshots on
the before-restart instance, third on the after-restart instance).
`transfer_id` must equal the derived quote `correlation_id`; ≥8
confirmation depth enforced. Self-verifies with
`verify_safepay_v2_artifact(doc, _canonical(doc))` in-process, then writes
the exact canonical bytes (no trailing newline) via mode-0600 write-once.

Output artifact target (per the release registry): `artifacts/live/
safepay-lite-replaysafe-v2.json` (Codex places it during live capture).

Tests: **29 passed** — 1 positive end-to-end (all 11 named adapter checks
+ fresh-process re-verify), a 23-case raw-input mutation matrix (each
refusing for its intended adapter reason), and write-once / canonical-
bytes / mode-0600 / relative-path guards.

**Honest coverage note:** the two pure self-consistency checks
(`quote_hash_recomputed`, `report_hash_recomputed_and_matches_quote`)
cannot be made to FAIL by corrupting a bundle input, because a
derive-everything generator recomputes both consistently. They are
instead exercised through malformed-preimage and chronology inputs —
the honest reachable rejection surface for a generator that derives
rather than trusts. This is inherent, not a coverage gap.

## Delivery — commits (all on `claude/overnight-capture`, base `b4115f1`)

| Commit | Content |
|---|---|
| `d737fd5` | C2 prepare + import generators + tests |
| `77dd1c7` | C1 SafePay v2 capture generator + tests |
| `a861b5c` | C2 official-x402 capture subcommand + tests |
| (this) | handoff manifest |

Changed-file map: `scripts/official_x402_capture.py` (new),
`scripts/safepay_v2_capture.py` (new),
`tests/test_official_x402_capture.py` (new),
`tests/test_safepay_v2_capture.py` (new),
`handoff/CLAUDE_OVERNIGHT_CAPTURE_MANIFEST.md` (new). No other file
touched; schemas, adapters, and the migration were read-only.

## Test gates (all green; independently re-run by me, not trusted from the builders)

- `tests/test_official_x402_capture.py` — **44 passed** (20 prepare/import
  + 24 capture; ed25519 + secp256k1; digest-golden; every fail-closed
  guard; failure-first mutations by adapter check name).
- `tests/test_safepay_v2_capture.py` — **29 passed** (positive end-to-end
  + 23-case mutation matrix + write-once/canonical/0600 guards).
- Full regression sweep (both capture suites + the reference adapter and
  SafePay suites) — **206 passed, 0 failed**, no regression.

## How Codex uses these at live-capture time

1. `prepare` → hand `eip712.digest_hex` to Asad's CSPR.click wallet.
2. Asad signs; the wallet returns `{signatureHex, publicKeyHex}`.
3. `import` (offline) → verifies + freezes the `/verify` and `/settle`
   request bytes; Codex sends those exact bytes to the facilitator.
4. Codex collects the raw evidence (facilitator exchanges, journal
   snapshots straddling a service restart, two Casper RPC observations,
   WCSPR readbacks, paid-resource exchanges, runtime digests) into the
   frozen capture bundle.
5. `capture` → derives every field, self-verifies against the accepted
   adapter, and write-once-emits the artifact for the release registry
   (official → the official-x402 live-artifact slot; SafePay →
   `artifacts/live/safepay-lite-replaysafe-v2.json`).

## Remaining live inputs (Codex supplies at live-capture time)

The generators are offline assembly tools; the RAW inputs they consume are
produced during the live capture Codex runs after the RC merge/deploy:
the real `/supported` + signed `/verify` + `/settle` exchanges, the three
finalized SQLite journal snapshots straddling a real service restart, the
two independent finalized Casper RPC observations, the WCSPR
balance/nonce readbacks, the finalized v3 proof, the paid-resource
first/retry/cross exchanges, and the runtime image/source digests. Asad
performs the browser signature (prepare → wallet → import).
