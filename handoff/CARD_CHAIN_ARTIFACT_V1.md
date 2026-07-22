# Concordia sealed card-chain artifact v1

Status: **mandatory post-G1 release delta** for the independent verifier.

The existing public evidence JSON is a humanized/reconciled view. It may rename
fields and summarize superseded receipt cards, so it is not a cryptographic hash
preimage and must never be used to claim that card hashes were recomputed.

## Exact artifact

Stable public route:

```text
GET /proof-artifacts/v1/{proposal_id}/card-chain
```

Committed capture path for the historical reviewer proposal:

```text
artifacts/live/canonical-card-chain-v1.json
```

The JSON object has exactly these fields:

```json
{
  "schema_version": "concordia.card_chain.v1",
  "proposal_id": "DAO-PROP-6CB25C",
  "captured_at": "RFC3339 UTC",
  "source_url": "https://.../proof-artifacts/v1/DAO-PROP-6CB25C/card-chain",
  "cards": []
}
```

Every item in `cards` has exactly:

```json
{
  "sequence_number": 1,
  "card_type": "ProposalCard",
  "card_hash": "lowercase 32-byte hex",
  "canonical_card_json": "the exact UTF-8 cards.card_json string stored by seal_card",
  "published_at": "RFC3339 UTC or null"
}
```

`canonical_card_json` is emitted byte-for-byte from the existing database row.
It is not parsed and reserialized by the producer. The frozen historical rows
are read in one SQLite read transaction ordered by `sequence_number`; no row is
updated and no card is appended.

## Independent verification

The verifier must ignore `chain_valid`, `verified`, `passed`, or any other
asserted boolean and derive all results:

1. Reject unknown/missing fields and duplicate JSON keys.
2. Require top-level and per-card types exactly as specified.
3. Require a non-empty chain with sequence numbers exactly `1..N`.
4. SHA-256 the exact UTF-8 bytes of `canonical_card_json` and compare with
   `card_hash` using constant-time equality.
5. Parse `canonical_card_json` as a JSON object and require its
   `sequence_number` and `card_type` to equal the wrapper.
6. Require the first parsed `previous_card_hash` to be null and every later
   parsed `previous_card_hash` to equal the preceding wrapper `card_hash`.
7. Reject a parsed `card_hash` field: the preimage stored by `seal_card`
   deliberately excludes it.
8. Require the terminal wrapper `card_hash` to equal the historical receipt's
   `final_card_hash` when the registry item supplies that receipt binding.

## Publication and registry rules

- The Gateway applies response-size and card-count limits and emits
  `Cache-Control: no-store` until the release capture is frozen.
- Before public deployment, the exact historical preimages must pass the
  repository secret/redaction scanner. Any secret-like value blocks release;
  the preimages may not be altered to make the scan pass.
- The historical `historical_odra_receipt_v2` registry item links this artifact
  with `rel=card_chain`, `kind=download`, its SHA-256, capture time, and source
  commit.
- Missing, malformed, unaudited, stale, or unreachable artifacts are
  `unavailable` or `invalid`, never verified.
- Publishing this read-only artifact does not rewrite the frozen 12-card chain
  and does not make v3 enforcement retroactive.
