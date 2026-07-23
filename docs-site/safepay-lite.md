# SafePay Lite

SafePay Lite is Concordia's **supplemental native-CSPR payment rail**: a
conditional paid specialist-report settlement between the Concordia Gateway
and a separate Risk Oracle provider service. It demonstrates that a governance
council can *buy* an external specialist report and prove exactly what was
bought, for how much, and that the same payment cannot be redeemed twice.

SafePay Lite is deliberately **not** described as full escrow, a refund
contract, or a marketplace.

!!! warning "Status: SafePay Lite v2 is finals work in progress — no live v2 evidence yet"
    The v2 quote/consumption model described on this page is the **finals
    implementation being integrated**; its corrected commit is not yet merged
    and no live on-chain v2 payment, quote, or fulfillment hash is citable. Every
    guarantee below describes the **intended** design and is `PENDING_PROOF`
    until the live v2 exercise is captured and reconciled into the release
    manifest. Only the **historical v1** SafePay payment (bottom of this page) is
    live, frozen proof today.

## v2 quote / consumption model (implementation in progress)

The finals SafePay implementation is the **v2 quote/consumption model**
(`schema_version: safepay-v2`). By design the provider is the only consumption
authority, and every step is fail-closed. The behavior described below is the
target design (`PENDING_PROOF` until live v2 evidence is published):

### 1. Provider-issued immutable quotes

The Gateway requests a quote with
`POST /x402/v2/quotes`. The provider **persists the issued quote before
responding**, then answers HTTP 402 with the quote and matching
`payment_requirements`. Each quote is immutable and carries its own identity:
`quote_id`, `proposal_id`, `resource_id`, `network`, `payee_account_hash`,
`amount_motes`, `correlation_id`, `report_version`, `report_hash`, a bounded
`expires_at`, a non-zero `quote_nonce`, and a `quote_hash` content commitment
over all of it. The Gateway echoes the provider-issued quote; it never
reconstructs one, and a caller-computed but never-issued quote is rejected.

### 2. Payment bound to the quote

The quote's `correlation_id` is derived from the quote identity and is used as
the **exact Casper native-transfer ID**. Payment observation requires a
finalized Casper transaction with no execution error and an exact payee,
amount, transfer ID, and network match — nothing looser.

### 3. Redemption and durable duplicate rejection

The Gateway redeems with `POST /x402/v2/redemptions`, submitting the complete
issued quote plus the payment's deploy hash. The provider validates the quote
against its own persisted record, observes the chain, and then **atomically
claims the payment in a durable consumption ledger** keyed by
`(network, payment_hash)`. Both quote and consumption rows survive provider
restart. The outcomes are exact:

| Case | Outcome |
|---|---|
| First valid redemption | Fulfillment stored and returned (`replay_disposition: first_consumption`) |
| Exact retry of the same quote + payment | The **same immutable fulfillment** and `response_hash` are returned (`replay_disposition: idempotent_replay`); nothing is consumed twice |
| Same payment reused for a **different** quote or resource | Terminal HTTP 409, `replay_disposition: cross_binding_rejected` |
| Unissued or mismatched quote | Terminal 404 / 422 before any chain lookup |
| Expired unconsumed quote | Terminal 410; never consumed |

Duplicate rejection is therefore a property of the provider's durable ledger
and its atomic claim transaction — not of a replayed demo response.

### 4. Content-addressed reports

The protected report bytes are stored once, content-addressed by SHA-256, at
quote-issue time. Redemption and retries serve only those persisted bytes, so
neither report mutation nor a provider restart can change what the payer
bought. The protected bytes are never included in the public quote.

### 5. Bounded, fail-closed service behavior

Quote issuance is rate-limited and capacity-capped with durable counters;
rejected requests never trigger report generation. Every error is a fixed
machine-readable schema (`{schema_version, error: {code, retryable},
delivery}`) with no exception text, request echoes, or secrets — an internal
failure degrades to a generic 503 rather than leaking detail.

## Evidence status

!!! note "Live v2 evidence pending"
    The v2 quote/consumption model described above is the finals implementation
    in progress, and its duplicate-rejection guarantees are the intended
    property of the provider's durable ledger. A **live on-chain v2 evidence
    packet has not been published yet** — no v2 payment hash, quote hash, or
    fulfillment hash is citable at this time. When the live v2 exercise completes
    and reconciles into the release manifest, its evidence will be published with
    exact values. `PENDING_PROOF`: SafePay Lite v2 replay-safe live artifact
    (idempotent same-resource retry + terminal cross-resource rejection, both
    surviving provider restart).

**Historical proof (v1 flow).** The Buildathon proof pack includes a real
SafePay Lite payment verified under the earlier v1 flow:
Casper transfer `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`,
redeemed against the hosted Risk Oracle provider. That receipt remains valid
historical evidence of the paid-report loop, but it predates the v2 wire
contract and does not substantiate v2-specific claims. The legacy v1 endpoint
may remain for historical continuity, but it can never generate new v2
evidence.

## Why this matters for governance

The council's paid specialist report is part of the governance evidence: the
report hash, payment observation, and consumption record are included in the
proposal's proof surfaces. A judge can confirm that the report Concordia
reasoned over is byte-for-byte the report that was paid for.
