# Official x402

Alongside the supplemental native-CSPR [SafePay Lite](safepay-lite.md) rail,
Concordia integrates the **official Casper x402 payment standard**: WCSPR
(Wrapped CSPR) transfers authorized off-chain and settled through the
CSPR.cloud x402 facilitator.

!!! warning "Status: integration in progress — no live settlement evidence yet"
    The official x402 service described here is current work. It depends on
    the v3 exact-envelope receipt contract (see
    [On-Chain Governance Receipts](governance-receipts.md)), which is not yet
    live. No live official-x402 settlement transaction exists to cite. The
    design below is what is being built, and it is fail-closed at every step:
    until its own proofs pass, the honest status is *not proven live* — never
    "assumed working".

## What it is

A local Concordia x402 service implements the standard facilitator-facing
surface — `GET /health`, `GET /supported`, `GET /resource/:resourceId`,
`POST /verify`, and `POST /settle` — emitting `PAYMENT-REQUIRED` on HTTP 402
and accepting `PAYMENT-SIGNATURE`, per x402 version 2 with the `exact` scheme
on network `casper:casper-test`.

Payments are WCSPR `transfer_with_authorization` operations: the payer signs a
typed authorization (from, to, value, validity window, unique nonce) and the
facilitator settles it on-chain. Token metadata (name "Wrapped CSPR", symbol
WCSPR, 9 decimals) is taken from the pinned live contract readback — never
inferred from facilitator responses.

## Governance-bound settlement

What makes Concordia's integration distinctive is that **settlement is bound
to governance**. Before the service makes *any* credentialed facilitator
call, it requires the payment payload to resolve to a unique, verified v3
governance record:

1. The service validates the request locally — shape, canonical number
   encoding, account formats, and signature — and computes the signed payment
   payload's hash.
2. It looks up that hash in Concordia's proof registry. The record must be a
   finalized, verified `OfficialX402SettlementV1` action with every required
   exact-envelope check present and passed.
3. Only then does it contact the facilitator. An ungoverned, ambiguous,
   stale, or invalid payload causes **zero upstream calls**.

If more than one current verified record matches the same payload hash, the
service refuses with an explicit ambiguity error rather than choosing one.

## Durable fulfillment ledger

Like SafePay v2, official x402 settlement keeps a durable fulfillment ledger,
keyed by `(network, signed_payment_payload_hash)`, recording the resource,
action, envelope, payer, and authorization-nonce binding. Exact same-binding
retries are idempotent; any changed binding is a terminal 409 **before** chain
submission. The ledger survives restarts and is reconciled on startup.

## Fail-closed success criteria

An HTTP 200 from the facilitator is never treated as success by itself.
Settlement counts as successful only when:

- the response reports `success: true` with a transaction hash, **and**
- the resulting WCSPR transfer is finalized on-chain with exact arguments,
  confirmed by post-settlement readback.

A malformed 2xx response, a missing field, an unverified governance binding,
or an unfinalized transfer are all safe failures. Facilitator capabilities are
checked via `GET /supported` (x402 version 2, `exact` scheme,
`casper:casper-test`), and facilitator signer identities are treated as opaque
— never reused as payees.

## Relationship to SafePay Lite

| | SafePay Lite (supplemental) | Official x402 (current work) |
|---|---|---|
| Asset | Native CSPR | WCSPR |
| Authorization | On-chain transfer with quote-derived transfer ID | Signed off-chain `transfer_with_authorization` |
| Settlement authority | Concordia Risk Oracle provider (consumption ledger) | CSPR.cloud x402 facilitator, governance-gated |
| Duplicate protection | Durable `(network, payment_hash)` consumption ledger | Durable `(network, signed_payment_payload_hash)` fulfillment ledger |
| Status | Implemented; live v2 evidence pending | In progress; depends on v3, no live evidence yet |
