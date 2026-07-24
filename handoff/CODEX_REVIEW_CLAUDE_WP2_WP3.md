# Codex integration review — Claude WP2/WP3

Status: **NO-GO pending corrective commits**.

Reviewed producer commits:

- WP2: `9a4d66f`
- WP3: `d096403` plus handoff `ac0ddda`

The good implementation work remains the base for corrections: SafePay's
atomic consumption, stored idempotent fulfillment, exact quote binding,
restart persistence and terminal 409 behavior; and the approval route's
bcrypt, allowlist, CSRF and nonce checks. The commits must not be cherry-picked
as complete work packages until every blocker below is fixed and retested.

## WP2 merge blockers

1. `shared/x402_payments.py` must parse the real CSPR.live
   `initiator_account_hash` field and bind the returned deploy hash, network,
   exactly one transfer, source, payee, amount and transfer ID. Add a frozen
   real-response-shaped fixture plus malformed/extra/mismatch negatives.
2. A CSPR.live `processed` status is not independently proven finality. Bind
   `casper-test`, exact deploy identity, execution success, block identity and
   a defined finality observation. Pending, wrong-chain and wrong-deploy
   responses fail closed.
3. `summarize_quote_evidence` may count a cross-binding rejection only when one
   canonical consumption exists and the same `(network,payment_hash)` has an
   append-only observation with `kind=cross_binding_rejected`, HTTP 409 and a
   genuinely different quote/resource binding. HTTP 200, same-binding and
   unrelated-payment observations remain false.

## WP3 merge blockers

1. Capability lifecycle is durable `ISSUED -> RUNNING -> COMPLETED|FAILED`.
   Claim, activation limits and state transition occur in one
   `BEGIN IMMEDIATE`. A concurrent RUNNING retry returns explicit 202; terminal
   retries return the exact stored status/body; no retry may return empty 200.
2. Simulator/preparer proposal IDs must exactly equal the preallocated unique
   `DAO-DEMO-*` ID. Canonical/historical or pre-existing IDs fail before the
   first proposal mutation.
3. Reserve `demo_run_id` provenance before the first durable mutation and keep
   it on every partial failure. Inject failures after prepare, room creation,
   message post and confirmation; every partial run remains discoverable and
   exactly cleanable.
4. Cleanup may select and delete only strict `DAO-DEMO-*`, `is_demo=1` rows
   owned by that exact run. Protect every frozen historical/canonical ID,
   enforce one-run ownership and select/delete inside one `BEGIN IMMEDIATE`.
5. Reject duplicate role keys and agent IDs at startup. Principal resolution
   must be unique and membership must bind the stable authenticated principal,
   not a set-iteration-dependent reverse lookup.
6. Capability issuance needs durable per-client/global limits, outstanding and
   retained-row caps, bounded expired-row cleanup and atomic admission across
   independent DB connections.
7. Migrate internal callers to omit caller identity metadata, then reject every
   supplied sender/participant identity field even when it happens to equal the
   authenticated principal.

## Codex integration blockers

1. The production global Gateway secret must have no room operation. Verify
   create, join, list, read and post all fail; only dedicated principal keys use
   the frozen matrix.
2. Fold the corrected capability/run schema, lifecycle constraints and unique
   ownership constraints into `gateway/database.py`.
3. Approval is releaseable only after Compose/Caddy load all `_FILE` secrets,
   apply Basic Auth, strip and overwrite `X-Proxy-Secret`, and make direct
   Gateway approval access unavailable. Run the complete live AU matrix.

## Acceptance gate

- Corrective commits stay in Claude-owned paths and are rooted at the same G1
  freeze.
- Every invariant above has a named regression test.
- The focused WP2/WP3 suite passes three consecutive runs.
- Codex independently reviews the corrective diff before cherry-pick.
- The integrated full Python, schema, hosted and live boundary gates pass.

## Mandatory post-freeze interface corrections

- A green SafePay item is exactly generation `v2`, lineage `supplemental`,
  observation `live|snapshot`, temporal scope `current`, and outcome
  `accepted`. Historical/canonical/rejection relabelling is invalid.
- SafePay and WP3 proof items emit strict UTC-Z check observations and capture
  time satisfying `max(check.observed_at) <= item.captured_at`; the integrated
  registry separately binds capture to generation/verifier time.
- Approval, demo-capability, and room-identity proof items are generation `v1`,
  supplemental, current, accepted, and live or dated-snapshot only.
- Producer interfaces must not add trust booleans as substitutes for the
  required observed checks. Missing raw observations stay unavailable.
