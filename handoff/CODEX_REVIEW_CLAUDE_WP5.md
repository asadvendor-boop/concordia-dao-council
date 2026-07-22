# Codex integration review — Claude WP5 (`f5cf748`)

## Verdict

**NO-GO as-is. Do not cherry-pick or deploy.** The local official-x402 service
has a good fail-closed foundation and all 128 current Vitest cases pass, but the
suite encodes several semantics that violate the frozen release contract. The
following corrections are mandatory in one Claude-owned follow-up commit.

## Release blockers

1. **Exact WCSPR readback is fail-open.** `TransactionReadback.args` is optional,
   and the validator accepts absent, empty, or partial values. Persist and verify
   all eight typed arguments (`from`, `to`, `value`, `valid_after`,
   `valid_before`, `nonce`, `public_key`, `signature`), their exact CL types and
   account variants, and the exact transaction identity. Restart reconciliation
   must retain every expected value. Add omitted/empty/partial, type, variant,
   order, identity, and per-field mutation tests.

2. **Pending finality is made terminal.** `finalized:false` must leave the row in
   `transaction_observed` and return retryable `reconciliation_pending`.
   Transition to `failed_terminal` only after finalized execution failure or a
   proven exact-binding mismatch.

3. **A lost settle response without a transaction hash deadlocks forever.** Add
   durable recovery by the exact payer/package/authorization-nonce binding (or
   a proven upstream idempotency/status identifier). The recovery path must find
   an already-submitted transaction without blindly calling `/settle` again and
   must prove exactly one settlement after restart.

4. **Production configuration can redirect credentials.** Production config
   loading must reject any value that differs from every G1-frozen constant,
   especially the facilitator and Gateway origins, network, package/contract
   identity and version, token metadata, port, ledger path, and secret-file
   paths. Test overrides belong in an explicit injected test constructor, not
   production environment parsing. Credential-bearing fetches also require a
   timeout, bounded response, and `redirect: "error"`.

5. **Exact retries are not durably idempotent.** Strictly parse and hash the
   request first, then consult the ledger before current-time signature and live
   registry gates. An exact terminal retry returns the validated stored response;
   an in-flight retry reconciles without a second settlement. Only a new claim
   runs all current-time governance/signature/upstream gates. Add retry-after-
   expiry and retry-during-registry-outage tests.

6. **Active-package and registry checks are incomplete.** Require package
   `lockStatus == "Unlocked"`; validate `finalized_at`, `observed_at`, and every
   check timestamp as RFC3339 UTC; validate check sources as repository-relative
   safe paths or HTTPS URLs. On startup and reconciliation, current package
   drift/unavailability must not leave the operational health state green.

## Literal freeze inventory and hardening

- Add the four required paths exactly:
  `config/secrets.example.json`, `test/facilitator.test.ts`,
  `test/governance-interlock.test.ts`, and `test/wording.test.ts`.
- Replace the literal NUL byte in `test/hashes.test.ts` with an escaped source
  representation so Git treats the test as text.
- Reject unknown resource-config fields, require exactly one of `reportFile` or
  `reportBase64`, cap report size, and pin the public resource origin/path.
- Bound and map upstream reason strings to stable local codes; do not echo or log
  untrusted upstream text.
- Add public `/verify` and `/settle` throttling and distinguish liveness from
  settlement readiness.

## Re-acceptance gate

Codex will accept WP5 only after the corrective commit passes typecheck, build,
`npm audit --omit=dev`, every old test, all new adversarial cases above, and a
second independent source review. The live claim remains blocked until Codex's
chain observer proves a real finalized hosted-facilitator v8 transaction with
all eight exact arguments; `/supported` or `isValid:true` is not settlement
proof.
