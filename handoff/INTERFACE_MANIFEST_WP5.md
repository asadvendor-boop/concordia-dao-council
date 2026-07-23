# INTERFACE MANIFEST — WP5 (official CSPR.cloud x402 settlement service)

- Producer branch: `claude/finals-product-security`
- Producer commit: `cc73c8a` (correction lineage: `f5cf748` → `929f4a2` → `1c832f7` → `2179eb0` → `96f0a1a` → `9391bf9` → `91b5498` schema-driven settlement item → `1bf4890` clean-install reproducibility → `0ce907d` validator-parity boundary pins (96-char names, calendar round-trip, pinned registry authority `7170c873fd20c1ff2e9e3115ec1523b9b1ea2c9b`) → `651f90a` truth pass #2: exact-microsecond timestamp parity + prototype-safe proof-type lookup → `7137674` manifests → `cc73c8a` truth pass #3: exact BigInt microsecond chronology in both JS parsers)
- Rooted at freeze: `concordia-g1-freeze-v2.0-a` (`b24c0409`)
- Spec authority: `handoff/G1_INTERFACE_SPEC.md` §6, §11, §12 "Official x402 local service v1", §13
- Lane status: proven at `1bf4890` from a BRAND-NEW detached checkout in which ONLY `services/x402-official` ran `npm ci` (verified: no `dashboard/node_modules`, no root `node_modules`, `NODE_PATH` unset, isolation re-checked after the runs): typecheck clean; 354/354 vitest green x3 consecutive; `npm audit --audit-level=high` 0 vulnerabilities. Codex independently reproduced the same result at `1bf4890`. Golden vectors cross-checked against an INDEPENDENT Python `hashlib.blake2b(digest_size=32)` reference. At `651f90a`: typecheck clean, **363/363**, audit 0 vulnerabilities. At `cc73c8a`: typecheck clean, **390/390 x3 consecutive**, `npm run build` OK, `npm audit --omit=dev` 0 vulnerabilities.

## Truth pass #3 (reviewer REJECT of `7137674`) — the timestamp contract

The reviewer accepted five of the six truth-pass-#2 repairs and rejected ONE:
both JavaScript parsers still lost exact RFC3339 microsecond ordering.

**Root cause (worse than a millisecond bug).** Microseconds-since-epoch pass
`Number.MAX_SAFE_INTEGER` (9007199254740991 µs) about **285 years either side
of 1970**, so a `number` of microseconds collapses adjacent instants in every
year before ~1684 **and** after ~2255 — not only in the far future. Reproduced
before the fix: `9999-12-31T23:59:59.000001Z` and `.000002Z` both yielded
`253402300799000000`, and the same collapse fired at year `0001`.

**The exact representation.** `services/x402-official/src/time.ts` now exports
**`rfc3339UtcOrdinal(value): bigint | null`** — exact microseconds since the
epoch. Every chronology comparison uses it. A BigInt is lossless at every
representable year and is what Python's full-microsecond `datetime`
comparison actually means.

**`parseRfc3339Utc` KEEPS its public contract: epoch MILLISECONDS as a
`number`.** This is deliberate, not an oversight: `pipeline.ts` compares it
against `validBeforeEpochMs` (canonical U64 epoch seconds × 1000), so
changing its units would have silently corrupted expiry terminalization by a
factor of 1000. Milliseconds for years 0001–9999 stay under 2.6e14 and are
therefore exact in a double. Sub-millisecond precision truncates **downward,
never upward**, so an observation can never be rounded past an expiry
boundary it did not cross.

Four defects closed in `time.ts` (it had been millisecond-based throughout):
1. `Math.round(Number(frac) * 1000)` mapped `.000001` AND `.000002` to `0 ms`.
2. `Date.UTC(year, …)` remaps years 0–99 onto 1900+year
   (`Date.UTC(1,0,1)` is 1901), so Python-valid years `0001`–`0099` were
   rejected by the round-trip guard. Fixed with `setUTCFullYear`.
3. **Leap second `:60` was accepted and clamped to `:59`** — inventing an
   instant that never existed, while Python raises
   `second must be in 0..59`. `registry.ts` had **no** guard of its own, so
   governance records carrying `:60` were accepted by JS and rejected by
   Python. Now refused at the parser. (Found while fixing, not reported by
   the reviewer.)
4. **1–9 fractional digits were accepted and truncated to six** — so
   `.1234567Z` and `.1234568Z` produced ONE ordinal: the same collapse class
   at a different digit. The grammar now caps at six digits and refuses
   sub-microsecond precision outright. (Found by differential fuzzing.)

Consumers updated to the exact ordinal (both private helpers, no public API
changed): `registry.ts requireRfc3339Utc` → `bigint`, with the
`maxObservedAtEpoch` accumulator moving from a `Number.NEGATIVE_INFINITY`
sentinel to an explicit `bigint | null` (BigInt has no infinity);
`settlement-item.ts requireRegistryUtc` → `bigint` and
`validateCheckObservations(checks, capturedAtEpoch: bigint)`.
**`pipeline.ts` is deliberately untouched** and still uses the millisecond
accessor — the one place where milliseconds are the correct unit.

**No BigInt reaches a JSON boundary.** To be exact about the surface:
`parseRfc3339Utc` is itself one of `provenance-pure.js`'s five exports and it
*does* return a BigInt — by design. The claim is about where that value can
travel. Its only two consumers (`registryItemErrors`'s observed-vs-captured
check and `provenance.js normalizeRegistryItem`) bind it to a local and use
it solely in `>` comparisons; it is never returned, stored on an item, spread
into props, or rendered. The other four exports
(`REQUIRED_CHECKS_BY_PROOF_TYPE`, `PUBLIC_ITEM_REQUIRED_FIELDS`,
`registryItemErrors`, `itemGreenVerified`) return only arrays, objects of
strings, and booleans. Verified three ways: a Next.js **production build**
(which prerenders through these validators) succeeds; explicit tests assert
`JSON.stringify` of every validator output does not throw; and the shared
vector table stores ordinals as decimal **strings** precisely so the fixtures
survive `JSON.stringify` on their way to Python. A future caller that
serializes the parser's return directly WOULD throw — hence the warning in
the function's own doc comment.

**Shared boundary vectors** live in `test/rfc3339-vectors.ts` and drive both
JavaScript parsers and Python from one table: years 0001, 0099, 0100, 1969,
1970, 2026, 2255 (the safe-integer boundary), 2256, 9999; adjacent
microseconds at each boundary year; leap days across the century rules
(1600/1700/1800/1900/2000/2400); impossible dates (Feb 30, Apr 31, month 0/13,
day 0, hour 24, year 0000, leap second). Every pinned ordinal is re-verified
against a live `python3` at test time, so the pins cannot rot.

**Deliberate strictness, pinned so nobody "fixes" it.** Nine inputs are
accepted by Python and refused by BOTH JavaScript parsers — lowercase `t`,
`+00:00`/`-00:00` offsets, a space separator, an empty fraction, an embedded
NUL byte (Python accepts it), and 7–9 fractional digits. All are refusals,
i.e. fail-closed, and both parsers agree on every one.

**Differential fuzz (my own, beyond the suites):** 471 candidates — format
attacks, a full month-length matrix, the century leap-year matrix, and 400
pseudo-random instants spanning years 1–9999 — compared across the dashboard
parser, the compiled x402 parser, and live Python. Result: **zero
over-acceptances, zero value differences, zero disagreements between the two
JavaScript parsers.** Only the nine intentional refusals above.

- Gates at this pass: typecheck clean, **390/390** vitest (363 → 382 → 390),
  `npm run build` OK, `npm audit --omit=dev` **0 vulnerabilities**.
- Failing-first: **10 of 14 red** in the new parity suite against the
  unmodified `7137674` code, including the behavioural proof that year-0001
  adjacent microseconds collapsed (`expected -62135596800000000 not to be
  -62135596800000000`).
- The 7–9-digit truncation collapse (defect 4) was found by the differential
  fuzz, NOT by a pre-written red test: against the pre-fix build the fuzz
  reported `JS-DISAGREE "2026-07-22T20:05:00.1234567Z" dashboard=null
  x402=1784750700123456`, and the pre-fix parser mapped `.1234567Z` and
  `.1234568Z` to the identical ordinal. It was fixed and then pinned by the
  refusal tests (suite 382 → 390); those tests fail against the pre-fix
  grammar, which accepted those values.

## Truth pass #2 (reviewer NO-GO on `f7c6f18`) — fixed at `651f90a`

> **Superseded by truth pass #3 — read that section first.** The note below
> concerns the DASHBOARD parser
> (`dashboard/app/_components/provenance-pure.js parseRfc3339Utc`), which at
> `651f90a` returned a `number` of microseconds and now returns an exact
> `BigInt`. It is NOT about the x402 parser
> (`services/x402-official/src/time.ts parseRfc3339Utc`), which is and
> remains epoch **milliseconds**; the x402 exact ordinal is the separate
> `rfc3339UtcOrdinal`. Two different functions share the name — the units
> statement below applies only to the dashboard one.

- **`parseRfc3339Utc` SEMANTIC CHANGE (Codex: re-audit any consumer):** the
  DASHBOARD parser returns exact **MICROSECONDS** since the Unix epoch, not
  milliseconds (as of truth pass #3, as an exact `BigInt`).
  Python compares full-microsecond `fromisoformat` datetimes, so a
  millisecond return collapsed `.000001Z`/`.000999Z` into one instant and
  silently skipped `check_observed_after_capture` violations Python reports.
  Callers must treat the return as an opaque ordinal (both in-repo consumers
  — the chronology comparison and the boundary suite — already do).
- Year `0000` is rejected (fromisoformat's calendar starts at 0001); years
  `0001`–`0099` remain accepted with positive-control vectors.
- Proof-type map lookups use `Object.hasOwn`: a hostile
  `proof_type="toString"/"__proto__"` now fails closed as
  `proof_type_invalid` on the dashboard exactly like Python's dict
  membership — previously it resolved Object.prototype members and threw.
- 4 new cross-language boundary tests (suite 359 → 363), each asserting the
  identical verdict from the pinned Python registry and the dashboard
  validator: year-0000 reject, low-years accept, exact-microsecond
  chronology both directions, prototype-key proof types for four hostile
  names. Failing-first: 3 of 4 were red against `f7c6f18`.

## Clean-install reproducibility (Codex blocker at `91b5498`) — fixed at `1bf4890`
Codex proved `91b5498` was NOT clean-install reproducible: the cross-language
suite imported `dashboard/app/_components/provenance.js` AS-IS, which contains
JSX and React-component imports, so the claimed 354/354 silently depended on a
sibling `dashboard/node_modules` (react/jsx-runtime) plus an undeclared
esbuild import in `vitest.config.ts`. Fix (no React/dashboard dependency added
to the service):
- NEW `dashboard/app/_components/provenance-pure.js` — JSX-free and
  dependency-free BY CONTRACT (header comment states the invariant); exact
  extraction, zero logic changes, of `REQUIRED_CHECKS_BY_PROOF_TYPE`,
  `PUBLIC_ITEM_REQUIRED_FIELDS`, `registryItemErrors`, `itemGreenVerified`,
  `parseRfc3339Utc`.
- `provenance.js` imports + re-exports the pure module; every dashboard
  consumer keeps importing from `./provenance` unchanged; renderers untouched.
- The cross-language suite imports ONLY `provenance-pure.js`; the vitest
  esbuild/JSX transform was deleted entirely.
- **Codex/integration invariant:** any future test or tool that wants the
  dashboard's validation logic from outside `dashboard/` must import
  `provenance-pure.js`, never `provenance.js`.

## Trusted client-identity throttling (final blocker) — at `96f0a1a`
x402-official settlement throttling keys client identity on the trusted `X-Concordia-Client-IP` header, following the same G1 §12 convention as the SafePay provider. **DEPLOYMENT REQUIREMENT (Caddy, x402 vhost — Codex-owned): Caddy MUST remove any caller-supplied `X-Concordia-Client-IP` and overwrite it with the actual remote peer address on every request proxied to x402-official (mirror the existing SafePay vhost rule).** The service accepts this header ONLY because it is never host-exposed. Precedence: a present single well-formed IP token IS the identity (lowercased, IPv4-mapped-IPv6 collapsed); missing/malformed values fall back to the immediate socket peer. One shared fixed-window budget per identity covers BOTH `POST /settle` and paid `GET /resource/*`; unpaid 402 discovery never draws from it. The throttle map is strictly bounded (10,000 windows; expired-first then oldest-live eviction; the >10k-identities-per-window early-refresh trade-off is documented in source and accepted to guarantee bounded memory). Unlike SafePay's fuller §12 mechanism there is NO CIDR/HMAC proxy attestation here — if this service were ever host-exposed the header would be spoofable; the Caddy strip+overwrite is therefore a hard deployment gate.

## Resource-route transport invariant (HTTP-surface blocker) — at `2179eb0`
`GET /resource/:resourceId` can return a 2xx ONLY when the exact protected report bytes are released from a finalized, integrity-verified fulfillment row with a valid PAYMENT-RESPONSE header — true success and the exact idempotent retry are the only 200 report responses. Every non-release outcome maps non-2xx at the resource boundary: 402 payment/governance/settlement refusals (including protocol-shaped `ServiceRefusal(200)` codes such as `ungoverned_payload`, `blocked_upgrade_drift`, `settlement_execution_failed`, `post_settle_readback_failed` when surfaced via the resource route), 409 terminal binding conflicts, 429 throttled paid attempts, 503 pending/retryable, 500 ledger-integrity; residual sub-400 statuses are hard-coerced. The `/verify` + `/settle` wire semantics (protocol-shaped 200 refusal bodies) are UNCHANGED — the fix is the resource route's mapping layer. Paid resource attempts draw from the SAME per-client fixed-window settlement budget as `POST /settle` (throttle bypass closed). Pinned by ten HTTP-level tests (`test/server.test.ts` "protected resource transport invariant"): seven non-release outcomes each asserting non-2xx + no bytes + no PAYMENT-RESPONSE + no false release audit code, two positive release controls, one throttle test.

## Correction pass (post NO-GO review) — what changed at `929f4a2`
- Readback fail-closed: `TransactionReadback.args` is mandatory; all EIGHT `transfer_with_authorization` args verified (exact CL type/ABI order, account-only Key variant, U256 value, validity window, nonce, public key, signature) + exact package/contract/transaction identity; `finalized:false` = resumable PENDING; lockStatus must be `Unlocked`.
- Lost `/settle` recovery via **ChainTransport method `locateSettlementByAuthorization(payer, package, contract, nonce)`** — **Codex: the live ChainTransport you inject must implement this third method** (in addition to `resolveActivePackage` / `getFinalizedTransaction`, and `getFinalizedTransaction` must return all 8 typed args + `transactionHash`). **CONTRACT CHANGE (security addendum at `1c832f7`): a negative result MUST be `{found:false, observed:{finalized:true, blockHeight:<finalized height>, stateRootHash:<64-hex state root actually queried>}}` and may only be returned when the absence was proven against a FINALIZED state snapshot. An indexer miss, mempool/non-finalized-head read, or unknown outcome must THROW instead. The service treats any boundary-less or malformed negative as indeterminate (stays pending, never resubmits). **SUPERSEDED at `9391bf9` — there is NO automatic resubmission at all.** A finalized `found:false` proves only 'not consumed yet' (a queued first request can still land later) and NEVER authorizes a second submission: the row stays pending and only the exact original transaction may be adopted. The hard invariant — AT MOST ONE facilitator /settle request per authorization, EVER (retries, concurrency, restarts, lost responses, elapsed time) — is enforced in code (single `facilitator.settle` call site behind the durable CAS; grep-based source regression) and proven by the migrated race/restart/alternating-locator tests. Terminal boundary: past `valid_before` + a finalized observation whose REQUIRED `blockTimestamp` is strictly after it → exactly-one CAS terminalization as `authorization_expired_unrecovered` (manual reauthorization with a FRESH authorization/nonce). The recovery lease is retired (columns inert, cleared on every transition). **ChainTransport contract update: `FinalizedObservationBoundary` now REQUIRES `blockTimestamp` (strict RFC3339 UTC) — Codex's live transport must supply it.**
- Production config frozen (any env differing from a G1 constant is rejected at startup); credentialed fetches: exact HTTPS origins, raw Authorization, `redirect:"error"`, bounded timeout/body.
- Exact terminal/idempotent retries resolve from the ledger BEFORE volatile registry/expiry/liveness gates.
- `src/settlement-item.ts` is a pure VALIDATING builder for the official §13 registry item, schema-driven from the current registry authority (`shared/proof_registry.py`, cross-checked against `handoff/G1_CROSS_LANE_SCHEMAS.json`) — Codex emits it at canary time; the service never chooses verifier observation URLs. Input: exact identity fields plus `claimScope`, `enforcementScope`, typed `links`, and `checks: [{name, passed, source, observed_at, evidence, detail_code?}]` — one independently captured receipt per required check. The builder validates the complete set (all **22** current required names exactly once — including the post-freeze snake-case `facilitator_verify_returned_is_valid_true` — no extras, no unknown receipt fields, `passed:true`, per-check artifact source, strict UTC-Z chronology vs `captured_at`, non-empty evidence) and REFUSES otherwise; `verification_status:"verified"` cannot be minted from identity fields. Emission is the exact public §13 shape: all **29** required public fields (including `claim_scope`, `enforcement_scope`, `links`), network exactly `casper:casper-test`, exact SHA-40 commits, `schema_version` exactly `concordia.official_x402_settlement.v1`, and emitted checks carrying ONLY `{name, required, passed, source, observed_at, detail_code?}` — the input `evidence` is validated then STRIPPED. Cross-language agreement (Python `normalize_proof_item` + dashboard `registryItemErrors`/`itemGreenVerified` accept one real builder output; mutations rejected identically) is pinned by `test/settlement-item-cross-language.test.ts`. `proof_id` format migrated to grammar-valid `official-x402-<48-hex>`. **NOTE for the schema owner: `G1_CROSS_LANE_SCHEMAS.json` is stale in two places vs the current registry (pre-rename camel-case check name; 28-field list missing `deployment_domain`) — regenerate or append a post-freeze-corrections note.**
- Ledger schema gained `valid_after`/`valid_before`/`public_key`/`signature` columns (restart reconciliation) and, at `1c832f7`, `recovery_lease_id`/`recovery_lease_expires_at` (durable exclusive submission/recovery ownership; additive `ALTER TABLE` auto-migration for existing volumes); state machine + unique keys unchanged. Terminal rows are invariant-checked on write (violations roll back) AND on read: a finalized row requires a 64-hex transaction, stored response bytes with a matching SHA-256 digest, `settled_at`, and no failure reason; a failed row requires its bounded failure code and matching stored failure response. Corrupt terminal rows fail closed and are never replayed as success — **WP10 rollout note: terminal rows written before this addendum without stored response bytes/digest will refuse replay instead of resynthesizing.**

Greenfield, isolated in `services/x402-official/`. It starts and remains
`blocked_fail_closed` until Codex injects live chain access — exactly §11's
required start state. Items below are Codex-owned for integration + the live canary.

## compose.prod.yml service entry (Codex / WP10)
Service `x402-official` (alias `concordia-x402-official`), build `services/x402-official/Dockerfile`, `restart: unless-stopped`, networks concordia-internal (+ edge vhost net), volume `x402_official_data:/data`. Env EXACTLY:
`NODE_ENV=production`, `X402_OFFICIAL_PORT=8787`, `X402_FACILITATOR_URL=https://x402-facilitator.cspr.cloud`, `X402_NETWORK=casper:casper-test`, `X402_SCHEME=exact`, `X402_WCSPR_PACKAGE_HASH=3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e`, `X402_WCSPR_CONTRACT_HASH=032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a`, `X402_WCSPR_CONTRACT_VERSION=8`, `X402_TOKEN_NAME='Wrapped CSPR'`, `X402_TOKEN_SYMBOL=WCSPR`, `X402_TOKEN_DECIMALS=9`, `X402_TOKEN_DOMAIN_VERSION=1`, **`X402_LEDGER_PATH=/data/x402-official.db`** (frozen name in G1_CROSS_LANE_SCHEMAS.json — distinct from the SafePay provider's ledger env), `X402_GATEWAY_INTERNAL_URL=http://gateway:8000`, `X402_RESOURCES_FILE=/run/config/x402-resources.json`.
Secrets: `X402_CSPR_CLOUD_TOKEN_FILE=/run/secrets/x402_official_cspr_cloud_token`, `X402_SIGNER_FILE=/run/secrets/x402_official_signer`, `X402_GATEWAY_TOKEN_FILE=/run/secrets/x402_official_gateway_token`.
Healthcheck: `node -e "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`.

## Caddy vhost (Codex / WP10)
`{$CONCORDIA_X402_HOSTNAME}` reverse_proxy `concordia-x402-official:8787` for `GET /health`, `GET /supported`, `GET /resource/*`, `POST /verify`, `POST /settle`. (This is the `x402.concordiadao.xyz` record — DNS only after the vhost is staged, per C3.)

## Gateway internal registry endpoint (Codex)
`GET /internal/proof-registry/v1/x402/{signed_payment_payload_hash}` per §13 EXACTLY. This service authenticates with `X-Concordia-Service-Token` from `/run/secrets/x402_official_gateway_token` and validates the 22-field record with **unknown-fields-REJECT** — so any extra field Codex adds will fail closed. Bodies: 404 `{error:'action_not_found'}`, 409 `{error:'ambiguous_governance_binding'}`. (Codex's WP4 registry commit `96312f0` already provides `/internal/proof-registry/...` — confirm the x402 sub-path + exact 22 fields match.)

## Live ChainTransport wiring (Codex, canary-time)
Implement/inject the Casper RPC observer for the frozen interface in `services/x402-official/src/chain.ts`, at deps construction in `src/index.ts`:
- `resolveActivePackage(packageHashHex) -> {lockStatus, enabledVersion, enabledContractHash}`
- `getFinalizedTransaction(txHashHex) -> {finalized, executionSuccess, targetContractHash, contractVersion, entryPoint, argNames[, args]}`
Until injected, the service is structurally `blocked_fail_closed` (drift guards refuse, zero credentialed calls).

## Resource config + report bytes (Codex / WP10)
Mount JSON per `services/x402-official/config/resources.example.json` (`{resources:[{id,url,description,mimeType,amount,payTo,maxTimeoutSeconds,reportFile|reportBase64}]}`) + the protected report bytes file. URLs must already be canonical per §6 — the loader **rejects, never normalizes**.

## Deviations / notes for Codex
- Local `GET /supported` returns THIS service's own frozen capability doc computed from config (no credentialed upstream). The §12 facilitator-`/supported` parser (kinds/extensions/signers) is implemented + tested in `src/facilitator.ts` for the Codex-run probe.
- No live Casper RPC readback client in-lane (Codex-owned live ops); default ChainTransport fails closed = §11 start state.
- `settlement_state → official_hosted_verified_live` only when a settlement row reaches `finalized` with post-settle v8 readback passed; production-reachable only via the real hosted canary.
- Dev deps: `vitest@3.2.7` (clears GHSA-5xrq-8626-4rwp), `better-sqlite3@12.4.1`, `blakejs@1.2.1` are the extra exact pins; the four §12 runtime pins are exact and untouched.
- EIP-712 verify reuses the pinned `@make-software/casper-x402` `ExactCasperScheme.verify()` offline (stub signer, `getNetworkConfig` only) — strict §12 canonical/shape validation runs FIRST because the official verify alone is looser.

## Open issues / live-gate flags
- **The `amount`-vs-`value` ABI trap is real:** the published 1.0.0 settlement builder uses runtime arg `amount` while live v8 requires `value`. If the hosted facilitator runs that builder, this service's post-settle readback correctly fails closed (argNames containing `amount` is a hard, test-covered failure). Codex must confirm the facilitator path before the canary.
- Production `/verify` + `/settle` cannot reach the credentialed facilitator until Codex injects the live ChainTransport — intended §11 behavior; make it an explicit gate in the WP10 rollout.
- `X402_SETTLEMENT_COMPATIBILITY_STATE` env from the schemas is informational; authoritative state is persisted in the ledger `service_state` table (starts blocked_fail_closed, survives restart) and reported by `/health`.
