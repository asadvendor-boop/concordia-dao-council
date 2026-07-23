# INTERFACE MANIFEST — WP7 (dashboard truth-first redesign)

- Producer branch: `claude/finals-product-security`
- Producer commit: `651f90a` — truth pass #2 (reviewer NO-GO on `f7c6f18`), on top of `0ce907d` (five truth-contract fixes: replay binding, policy summary, live-read strictness, display fallbacks, pinned test authority) → `f7c6f18` (WP2/WP3 manifests). At `651f90a` from a fresh production build: **Playwright 155/155 x3 consecutive**, dashboard contract **17/17**, `npm audit --audit-level=high` exit 0, `git diff --check` clean.

## Truth pass #2 (at `651f90a`) — six same-class gaps closed
1. **PolicyAuthorization detail rows** (`lib.js` cardDetailRows) no longer
   hardcode "Decision: Policy authorized": they render `Refused · <DECISION>`
   for explicit denials, `Policy authorized · <DECISION>` only for the strict
   affirmative predicate, and "No explicit decision recorded" otherwise.
2. **Execution telemetry uses the bound replay predicate**: "Execution
   verified" / "Casper receipt anchored · evidence chain valid" require
   `replayVerified` (chain_valid === true AND payload proposal binding) AND
   the verified-receipt predicate; a verified receipt alone reads "Receipt
   recorded" with an honest no-bound-chain note; the anchored/verified metric
   sublabels follow the same gate.
3. **Recording receipt surfaces are payload-derived**: both the recording
   chip (now "Casper receipt") and the recording header's receipt shortcut
   render ONLY from a positively verified CasperExecutionReceipt in the bound
   payload with a 64-lowercase-hex transaction hash, linking
   `https://testnet.cspr.live/deploy/<payload hash>`. The static
   `DEFAULT_CASPER_DEPLOY_HASH` literal never renders in recording mode.
   `ProofActionBar` gained an additive `overridesById` prop for this.
   NOTE for review scope: the Judge Walkthrough, Technical Jury Note, and
   Proof Center pages still cite the canonical deploy hash as LABELED
   historical references (previously reviewed framing) — flagged for the
   reviewer, unchanged here.
4. **`isCasperLiveReadComplete` allowlists exact producer provenance**:
   status must be `visible_in_evidence` and source must be
   `Casper Node RPC / CSPR.live public status` (the only producer,
   `shared/proof_pack.py`); `failed`/arbitrary strings never satisfy it.
5. **Timestamp parity** and 6. **prototype-safe lookups** are WP5-shared
   (`provenance-pure.js`) — see INTERFACE_MANIFEST_WP5.md truth pass #2.
- Failing-first: 10 Playwright tests red against the `f7c6f18` build; 11 net
  new tests (5 recording-receipt, 3 telemetry-binding, 3 policy-detail) plus
  2 live-read allowlist negatives (144 → 155). Deliberate migrations, none
  weakened: `COMPLETE_LIVE_READ` + fail-open live-read negative fixtures
  carry the recognized producer source so each still isolates exactly one
  malformed dimension; the recording-chip positive control now supplies the
  payload receipt it asserts.

Pre-pass-2 correction lineage: `dfa3cd2` → `9d623a7` → `c700fcc` → `a78d103` dependency gate → `60ee252` exact-commit-audit predicates → `72f1747` flake fix → `03863a4` final-audit fail-open closures → `1bf4890` provenance-pure extraction (re-exported, consumers unchanged) → `0dde3ae` two remaining e2e flake fixes; at `0dde3ae` from a fresh production build: Playwright 133 x3 consecutive + collapse test x25 + wp7-release-blockers x6 twice (210/210, 210/210) + contract 17/17 + `npm audit --audit-level=high` exit 0. Codex independently reproduced dashboard clean install/build with 132/133 at `1bf4890` — the single failure was the pre-hydration collapse click fixed in `0dde3ae`.
- Rooted at freeze: `concordia-g1-freeze-v2.0-a` (`b24c0409`)
- Spec authority: `handoff/G1_INTERFACE_SPEC.md` §13 (provenance-aware proof registry), §12 (SafePay v2 / official x402)
- Lane status: see the producer-commit line above for the CURRENT fresh counts (the per-pass sections below record each pass's own historical counts); `tests/test_dashboard_contract.py` fully migrated, nothing deleted; `git diff --check` clean.

## Correction pass (post NO-GO review) — what changed at `9d623a7`
- Proposal-switch isolation (generation counter + AbortController; stale generations discarded whole); two-step demo capability flow wired and judge-reachable, reset removed; chain_valid three-state (missing = unknown, never green); approval authorized only from an affirmative selected-proposal decision with exact plan/action-hash binding; SafePay availability fallbacks removed; duplicate static H1 proof summaries removed from `/judge` + `/proof`; `provenance.js` now validates the FULL 29-field §13 item (enums, provenance/temporal/outcome binding, required-check set exactly-once, chronology, freshness normalization at the registry boundary).
- **The 5 post-freeze check-name renames from `G1_POST_FREEZE_CORRECTIONS.json` are applied and verified byte-identical against `codex/finals-core-v3:shared/proof_registry.py`** (including keeping the legitimately distinct `payment_deploy_finalized_without_execution_error` x402 check). Fixtures updated to the 29-field shape (`deployment_domain` added).
- Taxonomy corrected everywhere: **four deliberative agents + authorization-bound Locke + deterministic Concordia Core + non-reasoning archivist Wells** (the earlier "Five reasoning agents" label below was wrong and is superseded).
- Partial connectivity renders "Partial availability" (never "All systems operational"); full tab ARIA/keyboard semantics; 4.5:1 contrast enforced in the accessibility spec.

The dashboard now renders honest **pending** states wherever the new registry
payload isn't served yet. To light up the verified surfaces, Codex must serve
the payloads below with the EXACT `G1_CROSS_LANE_SCHEMAS.json` shapes.

## Exact-commit audit pass (at `a78d103` + `60ee252` + `72f1747`)
- **Dependency gate**: exact `next@16.2.11`; `sharp` cleared via exact `0.35.3` override (next declares `^0.34.5`, no patched 0.34.x exists); `brace-expansion` 1.1.16; deterministic lockfile regeneration; 0 High/Critical (3 Low remain via `casper-js-sdk` — clearing them requires the breaking 5.x major, recorded as out of scope).
- **All eight semantic blockers fixed** with shared fail-closed predicates (`isApprovalBoundToProposal` / `isApprovalBoundToPlan` / `isAuthorizedApproval` in lib.js) + 35 new tests incl. 8 SOURCE-regression tests banning presence-only truth derivations from returning. DemoModal now speaks only the frozen WP3 `demo-run-v1` contract.
- **Golden-path decision needed (Codex)**: under the strict sealed-plan binding, the recorded canonical evidence renders fail-CLOSED (Approved step not complete) because the StructuredApproval's `plan_hash` is the gateway CONTENT hash (`compute_plan_hash` over normalized plan JSON, `shared/approval.py:80`), which does not equal the sealed ResponsePlan card hash and is not client-recomputable from the sanitized payload. For the golden path to render authorized, the gateway should serve a client-verifiable binding (e.g. expose the plan content hash on the served ResponsePlan card). No fail-open exists either way.
- Pre-existing tablet/mobile nav test flake root-caused (hydration-race click loss) and fixed with the standard retry idiom; viewport suite 72/72 under `--repeat-each=8`.

## Re-review predicate pass (at `c700fcc`) — new Codex-owned observations the fail-closed dashboard consumes
All ten reproduced fail-open predicates are fixed: affirmative-decision-only approvals (every card type), recovery ≠ verification (including `deriveProposalFacts.receiptVerified`, mandating test deliberately migrated), exact proposal/plan-hash binding (missing = NOT bound), per-check observed fields instead of one recycled `chain_valid`, explicit-predicate-only ProofCenter safety/reputation/live/IPFS panels, and zero static online indicators (including the workspace room header). **Consequence: live runs render the honest non-asserted state until the gateway emits these observations (all Codex-owned):**
- an explicit affirmative `decision` field on the authorization card (`APPROVED`/equivalent) — presence/not-denied no longer authorizes;
- the SEALED ResponsePlan card hash as the approval's plan-hash binding (the pre-seal SHA-256 no longer matches);
- `evidence.sender_roles_verified === true` (new field; renders "unavailable" until emitted);
- explicit `receipt_verified: true` observations on execution receipts (recovery events no longer count);
- `run.human_intervention === true` as the consumed-authorization observation.

## Public proof registry — `GET /proof-registry/v1/{proposal_id}` (Codex / WP4)
Serve the exact `public_proof_registry_v1` shape: `{schema_version:1, generated_at, proposal_id, items:[...]}`, each item the full 29-field object (`deployment_domain` included) with `checks:[{name, required, passed, source, observed_at, detail_code?}]`. Dashboard binding contracts:

- **`exact_envelope_v3` item → V3Sequence** via required check names:
  `pre_quorum_finalize_reverted_with_code_8`, `post_quorum_mutated_envelope_reverted_with_code_10`, `exact_envelope_finalization_accepted`, `repeat_finalization_reverted_with_code_12`; plus OPTIONAL extra check `repeat_authorization_reverted_with_code_13` to light the code-13 `ActionAlreadyAuthorized` card.
- **`safepay_v2` item** dispositions render from checks: `provider_consumption_row_matches_payment_and_binding` (first consumption), `exact_retry_returned_same_fulfillment_hash_without_second_consumption` (idempotent replay), `cross_binding_reuse_returned_terminal_409` (409). Payment/report shown from `settlement_transaction` + `report_hash`. Green only via the §13 predicate. (These check names must match what the WP2 provider's `summarize_quote_evidence` produces — see INTERFACE_MANIFEST_WP2.md.)
- **`official_x402_settlement_v1` item** stays 'pending live verification' until `verification_status=verified` with all 22 required checks passed; then renders `settlement_transaction` / `payment_requirements_hash` / `signed_payment_payload_hash`.

## `/judge-walkthrough/{id}` (Codex)
`invariant_runner` must carry real per-check results (`{id, label, passed, status?, evidence?}`). The legacy `safepay_lite` block is now display-neutral only (payment_hash echoed without success semantics) — the registry item is the SOLE SafePay truth source.

## `/proof-center/{id}` (Codex)
These blocks are now strictly payload-gated (UI shows honest pending until served): `compact_proof_table` (status `verified` is the only green), `locke_execution_firewall` booleans, `adversarial_safety_demo`, `council_reputation`, `rwa_template`, `mercer_live_casper_read`, `policy_leash_meter`, `ipfs_evidence`.

## Cross-lane: demo flow (WP3 already committed)
`ConcordiaApp.js` decomposition is done; the demo activation path must use the two-step capability flow from INTERFACE_MANIFEST_WP3.md (`POST /api/demo/capability` → `POST /api/demo/activate`) — the reset button/`reset` scenario is removed (public reset no longer exists). The `dashboard/app/api/demo/**` proxy routes were committed under WP3 (`d096403`).

## Truth repairs delivered (source-verified by me)
- No `duplicate_proof_rejected:true` anywhere in `app/`.
- `DEFAULT_X402_PAYMENT_HASH` removed; only `HISTORICAL_SAFEPAY_PAYMENT_HASH` remains, rendered with explicit historical labels, backing no replay-safety claim.
- `receiptVerified` derives from the explicit receipt-verification predicate `isReceiptVerified` (recovery is NOT verification — the earlier `recovered === true` rule was superseded at `c700fcc`).
- §13 green predicate implemented; `expected_rejection` renders as positive proof; top-level booleans never green.
- SafePay Lite vs official x402 permanently distinct panels; official x402 fail-closed pending.
- 7/7-vs-6/6 agents-online inconsistency fixed (single `agentStatusInfo()` source).
- `Seven council roles` label + Chamber/Gateway/Core responsibilities panel preserved; agent-count wording is the corrected taxonomy (four deliberative agents + authorization-bound Locke + deterministic Core + non-reasoning archivist Wells — the original "Five reasoning agents" phrasing recorded here was wrong and is superseded).
- `PROFILES.scribe` undefined-profile bug fixed to `PROFILES.wells`.
- Pre-existing CSS cascade bug fixed (base rules after media blocks had disabled mobile overrides).

## Open issues / deferred (need Codex or Asad decision)
- **MONITOR/GOVERN/PROVE nav regrouping NOT applied** — recon flagged mid-judging continuity risk and the route→group mapping was unresolved; all 8 nav ids/labels/hrefs/order preserved. Decide before/against for finals.
- **Self-hosted fonts (next/font/local) + next/image portrait re-encode deferred** — licensed WOFF2/OFL assets not available offline, remote fetches beyond npm prohibited; token pass shipped on the system font stack, portraits reused as-is per mandate. Codex/Asad can add licensed fonts later if wanted.
- One pre-existing Turbopack NFT-trace warning from the untouched `next.config.mjs` — not introduced here.
- Official x402 panel stays fail-closed/pending by design until Codex records the live WCSPR proof and the registry serves a verified item.
