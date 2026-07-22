# Codex integration review — Claude WP7 (`dfa3cd2`)

## Verdict

**NO-GO as-is. Do not cherry-pick or deploy.** The redesign is materially
better than the submitted dashboard: it has a distinctive control-room visual
system, a strong quorum refusal/acceptance centerpiece, good responsive
reflow, preserved routes, and no doubled `basePath` links. The source and
runtime audit nevertheless found truth, proposal-binding, demo-protocol, and
accessibility defects that would put false claims into the judge flow and final
video. Claude must correct every P0 and the committed P1 contract before a
second review.

## Runtime and visual evidence

The production build from Claude's branch was exercised through a read-only
same-origin proxy at 1440x900 and 390x844 with live public GET payloads. No
mutation endpoint was invoked. Browser console output was empty, no route had
horizontal page overflow, and no link contained `/dashboard/dashboard/`.

Audit images are in the sprint-local `audits/wp7-20260723/` bundle:

- `02-war-room-loaded-1440x900.jpg`
- `03-judge-walkthrough-1440x900.jpg`
- `04-proof-center-1440x900.jpg`
- `05-judge-mobile-390x844.jpg`
- `06-council-chamber-1440x900.jpg`
- `07-approvals-1440x900.jpg`

The strongest visual work to retain is the dark control-room shell, the
before/after quorum comparison, the two-lane proof composition, the exact
authorization panel, the responsive stacked Judge layout, and the clear
separation between SafePay Lite and official WCSPR x402.

## P0 release blockers

1. **The existing Python dashboard contract suite was not migrated.** The
   refactor moved behavior out of `ConcordiaApp.js`, while
   `tests/test_dashboard_contract.py` still inspects that monolith. The branch
   currently produces 12 failures and 5 passes. Migrate assertions to the
   extracted modules without deleting or weakening them.

2. **Proposal switching can render evidence from another proposal.**
   `dashboard/app/_components/useConcordiaData.js:57-69` neither clears old
   state nor cancels/generation-checks in-flight requests. A failed or reordered
   request can pair the new selected proposal with the old evidence/messages.
   Key every response to the requested proposal, discard stale generations,
   and clear each failed data class to an honest unavailable state.

3. **The demo UI contradicts the frozen capability protocol.**
   `OverviewPage.js:53-78` posts `{scenario_type}` directly, retains a forbidden
   public reset control, and never exposes the modal because `setDemoOpen(true)`
   has no caller. Implement the two-step issue-capability then activate flow
   with `{capability, scenario_id}`, remove reset, expose the judge-safe trigger,
   and cover capability replay, 202 in-flight, terminal idempotency, and error
   states.

4. **Legacy evidence surfaces remain fail-open.** `EvidencePage.js:29-91`
   turns card presence and missing `chain_valid` into green verification;
   `lib.js:432-445,610-617` labels any approval/receipt successful and treats a
   missing receipt-verification field as `Yes`; Replay and recent-run rows use
   unconditional green labels. Every status must come from the validated proof
   registry or an explicit parser result. Missing, stale, malformed, mismatched,
   or unavailable data is never green.

5. **A rejected approval can render as authorized.** `ApprovalPage.js:35-48`
   uses `Boolean(approvalCard)`. Require an affirmative decision, exact selected
   proposal/action/envelope binding, and verified approval-boundary evidence.
   One-time consumption must not be inferred from card presence.

6. **The Judge fallback repeats the invalid SafePay claim.** The ordered story
   in `JudgeWalkthroughPage.js:73-100` says a paid report was verified and
   duplicate-proof failures were caught when the current registry correctly
   reports SafePay v2 unavailable. Recording mode consumes this prose. Derive
   all steps from proof items, or label the unavailable step explicitly; no
   narrative-only fallback may assert a proof outcome.

7. **The accessible static summaries duplicate stale hardcoded proof.**
   `judge/page.js` and `proof/page.js` inject a screen-reader-visible first
   `<h1>` plus literal proposal IDs, hashes, block claims, and old framing.
   Browser inspection confirmed two exposed H1s on each route. Remove the
   duplicate summary or derive one accessible summary from the same validated
   registry data as the visible page.

## P1 committed corrections

- Make `provenance.js:132-149` enforce the full registry schema and enums,
  selected proposal identity, required proof identities, known proof types,
  unique unambiguous items, and staleness. An unknown proof type with an empty
  check set must never pass.
- Use the honest role taxonomy everywhere: **five model-involved roles,
  including authorization-bound Locke, plus deterministic Core and
  non-reasoning Wells**. Remove `7/7 agents`, `All council identities are AI
  agents`, `Wells · LLM`, and claims that Wells generated historical archives.
  Describe historical Wells labels as presentation attribution while
  Core/Locke produced the deterministic artifact.
- Replace every literal proof hash, receipt, block height, proposal count, and
  success status in `lib.js`, `shared.js`, `ProofCenterPage.js`, `judge/page.js`,
  and `proof/page.js` with artifact/registry-derived data and honest unavailable
  states.
- Preserve query parameters and hash state when selecting proposals; Proof tabs
  must deep-link through `?tab=` or the hash and survive proposal switching.
- Give Proof tabs `role=tab`, `aria-selected`, `aria-controls`, tab panels,
  roving focus, and arrow-key operation. Make evidence ledger rows retain button
  semantics instead of overriding buttons with `role=listitem`. Add modal focus
  trap, Escape close, and focus return.
- Restore the committed deterministic QA matrix: 1487x1058, 1440x900,
  1024x768, 768x1024, and 390x844 across loaded, error, empty, reviewer, and
  unavailable states. Enforce 4.5:1 normal-text contrast rather than 3:1.
- Add the licensed local Space Grotesk, Chakra Petch, and JetBrains Mono WOFF2
  assets with license files and no runtime font request. Use optimized
  `next/image` portraits.
- Topbar health must show the selected proposal and real integration status;
  partial agent availability cannot become `All systems operational`.
- Implement keyboard/click agent-to-evidence filtering in the Living Firewall
  view.
- Restore the canonical-gated War Room lead when the selected proof supports
  it: `An AI requested 30%. Concordia authorized at most 8%.` Never render it
  for an unsupported proposal.

## Re-acceptance gate

Claude should produce one or more correction commits only in its owned
frontend files, plus a handoff manifest. Codex will then require: fresh
production build; the deliberately migrated Python contracts; every existing
Playwright test; the expanded viewport/state/accessibility suite; no console
errors; no dead controls; proposal-race tests; exact demo-capability tests; and
a second read-only source and visual audit. The final video must not be recorded
until this gate is green on the hosted release candidate.
