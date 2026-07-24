// Fail-open predicate kill (product-security correction pass, route mocks only):
//   1. isAffirmativeApproval: missing/unknown decision is NOT affirmative — for
//      every card type, including PolicyAuthorization.
//   2. isReceiptVerified: a timeline event with `recovered: true` is recovery,
//      NOT verification; only an explicit receipt_verified === true counts.
//   3. Approval binding: a missing proposal_id is NOT a match; a missing plan
//      hash is NOT bound (no card-type exemption).
//   4. The Approvals "Executed" step requires the positive verified execution
//      predicate, never mere receipt presence.
//   5/7. Evidence: publication / sender-role / consumption checks render only
//      from their own observed fields, never from the generic chain_valid.
//   6. An unknown exact_match renders "Unavailable", never "Envelope bound".
//   8. Proof Center: safety, live-read, IPFS-pin and reputation cues each
//      require their own explicitly present and positive asserting field.
//   9. Historical replay cards, persona strips, reputation rows and fallback
//      working states never imply live "online" presence.
import { expect, test } from "@playwright/test";

const CANONICAL = "DAO-PROP-6CB25C";
const OTHER = "DAO-PROP-OTHER1";

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function idFromUrl(url, prefix) {
  const match = new URL(url).pathname.match(new RegExp(`${prefix}/([^/?]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function mockGateway(page, { proposals, evidenceById, runs = [] }) {
  await page.route("**/stats", (route) => json(route, {}));
  await page.route("**/stats/runsummary", (route) => json(route, { runs }));
  await page.route("**/agent-status", (route) => json(route, [{ agent_role: "rowan", online: true }]));
  await page.route("**/agent-skills", (route) => json(route, { skills: [] }));
  await page.route("**/suppression-rules", (route) => json(route, []));
  await page.route("**/proof-registry/v1/**", (route) => json(route, { error: "not_served" }, 404));
  await page.route("**/room-messages/*", (route) => json(route, { messages: [], room_id: "room", message_count: 0 }));
  // Predicate match (not a glob): the bare gateway list endpoint only. A glob
  // like "**/proposals" would also swallow the /dashboard/proposals page
  // navigation itself.
  await page.route((url) => url.pathname === "/proposals", (route) => json(route, proposals));
  await page.route("**/proposals/*", (route) => {
    const id = idFromUrl(route.request().url(), "proposals");
    const proposal = proposals.find((item) => item.proposal_id === id) || null;
    return json(route, { proposal });
  });
  await page.route("**/evidence/*", (route) => {
    const id = idFromUrl(route.request().url(), "evidence");
    const evidence = evidenceById[id];
    if (!evidence) return json(route, { error: "not_found" }, 404);
    return json(route, evidence);
  });
}

function proposalCard(title = "Risky treasury move", sequence = 1, extra = {}) {
  return { card_type: "ProposalCard", sequence, hash: `hash-proposal-${sequence}`, data: { title, raw_payload: { title } }, ...extra };
}

// DELIBERATE MIGRATION (WP7 final blocker 4 — exact action binding):
// isAuthorizedApproval now ALSO requires the approval's action_hash to exactly
// equal the plan's client-visible data.action_binding_hash. The plan fixture
// therefore carries action_binding_hash, and every approval fixture that is
// meant to isolate a DIFFERENT violated dimension (or to be the authorized
// positive control) carries the matching action_hash. No assertion below was
// weakened — each test still asserts exactly what it asserted before.
function planCard(extra = {}) {
  return {
    card_type: "ResponsePlan",
    sequence: 4,
    hash: "plan-hash-abc",
    data: { action_binding_hash: "action-hash-def", envelopes: [{ action_id: "execute_casper_governance_receipt", target: "treasury", parameters: { approved_allocation_bps: 800 } }] },
    ...extra,
  };
}

function approvalCard(data, cardType = "StructuredApproval", extra = {}) {
  return { card_type: cardType, sequence: 5, hash: "approval-hash", data, ...extra };
}

function receiptCard(data = {}, extra = {}) {
  return { card_type: "CasperExecutionReceipt", sequence: 6, hash: "receipt-hash", data, ...extra };
}

async function openApprovals(page, cards, runs = []) {
  await mockGateway(page, {
    proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
    evidenceById: { [CANONICAL]: { chain_valid: true, cards } },
    runs,
  });
  await page.goto("/dashboard/approvals", { waitUntil: "domcontentloaded" });
}

function executedStep(page) {
  return page.locator(".execution-status-step").filter({ hasText: "Executed" });
}

test.describe("affirmative approval requires an explicit decision", () => {
  test("a StructuredApproval with NO decision never renders as authorized", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
    ]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
  });

  test("an UNKNOWN decision value never renders as authorized", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ decision: "MAYBE_LATER", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
    ]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("a PolicyAuthorization with no decision and no plan hash never renders as authorized", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ proposal_id: CANONICAL, policy_id: "policy-low-risk" }, "PolicyAuthorization"),
    ]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
  });

  // Reviewer truth-contract pass: the PolicyAuthorization SUMMARY string must
  // also require an explicit affirmative decision — a missing/unknown decision
  // must never read as "issued ... authorization". The replay page renders
  // cardSummary for the current card, so it exercises the summary directly.
  test("a PolicyAuthorization summary with NO decision never says authorization was issued", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, proposal_id: CANONICAL, cards: [
        { card_type: "PolicyAuthorization", sequence: 1, hash: "policy-hash-1", data: { policy_id: "policy-low-risk" } },
      ] } },
    });
    await page.goto("/dashboard/runs", { waitUntil: "domcontentloaded" });
    await expect(page.getByText(/no authorization is asserted/).first()).toBeVisible();
    await expect(page.getByText(/issued a bounded low-risk authorization/)).toHaveCount(0);
  });

  test("positive control: an explicit affirmative PolicyAuthorization summary says the grant was issued", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, proposal_id: CANONICAL, cards: [
        { card_type: "PolicyAuthorization", sequence: 1, hash: "policy-hash-1", data: { decision: "AUTHORIZED", policy_id: "policy-low-risk" } },
      ] } },
    });
    await page.goto("/dashboard/runs", { waitUntil: "domcontentloaded" });
    await expect(page.getByText(/issued a bounded low-risk authorization/).first()).toBeVisible();
    await expect(page.getByText(/no authorization is asserted/)).toHaveCount(0);
  });

  test("an explicitly REFUSED PolicyAuthorization summary says refused, never issued", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, proposal_id: CANONICAL, cards: [
        { card_type: "PolicyAuthorization", sequence: 1, hash: "policy-hash-1", data: { decision: "REJECT", policy_id: "policy-low-risk" } },
      ] } },
    });
    await page.goto("/dashboard/runs", { waitUntil: "domcontentloaded" });
    await expect(page.getByText(/refused authorization/).first()).toBeVisible();
    await expect(page.getByText(/issued a bounded low-risk authorization/)).toHaveCount(0);
  });

  // Reviewer truth pass #2: the DETAIL rows previously hardcoded
  // "Decision: Policy authorized" for every PolicyAuthorization card. The row
  // must render the strictly validated decision or a neutral unavailable
  // state — never an authorization claim for a missing/denied decision.
  test("policy detail rows: NO decision renders a neutral Decision row, never Policy authorized", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, proposal_id: CANONICAL, cards: [
        { card_type: "PolicyAuthorization", sequence: 1, hash: "policy-hash-1", data: { policy_id: "policy-low-risk" } },
      ] } },
    });
    await page.goto("/dashboard/runs", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("No explicit decision recorded")).toBeVisible();
    await expect(page.getByText("Policy authorized")).toHaveCount(0);
  });

  test("policy detail rows: an explicit refusal renders the refusal decision, never Policy authorized", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, proposal_id: CANONICAL, cards: [
        { card_type: "PolicyAuthorization", sequence: 1, hash: "policy-hash-1", data: { decision: "REJECT", policy_id: "policy-low-risk" } },
      ] } },
    });
    await page.goto("/dashboard/runs", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Refused · REJECT")).toBeVisible();
    await expect(page.getByText("Policy authorized")).toHaveCount(0);
  });

  test("policy detail rows positive control: an explicit affirmative decision renders Policy authorized with its decision", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, proposal_id: CANONICAL, cards: [
        { card_type: "PolicyAuthorization", sequence: 1, hash: "policy-hash-1", data: { decision: "AUTHORIZED", policy_id: "policy-low-risk" } },
      ] } },
    });
    await page.goto("/dashboard/runs", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Policy authorized · AUTHORIZED")).toBeVisible();
    await expect(page.getByText("No explicit decision recorded")).toHaveCount(0);
  });
});

test.describe("approval binding requires explicit proposal + plan-hash equality", () => {
  test("an approved decision with a MISSING proposal_id is not a match", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ decision: "APPROVED", plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
    ]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("an approved decision bound to a DIFFERENT proposal is not a match", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ decision: "APPROVED", proposal_id: OTHER, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
    ]);
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("an approved decision with a MISSING plan hash is not bound — even for PolicyAuthorization", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, action_hash: "action-hash-def" }, "PolicyAuthorization"),
    ]);
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("an approved decision with a MISMATCHED plan hash is not bound", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "some-other-plan-hash", action_hash: "action-hash-def" }),
    ]);
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("positive control: an approved, exactly-bound approval renders authorized but unconsumed", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
    ]);
    await expect(page.getByRole("heading", { name: "Exact action authorized" })).toBeVisible();
    await expect(page.getByText("Authorization recorded · execution unconfirmed")).toBeVisible();
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
    await expect(executedStep(page)).not.toHaveClass(/done/);
  });
});

test.describe("execution requires positive receipt verification, never receipt presence", () => {
  const boundApproval = () => approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" });

  test("receipt PRESENCE without verification never marks Executed or consumed", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      boundApproval(),
      receiptCard({ actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success" }] }),
    ]);
    await expect(page.getByRole("heading", { name: "Exact action authorized" })).toBeVisible();
    await expect(executedStep(page)).not.toHaveClass(/done/);
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
    await expect(page.getByText("Authorization recorded · execution unconfirmed")).toBeVisible();
  });

  test("a recovered-but-unverified receipt is recovery, NOT verification", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      boundApproval(),
      receiptCard({
        actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success" }],
        timeline: [{ event: "receipt_verification", recovered: true, details: [{ recovered: true }] }],
      }),
    ]);
    await expect(executedStep(page)).not.toHaveClass(/done/);
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
  });

  test("positive control: an explicit receipt_verified observation marks Executed and consumed", async ({ page }) => {
    await openApprovals(page, [
      proposalCard(),
      planCard(),
      boundApproval(),
      receiptCard({
        actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success", transaction_hash: "tx-hash" }],
        timeline: [{ event: "casper_transaction_verified", receipt_verified: true, details: [] }],
      }),
    ]);
    await expect(executedStep(page)).toHaveClass(/done/);
    await expect(page.getByText("Authorization verified and consumed")).toBeVisible();
  });
});

test.describe("evidence checks render only from their own observed fields", () => {
  test("an unknown exact_match renders Unavailable, never Envelope bound", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: {
        [CANONICAL]: {
          chain_valid: true,
          collaboration: { handoff_count: 2, challenge_count: 1, human_decision_count: 1 },
          cards: [proposalCard()],
        },
      },
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Envelope bound")).toHaveCount(0);
    const conflictRow = page.locator(".summary-metric-grid > div").filter({ hasText: "Execution conflict control" });
    await expect(conflictRow).toContainText("Unavailable");
  });

  test("an explicit exact_match=true still renders Exact match", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: {
        [CANONICAL]: {
          chain_valid: true,
          collaboration: { execution_conflict_control: { exact_match: true } },
          cards: [proposalCard()],
        },
      },
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Exact match").first()).toBeVisible();
    await expect(page.getByText("Envelope bound")).toHaveCount(0);
  });

  test("generic chain_valid alone never lights publication, sender-role, consumption or receipt checks", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: {
        [CANONICAL]: {
          chain_valid: true,
          cards: [
            proposalCard(),
            planCard(),
            approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
          ],
        },
      },
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
    const verificationPanel = page.locator(".verification-list");
    await expect(verificationPanel).toBeVisible();
    // Only the two chain-integrity rows may pass from chain_valid.
    await expect(verificationPanel.locator(".pass")).toHaveCount(2);
    for (const label of [
      "Council publications verified",
      "Sender roles are verified",
      "Authorization consumed once",
      "Receipt positively verified",
    ]) {
      const row = verificationPanel.locator("> div").filter({ hasText: label });
      await expect(row).not.toHaveClass(/pass/);
      await expect(row.locator(".verification-unavailable")).toBeVisible();
    }
  });

  test("positive control: each subproof lights only from its own observed field", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: {
        [CANONICAL]: {
          chain_valid: true,
          sender_roles_verified: true,
          cards: [
            proposalCard("Risky treasury move", 1, { published: true }),
            planCard({ published: true }),
            approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }, "StructuredApproval", { published: true }),
          ],
        },
      },
      runs: [{ proposal_id: CANONICAL, human_intervention: true, receipt_verified: true }],
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
    const verificationPanel = page.locator(".verification-list");
    await expect(verificationPanel).toBeVisible();
    await expect(verificationPanel.locator(".pass")).toHaveCount(6);
  });
});

test.describe("proof center predicates each require their own asserting field", () => {
  const baseProposals = [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }];

  async function openProofTab(page, tab, { proofPayload = null, safetyPayload = null } = {}) {
    await mockGateway(page, {
      proposals: baseProposals,
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
    });
    await page.route("**/proof-center/**", (route) => (proofPayload ? json(route, proofPayload) : json(route, { error: "unavailable" }, 404)));
    await page.route("**/adversarial-safety-demo/**", (route) => (safetyPayload ? json(route, safetyPayload) : json(route, { error: "unavailable" }, 404)));
    await page.route("**/integrations/status", (route) => json(route, { error: "unavailable" }, 404));
    await page.route("**/cspr-click/unsigned-receipt/**", (route) => json(route, { error: "unavailable" }, 404));
    await page.goto(`/dashboard/proof?tab=${tab}`, { waitUntil: "domcontentloaded" });
  }

  test("a truthy safety payload WITHOUT an explicit blocked status never claims Rogue action refused", async ({ page }) => {
    await openProofTab(page, "safety", { safetyPayload: { summary: "Payload loaded without any asserted outcome.", locke_result: "unknown" } });
    await expect(page.locator(".safety-demo-card")).toBeVisible();
    await expect(page.getByText("Rogue action refused")).toHaveCount(0);
    await expect(page.getByText("Execution Blocked")).toHaveCount(0);
    await expect(page.locator(".safety-demo-card").getByText("Outcome unavailable").first()).toBeVisible();
  });

  test("positive control: an explicit blocked status renders Rogue action refused", async ({ page }) => {
    await openProofTab(page, "safety", { safetyPayload: { status: "blocked", summary: "Altered envelope refused.", locke_result: "refused_to_sign" } });
    await expect(page.getByText("Rogue action refused")).toBeVisible();
    await expect(page.getByText("Execution Blocked")).toBeVisible();
  });

  test("an incomplete live-read object never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "visible_in_evidence", source: "Casper Node RPC / CSPR.live public status" } },
    });
    // exact: the page subtitle mentions "live data sources" as prose; only the
    // asserting StatusPill is the claim under test.
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  // DELIBERATE MIGRATION (reviewer truth-contract pass): the live-read
  // predicate now requires the frozen Testnet network, an INTEGER block
  // height, a 64-LOWERCASE-hex state root, and explicit observation
  // provenance (source + status) — the positive control carries all of them
  // and each negative below isolates exactly one malformed dimension.
  test("positive control: a complete well-formed live read renders Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "visible_in_evidence", source: "Casper Node RPC / CSPR.live public status", latest_block_height: 8340490, state_root_hash: "a".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toBeVisible();
    await expect(page.getByText("Live read incomplete")).toHaveCount(0);
  });

  test("a live read with the WRONG network never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper", status: "visible_in_evidence", source: "Casper Node RPC / CSPR.live public status", latest_block_height: 8340490, state_root_hash: "a".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  test("a live read with a STRING block height never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "visible_in_evidence", source: "Casper Node RPC / CSPR.live public status", latest_block_height: "8340490", state_root_hash: "a".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  test("a live read with a malformed (uppercase) state root never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "visible_in_evidence", source: "Casper Node RPC / CSPR.live public status", latest_block_height: 8340490, state_root_hash: "A".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  test("a live read without observation provenance (source) never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "visible_in_evidence", latest_block_height: 8340490, state_root_hash: "a".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  // Reviewer truth pass #2: arbitrary non-empty provenance strings must not
  // satisfy the live-read predicate — only the exact producer-emitted success
  // status and recognized source are complete.
  test("a live read with a NON-SUCCESS status (failed) never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "failed", source: "Casper Node RPC / CSPR.live public status", latest_block_height: 8340490, state_root_hash: "a".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  test("a live read with unrecognized provenance text never claims Live data source", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { mercer_live_casper_read: { network: "casper-test", status: "visible_in_evidence", source: "x", latest_block_height: 8340490, state_root_hash: "a".repeat(64) } },
    });
    await expect(page.getByText("Live data source", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Live read incomplete")).toBeVisible();
  });

  test("a CID without a verified pin predicate never claims Pinned", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { ipfs_evidence: { cid: "bafkreitestcidwithoutpinpredicate", provider: "kubo", status: "uploaded" } },
    });
    await expect(page.getByText("Pinned", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Pin unverified")).toBeVisible();
  });

  test("positive control: an explicit pinned=true observation renders Pinned", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: { ipfs_evidence: { cid: "bafkreitestcidwithpinpredicate", provider: "kubo", pinned: true } },
    });
    await expect(page.getByText("Pinned", { exact: true })).toBeVisible();
    await expect(page.getByText("Pin unverified")).toHaveCount(0);
  });

  test("reputation rows are green only for explicitly positive values and never imply online presence", async ({ page }) => {
    await openProofTab(page, "data", {
      proofPayload: {
        council_reputation: [
          { agent: "Verity", metric: "Challenges raised", value: 1, signal: "+1 confirmed policy violation" },
          { agent: "Alden", metric: "Revisions accepted", value: 0, signal: "No revision recorded" },
          { agent: "Locke", metric: "Exact-envelope executions", signal: "No receipt anchored" },
        ],
      },
    });
    const reputationList = page.locator(".reputation-list");
    await expect(reputationList).toBeVisible();
    await expect(reputationList.locator("> div")).toHaveCount(3);
    await expect(reputationList.locator(".status-success")).toHaveCount(1);
    await expect(reputationList.locator(".avatar-status.online")).toHaveCount(0);
  });
});

test.describe("historical cards and personas never imply online presence", () => {
  test("overview persona strip and council activity rows carry no online dots", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: {
        [CANONICAL]: {
          chain_valid: true,
          cards: [
            proposalCard(),
            planCard(),
            approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" }),
            receiptCard({ actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success" }] }),
          ],
        },
      },
    });
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const personaStrip = page.locator(".council-persona-strip");
    await expect(personaStrip).toBeVisible();
    await expect(personaStrip.locator(".avatar-status.online")).toHaveCount(0);
    await expect(page.locator(".agent-mini-list .avatar-status.online")).toHaveCount(0);
    await expect(page.locator(".council-avatar-strip .avatar-status.online")).toHaveCount(0);
  });

  test("the proposal workspace fallback working state carries no online dot", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard(), planCard()] } },
    });
    await page.goto("/dashboard/proposals", { waitUntil: "domcontentloaded" });
    const workingState = page.locator(".working-state");
    await expect(workingState).toBeVisible();
    await expect(workingState.locator(".avatar-status.online")).toHaveCount(0);
  });

  test("historical replay recording cards carry no online dot", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard(), planCard()] } },
    });
    await page.goto("/dashboard/runs?recording=1", { waitUntil: "domcontentloaded" });
    const replayAgent = page.locator(".replay-recording-agent");
    await expect(replayAgent).toBeVisible();
    await expect(replayAgent.locator(".avatar-status.online")).toHaveCount(0);
  });
});
