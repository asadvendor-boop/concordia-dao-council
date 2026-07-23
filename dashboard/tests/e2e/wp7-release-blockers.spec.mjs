// WP7 release-blocker acceptance specs (exact-commit audit of f550c93; route
// mocks only — never the live app). Eight semantic fail-open kills:
//   1. Overview "Evidence chain" pill: ONLY chain_valid === true is green;
//      missing/unknown renders honest non-green "Unverified".
//   2. Overview council activity: "Authorized" requires the explicit
//      affirmative + bound approval predicate; "Execution complete" requires a
//      positively verified receipt.
//   3. AgentsPage: same strict predicates for "Plan authorized" and
//      "Governance execution and receipt complete".
//   4. deriveWorkflow/deriveLifecycle: Authorization/Approved/Execution/
//      Executed/Receipt steps never complete from card presence.
//   5. ApprovalPage guard preview: "Blocked before execution" renders only
//      from an observed refusal artifact; otherwise a neutral unavailable
//      state.
//   6. EvidencePage: "Multisig decisions" never counts approval-card presence;
//      explicit decision predicate or honest "—".
//   7. ProposalWorkspacePage: rejected/unknown/unbound approvals never
//      suppress the Review Approval CTA.
//   8. DemoModal: frozen WP3 demo-run-v1 contract — status:"idempotent_replay"
//      is never presented as a fresh start, proposal ids come only from
//      created_proposal_ids[0], the documented 202 status:"running" and stored
//      FAILED replay bodies are surfaced honestly.
// Plus a SOURCE regression test banning the removed presence-only truth
// derivations from returning.
import { expect, test } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const componentsDir = path.resolve(__dirname, "../../app/_components");

const CANONICAL = "DAO-PROP-6CB25C";
const OTHER = "DAO-PROP-OTHER1";

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function idFromUrl(url, prefix) {
  const match = new URL(url).pathname.match(new RegExp(`${prefix}/([^/?]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function mockGateway(page, { proposals, evidenceById, runs = [], safetyById = {} }) {
  await page.route("**/stats", (route) => json(route, {}));
  await page.route("**/stats/runsummary", (route) => json(route, { runs }));
  await page.route("**/agent-status", (route) => json(route, [{ agent_role: "rowan", online: true }]));
  await page.route("**/agent-skills", (route) => json(route, { skills: [] }));
  await page.route("**/suppression-rules", (route) => json(route, []));
  await page.route("**/proof-registry/v1/**", (route) => json(route, { error: "not_served" }, 404));
  await page.route("**/room-messages/*", (route) => json(route, { messages: [], room_id: "room", message_count: 0 }));
  await page.route("**/adversarial-safety-demo/**", (route) => {
    const id = idFromUrl(route.request().url(), "adversarial-safety-demo");
    const artifact = safetyById[id];
    if (!artifact) return json(route, { error: "unavailable" }, 404);
    return json(route, artifact);
  });
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

function proposalCard(title = "Risky treasury move", sequence = 1) {
  return { card_type: "ProposalCard", sequence, hash: `hash-proposal-${sequence}`, data: { title, raw_payload: { title } } };
}

function planCard(extra = {}) {
  return {
    card_type: "ResponsePlan",
    sequence: 4,
    hash: "plan-hash-abc",
    data: { envelopes: [{ action_id: "execute_casper_governance_receipt", target: "treasury", parameters: { approved_allocation_bps: 800 } }] },
    ...extra,
  };
}

function approvalCard(data, cardType = "StructuredApproval") {
  return { card_type: cardType, sequence: 5, hash: "approval-hash", data };
}

function receiptCard(data = {}) {
  return { card_type: "CasperExecutionReceipt", sequence: 6, hash: "receipt-hash", data };
}

const boundApproval = () => approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" });
const verifiedReceipt = () => receiptCard({
  actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success", transaction_hash: "tx-hash" }],
  timeline: [{ event: "casper_transaction_verified", receipt_verified: true, details: [] }],
});
const presenceOnlyCards = () => [
  proposalCard(),
  planCard(),
  // Approval WITHOUT any decision and receipt WITHOUT any verification: pure
  // card presence that must never light a success cue anywhere.
  approvalCard({ proposal_id: CANONICAL, plan_hash: "plan-hash-abc" }),
  receiptCard({ actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success" }] }),
];

async function openOverview(page, { cards, evidenceExtra = {}, state = "EXECUTED" }) {
  await mockGateway(page, {
    proposals: [{ proposal_id: CANONICAL, state, created_at: "2026-06-29T00:00:00Z" }],
    evidenceById: { [CANONICAL]: { ...evidenceExtra, cards } },
  });
  await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
}

function lifecycleStep(page, label) {
  return page.locator(".active-proposal-workflow .workflow-step").filter({ hasText: label });
}

function healthRow(page, label) {
  return page.locator(".health-list > div").filter({ hasText: label });
}

test.describe("overview chain pill requires explicit chain_valid === true", () => {
  test("a MISSING chain_valid renders Unverified, never the green Valid cue", async ({ page }) => {
    await openOverview(page, { cards: [proposalCard()], evidenceExtra: {} });
    const row = healthRow(page, "Evidence chain");
    await expect(row).toBeVisible();
    await expect(row).toContainText("Unverified");
    await expect(row.locator(".status-success")).toHaveCount(0);
  });

  test("an explicit chain_valid=false renders Invalid with a danger pill", async ({ page }) => {
    await openOverview(page, { cards: [proposalCard()], evidenceExtra: { chain_valid: false } });
    const row = healthRow(page, "Evidence chain");
    await expect(row).toContainText("Invalid");
    await expect(row.locator(".status-danger")).toHaveCount(1);
    await expect(row.locator(".status-success")).toHaveCount(0);
  });

  test("positive control: an explicit chain_valid=true renders the green Valid cue", async ({ page }) => {
    await openOverview(page, { cards: [proposalCard()], evidenceExtra: { chain_valid: true } });
    const row = healthRow(page, "Evidence chain");
    await expect(row).toContainText("Valid");
    await expect(row.locator(".status-success")).toHaveCount(1);
  });
});

test.describe("overview council activity and lifecycle never assert from card presence", () => {
  test("missing decision + unverified receipt: no Authorized, no Execution complete, no complete Approved/Executed steps", async ({ page }) => {
    await openOverview(page, { cards: presenceOnlyCards(), evidenceExtra: { chain_valid: true } });
    const activity = page.locator(".agent-mini-list");
    await expect(activity).toBeVisible();
    await expect(activity.getByText("Authorized", { exact: true })).toHaveCount(0);
    await expect(activity.getByText("Awaiting human", { exact: true })).toBeVisible();
    await expect(activity.getByText("Execution complete")).toHaveCount(0);
    await expect(activity.getByText("Receipt recorded · unverified")).toBeVisible();
    await expect(lifecycleStep(page, "Approved")).not.toHaveClass(/complete/);
    await expect(lifecycleStep(page, "Executed")).not.toHaveClass(/complete/);
  });

  test("an approval bound to a DIFFERENT proposal never renders Authorized or a complete Approved step", async ({ page }) => {
    await openOverview(page, {
      cards: [proposalCard(), planCard(), approvalCard({ decision: "APPROVED", proposal_id: OTHER, plan_hash: "plan-hash-abc" })],
      evidenceExtra: { chain_valid: true },
    });
    const activity = page.locator(".agent-mini-list");
    await expect(activity).toBeVisible();
    await expect(activity.getByText("Authorized", { exact: true })).toHaveCount(0);
    await expect(activity.getByText("Awaiting human", { exact: true })).toBeVisible();
    await expect(lifecycleStep(page, "Approved")).not.toHaveClass(/complete/);
  });

  test("a REJECTED approval renders Authorization rejected, never Authorized", async ({ page }) => {
    await openOverview(page, {
      cards: [proposalCard(), planCard(), approvalCard({ decision: "REJECT", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })],
      evidenceExtra: { chain_valid: true },
    });
    const activity = page.locator(".agent-mini-list");
    await expect(activity.getByText("Authorization rejected")).toBeVisible();
    await expect(activity.getByText("Authorized", { exact: true })).toHaveCount(0);
    await expect(lifecycleStep(page, "Approved")).not.toHaveClass(/complete/);
  });

  test("an approval with a MISMATCHED plan hash never renders Authorized", async ({ page }) => {
    await openOverview(page, {
      cards: [proposalCard(), planCard(), approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "some-other-plan-hash" })],
      evidenceExtra: { chain_valid: true },
    });
    const activity = page.locator(".agent-mini-list");
    await expect(activity).toBeVisible();
    await expect(activity.getByText("Authorized", { exact: true })).toHaveCount(0);
    await expect(lifecycleStep(page, "Approved")).not.toHaveClass(/complete/);
  });

  test("positive control: a bound affirmative approval and a verified receipt light the truthful cues", async ({ page }) => {
    await openOverview(page, {
      cards: [proposalCard(), planCard(), boundApproval(), verifiedReceipt()],
      evidenceExtra: { chain_valid: true },
    });
    const activity = page.locator(".agent-mini-list");
    await expect(activity.getByText("Authorized", { exact: true })).toBeVisible();
    await expect(activity.getByText("Execution complete")).toBeVisible();
    await expect(lifecycleStep(page, "Approved")).toHaveClass(/complete/);
    await expect(lifecycleStep(page, "Executed")).toHaveClass(/complete/);
  });
});

test.describe("agents page truth labels use the same strict predicates", () => {
  async function openAgents(page, cards) {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards } },
    });
    await page.goto("/dashboard/agents", { waitUntil: "domcontentloaded" });
  }

  test("presence-only approval and receipt never render Plan authorized or execution complete", async ({ page }) => {
    await openAgents(page, presenceOnlyCards());
    const directory = page.locator(".agent-directory-grid");
    await expect(directory).toBeVisible();
    await expect(directory.getByText("Plan authorized")).toHaveCount(0);
    await expect(directory.getByText("Awaiting human approval")).toBeVisible();
    await expect(directory.getByText("Governance execution and receipt complete")).toHaveCount(0);
    await expect(directory.getByText("Receipt recorded · verification not confirmed")).toBeVisible();
  });

  test("a rejected approval renders Authorization rejected, never Plan authorized", async ({ page }) => {
    await openAgents(page, [proposalCard(), planCard(), approvalCard({ decision: "REJECT", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })]);
    const directory = page.locator(".agent-directory-grid");
    await expect(directory.getByText("Authorization rejected")).toBeVisible();
    await expect(directory.getByText("Plan authorized")).toHaveCount(0);
  });

  test("positive control: bound affirmative approval + verified receipt render the complete labels", async ({ page }) => {
    await openAgents(page, [proposalCard(), planCard(), boundApproval(), verifiedReceipt()]);
    const directory = page.locator(".agent-directory-grid");
    await expect(directory.getByText("Plan authorized")).toBeVisible();
    await expect(directory.getByText("Governance execution and receipt complete")).toBeVisible();
  });
});

test.describe("workspace Review Approval CTA is suppressed only by genuine authorization", () => {
  async function openWorkspace(page, cards) {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "PLANNED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards } },
    });
    await page.goto("/dashboard/proposals", { waitUntil: "domcontentloaded" });
  }
  const cta = (page) => page.locator(".page-header").getByRole("link", { name: "Review Approval" });

  test("a REJECTED approval does not suppress the CTA", async ({ page }) => {
    await openWorkspace(page, [proposalCard(), planCard(), approvalCard({ decision: "REJECT", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })]);
    await expect(cta(page)).toBeVisible();
  });

  test("an approval with an UNKNOWN decision does not suppress the CTA", async ({ page }) => {
    await openWorkspace(page, [proposalCard(), planCard(), approvalCard({ decision: "MAYBE_LATER", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })]);
    await expect(cta(page)).toBeVisible();
  });

  test("a malformed approval with no decision does not suppress the CTA", async ({ page }) => {
    await openWorkspace(page, [proposalCard(), planCard(), approvalCard({ proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })]);
    await expect(cta(page)).toBeVisible();
  });

  test("an UNBOUND approval (wrong plan hash) does not suppress the CTA", async ({ page }) => {
    await openWorkspace(page, [proposalCard(), planCard(), approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "some-other-plan-hash" })]);
    await expect(cta(page)).toBeVisible();
  });

  test("an approval bound to a DIFFERENT proposal does not suppress the CTA", async ({ page }) => {
    await openWorkspace(page, [proposalCard(), planCard(), approvalCard({ decision: "APPROVED", proposal_id: OTHER, plan_hash: "plan-hash-abc" })]);
    await expect(cta(page)).toBeVisible();
  });

  test("positive control: a genuine bound affirmative approval suppresses the CTA", async ({ page }) => {
    await openWorkspace(page, [proposalCard(), planCard(), boundApproval()]);
    // The workspace still renders (Export Evidence action present) but the
    // Review Approval CTA is gone because authorization is genuinely complete.
    await expect(page.locator(".page-header").getByRole("button", { name: "Export Evidence" })).toBeVisible();
    await expect(cta(page)).toHaveCount(0);
  });
});

test.describe("approvals guard preview requires an observed refusal artifact", () => {
  async function openApprovals(page, { safetyById = {} } = {}) {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard(), planCard(), boundApproval()] } },
      safetyById,
    });
    await page.goto("/dashboard/approvals", { waitUntil: "domcontentloaded" });
  }

  test("without a refusal artifact the preview shows a neutral unavailable state, never Blocked before execution", async ({ page }) => {
    await openApprovals(page);
    await expect(page.getByTestId("tamper-refusal-unavailable")).toBeVisible();
    await expect(page.getByText("Refusal artifact unavailable")).toBeVisible();
    await expect(page.getByText("Blocked before execution")).toHaveCount(0);
  });

  test("a safety artifact WITHOUT an explicit blocked status still never claims Blocked before execution", async ({ page }) => {
    await openApprovals(page, { safetyById: { [CANONICAL]: { summary: "loaded, no asserted outcome", locke_result: "unknown" } } });
    await expect(page.getByTestId("tamper-refusal-unavailable")).toBeVisible();
    await expect(page.getByText("Blocked before execution")).toHaveCount(0);
  });

  test("positive control: an explicit blocked refusal artifact renders Blocked before execution", async ({ page }) => {
    await openApprovals(page, { safetyById: { [CANONICAL]: { status: "blocked", summary: "Altered envelope refused.", locke_result: "refused_to_sign" } } });
    await expect(page.getByText("Blocked before execution")).toBeVisible();
    await expect(page.getByText("Locke refused to sign the altered envelope")).toBeVisible();
    await expect(page.getByTestId("tamper-refusal-unavailable")).toHaveCount(0);
  });
});

test.describe("evidence multisig decisions require an explicit recorded decision", () => {
  async function openEvidence(page, { cards, collaboration, runs = [] }) {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, ...(collaboration ? { collaboration } : {}), cards } },
      runs,
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
  }
  const decisionsRow = (page) => page.locator(".summary-metric-grid > div").filter({ hasText: "Multisig decisions" });

  test("approval-card PRESENCE without a decision never counts as one Multisig decision", async ({ page }) => {
    await openEvidence(page, { cards: [proposalCard(), planCard(), approvalCard({ proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })] });
    await expect(decisionsRow(page)).toContainText("0");
  });

  test("an explicit REJECT decision counts as a recorded decision (a denial is still a human decision)", async ({ page }) => {
    await openEvidence(page, { cards: [proposalCard(), planCard(), approvalCard({ decision: "REJECT", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })] });
    await expect(decisionsRow(page)).toContainText("1");
  });

  test("positive control: the gateway-reported human_decision_count wins when present", async ({ page }) => {
    await openEvidence(page, {
      cards: [proposalCard(), planCard(), approvalCard({ proposal_id: CANONICAL, plan_hash: "plan-hash-abc" })],
      collaboration: { human_decision_count: 2 },
    });
    await expect(decisionsRow(page)).toContainText("2");
  });
});

test.describe("demo modal follows the frozen WP3 demo-run-v1 activation contract", () => {
  async function openDemoAndFire(page, activateHandler) {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
    });
    await page.route("**/api/demo/capability", (route) => json(route, { capability: "cap-test-123", scenario_id: "defi-treasury" }));
    await page.route("**/api/demo/activate", activateHandler);
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const trigger = page.getByTestId("overview-demo-trigger");
    await expect(trigger).toBeVisible();
    const dialog = page.getByRole("dialog");
    await expect(async () => {
      await trigger.click();
      await expect(dialog).toBeVisible({ timeout: 1500 });
    }).toPass({ timeout: 15000 });
    await dialog.getByRole("button", { name: /Start full pipeline/i }).click();
  }

  // The toast auto-dismisses after ~4.2s, so each test captures its text and
  // class once (immediately after it appears) and asserts on the captured
  // values — no assertion can race the dismissal timer.
  async function captureToast(page) {
    const toast = page.locator(".toast");
    await expect(toast).toBeVisible();
    return { message: await toast.textContent(), className: (await toast.getAttribute("class")) || "" };
  }

  test("an idempotent_replay is NEVER presented as a fresh start and derives the proposal from created_proposal_ids[0]", async ({ page }) => {
    await openDemoAndFire(page, (route) => json(route, {
      schema_version: "demo-run-v1",
      status: "idempotent_replay",
      demo_run_id: "demo-run-existing",
      scenario_id: "defi-treasury",
      is_demo: true,
      created_proposal_ids: ["DAO-PROP-DEMO-EXIST"],
    }));
    const { message, className } = await captureToast(page);
    expect(message).toContain("DAO-PROP-DEMO-EXIST");
    expect(message).toContain("already active — showing the existing run");
    expect(message).not.toContain("entering the full proposal pipeline");
    expect(className).not.toContain("toast-success");
  });

  test("the documented 202 status:running is surfaced honestly without asserting a fresh start", async ({ page }) => {
    await openDemoAndFire(page, (route) => json(route, {
      schema_version: "demo-run-v1",
      status: "running",
      demo_run_id: "demo-run-inflight",
      scenario_id: "defi-treasury",
      is_demo: true,
    }, 202));
    const { message, className } = await captureToast(page);
    expect(message).toContain("still running");
    expect(message).toContain("demo-run-inflight");
    expect(message).not.toContain("started");
    expect(className).not.toContain("toast-success");
  });

  test("a stored FAILED terminal replay surfaces the stored honest error, never a success", async ({ page }) => {
    await openDemoAndFire(page, (route) => json(route, {
      schema_version: "demo-run-v1",
      status: "failed",
      error: "Demo run did not finish (crash/expiry recovery)",
      demo_run_id: "demo-run-crashed",
      scenario_id: "defi-treasury",
      is_demo: true,
    }, 503));
    const { message, className } = await captureToast(page);
    expect(className).toContain("toast-error");
    expect(message).toContain("Demo run did not finish (crash/expiry recovery)");
    expect(message).not.toContain("entering the full proposal pipeline");
  });

  test("a fresh started run selects created_proposal_ids[0] (no scalar proposal_id exists in the contract)", async ({ page }) => {
    await openDemoAndFire(page, (route) => json(route, {
      schema_version: "demo-run-v1",
      status: "started",
      demo_run_id: "demo-run-fresh",
      scenario_id: "defi-treasury",
      is_demo: true,
      created_proposal_ids: ["DAO-PROP-DEMO-NEW"],
    }));
    const { message, className } = await captureToast(page);
    expect(className).toContain("toast-success");
    expect(message).toContain("DAO-PROP-DEMO-NEW started");
  });
});

test.describe("SOURCE regression: presence-only truth derivations are banned", () => {
  const read = (relative) => fs.readFileSync(path.join(componentsDir, relative), "utf8");

  test("lib.js derives Authorization/Execution/Receipt from shared fail-closed predicates only", () => {
    const lib = read("lib.js");
    // Corrected shared predicates exist.
    expect(lib).toMatch(/export function isAuthorizedApproval\(card, proposalId, planCard\)/);
    expect(lib).toMatch(/export function isApprovalBoundToProposal\(card, proposalId\)/);
    expect(lib).toMatch(/export function isApprovalBoundToPlan\(card, planCard\)/);
    // deriveWorkflow/deriveLifecycle consume them.
    expect(lib).toMatch(/const authorized = isAuthorizedApproval\(approval, proposalId, plan\);/);
    expect(lib).toMatch(/const executed = isReceiptVerified\(receipt\);/);
    expect(lib).toMatch(/\{ id: "authorization", label: "Authorization", done: authorized \}/);
    expect(lib).toMatch(/\{ id: "execution", label: "Execution", done: executed \}/);
    expect(lib).toMatch(/\{ id: "receipt", label: "Receipt", done: executed && terminal \}/);
    expect(lib).toMatch(/\{ id: "approved", label: "Approved", done: authorized \}/);
    expect(lib).toMatch(/\{ id: "executed", label: "Executed", done: executed \}/);
    // Banned presence-only derivations.
    expect(lib).not.toMatch(/done:\s*Boolean\(approval\)/);
    expect(lib).not.toMatch(/done:\s*Boolean\(receipt\)/);
  });

  test("OverviewPage.js chain pill and council activity are explicit-evidence-only", () => {
    const overview = read(path.join("pages", "OverviewPage.js"));
    expect(overview).toMatch(/chain_valid === true \? "success"/);
    expect(overview).toMatch(/isAuthorizedApproval\(approval, activeProposal\?\.proposal_id, plan\)/);
    expect(overview).toMatch(/deriveLifecycle\(cards, activeProposal\?\.proposal_id\)/);
    // Banned: green from anything except an explicit true; presence-driven
    // Authorized / Execution complete labels.
    expect(overview).not.toMatch(/chain_valid\s*!==\s*false/);
    expect(overview).not.toMatch(/activeEvidence\s*\?\s*"success"/);
    expect(overview).not.toMatch(/\bapproval\s*\?\s*"Authorized"/);
    expect(overview).not.toMatch(/\breceipt\s*\?\s*"Execution complete"/);
  });

  test("OverviewPage.js DemoModal speaks only the frozen WP3 activation contract", () => {
    const overview = read(path.join("pages", "OverviewPage.js"));
    expect(overview).toContain('result.status === "idempotent_replay"');
    expect(overview).toContain("result.created_proposal_ids");
    expect(overview).toContain("createdProposalIds[0]");
    expect(overview).toContain('result.status === "running"');
    expect(overview).toContain('result.status === "failed"');
    // Banned: the legacy statuses and the scalar proposal_id the API never returns.
    expect(overview).not.toContain("already_activated");
    expect(overview).not.toMatch(/result\.idempotent\s*===\s*true/);
    expect(overview).not.toMatch(/result\.replayed/);
    expect(overview).not.toMatch(/result\.proposal_id/);
  });

  test("AgentsPage.js activity labels use the strict predicates", () => {
    const agents = read(path.join("pages", "AgentsPage.js"));
    expect(agents).toMatch(/isAuthorizedApproval\(approvalCard, data\.selectedId, planCard\)/);
    expect(agents).toMatch(/isReceiptVerified\(receiptCard\)/);
    expect(agents).not.toMatch(/getCard\(cards, "StructuredApproval", true\)\s*\?\s*"Plan authorized"/);
    expect(agents).not.toMatch(/getCard\(cards, "CasperExecutionReceipt", true\)\s*\?\s*"Governance execution and receipt complete"/);
  });

  test("EvidencePage.js multisig decisions use the explicit decision predicate", () => {
    const evidence = read(path.join("pages", "EvidencePage.js"));
    expect(evidence).toContain("explicitMultisigDecisions");
    expect(evidence).toMatch(/isAffirmativeApproval\(card\) \|\| isDeniedApproval\(card\)/);
    expect(evidence).not.toMatch(/approval\s*\?\s*1\s*:\s*0/);
  });

  test("ProposalWorkspacePage.js CTA suppression requires genuine authorization", () => {
    const workspace = read(path.join("pages", "ProposalWorkspacePage.js"));
    expect(workspace).toMatch(/isAuthorizedApproval\(approvalCard, proposal\?\.proposal_id, planCard\)/);
    expect(workspace).toMatch(/planCard && !approvalAuthorized &&/);
    expect(workspace).toMatch(/deriveWorkflow\(cards, proposal\?\.state, proposal\?\.proposal_id\)/);
    expect(workspace).not.toMatch(/&&\s*!getCard\(cards,\s*"StructuredApproval",\s*true\)\s*&&/);
  });

  test("ApprovalPage.js gates the blocked-tamper claim on the observed refusal artifact", () => {
    const approvals = read(path.join("pages", "ApprovalPage.js"));
    expect(approvals).toContain('refusalArtifact?.status === "blocked"');
    expect(approvals).toMatch(/refusalObserved\s*\n?\s*\?/);
    expect(approvals).toMatch(/isAuthorizedApproval\(approvalCard, proposal\?\.proposal_id, planCard\)/);
  });

  test("no component derives a green chain state from chain_valid !== false", () => {
    const files = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".js")) files.push(fs.readFileSync(full, "utf8"));
      }
    };
    walk(componentsDir);
    const all = files.join("\n");
    expect(all).not.toMatch(/chain_valid\s*!==\s*false/);
    expect(all).not.toMatch(/done:\s*Boolean\(approval\)/);
    expect(all).not.toMatch(/done:\s*Boolean\(receipt\)/);
  });
});
