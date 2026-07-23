// WP7 correction acceptance specs (route mocks only — never the live app):
//   * P0-4 fail-open kill: a MISSING chain_valid renders honest "unavailable",
//     never a green "Evidence chain valid".
//   * P0-5 a rejected approval never renders as authorized.
//   * P0-3 the demo control is reachable and uses the two-step
//     issue-capability -> activate protocol with {capability, scenario_id};
//     there is no reset control and no {scenario_type} post.
//   * P0-2 proposal-switch generation guard: switching proposals never pairs the
//     new proposal with the previous proposal's evidence.
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

// Minimal base gateway mocks so proposals resolve and the selected proposal
// loads. evidenceById maps proposal_id -> evidence document.
async function mockGateway(page, { proposals, evidenceById }) {
  await page.route("**/stats", (route) => json(route, {}));
  await page.route("**/stats/runsummary", (route) => json(route, { runs: [] }));
  await page.route("**/agent-status", (route) => json(route, [{ agent_role: "rowan", online: true }]));
  await page.route("**/agent-skills", (route) => json(route, { skills: [] }));
  await page.route("**/suppression-rules", (route) => json(route, []));
  await page.route("**/proof-registry/v1/**", (route) => json(route, { error: "not_served" }, 404));
  await page.route("**/room-messages/*", (route) => json(route, { messages: [], room_id: "room", message_count: 0 }));
  await page.route("**/proposals", (route) => json(route, proposals));
  await page.route("**/proposals/*", (route) => {
    const id = idFromUrl(route.request().url(), "proposals");
    const proposal = proposals.find((item) => item.proposal_id === id) || null;
    return json(route, { proposal });
  });
  await page.route("**/evidence/*", async (route) => {
    const id = idFromUrl(route.request().url(), "evidence");
    const evidence = evidenceById[id];
    if (!evidence) return json(route, { error: "not_found" }, 404);
    if (evidence.__delayMs) await new Promise((resolve) => setTimeout(resolve, evidence.__delayMs));
    return json(route, evidence);
  });
}

function proposalCard(title, sequence = 1) {
  return { card_type: "ProposalCard", sequence, hash: `hash-proposal-${sequence}`, data: { title, raw_payload: { title } } };
}

test.describe("WP7 fail-open kill: chain validity", () => {
  test("missing chain_valid renders honest unavailable, never a green valid cue", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      // chain_valid intentionally OMITTED -> unknown, must not be green.
      evidenceById: { [CANONICAL]: { cards: [proposalCard("Risky treasury move")] } },
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Chain verification unavailable").first()).toBeVisible();
    await expect(page.getByText("Evidence chain valid")).toHaveCount(0);
    // The verification checklist asserts nothing as passed while validity is unknown.
    const verificationPanel = page.locator(".verification-list");
    await expect(verificationPanel).toBeVisible();
    await expect(verificationPanel.locator(".pass")).toHaveCount(0);
  });

  test("explicit chain_valid=true renders the verified cue", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard("Risky treasury move")] } },
    });
    await page.goto("/dashboard/evidence", { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Evidence chain valid").first()).toBeVisible();
  });
});

test.describe("WP7 approval authorization binding", () => {
  test("a rejected multisig decision never renders as authorized", async ({ page }) => {
    const cards = [
      proposalCard("Risky treasury move"),
      { card_type: "ResponsePlan", sequence: 4, hash: "plan-hash-abc", data: { envelopes: [{ action_id: "execute_casper_governance_receipt", target: "treasury", parameters: { approved_allocation_bps: 800 } }] } },
      { card_type: "StructuredApproval", sequence: 5, hash: "approval-hash", data: { decision: "REJECT", plan_hash: "plan-hash-abc" } },
    ];
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "REJECTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards } },
    });
    await page.goto("/dashboard/approvals", { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Authorization rejected" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
  });
});

test.describe("WP7 two-step demo capability protocol", () => {
  test("the trigger opens the modal and posts capability then activate with {capability, scenario_id}, no reset", async ({ page }) => {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard("Risky treasury move")] } },
    });
    const posted = { capability: null, activate: null };
    await page.route("**/api/demo/capability", (route) => {
      posted.capability = route.request().postDataJSON();
      return json(route, { capability: "cap-test-123", scenario_id: posted.capability?.scenario_id });
    });
    await page.route("**/api/demo/activate", (route) => {
      posted.activate = route.request().postDataJSON();
      return json(route, { proposal_id: "DAO-PROP-DEMO-NEW", target: "defi-treasury" });
    });

    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const trigger = page.getByTestId("overview-demo-trigger");
    await expect(trigger).toBeVisible();
    const dialog = page.getByRole("dialog");
    // The trigger's onClick only exists after React hydrates; retry the click
    // until the dialog actually opens so the test is not a hydration race.
    await expect(async () => {
      await trigger.click();
      await expect(dialog).toBeVisible({ timeout: 1500 });
    }).toPass({ timeout: 15000 });
    // No forbidden public reset control.
    await expect(page.getByText("Reset demo environment")).toHaveCount(0);
    await expect(dialog.getByText("There is no reset control.")).toBeVisible();

    await dialog.getByRole("button", { name: /Start full pipeline/i }).click();
    await expect.poll(() => posted.activate).not.toBeNull();
    // Step 1 issued a capability bound to the scenario.
    expect(posted.capability).toMatchObject({ scenario_id: "defi-treasury" });
    // Step 2 activated with the exact capability + scenario_id, NEVER {scenario_type}.
    expect(posted.activate).toMatchObject({ capability: "cap-test-123", scenario_id: "defi-treasury" });
    expect(posted.activate).not.toHaveProperty("scenario_type");
  });
});

test.describe("WP7 proposal-switch generation guard", () => {
  test("switching proposals never renders the previous proposal's evidence", async ({ page }) => {
    await mockGateway(page, {
      proposals: [
        { proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" },
        { proposal_id: OTHER, state: "EXECUTED", created_at: "2026-06-30T00:00:00Z" },
      ],
      evidenceById: {
        // The canonical proposal's evidence is slow; the switch must abort it.
        [CANONICAL]: { __delayMs: 2500, chain_valid: true, cards: [proposalCard("CANONICAL-PROPOSAL-EVIDENCE")] },
        [OTHER]: { chain_valid: true, cards: [proposalCard("OTHER-PROPOSAL-EVIDENCE")] },
      },
    });
    await page.goto(`/dashboard/evidence?proposal=${OTHER}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("OTHER-PROPOSAL-EVIDENCE").first()).toBeVisible();
    // Switch to the canonical proposal (slow evidence) then immediately back to OTHER.
    const selector = page.locator(".proposal-select select").first();
    await selector.selectOption(CANONICAL);
    await selector.selectOption(OTHER);
    // Wait past the slow canonical response window; it must never appear.
    await page.waitForTimeout(3000);
    await expect(page.getByText("CANONICAL-PROPOSAL-EVIDENCE")).toHaveCount(0);
    await expect(page.getByText("OTHER-PROPOSAL-EVIDENCE").first()).toBeVisible();
  });
});
