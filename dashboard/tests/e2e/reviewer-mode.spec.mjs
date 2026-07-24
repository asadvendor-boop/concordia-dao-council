import { expect, test } from "@playwright/test";


const CANONICAL = "DAO-PROP-6CB25C";


function json(route, body, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}


async function mockReviewerGateway(page) {
  const proposal = {
    proposal_id: CANONICAL,
    state: "EXECUTED",
    created_at: "2026-06-29T00:00:00Z",
  };
  await page.route("**/stats", (route) => json(route, {}));
  await page.route("**/stats/runsummary", (route) => json(route, { runs: [] }));
  await page.route("**/agent-status", (route) => json(route, []));
  await page.route("**/agent-skills", (route) => json(route, { skills: [] }));
  await page.route("**/suppression-rules", (route) => json(route, []));
  await page.route("**/proof-registry/v1/**", (route) => (
    json(route, { error: "not_served" }, 404)
  ));
  await page.route("**/room-messages/*", (route) => (
    json(route, { messages: [], room_id: "room", message_count: 0 })
  ));
  await page.route((url) => url.pathname === "/proposals", (route) => (
    json(route, [proposal])
  ));
  await page.route("**/proposals/*", (route) => json(route, { proposal }));
  await page.route("**/evidence/*", (route) => json(route, {
    chain_valid: true,
    cards: [{
      card_type: "ProposalCard",
      sequence: 1,
      hash: "reviewer-proposal-card",
      data: {
        title: "Risky treasury move",
        raw_payload: { title: "Risky treasury move" },
      },
    }],
  }));
}


const REFUSAL_CASES = [
  "fresh activation",
  "idempotent replay",
  "running activation",
  "failed activation replay",
  "started activation response",
];


test.describe("@reviewer-only public review mode refuses mutation", () => {
  for (const label of REFUSAL_CASES) {
    test(`${label}: View replay makes no capability or activation request`, async ({
      page,
    }) => {
      await mockReviewerGateway(page);
      const requests = [];
      await page.route("**/api/demo/capability", (route) => {
        requests.push(route.request().url());
        return json(route, { error: "must_not_be_called" }, 500);
      });
      await page.route("**/api/demo/activate", (route) => {
        requests.push(route.request().url());
        return json(route, { error: "must_not_be_called" }, 500);
      });

      await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
      const trigger = page.getByTestId("overview-demo-trigger");
      const dialog = page.getByRole("dialog");
      await expect(async () => {
        await trigger.click();
        await expect(dialog).toBeVisible({ timeout: 1500 });
      }).toPass({ timeout: 15000 });

      const replay = dialog.getByRole("button", { name: /View replay/i });
      await expect(replay).toBeVisible();
      await expect(
        dialog.getByRole("button", { name: /Start full pipeline/i }),
      ).toHaveCount(0);
      await replay.click();

      await expect(dialog).not.toBeVisible();
      await expect(page.locator(".toast")).toContainText(
        "Live mutations are disabled in Public Review Mode",
      );
      await page.waitForTimeout(100);
      expect(requests).toEqual([]);
    });
  }
});
