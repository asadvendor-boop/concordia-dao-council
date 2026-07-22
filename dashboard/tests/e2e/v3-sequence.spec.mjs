// FE-14: the four-outcome exact-envelope v3 sequence renders exclusively from
// registry fixture DATA — error names/codes 8/10/12/13 with expected_rejection
// styled as positive proof — and renders an honest pending state when the
// registry is absent. Route mocks only; never the live app.
import { expect, test } from "@playwright/test";
import { FIXTURES, loadFixture } from "../fixtures/registry-fixtures.mjs";

async function mockRegistry(page, payload) {
  await page.route("**/proof-registry/v1/**", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(payload) });
  });
}

async function gotoProof(page) {
  await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
  await page.locator("body").waitFor({ state: "attached" });
}

test.describe("v3 sequence renders from data", () => {
  test("verified fixture renders codes 8/10/12/13 as data with expected rejections as positive proof", async ({ page }) => {
    await mockRegistry(page, loadFixture(FIXTURES.verified));
    await gotoProof(page);
    const sequence = page.locator("[data-testid='v3-sequence']");
    await expect(sequence).toBeVisible();

    const expectations = [
      { code: "8", name: "QuorumNotMet" },
      { code: "10", name: "EnvelopeHashMismatch" },
      { code: "12", name: "AlreadyFinalized" },
      { code: "13", name: "ActionAlreadyAuthorized" },
    ];
    for (const { code, name } of expectations) {
      const outcome = sequence.locator(`[data-outcome-code='${code}']`);
      await expect(outcome).toBeVisible();
      await expect(outcome).toContainText(`error ${code}`);
      await expect(outcome).toContainText(name);
      await expect(outcome).toHaveClass(/v3-outcome-proof/);
      await expect(outcome.getByText("Expected rejection · proof")).toBeVisible();
      await expect(outcome).not.toHaveClass(/v3-outcome-failed/);
    }
    const accepted = sequence.locator("[data-outcome-code='accepted']");
    await expect(accepted).toBeVisible();
    await expect(accepted).toHaveClass(/v3-outcome-accepted/);
    await expect(accepted).toContainText("Accepted");
    await expect(sequence.locator(".v3-outcome-failed")).toHaveCount(0);
  });

  test("fixture swap changes the rendered outcomes (no literals): failed check renders failure, never proof", async ({ page }) => {
    await mockRegistry(page, loadFixture(FIXTURES.v3Failed));
    await gotoProof(page);
    const sequence = page.locator("[data-testid='v3-sequence']");
    await expect(sequence).toBeVisible();
    const failed = sequence.locator("[data-outcome-code='8']");
    await expect(failed).toHaveClass(/v3-outcome-failed/);
    await expect(failed).not.toHaveClass(/v3-outcome-proof/);
    // The item is invalid: nothing in the sequence may carry a green proof or
    // accepted style even though other checks passed.
    await expect(sequence.locator(".v3-outcome-proof")).toHaveCount(0);
    await expect(sequence.locator(".v3-outcome-accepted")).toHaveCount(0);
  });

  test("registry absence renders an honest pending state with no asserted outcome", async ({ page }) => {
    await page.route("**/proof-registry/v1/**", async (route) => {
      await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: "proposal_not_found" }) });
    });
    await gotoProof(page);
    await expect(page.locator("[data-testid='v3-sequence-pending']")).toBeVisible();
    await expect(page.locator(".v3-outcome-proof")).toHaveCount(0);
    await expect(page.locator(".v3-outcome-accepted")).toHaveCount(0);
    await expect(page.locator("[data-testid='v3-sequence-pending']")).toContainText("pending live verification");
  });
});
