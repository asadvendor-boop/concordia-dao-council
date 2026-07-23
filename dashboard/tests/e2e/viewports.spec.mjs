// FE-19-style viewport matrix: 1440x900 (desktop), 768x1024 (tablet portrait),
// 375x812 (phone). Every route must render without horizontal document
// overflow, the navigation must stay usable, and wide proof tables must scroll
// inside their own container instead of stretching the page.
import { expect, test } from "@playwright/test";

const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "mobile", width: 375, height: 812 },
];

const routes = [
  "/dashboard",
  "/dashboard/proposals",
  "/dashboard/approvals",
  "/dashboard/agents",
  "/dashboard/evidence",
  "/dashboard/proof",
  "/dashboard/judge",
  "/dashboard/runs",
  "/dashboard/technical-jury-note",
];

async function assertNoHorizontalOverflow(page, label) {
  await page.waitForTimeout(400);
  const overflow = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
    bodyScrollWidth: document.body?.scrollWidth || 0,
  }));
  expect(overflow.scrollWidth, `${label}: ${JSON.stringify(overflow)}`).toBeLessThanOrEqual(overflow.clientWidth + 2);
  expect(overflow.bodyScrollWidth, `${label}: ${JSON.stringify(overflow)}`).toBeLessThanOrEqual(overflow.clientWidth + 2);
}

for (const viewport of viewports) {
  test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport: { width: viewport.width, height: viewport.height } });

    test(`no horizontal overflow on any route at ${viewport.name}`, async ({ page }) => {
      for (const route of routes) {
        await page.goto(route, { waitUntil: "domcontentloaded" });
        await page.locator("body").waitFor({ state: "attached" });
        await assertNoHorizontalOverflow(page, `${route} @ ${viewport.name}`);
      }
    });

    test(`navigation is usable at ${viewport.name}`, async ({ page }) => {
      await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
      if (viewport.width < 1021) {
        // Mobile/tablet-portrait: the drawer opens from the menu button and
        // exposes all 8 destinations.
        const menu = page.getByRole("button", { name: "Open navigation" });
        await expect(menu).toBeVisible();
        // Retry the open-click until the drawer state lands: a click dispatched
        // before React hydration attaches the handler is silently lost (a
        // timing artifact of the test, not an app defect — no human clicks
        // within milliseconds of first paint).
        await expect(async () => {
          await menu.click();
          await expect(page.locator(".sidebar.sidebar-open")).toBeVisible({ timeout: 1000 });
        }).toPass({ timeout: 10_000 });
        await expect(page.locator(".sidebar .nav-item")).toHaveCount(8);
        await page.locator(".sidebar .nav-item", { hasText: "Proof Center" }).click();
        await expect(page).toHaveURL(/\/dashboard\/proof/);
      } else {
        await expect(page.locator(".sidebar .nav-item")).toHaveCount(8);
        await page.locator(".sidebar .nav-item", { hasText: "Proof Center" }).click();
        await expect(page).toHaveURL(/\/dashboard\/proof/);
        await expect(page.getByText("Canonical reviewer proof").first()).toBeVisible();
      }
    });

    test(`proof tables scroll inside their container at ${viewport.name}`, async ({ page }) => {
      await page.goto("/dashboard/technical-jury-note", { waitUntil: "domcontentloaded" });
      const wrap = page.locator(".table-wrap").first();
      await expect(wrap).toBeVisible();
      const overflowStyle = await wrap.evaluate((element) => window.getComputedStyle(element).overflowX);
      expect(["auto", "scroll"]).toContain(overflowStyle);
      await assertNoHorizontalOverflow(page, `technical-jury-note table @ ${viewport.name}`);
    });
  });
}
