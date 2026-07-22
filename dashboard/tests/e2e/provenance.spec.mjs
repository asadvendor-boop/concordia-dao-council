// FE-07: provenance-aware rendering. Unknown / failed / absent proof data NEVER
// renders a green/success cue; verified registry data does; the SafePay panel
// renders the three section-12 dispositions distinctly; the official-x402
// panel stays honestly fail-closed. Plus source-scan guards proving the old
// fabricated fallbacks cannot return.
import { expect, test } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FIXTURES, loadFixture } from "../fixtures/registry-fixtures.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const componentsDir = path.resolve(__dirname, "../../app/_components");

async function mockRegistry(page, payload) {
  await page.route("**/proof-registry/v1/**", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(payload) });
  });
}

function readComponentSources() {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".js")) files.push({ file: full, source: fs.readFileSync(full, "utf8") });
    }
  };
  walk(componentsDir);
  return files;
}

test.describe("provenance-aware rendering (FE-07)", () => {
  test("unverified/absent registry data renders zero green cues in proof surfaces", async ({ page }) => {
    await mockRegistry(page, loadFixture(FIXTURES.unverified));
    await page.goto("/dashboard/proof?tab=data", { waitUntil: "domcontentloaded" });
    const registryList = page.locator("[data-testid='proof-registry-list']");
    await expect(registryList).toBeVisible();
    // No item may render the green verified badge or any success pill.
    await expect(page.locator(".prov-verified")).toHaveCount(0);
    await expect(registryList.locator(".status-success")).toHaveCount(0);
    await expect(registryList.locator(".registry-item")).toHaveCount(3);

    // Summary tab: SafePay + official x402 panels must be non-green too.
    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const safepay = page.locator("[data-testid='safepay-panel']");
    await expect(safepay).toBeVisible();
    await expect(safepay.locator(".status-success")).toHaveCount(0);
    await expect(safepay.locator(".disposition-proof")).toHaveCount(0);
    const x402 = page.locator("[data-testid='official-x402-panel']");
    await expect(x402).toBeVisible();
    await expect(x402.locator(".status-success")).toHaveCount(0);
    await expect(page.locator("[data-testid='official-x402-blocked']")).toBeVisible();
    await expect(page.locator(".x402-panel")).toContainText("pending live verification");
  });

  test("verified registry fixture renders green cues and the three SafePay dispositions distinctly", async ({ page }) => {
    await mockRegistry(page, loadFixture(FIXTURES.verified));
    await page.goto("/dashboard/proof?tab=data", { waitUntil: "domcontentloaded" });
    await expect(page.locator("[data-testid='proof-registry-list']")).toBeVisible();
    expect(await page.locator(".prov-verified").count()).toBeGreaterThan(0);

    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const safepay = page.locator("[data-testid='safepay-panel']");
    await expect(safepay).toBeVisible();
    for (const disposition of ["first_consumption", "idempotent_replay", "cross_binding_rejected"]) {
      const row = safepay.locator(`[data-disposition='${disposition}']`);
      await expect(row).toBeVisible();
      await expect(row).toHaveClass(/disposition-proof/);
    }
    await expect(safepay.locator("[data-disposition='cross_binding_rejected']")).toContainText("409");
    // SafePay is native CSPR and never described as WCSPR; the official x402
    // panel is separate and remains fail-closed (its fixture item is the
    // unavailable initial state).
    await expect(safepay).toContainText("native CSPR");
    await expect(page.locator("[data-testid='official-x402-blocked']")).toBeVisible();
    await expect(page.locator(".x402-panel .status-success")).toHaveCount(0);
  });

  test("judge walkthrough without live payloads asserts nothing: no invariant results, no SafePay success", async ({ page }) => {
    await page.route("**/judge-walkthrough/**", (route) => route.fulfill({ status: 503, contentType: "application/json", body: "{}" }));
    await page.route("**/proof-registry/v1/**", (route) => route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: "proposal_not_found" }) }));
    await page.goto("/dashboard/judge", { waitUntil: "domcontentloaded" });
    const invariants = page.locator("[data-testid='invariant-runner-unavailable']");
    await expect(invariants).toBeVisible();
    await expect(invariants.locator(".status-success")).toHaveCount(0);
    const safepay = page.locator("[data-testid='safepay-panel']");
    await expect(safepay).toBeVisible();
    await expect(safepay.locator(".status-success")).toHaveCount(0);
    await expect(safepay).toContainText("unavailable");
    // The fallback story steps carry no asserted verified/passed statuses.
    const stepPills = page.locator(".judge-step-card .status-pill");
    const pillTexts = (await stepPills.allTextContents()).map((text) => text.trim().toLowerCase());
    for (const text of pillTexts) {
      expect(text).not.toContain("verified");
      expect(text).not.toContain("passed");
    }
  });

  test("source scan: fabricated fallbacks and fail-open verification cannot return", () => {
    const sources = readComponentSources();
    const all = sources.map((entry) => entry.source).join("\n");
    // The old hardcoded SafePay/invariant fallback literals must not exist.
    expect(all).not.toMatch(/duplicate_proof_rejected\s*:\s*true/);
    expect(all).not.toMatch(/duplicate_x402_proof_rejected/);
    // The old fallback agent counters must not exist.
    expect(all).not.toContain("6 / 6 agents online");
    expect(all).not.toMatch(/agents\.length\s*\|\|\s*6/);
    expect(all).not.toMatch(/\|\|\s*17/);
    expect(all).not.toMatch(/skills\.length\s*\|\|\s*7/);
    // The removed fake-live payment constant name must not exist; the recorded
    // historical payment constant must be explicitly historical.
    expect(all).not.toContain("DEFAULT_X402_PAYMENT_HASH");
    expect(all).toContain("HISTORICAL_SAFEPAY_PAYMENT_HASH");
    // receiptVerified must require positive verification (=== true), never the
    // old fail-open `!== false`.
    const lib = sources.find((entry) => entry.file.endsWith("lib.js"));
    expect(lib.source).toMatch(/receiptVerified:\s*Boolean\(receipt\)\s*&&\s*verification\?\.recovered\s*===\s*true/);
    expect(all).not.toMatch(/recovered\s*!==\s*false/);
  });
});
