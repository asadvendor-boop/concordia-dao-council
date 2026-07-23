import { expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const screenshotDir = path.join(repoRoot, "artifacts/frontend-review/screenshots");
const liveTarget = Boolean(process.env.CONCORDIA_DASHBOARD_BASE_URL);

const dashboardRoutes = [
  { name: "overview", path: "/dashboard" },
  { name: "proposals", path: "/dashboard/proposals" },
  { name: "approvals", path: "/dashboard/approvals" },
  { name: "council-chamber", path: "/dashboard/agents" },
  { name: "evidence", path: "/dashboard/evidence" },
  { name: "proof-center", path: "/dashboard/proof" },
  { name: "judge-walkthrough", path: "/dashboard/judge" },
  { name: "judge-recording", path: "/dashboard/judge?recording=1" },
  { name: "runs-replay", path: "/dashboard/runs" },
  { name: "record", path: "/dashboard/record" },
  { name: "technical-jury-note", path: "/dashboard/technical-jury-note" },
];

async function assertNoHorizontalOverflow(page) {
  await page.waitForLoadState("domcontentloaded", { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(500);
  const overflow = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
    bodyScrollWidth: document.body?.scrollWidth || 0,
  }));
  expect(overflow.scrollWidth, JSON.stringify(overflow)).toBeLessThanOrEqual(overflow.clientWidth + 2);
  expect(overflow.bodyScrollWidth, JSON.stringify(overflow)).toBeLessThanOrEqual(overflow.clientWidth + 2);
}

async function gotoDashboardRoute(page, routePath) {
  await page.goto(routePath, {
    waitUntil: liveTarget ? "commit" : "domcontentloaded",
    timeout: liveTarget ? 60_000 : 30_000,
  });
  await page.locator("body").waitFor({ state: "attached", timeout: 30_000 });
  if (liveTarget) {
    await page.waitForLoadState("domcontentloaded", { timeout: 30_000 }).catch(() => {});
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
  }
}

async function assertProofButtonsHealthy(page) {
  const buttons = await page.locator("[data-testid^='proof-action-']").evaluateAll((elements) =>
    elements.map((element) => ({
      tag: element.tagName.toLowerCase(),
      testId: element.getAttribute("data-testid"),
      text: element.textContent?.replace(/\s+/g, " ").trim() || "",
      href: element.getAttribute("href"),
      disabled: element.hasAttribute("disabled") || element.getAttribute("aria-disabled") === "true",
      title: element.getAttribute("title") || "",
      target: element.getAttribute("target") || "",
    })),
  );

  expect(buttons.length).toBeGreaterThan(0);
  for (const button of buttons) {
    if (button.disabled) {
      expect(button.title || button.text, `${button.testId} needs a disabled reason`).toBeTruthy();
      continue;
    }
    if (button.tag === "a") {
      expect(button.href, `${button.testId} must have href`).toBeTruthy();
      expect(
        button.href.startsWith("http://127.0.0.1") ||
          button.href.startsWith("https://") ||
          button.href.startsWith("/dashboard") ||
          button.href.startsWith("/proof-pack") ||
          button.href.startsWith("/certificate") ||
          button.href.startsWith("/api/") ||
          button.href.startsWith("/safepay-lite"),
        `${button.testId} has unexpected href ${button.href}`,
      ).toBeTruthy();
      if (button.target === "_blank" && button.href.startsWith("http")) {
        expect(button.href, `${button.testId} external links must be https`).toMatch(/^https:\/\//);
      }
    }
  }
}

function luminance([r, g, b]) {
  const channel = [r, g, b].map((value) => {
    const normalized = value / 255;
    return normalized <= 0.03928 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channel[0] + 0.7152 * channel[1] + 0.0722 * channel[2];
}

function contrastRatio(foreground, background) {
  const light = Math.max(luminance(foreground), luminance(background));
  const dark = Math.min(luminance(foreground), luminance(background));
  return (light + 0.05) / (dark + 0.05);
}

function parseRgba(value) {
  const match = String(value || "").match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/i);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3]), match[4] === undefined ? 1 : Number(match[4])];
}

function compositeOver(color, base = [7, 17, 30]) {
  const alpha = color[3] ?? 1;
  return [
    Math.round(color[0] * alpha + base[0] * (1 - alpha)),
    Math.round(color[1] * alpha + base[1] * (1 - alpha)),
    Math.round(color[2] * alpha + base[2] * (1 - alpha)),
  ];
}

test.describe("Concordia proof cockpit browser acceptance", () => {
  for (const route of dashboardRoutes) {
    test(`${route.name} has no horizontal overflow and healthy proof actions`, async ({ page }) => {
      await gotoDashboardRoute(page, route.path);
      await assertNoHorizontalOverflow(page);
      if (["proof-center", "judge-walkthrough", "judge-recording", "record", "technical-jury-note"].includes(route.name)) {
        await assertProofButtonsHealthy(page);
      }
      if (!liveTarget) {
        await page.screenshot({
          path: path.join(screenshotDir, `${route.name}-1440x900.png`),
          fullPage: true,
        });
      }
    });
  }

  test("desktop sidebar can collapse to 88px without causing overflow", async ({ page }) => {
    await gotoDashboardRoute(page, "/dashboard");
    const collapseButton = page.getByRole("button", { name: "Collapse sidebar" });
    await expect(collapseButton).toBeVisible();
    await expect(collapseButton).toBeEnabled();
    await collapseButton.click();
    await expect(page.locator(".app-shell.sidebar-collapsed")).toBeVisible();
    await expect(page.getByRole("button", { name: "Expand sidebar" })).toBeVisible();
    const sidebarWidth = await page.locator(".sidebar").evaluate((element) => Math.round(element.getBoundingClientRect().width));
    expect(sidebarWidth).toBe(88);
    await assertNoHorizontalOverflow(page);
  });

  test("proof center defaults to canonical proof and hides suppressed missing states", async ({ page }) => {
    await gotoDashboardRoute(page, "/dashboard/proof");
    await expect(page.getByText("Canonical reviewer proof").first()).toBeVisible();
    await expect(page.getByText("DAO-PROP-6CB25C").first()).toBeVisible();
    await expect(page.getByText(/Approved receipt anchored on Casper Testnet:\s*MISSING/i)).toHaveCount(0);
    await expect(page.getByRole("tablist", { name: "Proof Center sections" })).toBeVisible();
  });

  test("judge walkthrough exposes wallet sandbox and proof center deep-links to on-chain preview", async ({ page }) => {
    await gotoDashboardRoute(page, "/dashboard/judge");
    await expect(page.getByRole("heading", { name: "Live wallet / testnet sandbox" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Open Wallet Sandbox" })).toBeVisible();
    await gotoDashboardRoute(page, "/dashboard/proof?tab=onchain");
    // Proof-Center sections are now ARIA tabs (role=tab, aria-selected).
    const onchainTab = page.getByRole("tab", { name: "On-chain" });
    await expect(onchainTab).toHaveClass(/active/);
    await expect(onchainTab).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("heading", { name: "Judge Sandbox" })).toBeVisible();
    await expect(page.getByText("Advanced: re-run signing demo")).toBeVisible();
    await assertNoHorizontalOverflow(page);
  });

  test("judge adversarial replay displays deterministic mode without degraded fallback wording", async ({ page }) => {
    await page.route("**/adversarial-replay/**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "blocked",
          attempted_allocation_bps: 4000,
          max_allowed_allocation_bps: 800,
          invariant_result: "failed_policy_cap",
          mandate_result: "capped_to_800_bps",
          locke_result: "refused_to_sign",
          casper_transaction_triggered: false,
          proof_mode: "interactive_adversarial_replay",
          llm_mode: "deterministic_adversarial_replay_fallback",
        }),
      });
    });
    await gotoDashboardRoute(page, "/dashboard/judge");
    // Retry the trigger-click until the replay panel lands: a click dispatched
    // before React hydration attaches the handler is silently lost (test
    // timing artifact, not an app defect — same idiom as the nav-drawer test).
    await expect(async () => {
      await page.getByRole("button", { name: "Try to Break Concordia" }).click();
      await expect(page.getByText("Mode")).toBeVisible({ timeout: 1000 });
    }).toPass({ timeout: 10_000 });
    await expect(page.getByText("Deterministic Adversarial Replay")).toBeVisible();
    await expect(page.locator(".safety-demo-grid").getByText("Fallback")).toHaveCount(0);
  });

  test("recording mode hides dashboard chrome and exposes recording controls", async ({ page }) => {
    await gotoDashboardRoute(page, "/dashboard/judge?recording=1");
    await expect(page.locator(".sidebar")).toBeHidden();
    await expect(page.locator(".topbar")).toBeHidden();
    await expect(page.getByText("90-second Concordia proof path")).toBeVisible();
    await expect(page.getByRole("button", { name: /Next/i })).toBeVisible();
    await assertNoHorizontalOverflow(page);
  });

  test("technical jury note is styled inside the dashboard shell", async ({ page }) => {
    await gotoDashboardRoute(page, "/dashboard/technical-jury-note");
    await expect(page.getByRole("heading", { name: "Technical Jury Note" })).toBeVisible();
    await expect(page.getByText("Smart contract proof table")).toBeVisible();
    await expect(page.locator(".technical-note-grid").first()).toBeVisible();
    await assertNoHorizontalOverflow(page);
  });

  test("certificate artifact is responsive and avoids long URL overflow", async ({ page }) => {
    const certificatePath = path.join(repoRoot, "artifacts/live/certificate-current.html");
    for (const [width, height] of [
      [1280, 900],
      [1024, 900],
      [768, 900],
      [390, 844],
    ]) {
      await page.setViewportSize({ width, height });
      await page.goto(pathToFileURL(certificatePath).href, { waitUntil: "domcontentloaded" });
      await expect(page.locator(".qr-card").first()).toBeVisible();
      await assertNoHorizontalOverflow(page);
      await page.screenshot({
        path: path.join(screenshotDir, `certificate-${width}x${height}.png`),
        fullPage: true,
      });
    }
  });

  test("accessibility sanity: controls have names, keyboard focus works, and core contrast is readable", async ({ page }) => {
    await gotoDashboardRoute(page, "/dashboard/judge");
    const unnamedControls = await page.locator("a:visible, button:visible").evaluateAll((elements) =>
      elements
        .map((element) => ({
          tag: element.tagName.toLowerCase(),
          text: element.textContent?.replace(/\s+/g, " ").trim() || "",
          aria: element.getAttribute("aria-label") || "",
          title: element.getAttribute("title") || "",
          testId: element.getAttribute("data-testid") || "",
        }))
        .filter((control) => !control.text && !control.aria && !control.title),
    );
    expect(unnamedControls, JSON.stringify(unnamedControls.slice(0, 8))).toEqual([]);

    await page.keyboard.press("Tab");
    const focusState = await page.evaluate(() => {
      const active = document.activeElement;
      if (!active) return { tag: null, visible: false, text: "" };
      const rect = active.getBoundingClientRect();
      return {
        tag: active.tagName.toLowerCase(),
        visible: rect.width > 0 && rect.height > 0,
        text: active.textContent?.replace(/\s+/g, " ").trim() || active.getAttribute("aria-label") || active.getAttribute("title") || "",
      };
    });
    expect(focusState.visible, JSON.stringify(focusState)).toBeTruthy();
    expect(["a", "button", "select", "input"]).toContain(focusState.tag);
    expect(focusState.text, JSON.stringify(focusState)).toBeTruthy();

    const contrastSamples = await page.locator("h1, .page-header-copy p, .judge-step-card p, .status-pill").evaluateAll((elements) =>
      elements.slice(0, 12).map((element) => {
        const style = window.getComputedStyle(element);
        let ancestor = element;
        let background = style.backgroundColor;
        while ((!background || background === "rgba(0, 0, 0, 0)" || background === "transparent") && ancestor.parentElement) {
          ancestor = ancestor.parentElement;
          background = window.getComputedStyle(ancestor).backgroundColor;
        }
        return {
          text: element.textContent?.replace(/\s+/g, " ").trim().slice(0, 40),
          color: style.color,
          background,
        };
      }),
    );
    for (const sample of contrastSamples) {
      const fgRaw = parseRgba(sample.color);
      const bgRaw = parseRgba(sample.background);
      const fg = fgRaw ? compositeOver(fgRaw) : null;
      const bg = bgRaw ? compositeOver(bgRaw) : null;
      expect(fg, JSON.stringify(sample)).toBeTruthy();
      expect(bg, JSON.stringify(sample)).toBeTruthy();
      expect(contrastRatio(fg, bg), JSON.stringify(sample)).toBeGreaterThanOrEqual(4.5);
    }
  });
});
