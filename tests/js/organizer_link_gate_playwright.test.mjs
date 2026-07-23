import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  collectClientDownloads,
  collectDom,
  installReadOnlyWebSocketGuard,
} from "../../scripts/run_organizer_link_gate.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const runtimePackage = path.join(
  root,
  "scripts/g13-browser-runtime/package.json",
);
process.env.PLAYWRIGHT_BROWSERS_PATH = "0";
const requireRuntime = createRequire(runtimePackage);
const { chromium } = requireRuntime("playwright");

async function withBrowser(callback) {
  const browser = await chromium.launch({
    chromiumSandbox: true,
    headless: true,
  });
  try {
    const context = await browser.newContext({ acceptDownloads: true });
    try {
      await callback(context);
    } finally {
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

test("real Chromium derives route/tab identity and captures a client-side download", async () => {
  await withBrowser(async (context) => {
    const page = await context.newPage();
    await page.setContent(`
      <!doctype html>
      <title>Concordia test route</title>
      <main>
        <div class="brand-copy"><strong>Concordia DAO Council</strong></div>
        <a class="nav-item active" href="https://concordia.47.84.232.193.sslip.io/dashboard/proof">Proof Center</a>
        <h1>Proof Center</h1>
        <button
          id="proof-tab-onchain"
          role="tab"
          aria-selected="true"
          aria-controls="proof-tabpanel-onchain"
        >On-chain</button>
        <div
          id="proof-tabpanel-onchain"
          role="tabpanel"
        >On-chain proof</div>
        <button data-testid="export-proof">Export Evidence</button>
      </main>
      <script>
        document.querySelector('[data-testid="export-proof"]').addEventListener('click', () => {
          const link = document.createElement('a');
          link.download = 'concordia-proof.json';
          link.href = URL.createObjectURL(new Blob(['{"proof":true}\\n'], {
            type: 'application/json',
          }));
          link.click();
        });
      </script>
    `);

    const dom = await collectDom(page);
    assert.deepEqual(dom.route_identity, {
      brand_text: "Concordia DAO Council",
      active_navigation_path: "/dashboard/proof",
      primary_heading: "Proof Center",
      active_tab_id: "onchain",
      active_tabpanel_id: "proof-tabpanel-onchain",
    });
    assert.deepEqual(
      dom.rendered_download_controls.map(({ control_id, label }) => ({
        control_id,
        label,
      })),
      [{ control_id: "export-proof", label: "Export Evidence" }],
    );
    const downloads = await collectClientDownloads(
      page,
      dom.rendered_download_controls,
    );
    assert.equal(downloads.length, 1);
    assert.equal(downloads[0].control_id, "export-proof");
    assert.equal(downloads[0].suggested_filename, "concordia-proof.json");
    assert.equal(downloads[0].body_bytes, 15);
    assert.match(downloads[0].body_sha256, /^[0-9a-f]{64}$/u);
  });
});

test("real Chromium WebSocket routing aborts before server connection and records evidence", async () => {
  await withBrowser(async (context) => {
    const page = await context.newPage();
    const blocked = [];
    const browserSockets = [];
    page.on("websocket", (socket) => browserSockets.push(socket.url()));
    await installReadOnlyWebSocketGuard(page, blocked);
    await page.route(
      "https://concordia.47.84.232.193.sslip.io/websocket-test",
      (route) =>
        route.fulfill({
          contentType: "text/html",
          body: "<!doctype html><main><h1>Concordia</h1></main>",
        }),
    );
    await page.goto(
      "https://concordia.47.84.232.193.sslip.io/websocket-test",
    );
    const refusal = await page.evaluate(() => {
      try {
        new WebSocket("wss://sdk.cspr.click/concordia-test");
        return "not-blocked";
      } catch (error) {
        return `${error.name}:${error.message}`;
      }
    });
    assert.match(refusal, /^SecurityError:/u);
    for (let attempt = 0; attempt < 50 && blocked.length === 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.deepEqual(blocked, [
      {
        url_sha256: blocked[0].url_sha256,
        host: "sdk.cspr.click",
        disposition: "blocked_before_connect",
      },
    ]);
    assert.match(blocked[0].url_sha256, /^[0-9a-f]{64}$/u);
    assert.deepEqual(browserSockets, []);
  });
});
