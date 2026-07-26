import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  NAV_GROUPS,
  PUBLIC_APP_ORIGIN,
  PUBLIC_LINKS,
  RECORDED_PROOF_ROWS,
  normalizeDashboardHref,
  X402_RECORDED_SETTLEMENT_BADGE,
  X402_RECORDED_SETTLEMENT_COPY,
} from "../../app/_components/presentation-config.mjs";

const expectedRoutes = [
  "/",
  "/agents",
  "/proposals",
  "/approvals",
  "/evidence",
  "/proof",
  "/judge",
  "/runs",
];

test("V1.5 navigation groups preserve every V1 dashboard route exactly once", () => {
  assert.deepEqual(NAV_GROUPS.map((group) => group.label), ["MONITOR", "GOVERN", "PROVE"]);
  const routes = NAV_GROUPS.flatMap((group) => group.items.map((item) => item.href));
  assert.deepEqual(routes, expectedRoutes);
  assert.equal(new Set(routes).size, expectedRoutes.length);
});

test("judge-facing public links use only approved owned and publication origins", () => {
  assert.equal(PUBLIC_APP_ORIGIN, "https://concordiadao.xyz");
  assert.deepEqual(
    PUBLIC_LINKS.map(({ id, href }) => [id, href]),
    [
      ["canonical_receipt", "https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852"],
      ["docs", "https://docs.concordiadao.xyz"],
      ["github", "https://github.com/asadvendor-boop/concordia-dao-council"],
      ["npm", "https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.4"],
      ["x", "https://x.com/ConcordiaDAO"],
    ],
  );
  for (const { href } of PUBLIC_LINKS) {
    assert.doesNotMatch(href, /sslip\.io|https:\/\/(?:x402|safepay)\./i);
  }
});

test("legacy Concordia self-links normalize to the apex while true external links remain intact", () => {
  assert.equal(normalizeDashboardHref("/proof/DAO-PROP-6CB25C"), "/proof/DAO-PROP-6CB25C");
  assert.equal(normalizeDashboardHref("https://concordiadao.xyz/evidence/DAO-PROP-6CB25C"), "https://concordiadao.xyz/evidence/DAO-PROP-6CB25C");
  assert.equal(normalizeDashboardHref("https://concordia.47.84.232.193.sslip.io/evidence/x"), "https://concordiadao.xyz/evidence/x");
  assert.equal(normalizeDashboardHref("http://47.84.232.193/proof-pack/x"), "https://concordiadao.xyz/proof-pack/x");
  assert.equal(normalizeDashboardHref("http://127.0.0.1:8000/evidence/x"), "https://concordiadao.xyz/evidence/x");
  assert.equal(normalizeDashboardHref("https://testnet.cspr.live/deploy/abc"), "https://testnet.cspr.live/deploy/abc");
  assert.equal(normalizeDashboardHref("https://github.com/example/repo"), "https://github.com/example/repo");
});

test("SafePay Lite remains a recorded V1 proof under the apex domain", () => {
  const safePay = RECORDED_PROOF_ROWS.find((row) => row.id === "safepay-lite");
  assert.ok(safePay);
  assert.match(safePay.label, /recorded V1 native-CSPR SafePay Lite evidence/i);
  assert.equal(safePay.status, "recorded V1 proof");
  assert.equal(safePay.href, "https://concordiadao.xyz/safepay-lite/DAO-PROP-6CB25C");
});

test("Proof Center distinguishes the live x402 challenge from its recorded settlement", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  const fallbackStart = app.indexOf("const fallbackIntegrations = {");
  const fallbackEnd = app.indexOf("\n  };", fallbackStart);
  assert.notEqual(fallbackStart, -1);
  assert.notEqual(fallbackEnd, -1);

  const fallback = app.slice(fallbackStart, fallbackEnd);
  assert.match(fallback, /mode:\s*"casper_native_x402_v2_implemented"/);
  assert.match(fallback, /status:\s*"payment_intent_and_http_402_available"/);
  assert.match(fallback, /settlement_driver:\s*"native_cspr_historical_record"/);
  assert.match(fallback, /provider_url_configured:\s*false/);
  assert.match(fallback, /official_x402:\s*false/);
  assert.match(fallback, /live_facilitator:\s*false/);
  assert.match(fallback, /X402_RECORDED_SETTLEMENT_COPY/);
  assert.doesNotMatch(fallback, /mode:\s*"real"|external_paid_provider|provider_url_configured:\s*true/);
});

test("judge-facing x402 copy and badge state the verified public boundary", () => {
  assert.equal(
    X402_RECORDED_SETTLEMENT_COPY,
    "Casper-native x402 v2 is deployed. The public endpoint exposes a live HTTP 402 challenge, and a recorded Casper Testnet casper-transfer settlement finalized successfully. No external facilitator service is claimed.",
  );
  assert.equal(
    X402_RECORDED_SETTLEMENT_BADGE,
    "x402 · CASPER-TRANSFER · RECORDED SETTLEMENT",
  );

  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  const landing = readFileSync(new URL("../../app/_components/LandingPage.js", import.meta.url), "utf8");
  for (const source of [app, landing]) {
    assert.doesNotMatch(source, /no successful live-settlement|does not prove successful live settlement/i);
  }
  assert.match(app, /X402_RECORDED_SETTLEMENT_BADGE/);
  assert.match(app, /X402_RECORDED_SETTLEMENT_COPY/);
  assert.match(landing, /X402_RECORDED_SETTLEMENT_COPY/);
});

test("recorded x402 receipt links to CSPR.live and its settlement CSV remains downloadable", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  assert.match(
    app,
    /label="Recorded SafePay Lite payment"[\s\S]*?href=\{`https:\/\/testnet\.cspr\.live\/deploy\/\$\{DEFAULT_X402_PAYMENT_HASH\}`\}/,
  );
  assert.match(
    app,
    /exports\/x402_settlements\.csv[^<]*<\/a>/,
  );
});

test("normal UI images are eager purpose-sized WebP, never source PNGs", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  const landing = readFileSync(new URL("../../app/_components/LandingPage.js", import.meta.url), "utf8");
  for (const source of [app, landing]) {
    assert.doesNotMatch(source, /agents\/[^"'`]+\.png/);
    assert.doesNotMatch(source, /loading=["']lazy["']/);
  }
  assert.match(landing, /concordia-dao-logo-final\.webp/);
  const layout = readFileSync(new URL("../../app/layout.js", import.meta.url), "utf8");
  assert.match(layout, /apple:\s*"\/dashboard\/concordia-dao-apple-touch\.png"/);
  assert.doesNotMatch(layout, /icon:\s*"[^"]*concordia-dao-logo-final\.png"/);
});

test("unobserved agent state is never presented as live or connected", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  assert.doesNotMatch(app, /"6 \/ 6 agents online"/);
  assert.match(app, /"Current agent status unavailable"/);
  assert.match(app, /hasAgentObservation && onlineCount > 0/);
  assert.match(app, /value:\s*"Verified"/);
  assert.doesNotMatch(app, /value:\s*"Live proof"/);
});

test("production data requests stay same-origin for the shared-host gateway routes", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  assert.match(app, /const GW = process\.env\.NEXT_PUBLIC_GATEWAY_URL \|\| "";/);
  assert.doesNotMatch(app, /const GW = [^;]*127\.0\.0\.1/);
});

test("proposal workspace does not reference approval-only decision state", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  const workspaceStart = app.indexOf("function ProposalWorkspacePage");
  const approvalStart = app.indexOf("function ApprovalPage", workspaceStart);
  assert.notEqual(workspaceStart, -1);
  assert.notEqual(approvalStart, -1);
  assert.doesNotMatch(app.slice(workspaceStart, approvalStart), /decisionState/);
});

test("judge evidence disclosures are visible by default", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  assert.match(app, /const \[showAll, setShowAll\] = useState\(true\);/);
  assert.match(app, /<details className="advanced-actions" open>/);
});

test("landing leads with the approved authorization thesis without naming competitors", () => {
  const landing = readFileSync(new URL("../../app/_components/LandingPage.js", import.meta.url), "utf8");
  assert.match(
    landing,
    /Agentic payments on Casper are arriving\. The unsolved half is authorization:/,
  );
  assert.match(landing, /what refuses the ones that weren(?:'|&apos;)t\?/);
  assert.match(landing, /A gateway can be routed around\./);
  assert.match(landing, /the governed action path/);
  assert.doesNotMatch(
    landing,
    /AiFinPay|A2A Governance Gateway|LASTRE|Phoenix Zero|Sluice|AgentPay|CasperGuard/i,
  );
});
