import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  NAV_GROUPS,
  PUBLIC_APP_ORIGIN,
  PUBLIC_LINKS,
  RECORDED_PROOF_ROWS,
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
      ["website", "https://concordiadao.xyz"],
      ["docs", "https://docs.concordiadao.xyz"],
      ["github", "https://github.com/asadvendor-boop/concordia-dao-council"],
      ["npm", "https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.2"],
      ["x", "https://x.com/ConcordiaDAO"],
    ],
  );
  for (const { href } of PUBLIC_LINKS) {
    assert.doesNotMatch(href, /sslip\.io|https:\/\/(?:x402|safepay)\./i);
  }
});

test("SafePay Lite remains a recorded V1 proof under the apex domain", () => {
  const safePay = RECORDED_PROOF_ROWS.find((row) => row.id === "safepay-lite");
  assert.ok(safePay);
  assert.match(safePay.label, /recorded V1 native-CSPR SafePay Lite evidence/i);
  assert.equal(safePay.status, "recorded V1 proof");
  assert.equal(safePay.href, "https://concordiadao.xyz/safepay-lite/DAO-PROP-6CB25C");
});

test("Proof Center fallback never invents a live SafePay integration", () => {
  const app = readFileSync(new URL("../../app/_components/ConcordiaApp.js", import.meta.url), "utf8");
  const fallbackStart = app.indexOf("const fallbackIntegrations = {");
  const fallbackEnd = app.indexOf("\n  };", fallbackStart);
  assert.notEqual(fallbackStart, -1);
  assert.notEqual(fallbackEnd, -1);

  const fallback = app.slice(fallbackStart, fallbackEnd);
  assert.match(fallback, /mode:\s*"recorded_v1_evidence"/);
  assert.match(fallback, /status:\s*"recorded_v1_native_cspr_safepay_lite_evidence"/);
  assert.match(fallback, /settlement_driver:\s*"native_cspr_historical_record"/);
  assert.match(fallback, /provider_url_configured:\s*false/);
  assert.match(fallback, /official_x402:\s*false/);
  assert.match(fallback, /live_facilitator:\s*false/);
  assert.match(fallback, /not official x402 and not a live facilitator/i);
  assert.doesNotMatch(fallback, /mode:\s*"real"|external_paid_provider|provider_url_configured:\s*true/);
});
