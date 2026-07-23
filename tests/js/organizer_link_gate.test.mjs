import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import gate from "../../scripts/organizer-link-gate-core.mjs";

const testRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testRoot, "../..");
const corePath = path.join(repositoryRoot, "scripts/organizer-link-gate-core.mjs");
const runnerPath = path.join(repositoryRoot, "scripts/run_organizer_link_gate.mjs");
const requestPath = path.join(
  repositoryRoot,
  "handoff/ORGANIZER_LINK_GATE_REQUEST.json",
);
const fixturePath = path.join(
  repositoryRoot,
  "tests/fixtures/organizer-link-gate-pass.json",
);

test("the organizer rendered-link gate has an isolated pure core", () => {
  assert.equal(existsSync(corePath), true);
});

test("the pure core exposes the fail-closed audit contract", () => {
  for (const name of [
    "buildInventory",
    "canonicalJson",
    "classifyRenderedTarget",
    "validateRequest",
    "validateRouteObservation",
    "validateLinkObservation",
    "buildResult",
  ]) {
    assert.equal(typeof gate[name], "function", `${name} must be a function`);
  }
  assert.equal(typeof gate.GateFailure, "function");
});

function expectedRequest() {
  return {
    schema_version: gate.REQUEST_SCHEMA,
    app_origin: gate.APP_ORIGIN,
    docs_origin: gate.DOCS_ORIGIN,
    proposal_id: gate.PROPOSAL_ID,
    known_links: Object.entries(gate.KNOWN_LINKS).map(
      ([link_id, link]) => ({
        link_id,
        url: link.url,
        allowed_redirects: [...link.allowed_redirects],
      }),
    ),
  };
}

function expectFailure(code, callback) {
  assert.throws(callback, (error) => {
    assert.equal(error?.name, "GateFailure");
    assert.equal(error?.code, code);
    return true;
  });
}

test("the frozen inventory contains all 11 route states, five Proof tabs, and preserved query state", () => {
  const inventory = gate.buildInventory();
  assert.equal(inventory.dashboard_routes.length, 11);
  assert.deepEqual(
    inventory.dashboard_routes.map((route) => route.route_id),
    [
      "overview",
      "proposals",
      "approvals",
      "council_chamber",
      "evidence",
      "proof_center",
      "judge_walkthrough",
      "judge_recording",
      "runs_replay",
      "record",
      "technical_jury_note",
    ],
  );
  assert.deepEqual(
    inventory.proof_tabs.map((tab) => tab.tab_id),
    ["summary", "safety", "onchain", "data", "exports"],
  );
  assert.deepEqual(inventory.dashboard_routes[1].expected_query, {
    proposal: gate.PROPOSAL_ID,
  });
  assert.deepEqual(inventory.dashboard_routes[7].expected_query, {
    recording: "1",
  });
  for (const tab of inventory.proof_tabs) {
    assert.deepEqual(tab.expected_query, {
      proposal: gate.PROPOSAL_ID,
      tab: tab.tab_id,
    });
  }
});

test("the request is exact, public, and cannot widen the frozen URL inventory", () => {
  const request = expectedRequest();
  const validated = gate.validateRequest(request);
  assert.deepEqual(validated, request);

  const widenedHost = structuredClone(request);
  widenedHost.known_links[0].url = "https://example.com/";
  expectFailure("REQUEST_LINK_MISMATCH", () =>
    gate.validateRequest(widenedHost),
  );

  const extraField = { ...request, token: "must-not-exist" };
  expectFailure("REQUEST_FIELDS_INVALID", () =>
    gate.validateRequest(extraField),
  );
});

test("rendered targets reject invalid URLs and doubled dashboard base paths", () => {
  const firstParty = gate.classifyRenderedTarget(
    "/dashboard/proof?proposal=DAO-PROP-6CB25C",
    `${gate.APP_ORIGIN}/dashboard`,
    { element_kind: "anchor", download: false },
  );
  assert.equal(firstParty.kind, "first_party_anchor");

  const sameDocument = gate.classifyRenderedTarget(
    "#trust-boundary",
    `${gate.DOCS_ORIGIN}/architecture/`,
    { element_kind: "anchor", download: false },
  );
  assert.equal(sameDocument.kind, "document_anchor");
  assert.equal(sameDocument.fragment, "trust-boundary");

  const generatedFavicon = gate.classifyRenderedTarget(
    "/dashboard/favicon.ico?favicon.2vob68tjqpejf.ico",
    `${gate.APP_ORIGIN}/dashboard`,
    { element_kind: "asset", download: false },
  );
  assert.equal(generatedFavicon.kind, "first_party_asset");

  expectFailure("INVALID_URL", () =>
    gate.classifyRenderedTarget(
      "javascript:alert(1)",
      `${gate.APP_ORIGIN}/dashboard`,
      { element_kind: "anchor", download: false },
    ),
  );
  assert.throws(
    () =>
      gate.classifyRenderedTarget(
        "/dashboard/proof?unexpected=1",
        `${gate.APP_ORIGIN}/dashboard`,
        { element_kind: "anchor", download: false },
      ),
    (error) => {
      assert.equal(error?.code, "INVALID_URL");
      assert.match(error?.message ?? "", /query key unexpected/u);
      return true;
    },
  );
  expectFailure("DOUBLED_BASE_PATH", () =>
    gate.classifyRenderedTarget(
      "/dashboard/dashboard/proof",
      `${gate.APP_ORIGIN}/dashboard`,
      { element_kind: "anchor", download: false },
    ),
  );
});

function passingRouteObservation(spec) {
  return {
    route_id: spec.route_id,
    requested_url: spec.url,
    final_url: spec.url,
    status: 200,
    redirects: [],
    active_proof_tab: spec.active_proof_tab ?? null,
    console_errors: [],
    page_errors: [],
    blocked_non_read_requests: [],
    first_party_failures: [],
    rendered_links: [],
    rendered_assets: [],
    document_ids: ["top"],
    document_names: [],
  };
}

test("route observations fail closed on query loss, wrong tabs, browser errors, and failed first-party requests", () => {
  const inventory = gate.buildInventory();
  const proposalRoute = inventory.dashboard_routes.find(
    (route) => route.route_id === "proposals",
  );
  const proposalObservation = passingRouteObservation(proposalRoute);
  proposalObservation.final_url = `${gate.APP_ORIGIN}/dashboard/proposals`;
  expectFailure("QUERY_STATE_LOST", () =>
    gate.validateRouteObservation(proposalRoute, proposalObservation),
  );

  const tabSpec = inventory.proof_tabs.find((tab) => tab.tab_id === "onchain");
  const tabObservation = passingRouteObservation(tabSpec);
  tabObservation.active_proof_tab = "summary";
  expectFailure("PROOF_TAB_NOT_ACTIVE", () =>
    gate.validateRouteObservation(tabSpec, tabObservation),
  );

  const overview = inventory.dashboard_routes[0];
  for (const [field, code, value] of [
    ["console_errors", "CONSOLE_ERROR", [{ sha256: "a".repeat(64) }]],
    ["page_errors", "PAGE_ERROR", [{ sha256: "b".repeat(64) }]],
    [
      "blocked_non_read_requests",
      "NON_READ_REQUEST",
      [{ method: "POST", url: `${gate.APP_ORIGIN}/api/demo/activate` }],
    ],
    [
      "first_party_failures",
      "FIRST_PARTY_REQUEST_FAILED",
      [{ status: 404, url: `${gate.APP_ORIGIN}/dashboard/missing.js` }],
    ],
  ]) {
    const observation = passingRouteObservation(overview);
    observation[field] = value;
    expectFailure(code, () =>
      gate.validateRouteObservation(overview, observation),
    );
  }

  const doubled = passingRouteObservation(overview);
  doubled.rendered_links = [
    {
      href: `${gate.APP_ORIGIN}/dashboard/dashboard/proof`,
      element_kind: "anchor",
      download: false,
    },
  ];
  expectFailure("DOUBLED_BASE_PATH", () =>
    gate.validateRouteObservation(overview, doubled),
  );
});

test("link observations require documented redirects, successful bytes, and real documentation anchors", () => {
  const plainSpec = {
    link_id: "github_repository",
    url: gate.KNOWN_LINKS.github_repository.url,
    allowed_redirects: [],
  };
  const passing = {
    link_id: plainSpec.link_id,
    requested_url: plainSpec.url,
    effective_url: plainSpec.url,
    status: 200,
    redirects: [],
    body_bytes: 128,
    body_sha256: "c".repeat(64),
    anchor_found: null,
  };
  assert.deepEqual(
    gate.validateLinkObservation(plainSpec, passing),
    passing,
  );

  const redirected = {
    ...passing,
    effective_url: `${plainSpec.url}/`,
    redirects: [
      {
        from: plainSpec.url,
        to: `${plainSpec.url}/`,
        status: 301,
      },
    ],
  };
  expectFailure("UNDOCUMENTED_REDIRECT", () =>
    gate.validateLinkObservation(plainSpec, redirected),
  );

  expectFailure("LINK_HTTP_FAILURE", () =>
    gate.validateLinkObservation(plainSpec, { ...passing, status: 404 }),
  );
  expectFailure("EMPTY_RESPONSE", () =>
    gate.validateLinkObservation(plainSpec, { ...passing, body_bytes: 0 }),
  );

  const docsSpec = {
    link_id: "docs_judge_quickstart_anchor",
    url: gate.KNOWN_LINKS.docs_judge_quickstart_anchor.url,
    allowed_redirects: [],
  };
  expectFailure("MISSING_DOC_ANCHOR", () =>
    gate.validateLinkObservation(docsSpec, {
      ...passing,
      link_id: docsSpec.link_id,
      requested_url: docsSpec.url,
      effective_url: docsSpec.url,
      anchor_found: false,
    }),
  );
});

test("canonical output is stable and refuses an incomplete route or Proof-tab census", () => {
  const request = expectedRequest();
  const inventory = gate.buildInventory();
  const routes = inventory.dashboard_routes.map(passingRouteObservation);
  const proofTabs = inventory.proof_tabs.map(passingRouteObservation);
  const links = request.known_links.map((spec) => ({
    link_id: spec.link_id,
    requested_url: spec.url,
    effective_url: spec.url,
    status: 200,
    redirects: [],
    body_bytes: 128,
    body_sha256: "d".repeat(64),
    anchor_found: spec.url.includes("#") ? true : null,
  }));
  const result = gate.buildResult({
    request,
    routes,
    proof_tabs: proofTabs,
    links,
    runtime: {
      node: "v22.12.0",
      playwright: "1.58.2",
      chromium: "test",
      chromium_executable_sha256: "e".repeat(64),
    },
    started_at: "2026-07-24T00:00:00.000Z",
    captured_at: "2026-07-24T00:01:00.000Z",
    collection_mode: "fixture",
  });
  assert.equal(result.verdict, "PASS");
  assert.equal(result.collection_mode, "fixture");
  assert.deepEqual(result.summary, {
    dashboard_route_states: 11,
    proof_tabs: 5,
    unique_links: request.known_links.length,
    blocked_non_read_requests: 0,
    console_errors: 0,
    page_errors: 0,
    first_party_failures: 0,
  });
  assert.equal(
    gate.canonicalJson(result),
    gate.canonicalJson(structuredClone(result)),
  );
  expectFailure("ROUTE_INVENTORY_INCOMPLETE", () =>
    gate.buildResult({
      request,
      routes: routes.slice(1),
      proof_tabs: proofTabs,
      links,
      runtime: result.runtime,
      started_at: result.started_at,
      captured_at: result.captured_at,
      collection_mode: "fixture",
    }),
  );
  const unprobedRoutes = structuredClone(routes);
  unprobedRoutes[0].rendered_links = [
    {
      href: `${gate.APP_ORIGIN}/dashboard/proof`,
      element_kind: "anchor",
      download: false,
    },
  ];
  expectFailure("RENDERED_TARGET_UNCHECKED", () =>
    gate.buildResult({
      request,
      routes: unprobedRoutes,
      proof_tabs: proofTabs,
      links,
      runtime: result.runtime,
      started_at: result.started_at,
      captured_at: result.captured_at,
      collection_mode: "fixture",
    }),
  );
  expectFailure("LINK_HTTP_FAILURE", () =>
    gate.buildResult({
      request,
      routes,
      proof_tabs: proofTabs,
      links: [
        ...links,
        {
          link_id: "rendered_deadbeefdeadbeefdeadbeef",
          requested_url: `${gate.APP_ORIGIN}/dashboard/missing`,
          effective_url: `${gate.APP_ORIGIN}/dashboard/missing`,
          status: 404,
          redirects: [],
          body_bytes: 32,
          body_sha256: "f".repeat(64),
          anchor_found: null,
        },
      ],
      runtime: result.runtime,
      started_at: result.started_at,
      captured_at: result.captured_at,
      collection_mode: "fixture",
    }),
  );
});

test("the locked collector and exact public request are committed as separate release inputs", async () => {
  assert.equal(existsSync(runnerPath), true);
  assert.equal(existsSync(requestPath), true);
  const request = JSON.parse(
    await import("node:fs/promises").then(({ readFile }) =>
      readFile(requestPath, "utf8"),
    ),
  );
  assert.deepEqual(gate.validateRequest(request), expectedRequest());
  const help = spawnSync(process.execPath, [runnerPath, "--help"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /--input/);
  assert.match(help.stdout, /stdout/);
});

test("fixture mode is deterministic, offline, and runs through the same fail-closed validators", async () => {
  assert.equal(existsSync(fixturePath), true);
  const argv = [
    runnerPath,
    "--input",
    requestPath,
    "--fixture",
    fixturePath,
  ];
  const first = spawnSync(process.execPath, argv, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  const second = spawnSync(process.execPath, argv, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stdout, second.stdout);
  const result = JSON.parse(first.stdout);
  assert.equal(result.collection_mode, "fixture");
  assert.equal(result.verdict, "PASS");
  assert.equal(result.summary.dashboard_route_states, 11);
  assert.equal(result.summary.proof_tabs, 5);

  const temporary = await mkdtemp(
    path.join(os.tmpdir(), "concordia-organizer-link-fixture-"),
  );
  try {
    const broken = JSON.parse(await readFile(fixturePath, "utf8"));
    broken.route_overrides = {
      overview: {
        console_errors: [{ sha256: "f".repeat(64) }],
      },
    };
    const brokenPath = path.join(temporary, "broken.json");
    await writeFile(brokenPath, `${JSON.stringify(broken)}\n`, {
      mode: 0o600,
    });
    const refused = spawnSync(
      process.execPath,
      [runnerPath, "--input", requestPath, "--fixture", brokenPath],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: { PATH: process.env.PATH },
      },
    );
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /CONSOLE_ERROR/);
    assert.equal(refused.stdout, "");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
