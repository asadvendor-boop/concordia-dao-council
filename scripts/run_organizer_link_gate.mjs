#!/usr/bin/env node

/**
 * Read-only rendered-DOM and link collector for the organizer-mandated finals
 * release gate.
 *
 * The runner accepts one frozen request document, launches the same locked
 * Playwright version used by G13 in a new non-persistent Chromium context,
 * blocks every non-read browser request, and writes one canonical JSON result
 * to stdout. It does not write screenshots, traces, cookies, storage state, or
 * output files. G12 and G13 remain independent gates; this audit must pass
 * immediately before each of them.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  APP_ORIGIN,
  DOCS_ORIGIN,
  GateFailure,
  buildInventory,
  buildResult,
  canonicalJson,
  classifyRenderedTarget,
  validateLinkObservation,
  validateRequest,
  validateRouteObservation,
} from "./organizer-link-gate-core.mjs";

const HELP = `Usage:
  node scripts/run_organizer_link_gate.mjs --input handoff/ORGANIZER_LINK_GATE_REQUEST.json
  node scripts/run_organizer_link_gate.mjs --input handoff/ORGANIZER_LINK_GATE_REQUEST.json --fixture tests/fixtures/organizer-link-gate-pass.json

The collector emits exactly one canonical JSON audit to stdout. Redirect a
live-incognito run only for diagnostics. Authoritative G12/G13 evidence must be
created by build_release_manifest.py capture-organizer-g12 or
capture-organizer-g13, which binds the no-fixture invocation and audit in one
immutable batch. Fixture mode is deterministic, offline CI validation only and
never qualifies as release evidence. No browser state or other local artifact
is written by this runner.
`;
const FIXTURE_SCHEMA = "concordia.organizer_rendered_link_fixture.v1";
const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const INPUT_LIMIT = 256 * 1024;
const BODY_LIMIT = 32 * 1024 * 1024;
const DOM_ITEM_LIMIT = 4_096;
const NAVIGATION_TIMEOUT_MS = 45_000;
const ROUTE_SETTLE_MS = 1_200;
const MAX_REDIRECTS = 5;
const FIRST_PARTY_ORIGIN = new URL(APP_ORIGIN).origin;

function digestBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function opaqueError(value) {
  const text = String(value ?? "unknown");
  return {
    chars: text.length,
    sha256: digestBytes(Buffer.from(text, "utf8")),
  };
}

function publicUrl(value) {
  const result = classifyRenderedTarget(value, `${APP_ORIGIN}/dashboard`, {
    element_kind: "anchor",
    download: false,
  });
  return result.url;
}

function parseArguments(argv) {
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0])) {
    process.stdout.write(HELP);
    return null;
  }
  if (
    ![2, 4].includes(argv.length) ||
    argv[0] !== "--input" ||
    !argv[1] ||
    (argv.length === 4 && (argv[2] !== "--fixture" || !argv[3]))
  ) {
    throw new GateFailure("ARGUMENTS_INVALID", HELP.trim());
  }
  return {
    input_path: argv[1],
    fixture_path: argv.length === 4 ? argv[3] : null,
  };
}

async function loadRequest(requestPath) {
  const bytes = await readFile(requestPath);
  if (bytes.length === 0 || bytes.length > INPUT_LIMIT) {
    throw new GateFailure(
      "REQUEST_SIZE_INVALID",
      "organizer gate request size is invalid",
    );
  }
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new GateFailure(
      "REQUEST_JSON_INVALID",
      "organizer gate request is not valid UTF-8 JSON",
    );
  }
  return validateRequest(document);
}

function exactFixtureKeys(value, expected, code, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new GateFailure(code, `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new GateFailure(code, `${label} has a non-exact field set`);
  }
}

async function loadFixture(fixturePath) {
  const bytes = await readFile(fixturePath);
  if (bytes.length === 0 || bytes.length > INPUT_LIMIT) {
    throw new GateFailure(
      "FIXTURE_SIZE_INVALID",
      "organizer gate fixture size is invalid",
    );
  }
  let fixture;
  try {
    fixture = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new GateFailure(
      "FIXTURE_JSON_INVALID",
      "organizer gate fixture is not valid UTF-8 JSON",
    );
  }
  exactFixtureKeys(
    fixture,
    [
      "schema_version",
      "started_at",
      "captured_at",
      "runtime",
      "route_overrides",
      "proof_tab_overrides",
      "link_overrides",
    ],
    "FIXTURE_FIELDS_INVALID",
    "organizer gate fixture",
  );
  if (fixture.schema_version !== FIXTURE_SCHEMA) {
    throw new GateFailure(
      "FIXTURE_SCHEMA_INVALID",
      "organizer gate fixture schema differs",
    );
  }
  for (const field of [
    "route_overrides",
    "proof_tab_overrides",
    "link_overrides",
  ]) {
    if (
      fixture[field] === null ||
      typeof fixture[field] !== "object" ||
      Array.isArray(fixture[field])
    ) {
      throw new GateFailure(
        "FIXTURE_FIELDS_INVALID",
        `${field} must be an object`,
      );
    }
  }
  return fixture;
}

async function sha256File(filename) {
  return digestBytes(await readFile(filename));
}

async function loadPlaywright() {
  process.env.PLAYWRIGHT_BROWSERS_PATH = "0";
  const scriptPath = fileURLToPath(import.meta.url);
  const repositoryRoot = path.resolve(path.dirname(scriptPath), "..");
  const runtimePackage = path.join(
    repositoryRoot,
    "scripts",
    "g13-browser-runtime",
    "package.json",
  );
  const requireRuntime = createRequire(runtimePackage);
  let playwright;
  let version;
  try {
    playwright = requireRuntime("playwright");
    version = requireRuntime("playwright/package.json").version;
  } catch (error) {
    throw new GateFailure(
      "PLAYWRIGHT_UNAVAILABLE",
      `locked Playwright runtime is unavailable: ${error.message}`,
    );
  }
  if (!playwright?.chromium || typeof playwright.chromium.launch !== "function") {
    throw new GateFailure(
      "PLAYWRIGHT_INVALID",
      "locked Playwright runtime lacks Chromium",
    );
  }
  const executable = playwright.chromium.executablePath();
  return {
    chromium: playwright.chromium,
    version: String(version),
    executable_sha256: await sha256File(executable),
  };
}

async function redirectChain(response) {
  const reverse = [];
  let request = response.request();
  while (request.redirectedFrom()) {
    const previous = request.redirectedFrom();
    const previousResponse = await previous.response();
    reverse.push({
      from: publicUrl(previous.url()),
      to: publicUrl(request.url()),
      status: previousResponse?.status() ?? 0,
    });
    request = previous;
  }
  return reverse.reverse();
}

function firstParty(value) {
  try {
    return new URL(value).origin === FIRST_PARTY_ORIGIN;
  } catch {
    return false;
  }
}

export async function collectDom(page) {
  return page.evaluate(({ limit }) => {
    const links = Array.from(document.querySelectorAll("a[href]")).map(
      (element) => ({
        href: element.href,
        element_kind: "anchor",
        download: element.hasAttribute("download"),
      }),
    );
    const assetSelectors = [
      "script[src]",
      "img[src]",
      "source[src]",
      "iframe[src]",
      'link[rel~="stylesheet"][href]',
      'link[rel~="icon"][href]',
      'link[rel="manifest"][href]',
      'link[rel="modulepreload"][href]',
      'link[rel="preload"][href]',
    ];
    const assets = Array.from(
      document.querySelectorAll(assetSelectors.join(",")),
    ).map((element) => ({
      href:
        element.currentSrc ||
        element.src ||
        element.href ||
        element.getAttribute("src") ||
        element.getAttribute("href"),
      element_kind: "asset",
      download: false,
    }));
    const ids = Array.from(document.querySelectorAll("[id]")).map(
      (element) => element.id,
    );
    const names = Array.from(document.querySelectorAll("[name]")).map(
      (element) => element.getAttribute("name"),
    );
    if (
      links.length > limit ||
      assets.length > limit ||
      ids.length > limit ||
      names.length > limit
    ) {
      return { overflow: true };
    }
    const selected = document.querySelector('[role="tab"][aria-selected="true"]');
    const selectedId = selected?.id ?? "";
    const selectedPanelId = selected?.getAttribute("aria-controls") ?? null;
    const selectedPanel = selectedPanelId
      ? document.getElementById(selectedPanelId)
      : null;
    const activeNavigation = document.querySelector("a.nav-item.active[href]");
    const primaryHeading = document.querySelector("main h1,[role=main] h1");
    const brand = document.querySelector(".brand-copy strong");
    const renderedDownloadControls = Array.from(
      document.querySelectorAll("button:not([disabled])"),
    )
      .map((element, selectorIndex) => {
        const label = (element.innerText || element.textContent || "")
          .replace(/\s+/gu, " ")
          .trim();
        const dataTestId = element.getAttribute("data-testid");
        return {
          selector_index: selectorIndex,
          control_id:
            dataTestId ||
            `download-${selectorIndex}-${label
              .toLowerCase()
              .replace(/[^a-z0-9]+/gu, "-")
              .replace(/^-|-$/gu, "")
              .slice(0, 64)}`,
          label,
        };
      })
      .filter((item) => /^(?:export|download)\b/iu.test(item.label));
    return {
      overflow: false,
      links,
      assets,
      ids,
      names,
      active_proof_tab: selectedId.startsWith("proof-tab-")
        ? selectedId.slice("proof-tab-".length)
        : null,
      route_identity: {
        brand_text: (brand?.textContent || "").replace(/\s+/gu, " ").trim(),
        active_navigation_path: activeNavigation
          ? new URL(activeNavigation.href).pathname
          : null,
        primary_heading: (primaryHeading?.textContent || "")
          .replace(/\s+/gu, " ")
          .trim(),
        active_tab_id: selectedId.startsWith("proof-tab-")
          ? selectedId.slice("proof-tab-".length)
          : null,
        active_tabpanel_id:
          selectedPanel && selectedPanel.getAttribute("role") === "tabpanel"
            ? selectedPanelId
            : null,
      },
      rendered_download_controls: renderedDownloadControls,
      title: document.title,
      main_count: document.querySelectorAll("main,[role=main]").length,
      heading_count: document.querySelectorAll("h1,h2,h3,h4,h5,h6").length,
      next_error_overlay_count: document.querySelectorAll(
        "nextjs-portal,[data-nextjs-dialog-overlay],[data-next-badge]",
      ).length,
    };
  }, { limit: DOM_ITEM_LIMIT });
}

function validateDocumentAnchors(observation) {
  const available = new Set([
    ...observation.document_ids,
    ...observation.document_names,
  ]);
  for (const item of observation.rendered_links) {
    const classified = classifyRenderedTarget(
      item.href,
      observation.final_url,
      item,
    );
    if (
      classified.kind === "document_anchor" &&
      !available.has(classified.fragment)
    ) {
      throw new GateFailure(
        "MISSING_DOCUMENT_ANCHOR",
        `${observation.route_id} renders a missing document anchor`,
      );
    }
  }
}

async function digestDownload(download) {
  const stream = await download.createReadStream();
  if (!stream) {
    throw new GateFailure(
      "CLIENT_DOWNLOAD_FAILED",
      "browser did not expose client-download bytes",
    );
  }
  const digest = createHash("sha256");
  let bytes = 0;
  for await (const chunk of stream) {
    bytes += chunk.length;
    if (bytes > BODY_LIMIT) {
      throw new GateFailure(
        "CLIENT_DOWNLOAD_OVERSIZED",
        "client download exceeded the byte limit",
      );
    }
    digest.update(chunk);
  }
  if (bytes === 0) {
    throw new GateFailure(
      "CLIENT_DOWNLOAD_EMPTY",
      "client download returned no bytes",
    );
  }
  return {
    suggested_filename: download.suggestedFilename(),
    body_bytes: bytes,
    body_sha256: digest.digest("hex"),
  };
}

export async function collectClientDownloads(page, controls) {
  const buttons = page.locator("button:not([disabled])");
  const observed = [];
  for (const control of controls) {
    const button = buttons.nth(control.selector_index);
    const downloadPromise = page.waitForEvent("download", {
      timeout: NAVIGATION_TIMEOUT_MS,
    });
    await button.click({ timeout: NAVIGATION_TIMEOUT_MS });
    const download = await downloadPromise;
    observed.push({
      control_id: control.control_id,
      ...(await digestDownload(download)),
    });
    await download.delete();
  }
  return observed;
}

function websocketEvidence(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new GateFailure(
      "WEBSOCKET_URL_INVALID",
      "WebSocket attempt URL is invalid",
    );
  }
  if (
    parsed.protocol !== "wss:" ||
    parsed.username ||
    parsed.password ||
    parsed.port
  ) {
    throw new GateFailure(
      "WEBSOCKET_URL_INVALID",
      "WebSocket attempt escaped the public secure surface",
    );
  }
  return {
    url_sha256: digestBytes(Buffer.from(parsed.href, "utf8")),
    host: parsed.hostname,
    disposition: "blocked_before_connect",
  };
}

export async function installReadOnlyWebSocketGuard(page, evidence) {
  await page.exposeBinding("__concordiaBlockWebSocket", (_source, value) => {
    evidence.push(websocketEvidence(value));
    return false;
  });
  await page.addInitScript(() => {
    const NativeWebSocket = window.WebSocket;
    class ReadOnlyBlockedWebSocket extends EventTarget {
      static CONNECTING = NativeWebSocket.CONNECTING;
      static OPEN = NativeWebSocket.OPEN;
      static CLOSING = NativeWebSocket.CLOSING;
      static CLOSED = NativeWebSocket.CLOSED;

      constructor(value) {
        super();
        const url = new URL(String(value), window.location.href).href;
        void window.__concordiaBlockWebSocket(url);
        throw new DOMException(
          "WebSocket blocked by read-only release collector",
          "SecurityError",
        );
      }
    }
    Object.defineProperty(window, "WebSocket", {
      configurable: false,
      enumerable: true,
      value: ReadOnlyBlockedWebSocket,
      writable: false,
    });
  });
}

async function captureRoute(context, spec) {
  const page = await context.newPage();
  const consoleErrors = [];
  const pageErrors = [];
  const blockedNonReadRequests = [];
  const firstPartyFailures = [];
  const blockedWebSockets = [];
  const failedReadRequests = new WeakSet();

  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(opaqueError(message.text()));
    }
  });
  page.on("pageerror", (error) => {
    pageErrors.push(opaqueError(error.message));
  });
  page.on("response", (response) => {
    if (firstParty(response.url()) && response.status() >= 400) {
      firstPartyFailures.push({
        url: publicUrl(response.url()),
        status: response.status(),
        resource_type: response.request().resourceType(),
      });
    }
  });
  page.on("requestfailed", (request) => {
    if (
      READ_METHODS.has(request.method()) &&
      firstParty(request.url()) &&
      !failedReadRequests.has(request)
    ) {
      failedReadRequests.add(request);
      firstPartyFailures.push({
        url: publicUrl(request.url()),
        status: null,
        resource_type: request.resourceType(),
        failure: opaqueError(request.failure()?.errorText),
      });
    }
  });
  await page.route("**/*", async (intercepted) => {
    const request = intercepted.request();
    if (!READ_METHODS.has(request.method())) {
      blockedNonReadRequests.push({
        method: request.method(),
        url: publicUrl(request.url()),
        resource_type: request.resourceType(),
      });
      await intercepted.abort("blockedbyclient");
      return;
    }
    await intercepted.continue();
  });
  await installReadOnlyWebSocketGuard(page, blockedWebSockets);

  try {
    const response = await page.goto(spec.url, {
      waitUntil: "domcontentloaded",
      timeout: NAVIGATION_TIMEOUT_MS,
    });
    if (!response) {
      throw new GateFailure(
        "ROUTE_NO_RESPONSE",
        `${spec.route_id} returned no navigation response`,
      );
    }
    await page.locator("body").waitFor({
      state: "attached",
      timeout: NAVIGATION_TIMEOUT_MS,
    });
    await page.waitForTimeout(ROUTE_SETTLE_MS);
    const dom = await collectDom(page);
    if (dom.overflow) {
      throw new GateFailure(
        "DOM_INVENTORY_OVERFLOW",
        `${spec.route_id} exceeds the DOM inventory limit`,
      );
    }
    if (
      dom.next_error_overlay_count !== 0 ||
      (dom.main_count < 1 && dom.heading_count < 1)
    ) {
      throw new GateFailure(
        "ROUTE_DOM_INVALID",
        `${spec.route_id} lacks the required judge-facing DOM`,
      );
    }
    const redirects = await redirectChain(response);
    const clientDownloads = await collectClientDownloads(
      page,
      dom.rendered_download_controls,
    );
    const observation = {
      route_id: spec.route_id,
      requested_url: spec.url,
      final_url: publicUrl(page.url()),
      status: response.status(),
      redirects,
      active_proof_tab: dom.active_proof_tab,
      console_errors: consoleErrors,
      page_errors: pageErrors,
      blocked_non_read_requests: blockedNonReadRequests,
      first_party_failures: firstPartyFailures,
      rendered_links: dom.links,
      rendered_assets: dom.assets,
      document_ids: dom.ids,
      document_names: dom.names,
      route_identity: dom.route_identity,
      rendered_download_controls: dom.rendered_download_controls.map(
        ({ control_id, label }) => ({ control_id, label }),
      ),
      client_downloads: clientDownloads,
      blocked_websockets: blockedWebSockets,
      document: {
        title_sha256: digestBytes(Buffer.from(dom.title, "utf8")),
        main_count: dom.main_count,
        heading_count: dom.heading_count,
      },
    };
    validateDocumentAnchors(observation);
    validateRouteObservation(spec, observation);
    return observation;
  } finally {
    await page.close();
  }
}

function renderedLinkSpecs(request, pages) {
  const byUrl = new Map();
  for (const spec of request.known_links) {
    byUrl.set(spec.url, {
      ...spec,
      kind: "known_external",
      sources: [`known:${spec.link_id}`],
    });
  }
  for (const page of pages) {
    for (const item of [
      ...page.rendered_links,
      ...page.rendered_assets,
    ]) {
      const classified = classifyRenderedTarget(item.href, page.final_url, item);
      if (
        classified.kind === "document_anchor"
      ) {
        continue;
      }
      const existing = byUrl.get(classified.url);
      const source = `${page.route_id}:${classified.kind}`;
      if (existing) {
        if (!existing.sources.includes(source)) existing.sources.push(source);
        continue;
      }
      byUrl.set(classified.url, {
        link_id: `rendered_${digestBytes(classified.url).slice(0, 24)}`,
        url: classified.url,
        allowed_redirects: [],
        kind: classified.kind,
        sources: [source],
      });
    }
  }
  return [...byUrl.values()]
    .map((row) => ({
      ...row,
      sources: [...row.sources].sort(),
    }))
    .sort((left, right) => left.link_id.localeCompare(right.link_id));
}

async function probeWithRequest(context, spec) {
  const initial = new URL(spec.url);
  const fragment = initial.hash;
  let current = new URL(initial);
  current.hash = "";
  const redirects = [];
  let response;
  for (let index = 0; index <= MAX_REDIRECTS; index += 1) {
    response = await context.request.get(current.href, {
      failOnStatusCode: false,
      maxRedirects: 0,
      timeout: NAVIGATION_TIMEOUT_MS,
      headers: {
        accept:
          "text/html,application/xhtml+xml,application/json,text/plain,*/*",
      },
    });
    if (response.status() < 300 || response.status() >= 400) break;
    const location = response.headers().location;
    if (!location) {
      throw new GateFailure(
        "REDIRECT_LOCATION_MISSING",
        `${spec.link_id} returned a redirect without Location`,
      );
    }
    const next = new URL(location, current);
    if (!next.hash && fragment) next.hash = fragment;
    publicUrl(next.href);
    redirects.push({
      from:
        index === 0 && fragment
          ? spec.url
          : publicUrl(current.href),
      to: publicUrl(next.href),
      status: response.status(),
    });
    current = new URL(next);
    current.hash = "";
  }
  if (!response || (response.status() >= 300 && response.status() < 400)) {
    throw new GateFailure(
      "REDIRECT_LIMIT_EXCEEDED",
      `${spec.link_id} exceeded the redirect limit`,
    );
  }
  const body = await response.body();
  if (body.length > BODY_LIMIT) {
    throw new GateFailure(
      "LINK_BODY_OVERSIZED",
      `${spec.link_id} returned an oversized body`,
    );
  }
  const finalWithFragment = new URL(current);
  if (fragment) finalWithFragment.hash = fragment;
  return {
    status: response.status(),
    redirects,
    effective_url: publicUrl(finalWithFragment.href),
    body,
    content_type: response.headers()["content-type"] ?? "",
  };
}

async function documentAnchorFound(context, html, url) {
  const parsed = new URL(url);
  if (
    ![APP_ORIGIN, DOCS_ORIGIN].includes(parsed.origin) ||
    !parsed.hash
  ) {
    return null;
  }
  const fragment = decodeURIComponent(parsed.hash.slice(1));
  const page = await context.newPage();
  try {
    await page.setContent(html.toString("utf8"), {
      waitUntil: "domcontentloaded",
      timeout: NAVIGATION_TIMEOUT_MS,
    });
    return page.evaluate((name) => {
      if (document.getElementById(name)) return true;
      return Array.from(document.getElementsByName(name)).length > 0;
    }, fragment);
  } finally {
    await page.close();
  }
}

async function concordiaIdentity(context, html, spec) {
  if (spec.identity === null) return null;
  const page = await context.newPage();
  try {
    await page.setContent(html.toString("utf8"), {
      waitUntil: "domcontentloaded",
      timeout: NAVIGATION_TIMEOUT_MS,
    });
    const facts = await page.evaluate(() => ({
      title: document.title,
      text: document.body?.innerText ?? "",
    }));
    return {
      kind: "concordia_home",
      title_match: /\bconcordia\b/iu.test(facts.title),
      visible_marker_match: /\bconcordia\b/iu.test(facts.text),
    };
  } finally {
    await page.close();
  }
}

async function probeLink(context, spec) {
  const captured = await probeWithRequest(context, spec);
  const observation = {
    link_id: spec.link_id,
    requested_url: spec.url,
    effective_url: captured.effective_url,
    status: captured.status,
    redirects: captured.redirects,
    body_bytes: captured.body.length,
    body_sha256: digestBytes(captured.body),
    anchor_found: await documentAnchorFound(
      context,
      captured.body,
      captured.effective_url,
    ),
    concordia_identity: await concordiaIdentity(
      context,
      captured.body,
      spec,
    ),
    kind: spec.kind,
    sources: spec.sources,
    content_type: captured.content_type.slice(0, 256),
  };
  validateLinkObservation(spec, observation);
  return observation;
}

const FIXTURE_ROUTE_OVERRIDE_FIELDS = new Set([
  "requested_url",
  "final_url",
  "status",
  "redirects",
  "active_proof_tab",
  "console_errors",
  "page_errors",
  "blocked_non_read_requests",
  "first_party_failures",
  "rendered_links",
  "rendered_assets",
  "document_ids",
  "document_names",
  "route_identity",
  "rendered_download_controls",
  "client_downloads",
  "blocked_websockets",
]);
const FIXTURE_LINK_OVERRIDE_FIELDS = new Set([
  "requested_url",
  "effective_url",
  "status",
  "redirects",
  "body_bytes",
  "body_sha256",
  "anchor_found",
  "concordia_identity",
]);

function fixtureOverride(overrides, id, allowedFields, knownIds, label) {
  for (const candidate of Object.keys(overrides)) {
    if (!knownIds.has(candidate)) {
      throw new GateFailure(
        "FIXTURE_OVERRIDE_ID_INVALID",
        `${label} override ID is not in the frozen inventory`,
      );
    }
  }
  const value = overrides[id] ?? {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new GateFailure(
      "FIXTURE_OVERRIDE_INVALID",
      `${label} override must be an object`,
    );
  }
  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      throw new GateFailure(
        "FIXTURE_OVERRIDE_INVALID",
        `${label} override field is not allowed`,
      );
    }
  }
  return structuredClone(value);
}

function fixtureRoute(spec, overrides, knownIds) {
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
    document_ids: ["fixture-anchor"],
    document_names: [],
    route_identity: {
      brand_text: "Concordia DAO Council",
      active_navigation_path: spec.expected_dom.active_navigation_path,
      primary_heading: spec.expected_dom.primary_headings[0],
      active_tab_id: spec.active_proof_tab ?? null,
      active_tabpanel_id:
        spec.active_proof_tab === null
          ? null
          : `proof-tabpanel-${spec.active_proof_tab}`,
    },
    rendered_download_controls: [],
    client_downloads: [],
    blocked_websockets: [],
    document: {
      title_sha256: digestBytes(
        Buffer.from(`fixture:${spec.route_id}`, "utf8"),
      ),
      main_count: 1,
      heading_count: 1,
    },
    ...fixtureOverride(
      overrides,
      spec.route_id,
      FIXTURE_ROUTE_OVERRIDE_FIELDS,
      knownIds,
      "route",
    ),
  };
}

function fixtureLink(spec, overrides, knownIds) {
  const hasDocsAnchor =
    new URL(spec.url).origin === DOCS_ORIGIN && Boolean(new URL(spec.url).hash);
  return {
    link_id: spec.link_id,
    requested_url: spec.url,
    effective_url: spec.allowed_redirects.at(-1)?.to ?? spec.url,
    status: 200,
    redirects: structuredClone(spec.allowed_redirects),
    body_bytes: 128,
    body_sha256: digestBytes(Buffer.from(`fixture:${spec.url}`, "utf8")),
    anchor_found: hasDocsAnchor ? true : null,
    concordia_identity:
      spec.identity === null
        ? null
        : {
            kind: "concordia_home",
            title_match: true,
            visible_marker_match: true,
          },
    kind: spec.kind ?? "known_external",
    sources: structuredClone(
      spec.sources ?? [`known:${spec.link_id}`],
    ),
    content_type: "text/html; fixture=true",
    ...fixtureOverride(
      overrides,
      spec.link_id,
      FIXTURE_LINK_OVERRIDE_FIELDS,
      knownIds,
      "link",
    ),
  };
}

function buildFixtureResult(request, fixture) {
  const inventory = buildInventory();
  const routeIds = new Set(
    inventory.dashboard_routes.map((row) => row.route_id),
  );
  const proofTabIds = new Set(inventory.proof_tabs.map((row) => row.route_id));
  const linkIds = new Set(request.known_links.map((row) => row.link_id));
  const routes = inventory.dashboard_routes.map((spec) =>
    fixtureRoute(spec, fixture.route_overrides, routeIds),
  );
  const proofTabs = inventory.proof_tabs.map((spec) =>
    fixtureRoute(spec, fixture.proof_tab_overrides, proofTabIds),
  );
  const links = request.known_links.map((spec) =>
    fixtureLink(spec, fixture.link_overrides, linkIds),
  );
  return buildResult({
    request,
    routes,
    proof_tabs: proofTabs,
    links,
    runtime: fixture.runtime,
    started_at: fixture.started_at,
    captured_at: fixture.captured_at,
    collection_mode: "fixture",
  });
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  if (arguments_ === null) return;
  const request = await loadRequest(arguments_.input_path);
  if (arguments_.fixture_path !== null) {
    const fixture = await loadFixture(arguments_.fixture_path);
    process.stdout.write(`${canonicalJson(buildFixtureResult(request, fixture))}\n`);
    return;
  }
  const startedAt = new Date().toISOString();
  const locked = await loadPlaywright();
  const browser = await locked.chromium.launch({
    headless: true,
    chromiumSandbox: true,
  });
  try {
    const context = await browser.newContext({
      acceptDownloads: true,
      ignoreHTTPSErrors: false,
      javaScriptEnabled: true,
      locale: "en-US",
      permissions: [],
      serviceWorkers: "block",
      timezoneId: "UTC",
      viewport: { width: 1440, height: 900 },
    });
    try {
      context.setDefaultNavigationTimeout(NAVIGATION_TIMEOUT_MS);
      context.setDefaultTimeout(NAVIGATION_TIMEOUT_MS);
      const inventory = buildInventory();
      const routes = [];
      for (const spec of inventory.dashboard_routes) {
        routes.push(await captureRoute(context, spec));
      }
      const proofTabs = [];
      for (const spec of inventory.proof_tabs) {
        proofTabs.push(await captureRoute(context, spec));
      }
      const linkSpecs = renderedLinkSpecs(request, [...routes, ...proofTabs]);
      const links = [];
      for (const spec of linkSpecs) {
        links.push(await probeLink(context, spec));
      }
      const result = buildResult({
        request,
        routes,
        proof_tabs: proofTabs,
        links,
        runtime: {
          node: process.version,
          playwright: locked.version,
          chromium: browser.version(),
          chromium_executable_sha256: locked.executable_sha256,
        },
        started_at: startedAt,
        captured_at: new Date().toISOString(),
        collection_mode: "live_incognito",
      });
      process.stdout.write(`${canonicalJson(result)}\n`);
    } finally {
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    const code =
      error instanceof GateFailure
        ? error.code
        : "UNEXPECTED_COLLECTOR_FAILURE";
    const message =
      error instanceof GateFailure
        ? error.message
        : `unexpected collector failure ${opaqueError(error?.message).sha256}`;
    process.stderr.write(
      `organizer rendered-link gate refused ${code}: ${message}\n`,
    );
    process.exitCode = 1;
  });
}
