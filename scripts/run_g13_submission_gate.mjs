#!/usr/bin/env node

/**
 * Read-only Playwright collector for the external G13 submission gate.
 *
 * Input is a strict JSON document supplied with `--input <path>` (or `-` for
 * stdin). The collector launches a fresh Chromium context with no persisted
 * storage, blocks every non-read HTTP request, visits the final public
 * judge-facing pages, and emits one JSON document to stdout. It never writes
 * screenshots, storage state, traces, cookies, or any other local artifact.
 *
 * This program deliberately reports raw response/network/DOM observations
 * rather than accepting an operator-provided `verified` flag. The release
 * verifier is responsible for binding this stdout byte stream to committed
 * G13 evidence and for independently re-probing final links.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const INPUT_SCHEMA = "concordia.g13_browser_probe_request.v1";
const OUTPUT_SCHEMA = "concordia.g13_browser_probe_result.v1";
const NAVIGATION_TIMEOUT_MS = 45_000;
const SETTLE_TIMEOUT_MS = 1_500;
const MAX_INPUT_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAX_NETWORK_EVENTS = 5_000;
const MAX_DOM_ITEMS = 512;
const MAX_TEXT_ITEM_LENGTH = 512;
const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const REQUIRED_ROUTE_IDS = new Set([
  "dashboard_judge",
  "dashboard_proof",
  "dashboard_evidence",
  "dashboard_technical_note",
  "youtube_new_video",
  "dorahacks_buidl_46732",
]);
const ALLOWED_TOP_LEVEL_HOSTS = new Set([
  "concordia.47.84.232.193.sslip.io",
  "x402-provider.47.84.232.193.sslip.io",
  "concordiadao.xyz",
  "www.concordiadao.xyz",
  "docs.concordiadao.xyz",
  "x402.concordiadao.xyz",
  "www.youtube.com",
  "dorahacks.io",
]);
const PUBLIC_QUERY_VALUE_KEYS = new Set(["proposal", "v"]);
const FIRST_PARTY_HTML_HOSTS = new Set([
  "concordia.47.84.232.193.sslip.io",
  "concordiadao.xyz",
  "www.concordiadao.xyz",
  "docs.concordiadao.xyz",
]);
const APP_ORIGIN = "https://concordia.47.84.232.193.sslip.io";
const FIXED_BROWSER_ROUTES = new Map([
  ["sslip_app_root", `${APP_ORIGIN}/`],
  ["custom_apex_root", "https://concordiadao.xyz/"],
  ["custom_www_root", "https://www.concordiadao.xyz/"],
  ["custom_docs_root", "https://docs.concordiadao.xyz/"],
  ["dashboard", `${APP_ORIGIN}/dashboard`],
  ["dashboard_judge", `${APP_ORIGIN}/dashboard/judge`],
  ["dashboard_proof", `${APP_ORIGIN}/dashboard/proof`],
  ["dashboard_agents", `${APP_ORIGIN}/dashboard/agents`],
  [
    "dashboard_proposals",
    `${APP_ORIGIN}/dashboard/proposals?proposal=DAO-PROP-6CB25C`,
  ],
  ["dashboard_approvals", `${APP_ORIGIN}/dashboard/approvals`],
  ["dashboard_evidence", `${APP_ORIGIN}/dashboard/evidence`],
  ["dashboard_runs", `${APP_ORIGIN}/dashboard/runs`],
  ["dashboard_record", `${APP_ORIGIN}/dashboard/record`],
  [
    "dashboard_technical_note",
    `${APP_ORIGIN}/dashboard/technical-jury-note`,
  ],
  ["technical_note", `${APP_ORIGIN}/technical-jury-note`],
  [
    "certificate_html",
    `${APP_ORIGIN}/certificate/DAO-PROP-6CB25C`,
  ],
  ["dorahacks_buidl_46732", "https://dorahacks.io/buidl/46732"],
]);

class GateError extends Error {
  constructor(message) {
    super(message);
    this.name = "GateError";
  }
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  return JSON.stringify(value, (_key, nested) => {
    if (
      nested !== null &&
      typeof nested === "object" &&
      !Array.isArray(nested)
    ) {
      return Object.fromEntries(
        Object.keys(nested)
          .sort()
          .map((key) => [key, nested[key]]),
      );
    }
    return nested;
  });
}

function strictKeys(value, expected, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new GateError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((entry, index) => entry !== wanted[index])
  ) {
    throw new GateError(`${label} field set is not exact`);
  }
}

function requireText(value, label, pattern, maximum = MAX_TEXT_ITEM_LENGTH) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    (pattern && !pattern.test(value))
  ) {
    throw new GateError(`${label} is invalid`);
  }
  return value;
}

function sanitizeText(value) {
  return String(value ?? "")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, MAX_TEXT_ITEM_LENGTH);
}

function opaqueErrorFact(value) {
  const text = String(value ?? "unknown");
  return {
    chars: text.length,
    sha256: sha256Bytes(Buffer.from(text, "utf8")),
  };
}

function parseHttpsUrl(value, label) {
  const text = requireText(value, label, null, 2_048);
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new GateError(`${label} is not a URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    parsed.port ||
    !ALLOWED_TOP_LEVEL_HOSTS.has(parsed.hostname)
  ) {
    throw new GateError(`${label} is outside the fixed public HTTPS allowlist`);
  }
  return parsed;
}

function safeUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return {
      origin_path: "invalid-url",
      query_keys: [],
      raw_sha256: sha256Bytes(String(value)),
    };
  }
  const safeQuery = new URLSearchParams();
  const queryKeys = [...new Set([...parsed.searchParams.keys()])].sort();
  for (const key of queryKeys) {
    if (PUBLIC_QUERY_VALUE_KEYS.has(key)) {
      for (const item of parsed.searchParams.getAll(key)) {
        safeQuery.append(key, item);
      }
    }
  }
  const query = safeQuery.toString();
  return {
    origin_path: `${parsed.protocol}//${parsed.host}${parsed.pathname}${
      query ? `?${query}` : ""
    }`,
    query_keys: queryKeys,
    raw_sha256: sha256Bytes(String(value)),
  };
}

function safeResponseHeaders(headers) {
  const selected = {};
  for (const name of [
    "cache-control",
    "content-length",
    "content-security-policy",
    "content-type",
    "etag",
    "last-modified",
  ]) {
    const value = headers[name];
    if (typeof value === "string" && value.length <= 4_096) {
      selected[name] = value;
    }
  }
  if (typeof headers.location === "string") {
    selected.location = safeUrl(headers.location);
  }
  return selected;
}

async function readInput(inputPath) {
  let raw;
  if (inputPath === "-") {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > MAX_INPUT_BYTES) {
        throw new GateError("G13 input exceeds the byte limit");
      }
      chunks.push(chunk);
    }
    raw = Buffer.concat(chunks);
  } else {
    raw = await readFile(inputPath);
    if (raw.length > MAX_INPUT_BYTES) {
      throw new GateError("G13 input exceeds the byte limit");
    }
  }
  let value;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new GateError("G13 input is not valid UTF-8 JSON");
  }
  return value;
}

function validateInput(value) {
  strictKeys(value, ["schema_version", "video_id", "routes"], "G13 input");
  if (value.schema_version !== INPUT_SCHEMA) {
    throw new GateError("G13 input schema version differs");
  }
  const videoId = requireText(
    value.video_id,
    "G13 video ID",
    /^[A-Za-z0-9_-]{11}$/u,
    11,
  );
  if (
    !Array.isArray(value.routes) ||
    value.routes.length < REQUIRED_ROUTE_IDS.size ||
    value.routes.length > 64
  ) {
    throw new GateError("G13 route inventory size is invalid");
  }

  const routes = [];
  const seenIds = new Set();
  for (const [index, row] of value.routes.entries()) {
    strictKeys(row, ["link_id", "url"], `G13 route ${index}`);
    const linkId = requireText(
      row.link_id,
      `G13 route ${index} link_id`,
      /^[a-z][a-z0-9_]{1,79}$/u,
      80,
    );
    if (seenIds.has(linkId)) {
      throw new GateError("G13 route inventory contains duplicate IDs");
    }
    seenIds.add(linkId);
    const parsed = parseHttpsUrl(row.url, `G13 route ${linkId} URL`);
    if (linkId === "youtube_new_video") {
      // The exact dynamic URL is validated against video_id below.
    } else if (
      !FIXED_BROWSER_ROUTES.has(linkId) ||
      FIXED_BROWSER_ROUTES.get(linkId) !== parsed.href
    ) {
      throw new GateError(
        `G13 route ${linkId} is not a fixed judge-facing browser route`,
      );
    }
    routes.push({ link_id: linkId, url: parsed.href });
  }
  for (const required of REQUIRED_ROUTE_IDS) {
    if (!seenIds.has(required)) {
      throw new GateError(`G13 route inventory is missing ${required}`);
    }
  }

  const youtube = routes.find((item) => item.link_id === "youtube_new_video");
  const dorahacks = routes.find(
    (item) => item.link_id === "dorahacks_buidl_46732",
  );
  if (youtube.url !== `https://www.youtube.com/watch?v=${videoId}`) {
    throw new GateError("G13 YouTube route does not bind the supplied video ID");
  }
  if (
    dorahacks.url !== FIXED_BROWSER_ROUTES.get("dorahacks_buidl_46732")
  ) {
    throw new GateError("G13 DoraHacks route is not the fixed finals BUIDL");
  }

  routes.sort((left, right) => left.link_id.localeCompare(right.link_id));
  return { videoId, routes };
}

function parseArguments(argv) {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stdout.write(
      "Usage: node scripts/run_g13_submission_gate.mjs --input <request.json|->\n",
    );
    process.exit(0);
  }
  if (argv.length !== 2 || argv[0] !== "--input") {
    throw new GateError(
      "usage: run_g13_submission_gate.mjs --input <request.json|->",
    );
  }
  return argv[1];
}

async function sha256File(inputPath) {
  const digest = createHash("sha256");
  await new Promise((resolve, reject) => {
    const stream = createReadStream(inputPath);
    stream.on("data", (chunk) => digest.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return digest.digest("hex");
}

async function loadPlaywright() {
  process.env.PLAYWRIGHT_BROWSERS_PATH = "0";
  const scriptPath = fileURLToPath(import.meta.url);
  const repositoryRoot = path.resolve(path.dirname(scriptPath), "..");
  const requireFromRuntime = createRequire(
    path.join(
      repositoryRoot,
      "scripts",
      "g13-browser-runtime",
      "package.json",
    ),
  );
  let api;
  let version;
  try {
    api = requireFromRuntime("playwright");
    version = requireFromRuntime("playwright/package.json").version;
  } catch (primaryError) {
    throw new GateError(
      `Playwright is unavailable from the locked G13 runtime: ${primaryError.message}`,
    );
  }
  if (!api?.chromium || typeof api.chromium.launch !== "function") {
    throw new GateError("dashboard Playwright dependency has no Chromium API");
  }
  return {
    chromium: api.chromium,
    playwrightVersion: String(version),
    chromiumExecutableSha256: await sha256File(api.chromium.executablePath()),
  };
}

function buildNetworkRecorder(page) {
  const requestIds = new WeakMap();
  const events = [];
  let nextRequestId = 1;
  let sequence = 1;
  let overflowed = false;
  let stopped = false;

  function append(event) {
    if (events.length >= MAX_NETWORK_EVENTS) {
      overflowed = true;
      return;
    }
    events.push({ sequence, ...event });
    sequence += 1;
  }

  const onRequest = (request) => {
    const requestId = nextRequestId;
    nextRequestId += 1;
    requestIds.set(request, requestId);
    append({
      event: "request",
      request_id: requestId,
      method: request.method(),
      resource_type: request.resourceType(),
      navigation_request: request.isNavigationRequest(),
      url: safeUrl(request.url()),
    });
  };
  const onResponse = (response) => {
    const request = response.request();
    append({
      event: "response",
      request_id: requestIds.get(request) ?? 0,
      status: response.status(),
      service_worker: response.fromServiceWorker(),
      url: safeUrl(response.url()),
      headers: safeResponseHeaders(response.headers()),
    });
  };
  const onRequestFailed = (request) => {
    append({
      event: "request_failed",
      request_id: requestIds.get(request) ?? 0,
      method: request.method(),
      resource_type: request.resourceType(),
      url: safeUrl(request.url()),
      error_text: sanitizeText(request.failure()?.errorText ?? "unknown"),
    });
  };
  page.on("request", onRequest);
  page.on("response", onResponse);
  page.on("requestfailed", onRequestFailed);

  const stop = () => {
    if (!stopped) {
      page.off("request", onRequest);
      page.off("response", onResponse);
      page.off("requestfailed", onRequestFailed);
      stopped = true;
    }
    if (overflowed) {
      throw new GateError("G13 network event limit was exceeded");
    }
    return events.map((event) => structuredClone(event));
  };
  return { stop };
}

async function collectDomFacts(page) {
  const html = await page.content();
  const facts = await page.evaluate(
    ({ maxItems, maxLength }) => {
      const clean = (value) =>
        String(value ?? "")
          .replace(/\s+/gu, " ")
          .trim()
          .slice(0, maxLength);
      const visible = (element) => {
        const style = window.getComputedStyle(element);
        const box = element.getBoundingClientRect();
        return (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          Number(style.opacity || "1") > 0 &&
          box.width > 0 &&
          box.height > 0
        );
      };
      const selected = (selector, mapper) => {
        const all = Array.from(document.querySelectorAll(selector));
        return {
          count: all.length,
          items: all.slice(0, maxItems).map(mapper),
          truncated: all.length > maxItems,
        };
      };
      const bodyText = String(document.body?.innerText ?? "")
        .replace(/\s+/gu, " ")
        .trim();
      return {
        document_url: document.location.href,
        title: clean(document.title),
        language: clean(document.documentElement.lang),
        body_text: bodyText,
        headings: selected("h1,h2,h3,h4,h5,h6", (element) => ({
          level: element.tagName.toLowerCase(),
          text: clean(element.textContent),
          visible: visible(element),
        })),
        landmarks: {
          main: document.querySelectorAll("main,[role=main]").length,
          navigation: document.querySelectorAll("nav,[role=navigation]").length,
          tablist: document.querySelectorAll("[role=tablist]").length,
        },
        links: selected("a[href]", (element) => ({
          text: clean(element.textContent || element.getAttribute("aria-label")),
          href: element.href,
          visible: visible(element),
        })),
        frames: selected("iframe[src]", (element) => ({
          title: clean(element.title),
          src: element.src,
          visible: visible(element),
        })),
        test_ids: selected("[data-testid]", (element) => ({
          value: clean(element.getAttribute("data-testid")),
          visible: visible(element),
        })),
        error_overlays: document.querySelectorAll(
          "nextjs-portal,[data-nextjs-dialog-overlay],[data-next-badge]",
        ).length,
      };
    },
    { maxItems: MAX_DOM_ITEMS, maxLength: MAX_TEXT_ITEM_LENGTH },
  );
  const bodyBytes = Buffer.from(facts.body_text, "utf8");
  const summarizeCollection = (collection) => {
    const items = collection.items.map((item) => {
      const output = { ...item };
      if (typeof output.href === "string") {
        output.href = safeUrl(output.href);
      }
      if (typeof output.src === "string") {
        output.src = safeUrl(output.src);
      }
      return output;
    });
    return {
      count: collection.count,
      items,
      items_sha256: sha256Bytes(Buffer.from(canonicalJson(items), "utf8")),
      truncated: collection.truncated,
    };
  };
  return {
    document_url: safeUrl(facts.document_url),
    title: facts.title,
    language: facts.language,
    html_bytes: Buffer.byteLength(html, "utf8"),
    html_sha256: sha256Bytes(Buffer.from(html, "utf8")),
    visible_text_chars: facts.body_text.length,
    visible_text_sha256: sha256Bytes(bodyBytes),
    concordia_occurrences: (
      facts.body_text.match(/Concordia/giu) ?? []
    ).length,
    canonical_proposal_occurrences: (
      facts.body_text.match(/DAO-PROP-6CB25C/gu) ?? []
    ).length,
    headings: summarizeCollection(facts.headings),
    landmarks: facts.landmarks,
    links: summarizeCollection(facts.links),
    frames: summarizeCollection(facts.frames),
    test_ids: summarizeCollection(facts.test_ids),
    error_overlays: facts.error_overlays,
  };
}

async function collectYoutubeFacts(page, videoId) {
  const video = page.locator("video").first();
  await video.waitFor({ state: "attached", timeout: NAVIGATION_TIMEOUT_MS });
  await page.evaluate(async () => {
    const element = document.querySelector("video");
    if (!element) {
      throw new Error("YouTube video element is unavailable");
    }
    element.muted = true;
    try {
      await element.play();
    } catch {
      // The state is checked from the element below; no claimed success here.
    }
  });

  const captionsButton = page.locator(".ytp-subtitles-button").first();
  if (await captionsButton.count()) {
    const pressed = await captionsButton.getAttribute("aria-pressed");
    if (pressed !== "true") {
      await captionsButton.click({ timeout: 10_000 });
    }
  }

  const deadline = Date.now() + 15_000;
  let facts;
  do {
    facts = await page.evaluate((expectedVideoId) => {
      const element = document.querySelector("video");
      const button = document.querySelector(".ytp-subtitles-button");
      const segments = Array.from(
        document.querySelectorAll(".ytp-caption-segment"),
      ).map((item) =>
        String(item.textContent ?? "")
          .replace(/\s+/gu, " ")
          .trim()
          .slice(0, 512),
      );
      const trackFacts = element
        ? Array.from(element.textTracks).map((track) => ({
            kind: track.kind,
            label: track.label,
            language: track.language,
            mode: track.mode,
            active_cue_count: track.activeCues?.length ?? 0,
          }))
        : [];
      const playerVideoId =
        globalThis.ytInitialPlayerResponse?.videoDetails?.videoId ?? null;
      return {
        expected_video_id: expectedVideoId,
        player_video_id:
          typeof playerVideoId === "string" ? playerVideoId : null,
        current_time_seconds: element
          ? Number(element.currentTime.toFixed(3))
          : null,
        duration_seconds:
          element && Number.isFinite(element.duration)
            ? Math.floor(element.duration)
            : null,
        paused: element?.paused ?? null,
        ended: element?.ended ?? null,
        ready_state: element?.readyState ?? null,
        caption_button_aria_pressed: button?.getAttribute("aria-pressed") ?? null,
        visible_caption_segments: segments,
        text_tracks: trackFacts,
      };
    }, videoId);
    if (
      facts &&
      (facts.ended === true ||
        (facts.paused === false && facts.current_time_seconds > 0)) &&
      facts.caption_button_aria_pressed === "true" &&
      facts.visible_caption_segments.some((segment) => segment.length > 0)
    ) {
      break;
    }
    await page.waitForTimeout(500);
  } while (Date.now() < deadline);

  if (
    !facts ||
    facts.player_video_id !== videoId ||
    !Number.isInteger(facts.duration_seconds) ||
    facts.duration_seconds <= 0 ||
    !(
      facts.ended === true ||
      (facts.paused === false && facts.current_time_seconds > 0)
    ) ||
    facts.caption_button_aria_pressed !== "true" ||
    !facts.visible_caption_segments.some((segment) => segment.length > 0)
  ) {
    throw new GateError(
      "YouTube playback and visible captions were not observed from the DOM",
    );
  }
  return facts;
}

async function collectDorahacksFacts(page, videoId) {
  const facts = await page.evaluate((expectedVideoId) => {
    const candidates = Array.from(
      document.querySelectorAll("[href],[src],[data-src]"),
    ).flatMap((element) =>
      ["href", "src", "data-src"]
        .map((attribute) => ({
          tag: element.tagName.toLowerCase(),
          attribute,
          value: element.getAttribute(attribute),
        }))
        .filter((item) => typeof item.value === "string"),
    );
    const matching = candidates
      .filter((item) => item.value.includes(expectedVideoId))
      .slice(0, 64);
    const html = document.documentElement.outerHTML;
    return {
      video_id: expectedVideoId,
      html_occurrences: html.split(expectedVideoId).length - 1,
      matching_elements: matching,
      canonical_href:
        document.querySelector("link[rel=canonical]")?.getAttribute("href") ??
        null,
    };
  }, videoId);
  const matchingElements = facts.matching_elements.map((item) => ({
    tag: item.tag,
    attribute: item.attribute,
    value: safeUrl(item.value),
  }));
  if (
    facts.html_occurrences < 1 ||
    !Array.isArray(facts.matching_elements) ||
    facts.matching_elements.length < 1
  ) {
    throw new GateError(
      "DoraHacks public BUIDL DOM does not embed the submitted video ID",
    );
  }
  return {
    video_id: facts.video_id,
    html_occurrences: facts.html_occurrences,
    matching_elements: matchingElements,
    matching_elements_sha256: sha256Bytes(
      Buffer.from(canonicalJson(matchingElements), "utf8"),
    ),
    canonical_href:
      typeof facts.canonical_href === "string"
        ? safeUrl(facts.canonical_href)
        : null,
  };
}

async function collectRoute(context, route, videoId) {
  const page = await context.newPage();
  const networkRecorder = buildNetworkRecorder(page);
  const blockedNonReadRequests = [];
  const pageErrors = [];
  const consoleErrors = [];

  page.on("pageerror", (error) => {
    pageErrors.push(opaqueErrorFact(error.message));
  });
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(opaqueErrorFact(message.text()));
    }
  });
  await page.route("**/*", async (intercepted) => {
    const request = intercepted.request();
    if (!READ_METHODS.has(request.method())) {
      blockedNonReadRequests.push({
        method: request.method(),
        resource_type: request.resourceType(),
        url: safeUrl(request.url()),
      });
      await intercepted.abort("blockedbyclient");
      return;
    }
    await intercepted.continue();
  });

  try {
    const response = await page.goto(route.url, {
      waitUntil: "domcontentloaded",
      timeout: NAVIGATION_TIMEOUT_MS,
    });
    if (!response) {
      throw new GateError(`${route.link_id} returned no navigation response`);
    }
    const status = response.status();
    if (status < 200 || status >= 300) {
      throw new GateError(`${route.link_id} returned HTTP ${status}`);
    }
    const finalUrl = new URL(page.url());
    if (
      finalUrl.protocol !== "https:" ||
      !ALLOWED_TOP_LEVEL_HOSTS.has(finalUrl.hostname)
    ) {
      throw new GateError(`${route.link_id} redirected outside the allowlist`);
    }

    await page.waitForTimeout(SETTLE_TIMEOUT_MS);
    const headers = await response.allHeaders();
    const body = await response.body();
    if (body.length > MAX_RESPONSE_BYTES) {
      throw new GateError(`${route.link_id} response body is oversized`);
    }
    const contentType = headers["content-type"] ?? "";
    const isHtml =
      contentType.toLowerCase().includes("text/html") ||
      contentType.toLowerCase().includes("application/xhtml+xml");
    const dom = isHtml ? await collectDomFacts(page) : null;
    if (
      isHtml &&
      FIRST_PARTY_HTML_HOSTS.has(finalUrl.hostname) &&
      (!dom ||
        dom.concordia_occurrences < 1 ||
        dom.error_overlays !== 0 ||
        (dom.landmarks.main < 1 && dom.headings.count < 1))
    ) {
      throw new GateError(
        `${route.link_id} lacks the required first-party judge DOM`,
      );
    }

    let specialized = null;
    if (route.link_id === "youtube_new_video") {
      specialized = {
        kind: "youtube",
        facts: await collectYoutubeFacts(page, videoId),
      };
    } else if (route.link_id === "dorahacks_buidl_46732") {
      specialized = {
        kind: "dorahacks",
        facts: await collectDorahacksFacts(page, videoId),
      };
    }

    if (pageErrors.length > 0) {
      throw new GateError(
        `${route.link_id} emitted browser page error ${pageErrors[0].sha256}`,
      );
    }
    if (
      FIRST_PARTY_HTML_HOSTS.has(finalUrl.hostname) &&
      consoleErrors.length > 0
    ) {
      throw new GateError(
        `${route.link_id} emitted browser console error ${consoleErrors[0].sha256}`,
      );
    }
    const networkEvents = networkRecorder.stop();
    return {
      link_id: route.link_id,
      requested_url: safeUrl(route.url),
      final_url: safeUrl(page.url()),
      main_response: {
        status,
        headers: safeResponseHeaders(headers),
        body_bytes: body.length,
        body_sha256: sha256Bytes(body),
      },
      dom,
      specialized,
      network_events: networkEvents,
      network_events_sha256: sha256Bytes(
        Buffer.from(canonicalJson(networkEvents), "utf8"),
      ),
      blocked_non_read_requests: blockedNonReadRequests,
      console_errors: consoleErrors,
      page_errors: pageErrors,
    };
  } finally {
    networkRecorder.stop();
    await page.close();
  }
}

async function main() {
  const inputPath = parseArguments(process.argv.slice(2));
  const request = validateInput(await readInput(inputPath));
  const startedAt = new Date().toISOString();
  const { chromium, playwrightVersion, chromiumExecutableSha256 } =
    await loadPlaywright();
  const browser = await chromium.launch({
    headless: true,
    chromiumSandbox: true,
  });
  try {
    const context = await browser.newContext({
      acceptDownloads: false,
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
      const results = await Promise.all(
        request.routes.map((route) =>
          collectRoute(context, route, request.videoId),
        ),
      );
      results.sort((left, right) => left.link_id.localeCompare(right.link_id));
      const capturedAt = new Date().toISOString();
      const output = {
        schema_version: OUTPUT_SCHEMA,
        started_at: startedAt,
        captured_at: capturedAt,
        incognito_context: {
          persistent_profile: false,
          storage_state_loaded: false,
          cookies_at_start: 0,
        },
        mutation_guard: {
          allowed_http_methods: [...READ_METHODS].sort(),
          blocked_non_read_request_count: results.reduce(
            (total, result) =>
              total + result.blocked_non_read_requests.length,
            0,
          ),
        },
        runtime_versions: {
          chromium: browser.version(),
          chromium_executable_sha256: chromiumExecutableSha256,
          node: process.version,
          playwright: playwrightVersion,
        },
        routes: results,
      };
      process.stdout.write(`${canonicalJson(output)}\n`);
    } finally {
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  const message =
    error instanceof GateError
      ? error.message
      : `unexpected browser collector failure: ${sanitizeText(error?.message)}`;
  process.stderr.write(`G13 browser collector failed: ${message}\n`);
  process.exitCode = 1;
});
