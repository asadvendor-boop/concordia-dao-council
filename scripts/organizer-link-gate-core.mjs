import { createHash } from "node:crypto";

export const REQUEST_SCHEMA =
  "concordia.organizer_rendered_link_request.v2";
export const RESULT_SCHEMA =
  "concordia.organizer_rendered_link_audit.v2";
export const APP_ORIGIN =
  "https://concordia.47.84.232.193.sslip.io";
export const DOCS_ORIGIN = "https://docs.concordiadao.xyz";
export const PROPOSAL_ID = "DAO-PROP-6CB25C";

const CASPER_DEPLOYS = Object.freeze({
  canonical:
    "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852",
  quorum_refusal:
    "6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431",
  quorum_approval:
    "7ee77b11b8373fa55976b047e5613d391dd2ece5b6c2f0671c7232183cc875da",
  quorum_acceptance:
    "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928",
  wallet:
    "56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf",
  supplemental:
    "68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0",
  historical_safepay:
    "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c",
});

function knownLink(url, allowedRedirects = [], identity = null) {
  return Object.freeze({
    url,
    allowed_redirects: Object.freeze(
      allowedRedirects.map((row) => Object.freeze({ ...row })),
    ),
    identity: identity === null ? null : Object.freeze({ ...identity }),
  });
}

export const KNOWN_LINKS = Object.freeze({
  custom_apex: knownLink(
    "https://concordiadao.xyz/",
    [],
    { kind: "concordia_home" },
  ),
  custom_www: knownLink(
    "https://www.concordiadao.xyz/",
    [
      {
        from: "https://www.concordiadao.xyz/",
        to: "https://concordiadao.xyz/",
        status: 308,
      },
    ],
    { kind: "concordia_home" },
  ),
  docs_root: knownLink(`${DOCS_ORIGIN}/`),
  docs_judge_quickstart_anchor: knownLink(
    `${DOCS_ORIGIN}/judge-walkthrough/#judge-walkthrough`,
  ),
  github_repository: knownLink(
    "https://github.com/asadvendor-boop/concordia-dao-council",
  ),
  dorahacks_buidl: knownLink("https://dorahacks.io/buidl/46732"),
  youtube_initial_round: knownLink(
    "https://www.youtube.com/watch?v=GU01V83Jrko",
  ),
  twitter_profile: knownLink("https://x.com/ConcordiaDAO"),
  twitter_launch_post: knownLink(
    "https://x.com/ConcordiaDAO/status/2074438324769689653",
  ),
  canonical_receipt: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.canonical}`,
  ),
  canonical_contract: knownLink(
    "https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1",
  ),
  quorum_precondition_refusal: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.quorum_refusal}`,
  ),
  quorum_approval: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.quorum_approval}`,
  ),
  quorum_acceptance: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.quorum_acceptance}`,
  ),
  wallet_receipt: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.wallet}`,
  ),
  supplemental_dynamic_receipt: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.supplemental}`,
  ),
  historical_safepay_payment: knownLink(
    `https://testnet.cspr.live/deploy/${CASPER_DEPLOYS.historical_safepay}`,
  ),
});

const ALLOWED_HOSTS = new Set([
  new URL(APP_ORIGIN).hostname,
  new URL(DOCS_ORIGIN).hostname,
  "concordiadao.xyz",
  "www.concordiadao.xyz",
  "github.com",
  "dorahacks.io",
  "www.youtube.com",
  "youtube.com",
  "youtu.be",
  "x.com",
  "testnet.cspr.live",
  "cdn.cspr.click",
  "sdk.cspr.click",
]);
const ALLOWED_APP_QUERY_KEYS = new Set([
  "proposal",
  "tab",
  "recording",
  "quorum_demo",
  "url",
  "w",
  "q",
  "v",
  "dpl",
  "_rsc",
]);
const DOWNLOAD_PATH = /(?:\/download|\/exports\/|\.csv$|\.json$|\.pdf$)/u;
const HEX_64 = /^[a-f0-9]{64}$/u;

export class GateFailure extends Error {
  constructor(code, message) {
    super(message);
    this.name = "GateFailure";
    this.code = code;
  }
}

function fail(code, message) {
  throw new GateFailure(code, message);
}

function exactKeys(value, keys, code, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(code, `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(code, `${label} has a non-exact field set`);
  }
}

function clone(value) {
  return structuredClone(value);
}

function strictPublicUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail("INVALID_URL", `${label} is not a URL`);
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    !ALLOWED_HOSTS.has(url.hostname)
  ) {
    fail("INVALID_URL", `${label} is outside the fixed public HTTPS surface`);
  }
  if (/\/dashboard\/dashboard(?:\/|$)/u.test(url.pathname)) {
    fail("DOUBLED_BASE_PATH", `${label} contains a doubled dashboard basePath`);
  }
  if (url.origin === APP_ORIGIN) {
    const queryEntries = [...url.searchParams.entries()];
    const generatedFaviconQuery =
      url.pathname === "/dashboard/favicon.ico" &&
      queryEntries.length === 1 &&
      queryEntries[0][1] === "" &&
      /^favicon\.[a-z0-9]{8,32}\.ico$/u.test(queryEntries[0][0]);
    for (const [key] of queryEntries) {
      if (!ALLOWED_APP_QUERY_KEYS.has(key) && !generatedFaviconQuery) {
        fail(
          "INVALID_URL",
          `${label} contains an unapproved application query key ${key}`,
        );
      }
    }
  }
  return url;
}

function route(
  routeId,
  pathname,
  expectedQuery = {},
  activeProofTab = null,
  expectedDom = {},
) {
  const url = new URL(pathname, APP_ORIGIN);
  for (const [key, value] of Object.entries(expectedQuery)) {
    url.searchParams.set(key, value);
  }
  return Object.freeze({
    route_id: routeId,
    url: url.href,
    expected_query: Object.freeze({ ...expectedQuery }),
    active_proof_tab: activeProofTab,
    expected_dom: Object.freeze({
      active_navigation_path:
        expectedDom.active_navigation_path === undefined
          ? url.pathname
          : expectedDom.active_navigation_path,
      primary_headings: Object.freeze([
        ...(expectedDom.primary_headings ?? ["*"]),
      ]),
    }),
    allowed_redirects: Object.freeze([]),
  });
}

export function buildInventory() {
  const dashboardRoutes = [
    route("overview", "/dashboard", {}, null, {
      primary_headings: ["Concordia DAO Council"],
    }),
    route(
      "proposals",
      "/dashboard/proposals",
      { proposal: PROPOSAL_ID },
      null,
      { primary_headings: ["*"] },
    ),
    route("approvals", "/dashboard/approvals", {}, null, {
      primary_headings: ["Review Exact Governance execution"],
    }),
    route("council_chamber", "/dashboard/agents", {}, null, {
      primary_headings: ["Council Chamber"],
    }),
    route("evidence", "/dashboard/evidence", {}, null, {
      primary_headings: ["Evidence & Audit"],
    }),
    route("proof_center", "/dashboard/proof", {}, null, {
      primary_headings: ["Proof Center"],
    }),
    route("judge_walkthrough", "/dashboard/judge", {}, null, {
      primary_headings: ["Judge Walkthrough"],
    }),
    route(
      "judge_recording",
      "/dashboard/judge",
      { recording: "1" },
      null,
      {
        active_navigation_path: "/dashboard/judge",
        primary_headings: ["90-second Concordia proof path"],
      },
    ),
    route("runs_replay", "/dashboard/runs", {}, null, {
      primary_headings: ["Runs & Verified Replay", "Runs & Recorded Replay"],
    }),
    route("record", "/dashboard/record", {}, null, {
      active_navigation_path: "/dashboard/judge",
      primary_headings: ["90-second Concordia proof path"],
    }),
    route("technical_jury_note", "/dashboard/technical-jury-note", {}, null, {
      active_navigation_path: null,
      primary_headings: ["Technical Jury Note"],
    }),
  ];
  const proofTabs = ["summary", "safety", "onchain", "data", "exports"].map(
    (tabId) =>
      Object.freeze({
        ...route(
          `proof_tab_${tabId}`,
          "/dashboard/proof",
          { proposal: PROPOSAL_ID, tab: tabId },
          tabId,
          {
            active_navigation_path: "/dashboard/proof",
            primary_headings: ["Proof Center"],
          },
        ),
        tab_id: tabId,
      }),
  );
  return {
    dashboard_routes: dashboardRoutes.map(clone),
    proof_tabs: proofTabs.map(clone),
  };
}

export function canonicalJson(value) {
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

function expectedRequest() {
  return {
    schema_version: REQUEST_SCHEMA,
    app_origin: APP_ORIGIN,
    docs_origin: DOCS_ORIGIN,
    proposal_id: PROPOSAL_ID,
    known_links: Object.entries(KNOWN_LINKS).map(([link_id, link]) => ({
      link_id,
      url: link.url,
      allowed_redirects: clone(link.allowed_redirects),
      identity: clone(link.identity),
    })),
  };
}

export function validateRequest(value) {
  exactKeys(
    value,
    [
      "schema_version",
      "app_origin",
      "docs_origin",
      "proposal_id",
      "known_links",
    ],
    "REQUEST_FIELDS_INVALID",
    "organizer gate request",
  );
  const expected = expectedRequest();
  if (
    value.schema_version !== REQUEST_SCHEMA ||
    value.app_origin !== APP_ORIGIN ||
    value.docs_origin !== DOCS_ORIGIN ||
    value.proposal_id !== PROPOSAL_ID
  ) {
    fail("REQUEST_IDENTITY_MISMATCH", "organizer gate request identity differs");
  }
  if (
    !Array.isArray(value.known_links) ||
    canonicalJson(value.known_links) !== canonicalJson(expected.known_links)
  ) {
    fail(
      "REQUEST_LINK_MISMATCH",
      "organizer gate known-link inventory differs",
    );
  }
  for (const link of value.known_links) {
    strictPublicUrl(link.url, `known link ${link.link_id}`);
  }
  return clone(expected);
}

export function classifyRenderedTarget(
  href,
  documentUrl,
  { element_kind: elementKind, download },
) {
  if (typeof href !== "string" || href.trim() === "") {
    fail("INVALID_URL", "rendered target is empty");
  }
  let base;
  try {
    base = strictPublicUrl(documentUrl, "rendered document URL");
  } catch (error) {
    throw error;
  }
  let target;
  try {
    target = new URL(href, base);
  } catch {
    fail("INVALID_URL", "rendered target is not a URL");
  }
  strictPublicUrl(target.href, "rendered target");
  const sameDocument =
    target.origin === base.origin &&
    target.pathname === base.pathname &&
    target.search === base.search &&
    Boolean(target.hash);
  if (sameDocument) {
    return {
      kind: "document_anchor",
      url: target.href,
      fragment: decodeURIComponent(target.hash.slice(1)),
    };
  }
  if (target.origin === APP_ORIGIN) {
    const kind =
      elementKind === "asset"
        ? "first_party_asset"
        : download || DOWNLOAD_PATH.test(target.pathname)
          ? "first_party_download"
          : "first_party_anchor";
    return { kind, url: target.href, fragment: target.hash.slice(1) || null };
  }
  if (target.origin === DOCS_ORIGIN) {
    return {
      kind: target.hash ? "documentation_anchor" : "documentation_link",
      url: target.href,
      fragment: target.hash
        ? decodeURIComponent(target.hash.slice(1))
        : null,
    };
  }
  return {
    kind: elementKind === "asset" ? "external_asset" : "external_anchor",
    url: target.href,
    fragment: target.hash
      ? decodeURIComponent(target.hash.slice(1))
      : null,
  };
}

function redirectsMatch(actual, expected) {
  return canonicalJson(actual) === canonicalJson(expected);
}

function validateQuery(spec, finalUrl) {
  const parsed = strictPublicUrl(finalUrl, `${spec.route_id} final URL`);
  const actual = [...parsed.searchParams.entries()].sort(([leftKey, leftValue], [rightKey, rightValue]) =>
    leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue),
  );
  const expected = Object.entries(spec.expected_query).sort(([leftKey, leftValue], [rightKey, rightValue]) =>
    leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue),
  );
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(
      "QUERY_STATE_LOST",
      `${spec.route_id} did not preserve the exact query multiset`,
    );
  }
  return parsed;
}

function validateRouteIdentity(spec, observation) {
  const identity = observation.route_identity;
  exactKeys(
    identity,
    [
      "brand_text",
      "active_navigation_path",
      "primary_heading",
      "active_tab_id",
      "active_tabpanel_id",
    ],
    "ROUTE_DOM_IDENTITY_MISMATCH",
    `${spec.route_id} DOM identity`,
  );
  const headings = spec.expected_dom.primary_headings;
  const headingMatches =
    typeof identity.primary_heading === "string" &&
    identity.primary_heading.trim() !== "" &&
    (headings.includes("*") || headings.includes(identity.primary_heading));
  const expectedPanel =
    spec.active_proof_tab === null
      ? null
      : `proof-tabpanel-${spec.active_proof_tab}`;
  if (
    identity.brand_text !== "Concordia DAO Council" ||
    identity.active_navigation_path !==
      spec.expected_dom.active_navigation_path ||
    !headingMatches ||
    identity.active_tab_id !== spec.active_proof_tab ||
    identity.active_tabpanel_id !== expectedPanel
  ) {
    fail(
      "ROUTE_DOM_IDENTITY_MISMATCH",
      `${spec.route_id} rendered the wrong route-specific DOM`,
    );
  }
}

function validateClientDownloads(spec, observation) {
  if (
    !Array.isArray(observation.rendered_download_controls) ||
    !Array.isArray(observation.client_downloads)
  ) {
    fail(
      "OBSERVATION_FIELDS_INVALID",
      `${spec.route_id} lacks client-download evidence`,
    );
  }
  const expectedIds = observation.rendered_download_controls.map(
    (row) => row.control_id,
  );
  const observedIds = observation.client_downloads.map(
    (row) => row.control_id,
  );
  if (
    expectedIds.length !== new Set(expectedIds).size ||
    observedIds.length !== new Set(observedIds).size ||
    canonicalJson([...expectedIds].sort()) !==
      canonicalJson([...observedIds].sort())
  ) {
    fail(
      "CLIENT_DOWNLOAD_MISSING",
      `${spec.route_id} did not capture every rendered client download`,
    );
  }
  for (const row of observation.client_downloads) {
    if (
      typeof row.suggested_filename !== "string" ||
      row.suggested_filename.trim() === "" ||
      !Number.isInteger(row.body_bytes) ||
      row.body_bytes <= 0 ||
      typeof row.body_sha256 !== "string" ||
      !HEX_64.test(row.body_sha256)
    ) {
      fail(
        "CLIENT_DOWNLOAD_INVALID",
        `${spec.route_id} has invalid client-download evidence`,
      );
    }
  }
}

export function validateRouteObservation(spec, observation) {
  if (
    observation?.route_id !== spec.route_id ||
    observation.requested_url !== spec.url
  ) {
    fail("ROUTE_IDENTITY_MISMATCH", `${spec.route_id} observation differs`);
  }
  if (
    !Number.isInteger(observation.status) ||
    observation.status < 200 ||
    observation.status >= 300
  ) {
    fail("ROUTE_HTTP_FAILURE", `${spec.route_id} did not return HTTP 2xx`);
  }
  if (!redirectsMatch(observation.redirects, spec.allowed_redirects)) {
    fail("UNDOCUMENTED_REDIRECT", `${spec.route_id} redirected unexpectedly`);
  }
  const finalUrl = validateQuery(spec, observation.final_url);
  const expectedPath = new URL(spec.url).pathname;
  if (finalUrl.origin !== APP_ORIGIN || finalUrl.pathname !== expectedPath) {
    fail("ROUTE_TARGET_MISMATCH", `${spec.route_id} changed route target`);
  }
  if (
    spec.active_proof_tab !== null &&
    observation.active_proof_tab !== spec.active_proof_tab
  ) {
    fail(
      "PROOF_TAB_NOT_ACTIVE",
      `${spec.route_id} did not activate ${spec.active_proof_tab}`,
    );
  }
  validateRouteIdentity(spec, observation);
  validateClientDownloads(spec, observation);
  if (!Array.isArray(observation.blocked_websockets)) {
    fail(
      "OBSERVATION_FIELDS_INVALID",
      `${spec.route_id} lacks WebSocket guard evidence`,
    );
  }
  if (observation.blocked_websockets.length > 0) {
    fail(
      "WEBSOCKET_ATTEMPT",
      `${spec.route_id} attempted a bidirectional WebSocket connection`,
    );
  }
  for (const [field, code] of [
    ["console_errors", "CONSOLE_ERROR"],
    ["page_errors", "PAGE_ERROR"],
    ["blocked_non_read_requests", "NON_READ_REQUEST"],
    ["first_party_failures", "FIRST_PARTY_REQUEST_FAILED"],
  ]) {
    if (!Array.isArray(observation[field])) {
      fail("OBSERVATION_FIELDS_INVALID", `${spec.route_id} lacks ${field}`);
    }
    if (observation[field].length > 0) {
      fail(code, `${spec.route_id} recorded ${field}`);
    }
  }
  for (const item of [
    ...(observation.rendered_links ?? []),
    ...(observation.rendered_assets ?? []),
  ]) {
    classifyRenderedTarget(item.href, observation.final_url, item);
  }
  return clone(observation);
}

export function validateLinkObservation(spec, observation) {
  if (
    observation?.link_id !== spec.link_id ||
    observation.requested_url !== spec.url
  ) {
    fail("LINK_IDENTITY_MISMATCH", `${spec.link_id} observation differs`);
  }
  if (
    !Number.isInteger(observation.status) ||
    observation.status < 200 ||
    observation.status >= 300
  ) {
    fail("LINK_HTTP_FAILURE", `${spec.link_id} did not return HTTP 2xx`);
  }
  if (
    !Array.isArray(observation.redirects) ||
    !redirectsMatch(observation.redirects, spec.allowed_redirects)
  ) {
    fail("UNDOCUMENTED_REDIRECT", `${spec.link_id} redirected unexpectedly`);
  }
  const expectedFinal =
    spec.allowed_redirects.at(-1)?.to ?? spec.url;
  if (observation.effective_url !== expectedFinal) {
    fail("LINK_TARGET_MISMATCH", `${spec.link_id} final target differs`);
  }
  strictPublicUrl(observation.effective_url, `${spec.link_id} effective URL`);
  if (
    !Number.isInteger(observation.body_bytes) ||
    observation.body_bytes <= 0
  ) {
    fail("EMPTY_RESPONSE", `${spec.link_id} returned an empty response`);
  }
  if (
    typeof observation.body_sha256 !== "string" ||
    !HEX_64.test(observation.body_sha256)
  ) {
    fail("BODY_DIGEST_INVALID", `${spec.link_id} body digest is invalid`);
  }
  const requested = new URL(spec.url);
  if (
    [APP_ORIGIN, DOCS_ORIGIN].includes(requested.origin) &&
    requested.hash &&
    observation.anchor_found !== true
  ) {
    fail(
      requested.origin === DOCS_ORIGIN
        ? "MISSING_DOC_ANCHOR"
        : "MISSING_DOCUMENT_ANCHOR",
      `${spec.link_id} cross-document anchor is absent`,
    );
  }
  const expectedIdentity = spec.identity ?? null;
  if (expectedIdentity !== null) {
    if (
      expectedIdentity.kind !== "concordia_home" ||
      canonicalJson(observation.concordia_identity) !==
        canonicalJson({
          kind: "concordia_home",
          title_match: true,
          visible_marker_match: true,
        })
    ) {
      fail(
        "CONCORDIA_IDENTITY_MISMATCH",
        `${spec.link_id} did not render the Concordia home identity`,
      );
    }
  } else if (
    observation.concordia_identity !== undefined &&
    observation.concordia_identity !== null
  ) {
    fail(
      "CONCORDIA_IDENTITY_MISMATCH",
      `${spec.link_id} has unexpected identity evidence`,
    );
  }
  return clone(observation);
}

function exactIdCensus(actual, expected, code, label) {
  const ids = actual.map((row) => row.route_id);
  const expectedIds = expected.map((row) => row.route_id);
  if (
    ids.length !== new Set(ids).size ||
    [...ids].sort().join("\0") !== [...expectedIds].sort().join("\0")
  ) {
    fail(code, `${label} is incomplete or contains duplicates`);
  }
}

export function buildResult({
  request,
  routes,
  proof_tabs: proofTabs,
  links,
  runtime,
  started_at: startedAt,
  captured_at: capturedAt,
  collection_mode: collectionMode,
}) {
  if (!["fixture", "live_incognito"].includes(collectionMode)) {
    fail(
      "COLLECTION_MODE_INVALID",
      "organizer audit collection mode is invalid",
    );
  }
  const validatedRequest = validateRequest(request);
  const inventory = buildInventory();
  if (!Array.isArray(routes)) {
    fail("ROUTE_INVENTORY_INCOMPLETE", "dashboard route results are absent");
  }
  if (!Array.isArray(proofTabs)) {
    fail("PROOF_TAB_INVENTORY_INCOMPLETE", "Proof tab results are absent");
  }
  exactIdCensus(
    routes,
    inventory.dashboard_routes,
    "ROUTE_INVENTORY_INCOMPLETE",
    "dashboard route census",
  );
  exactIdCensus(
    proofTabs,
    inventory.proof_tabs,
    "PROOF_TAB_INVENTORY_INCOMPLETE",
    "Proof tab census",
  );
  const routeById = new Map(routes.map((row) => [row.route_id, row]));
  const tabById = new Map(proofTabs.map((row) => [row.route_id, row]));
  const validatedRoutes = inventory.dashboard_routes.map((spec) =>
    validateRouteObservation(spec, routeById.get(spec.route_id)),
  );
  const validatedTabs = inventory.proof_tabs.map((spec) =>
    validateRouteObservation(spec, tabById.get(spec.route_id)),
  );
  if (!Array.isArray(links)) {
    fail("LINK_INVENTORY_INCOMPLETE", "link results are absent");
  }
  const linkById = new Map(links.map((row) => [row.link_id, row]));
  if (linkById.size !== links.length) {
    fail("LINK_INVENTORY_INCOMPLETE", "link results contain duplicate IDs");
  }
  const knownSpecs = validatedRequest.known_links;
  const knownSpecById = new Map(
    knownSpecs.map((spec) => [spec.link_id, spec]),
  );
  for (const spec of knownSpecs) {
    if (!linkById.has(spec.link_id)) {
      fail(
        "LINK_INVENTORY_INCOMPLETE",
        `known link ${spec.link_id} was not checked`,
      );
    }
    validateLinkObservation(spec, linkById.get(spec.link_id));
  }
  const validatedLinks = [...links]
    .sort((left, right) => left.link_id.localeCompare(right.link_id))
    .map((row) => {
      const spec = knownSpecById.get(row.link_id) ?? {
        link_id: row.link_id,
        url: row.requested_url,
        allowed_redirects: [],
      };
      return validateLinkObservation(spec, row);
    });
  const allPages = [...validatedRoutes, ...validatedTabs];
  const checkedUrls = new Set(
    validatedLinks.map((row) => row.requested_url),
  );
  for (const page of allPages) {
    for (const item of [
      ...page.rendered_links,
      ...page.rendered_assets,
    ]) {
      const classified = classifyRenderedTarget(
        item.href,
        page.final_url,
        item,
      );
      if (
        classified.kind !== "document_anchor" &&
        !checkedUrls.has(classified.url)
      ) {
        fail(
          "RENDERED_TARGET_UNCHECKED",
          `${page.route_id} contains a rendered target without a link observation`,
        );
      }
    }
  }
  const sum = (field) =>
    allPages.reduce((total, row) => total + row[field].length, 0);
  const result = {
    schema_version: RESULT_SCHEMA,
    verdict:
      collectionMode === "live_incognito" ? "PASS" : "NON_QUALIFYING",
    release_qualified: collectionMode === "live_incognito",
    collection_mode: collectionMode,
    started_at: startedAt,
    captured_at: capturedAt,
    request_sha256: createHash("sha256")
      .update(canonicalJson(validatedRequest))
      .digest("hex"),
    runtime: clone(runtime),
    inventory: {
      dashboard_route_ids: inventory.dashboard_routes.map(
        (row) => row.route_id,
      ),
      proof_tab_ids: inventory.proof_tabs.map((row) => row.tab_id),
      known_link_ids: knownSpecs.map((row) => row.link_id),
    },
    summary: {
      dashboard_route_states: validatedRoutes.length,
      proof_tabs: validatedTabs.length,
      unique_links: validatedLinks.length,
      blocked_non_read_requests: sum("blocked_non_read_requests"),
      console_errors: sum("console_errors"),
      page_errors: sum("page_errors"),
      first_party_failures: sum("first_party_failures"),
      blocked_websockets: sum("blocked_websockets"),
      client_downloads: sum("client_downloads"),
    },
    dashboard_routes: validatedRoutes,
    proof_tabs: validatedTabs,
    links: validatedLinks,
  };
  return result;
}

export function validateResultDocument(value) {
  exactKeys(
    value,
    [
      "schema_version",
      "verdict",
      "release_qualified",
      "collection_mode",
      "started_at",
      "captured_at",
      "request_sha256",
      "runtime",
      "inventory",
      "summary",
      "dashboard_routes",
      "proof_tabs",
      "links",
    ],
    "RESULT_DOCUMENT_INVALID",
    "organizer rendered-link audit",
  );
  if (value.schema_version !== RESULT_SCHEMA) {
    fail(
      "RESULT_DOCUMENT_INVALID",
      "organizer rendered-link audit schema differs",
    );
  }
  const rebuilt = buildResult({
    request: expectedRequest(),
    routes: value.dashboard_routes,
    proof_tabs: value.proof_tabs,
    links: value.links,
    runtime: value.runtime,
    started_at: value.started_at,
    captured_at: value.captured_at,
    collection_mode: value.collection_mode,
  });
  if (canonicalJson(rebuilt) !== canonicalJson(value)) {
    fail(
      "RESULT_DOCUMENT_INVALID",
      "organizer rendered-link audit is not self-consistent",
    );
  }
  return clone(rebuilt);
}

export default Object.freeze({
  APP_ORIGIN,
  DOCS_ORIGIN,
  GateFailure,
  KNOWN_LINKS,
  PROPOSAL_ID,
  REQUEST_SCHEMA,
  RESULT_SCHEMA,
  buildInventory,
  buildResult,
  canonicalJson,
  classifyRenderedTarget,
  validateLinkObservation,
  validateRequest,
  validateResultDocument,
  validateRouteObservation,
});
