// WP7 FINAL fail-open blockers (route mocks only — never the live app).
// Four adversarial classes, each with positive controls:
//   1. Overview initial/unobserved state: Gateway "Operational", Council
//      "Connected", simulator "Healthy" and the "CASPER TESTNET LIVE" chip
//      render ONLY from an actual fresh observation; unknown/loading/error
//      renders honest non-green Checking/Reconnecting/Unknown/recorded states.
//   2. Proof Center: CANONICAL_RECEIPT_FACTS never backs a "Verified receipts"
//      claim — recorded facts render only under explicit recorded/historical
//      labeling with neutral tone; a live receipt payload restores the
//      verified presentation.
//   3. Compact proof-table rows: status === "verified" alone NEVER turns a row
//      green — green requires the provenance-aware registry item (strict
//      provenance.js validation, every required check passed:true) backing the
//      row via proof_id/proof_type; missing/failed/unknown stays non-green.
//   4. Exact authorization binding: approval action_hash must exactly equal
//      the plan's client-visible data.action_binding_hash in addition to the
//      proposal and plan-hash bindings; a missing field on either side is NOT
//      bound — across Overview, Agents, Workspace and Approval pages.
//   5. Label families "Verified proposal replay" / "Review complete" /
//      "Recent verified runs": every "verified"/"complete" cue derives from an
//      explicit observed field (chain_valid, verdict decision,
//      receipt_verified) — never from card/row presence or static text; the
//      historical fallback stays visible but is explicitly recorded/dated.
// Plus SOURCE regression tests banning the removed fail-open patterns.
import { expect, test } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FIXTURES, loadFixture } from "../fixtures/registry-fixtures.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const componentsDir = path.resolve(__dirname, "../../app/_components");

const CANONICAL = "DAO-PROP-6CB25C";
const OTHER = "DAO-PROP-OTHER1";

function json(route, body, status = 200) {
  return route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

function idFromUrl(url, prefix) {
  const match = new URL(url).pathname.match(new RegExp(`${prefix}/([^/?]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

// A handler that never answers: simulates the genuinely-unobserved initial
// window in which no payload has arrived yet.
const neverAnswer = () => new Promise(() => {});

async function mockGateway(page, {
  proposals = [],
  evidenceById = {},
  runs = [],
  base = "ok", // "ok" | "fail" | "pending"
  room = "ok", // "ok" | "fail" | "pending"
  proofById = {},
  registry = null,
} = {}) {
  const baseHandler = (payload) => (route) => {
    if (base === "pending") return neverAnswer();
    if (base === "fail") return json(route, { error: "unavailable" }, 500);
    return json(route, payload);
  };
  await page.route("**/stats", baseHandler({}));
  await page.route("**/stats/runsummary", baseHandler({ runs }));
  await page.route("**/agent-status", baseHandler([{ agent_role: "rowan", online: true }]));
  await page.route("**/agent-skills", baseHandler({ skills: [] }));
  await page.route("**/suppression-rules", baseHandler([]));
  await page.route((url) => url.pathname === "/proposals", (route) => {
    if (base === "pending") return neverAnswer();
    if (base === "fail") return json(route, { error: "unavailable" }, 500);
    return json(route, proposals);
  });
  await page.route("**/proposals/*", (route) => {
    if (base === "pending") return neverAnswer();
    const id = idFromUrl(route.request().url(), "proposals");
    const proposal = proposals.find((item) => item.proposal_id === id) || null;
    return json(route, { proposal });
  });
  await page.route("**/evidence/*", (route) => {
    if (base === "pending") return neverAnswer();
    const id = idFromUrl(route.request().url(), "evidence");
    const evidence = evidenceById[id];
    if (!evidence) return json(route, { error: "not_found" }, 404);
    return json(route, evidence);
  });
  await page.route("**/room-messages/*", (route) => {
    if (room === "pending") return neverAnswer();
    if (room === "fail") return json(route, { error: "unavailable" }, 500);
    return json(route, { messages: [], room_id: "room", message_count: 0 });
  });
  await page.route("**/proof-center/**", (route) => {
    const id = idFromUrl(route.request().url(), "proof-center");
    const proof = proofById[id];
    if (!proof) return json(route, { error: "unavailable" }, 404);
    return json(route, proof);
  });
  await page.route("**/proof-registry/v1/**", (route) => (registry ? json(route, registry) : json(route, { error: "not_served" }, 404)));
  await page.route("**/adversarial-safety-demo/**", (route) => json(route, { error: "unavailable" }, 404));
  await page.route("**/integrations/status", (route) => json(route, { error: "unavailable" }, 404));
  await page.route("**/cspr-click/unsigned-receipt/**", (route) => json(route, { error: "unavailable" }, 404));
}

function proposalCard(title = "Risky treasury move", sequence = 1) {
  return { card_type: "ProposalCard", sequence, hash: `hash-proposal-${sequence}`, data: { title, raw_payload: { title } } };
}

// Plan carries the client-visible exact-action binding hash; approvals that
// authorize must present the exactly matching action_hash.
function planCard(data = {}) {
  return {
    card_type: "ResponsePlan",
    sequence: 4,
    hash: "plan-hash-abc",
    data: { action_binding_hash: "action-hash-def", envelopes: [{ action_id: "execute_casper_governance_receipt", target: "treasury", parameters: { approved_allocation_bps: 800 } }], ...data },
  };
}

function planCardWithoutActionBinding() {
  return {
    card_type: "ResponsePlan",
    sequence: 4,
    hash: "plan-hash-abc",
    data: { envelopes: [{ action_id: "execute_casper_governance_receipt", target: "treasury", parameters: { approved_allocation_bps: 800 } }] },
  };
}

function approvalCard(data, cardType = "StructuredApproval") {
  return { card_type: cardType, sequence: 5, hash: "approval-hash", data };
}

const fullyBoundApproval = () => approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "action-hash-def" });

const verifiedReceipt = () => ({
  card_type: "CasperExecutionReceipt",
  sequence: 6,
  hash: "receipt-hash",
  data: {
    actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success", transaction_hash: "tx-hash" }],
    timeline: [{ event: "casper_transaction_verified", receipt_verified: true, details: [] }],
  },
});

const executedProposal = () => [{ proposal_id: CANONICAL, state: "EXECUTED", created_at: "2026-06-29T00:00:00Z" }];

function healthRow(page, label) {
  return page.locator(".health-list > div").filter({ hasText: label });
}

// DELIBERATE MIGRATION (reviewer truth-contract pass): a "complete" live read
// now also requires explicit observation provenance — a non-empty status
// alongside the source — matching the strengthened isCasperLiveReadComplete.
// DELIBERATE MIGRATION (reviewer truth pass #2): the live-read predicate now
// allowlists the exact producer-emitted status and source strings
// (shared/proof_pack.py mercer_live_casper_read); arbitrary non-empty
// provenance text no longer satisfies it.
const COMPLETE_LIVE_READ = { network: "casper-test", status: "visible_in_evidence", latest_block_height: 8340490, state_root_hash: "a".repeat(64), source: "Casper Node RPC / CSPR.live public status" };

test.describe("1. overview unobserved/initial state never renders positive protocol cues", () => {
  test("with every payload still pending, health pills read Checking and nothing is Operational/Connected/Healthy/LIVE", async ({ page }) => {
    await mockGateway(page, { base: "pending", room: "pending" });
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const health = page.locator(".health-list");
    await expect(health).toBeVisible();
    await expect(healthRow(page, "Gateway")).toContainText("Checking");
    await expect(healthRow(page, "Council Chambers")).toContainText("Checking");
    await expect(healthRow(page, "Proposal simulator")).toContainText("Checking");
    await expect(health.getByText("Operational")).toHaveCount(0);
    await expect(health.getByText("Connected")).toHaveCount(0);
    await expect(health.getByText("Healthy")).toHaveCount(0);
    // Only the (unrelated) chain-validity row may not be green either: zero
    // success pills anywhere in the health list.
    await expect(health.locator(".status-success")).toHaveCount(0);
    // No static live-testnet claim; the honest recorded chip renders instead.
    await expect(page.getByText("CASPER TESTNET LIVE")).toHaveCount(0);
    await expect(page.getByTestId("overview-casper-chip")).toContainText("RECORDED PROOF");
  });

  test("an observed base failure renders Reconnecting/Unknown immediately — never Operational or Healthy", async ({ page }) => {
    await mockGateway(page, { base: "fail", room: "fail" });
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const health = page.locator(".health-list");
    await expect(healthRow(page, "Gateway")).toContainText("Reconnecting");
    await expect(healthRow(page, "Proposal simulator")).toContainText("Unknown");
    await expect(health.getByText("Operational")).toHaveCount(0);
    await expect(health.getByText("Healthy")).toHaveCount(0);
    await expect(health.locator(".status-success")).toHaveCount(0);
    await expect(page.getByText("CASPER TESTNET LIVE")).toHaveCount(0);
  });

  test("a failing Council Chamber renders Reconnecting, never Connected", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      room: "fail",
    });
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const row = healthRow(page, "Council Chambers");
    await expect(row).toContainText("Reconnecting");
    await expect(row.getByText("Connected")).toHaveCount(0);
  });

  test("an incomplete live Casper read never renders the CASPER TESTNET LIVE chip", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      proofById: { [CANONICAL]: { mercer_live_casper_read: { network: "casper-test", latest_block_height: 8340490 } } },
    });
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("overview-casper-chip")).toContainText("RECORDED PROOF");
    await expect(page.getByText("CASPER TESTNET LIVE")).toHaveCount(0);
  });

  test("positive control: fresh observations light Operational, Connected, Healthy and the LIVE chip", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      proofById: { [CANONICAL]: { mercer_live_casper_read: COMPLETE_LIVE_READ } },
    });
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const gateway = healthRow(page, "Gateway");
    await expect(gateway).toContainText("Operational");
    await expect(gateway.locator(".status-success")).toHaveCount(1);
    await expect(healthRow(page, "Council Chambers")).toContainText("Connected");
    const simulator = healthRow(page, "Proposal simulator");
    await expect(simulator).toContainText("Healthy");
    await expect(simulator.locator(".status-success")).toHaveCount(1);
    await expect(page.getByTestId("overview-casper-chip")).toHaveText("CASPER TESTNET LIVE");
  });
});

test.describe("2. proof center never presents recorded canonical facts as verified receipts", () => {
  test("without a live receipt payload the receipts panel is explicitly recorded/historical with neutral tone", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
    });
    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const panel = page.locator(".receipts-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Recorded receipts · historical" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Verified receipts" })).toHaveCount(0);
    await expect(panel.getByText("Canonical receipt (recorded)")).toBeVisible();
    await expect(panel.locator(".hash-chip-success")).toHaveCount(0);
    await expect(panel.getByText("No live verification is asserted")).toBeVisible();
  });

  test("positive control: a live receipt payload restores the Verified receipts presentation", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      proofById: {
        [CANONICAL]: {
          casper_receipt: {
            decision: "APPROVED_WITH_LIMITS",
            deploy_hash: "b".repeat(64),
            explorer_url: `https://testnet.cspr.live/deploy/${"b".repeat(64)}`,
          },
        },
      },
    });
    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const panel = page.locator(".receipts-panel");
    await expect(panel.getByRole("heading", { name: "Verified receipts" })).toBeVisible();
    await expect(panel.getByText("Recorded receipts · historical")).toHaveCount(0);
    await expect(panel.locator(".hash-chip-success")).toHaveCount(1);
  });
});

test.describe("3. compact proof-table rows require provenance-registry backing to turn green", () => {
  const verifiedRows = [
    { claim: "Exact envelope v3 enforced on-chain", status: "verified", proof_type: "exact_envelope_v3", evidence: "registry-backed claim" },
    { claim: "Blocked tamper attempt", status: "verified", evidence: "no registry reference on this row" },
  ];

  test("status verified alone (registry absent) renders zero green rows and honest unconfirmed pills", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      proofById: { [CANONICAL]: { compact_proof_table: verifiedRows } },
    });
    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const table = page.locator(".proof-table");
    await expect(table).toBeVisible();
    await expect(table.locator("> div")).toHaveCount(2);
    await expect(table.locator(".status-success")).toHaveCount(0);
    await expect(table.getByText("unconfirmed")).toHaveCount(2);
    await expect(table.getByText("verified", { exact: true })).toHaveCount(0);
  });

  test("a registry item that is not green (pending) still never turns its row green", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      proofById: { [CANONICAL]: { compact_proof_table: verifiedRows } },
      registry: loadFixture(FIXTURES.unverified),
    });
    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const table = page.locator(".proof-table");
    await expect(table).toBeVisible();
    await expect(table.locator(".status-success")).toHaveCount(0);
    await expect(table.getByText("unconfirmed")).toHaveCount(2);
  });

  test("positive control: rows backed by a fully-verified registry item (by proof_type and by proof_id) render green", async ({ page }) => {
    await mockGateway(page, {
      proposals: executedProposal(),
      evidenceById: { [CANONICAL]: { chain_valid: true, cards: [proposalCard()] } },
      proofById: {
        [CANONICAL]: {
          compact_proof_table: [
            { claim: "Exact envelope v3 enforced on-chain", status: "verified", proof_type: "exact_envelope_v3", evidence: "registry-backed by type" },
            { claim: "SafePay v2 settlement verified", status: "verified", proof_id: "fixture-safepay-v2", evidence: "registry-backed by id" },
            { claim: "Blocked tamper attempt", status: "verified", evidence: "no registry reference — must stay neutral" },
          ],
        },
      },
      registry: loadFixture(FIXTURES.verified),
    });
    await page.goto("/dashboard/proof", { waitUntil: "domcontentloaded" });
    const table = page.locator(".proof-table");
    await expect(table).toBeVisible();
    await expect(table.locator(".status-success")).toHaveCount(2);
    await expect(table.getByText("verified", { exact: true })).toHaveCount(2);
    await expect(table.getByText("unconfirmed")).toHaveCount(1);
  });
});

test.describe("4. exact authorization binding: action_hash must equal the plan's action_binding_hash", () => {
  async function openPage(page, route, cards, state = "EXECUTED") {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state, created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { chain_valid: true, cards } },
    });
    await page.goto(route, { waitUntil: "domcontentloaded" });
  }
  const missingActionHash = () => approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc" });
  const mismatchedActionHash = () => approvalCard({ decision: "APPROVED", proposal_id: CANONICAL, plan_hash: "plan-hash-abc", action_hash: "some-other-action-hash" });

  test("approvals page: a MISSING approval action_hash never authorizes", async ({ page }) => {
    await openPage(page, "/dashboard/approvals", [proposalCard(), planCard(), missingActionHash()]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
    await expect(page.getByText("Authorization verified and consumed")).toHaveCount(0);
  });

  test("approvals page: a MISMATCHED action_hash never authorizes", async ({ page }) => {
    await openPage(page, "/dashboard/approvals", [proposalCard(), planCard(), mismatchedActionHash()]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("approvals page: a plan LACKING action_binding_hash never authorizes, even when the approval carries an action_hash", async ({ page }) => {
    await openPage(page, "/dashboard/approvals", [proposalCard(), planCardWithoutActionBinding(), fullyBoundApproval()]);
    await expect(page.getByRole("heading", { name: "Authorization boundary visible" })).toBeVisible();
    await expect(page.getByText("Exact action authorized")).toHaveCount(0);
  });

  test("overview: an action-unbound approval never renders Authorized or a complete Approved step", async ({ page }) => {
    await openPage(page, "/dashboard", [proposalCard(), planCard(), mismatchedActionHash()]);
    const activity = page.locator(".agent-mini-list");
    await expect(activity).toBeVisible();
    await expect(activity.getByText("Authorized", { exact: true })).toHaveCount(0);
    await expect(activity.getByText("Awaiting human", { exact: true })).toBeVisible();
    await expect(page.locator(".active-proposal-workflow .workflow-step").filter({ hasText: "Approved" })).not.toHaveClass(/complete/);
  });

  test("agents page: an action-unbound approval never renders Plan authorized", async ({ page }) => {
    await openPage(page, "/dashboard/agents", [proposalCard(), planCard(), missingActionHash()]);
    const directory = page.locator(".agent-directory-grid");
    await expect(directory).toBeVisible();
    await expect(directory.getByText("Plan authorized")).toHaveCount(0);
    await expect(directory.getByText("Awaiting human approval")).toBeVisible();
  });

  test("workspace: an action-unbound approval does not suppress the Review Approval CTA", async ({ page }) => {
    await openPage(page, "/dashboard/proposals", [proposalCard(), planCard(), mismatchedActionHash()], "PLANNED");
    await expect(page.locator(".page-header").getByRole("link", { name: "Review Approval" })).toBeVisible();
  });

  test("positive control: an exactly action-bound approval authorizes across approvals and overview", async ({ page }) => {
    await openPage(page, "/dashboard/approvals", [proposalCard(), planCard(), fullyBoundApproval(), verifiedReceipt()]);
    await expect(page.getByRole("heading", { name: "Exact action authorized" })).toBeVisible();
    await expect(page.getByText("Authorization verified and consumed")).toBeVisible();
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    const activity = page.locator(".agent-mini-list");
    await expect(activity.getByText("Authorized", { exact: true })).toBeVisible();
    await expect(page.locator(".active-proposal-workflow .workflow-step").filter({ hasText: "Approved" })).toHaveClass(/complete/);
  });
});

test.describe("5. verified/complete label families require real predicates", () => {
  async function openWith(page, route, { cards, evidenceExtra = {}, runs = [], state = "EXECUTED" }) {
    await mockGateway(page, {
      proposals: [{ proposal_id: CANONICAL, state, created_at: "2026-06-29T00:00:00Z" }],
      evidenceById: { [CANONICAL]: { ...evidenceExtra, cards } },
      runs,
    });
    await page.goto(route, { waitUntil: "domcontentloaded" });
  }
  const undecidedVerdict = () => ({ card_type: "Verdict", sequence: 3, hash: "verdict-hash", data: { reasoning: "review notes without any decision field" } });
  const decidedVerdict = () => ({ card_type: "Verdict", sequence: 3, hash: "verdict-hash", data: { decision: "CONFIRM", reasoning: "revised evidence threshold met" } });

  test("overview: evidence without chain_valid renders Recorded proposal replay, never Verified", async ({ page }) => {
    await openWith(page, "/dashboard", { cards: [proposalCard()] });
    await expect(page.locator(".active-proposal-head .eyebrow")).toHaveText("Recorded proposal replay");
    await expect(page.getByText("Verified proposal replay")).toHaveCount(0);
  });

  test("positive control: chain_valid === true renders Verified proposal replay", async ({ page }) => {
    await openWith(page, "/dashboard", { cards: [proposalCard()], evidenceExtra: { chain_valid: true } });
    await expect(page.locator(".active-proposal-head .eyebrow")).toHaveText("Verified proposal replay");
  });

  test("overview: a Verdict WITHOUT a decision never renders the green Review complete cue", async ({ page }) => {
    await openWith(page, "/dashboard", { cards: [proposalCard(), undecidedVerdict()], evidenceExtra: { chain_valid: true } });
    const activity = page.locator(".agent-mini-list");
    await expect(activity).toBeVisible();
    await expect(activity.getByText("Review recorded · undecided")).toBeVisible();
    await expect(activity.getByText("Review complete")).toHaveCount(0);
    await expect(activity.locator(".status-success")).toHaveCount(0);
  });

  test("positive control: an explicit verdict decision renders Review complete", async ({ page }) => {
    await openWith(page, "/dashboard", { cards: [proposalCard(), decidedVerdict()], evidenceExtra: { chain_valid: true } });
    const activity = page.locator(".agent-mini-list");
    await expect(activity.getByText("Review complete")).toBeVisible();
  });

  test("agents page: a Verdict WITHOUT a decision never claims Independent review complete", async ({ page }) => {
    await openWith(page, "/dashboard/agents", { cards: [proposalCard(), undecidedVerdict()], evidenceExtra: { chain_valid: true } });
    const directory = page.locator(".agent-directory-grid");
    await expect(directory).toBeVisible();
    await expect(directory.getByText("Independent review complete")).toHaveCount(0);
    await expect(directory.getByText("Review recorded · decision unavailable")).toBeVisible();
  });

  test("positive control: an explicit verdict decision renders Independent review complete", async ({ page }) => {
    await openWith(page, "/dashboard/agents", { cards: [proposalCard(), decidedVerdict()], evidenceExtra: { chain_valid: true } });
    await expect(page.locator(".agent-directory-grid").getByText("Independent review complete")).toBeVisible();
  });

  test("recent runs: rows without observed verification fields render zero success pills and the heading claims nothing", async ({ page }) => {
    await openWith(page, "/dashboard", {
      cards: [proposalCard()],
      evidenceExtra: { chain_valid: true },
      runs: [{ proposal_id: CANONICAL, state: "CLOSED_FALSE_ALARM", proposal_family: "defi_treasury" }],
    });
    await expect(page.getByRole("heading", { name: "Recent runs" })).toBeVisible();
    await expect(page.getByText("Recent verified runs")).toHaveCount(0);
    const table = page.locator(".recent-runs-table");
    await expect(table).toBeVisible();
    await expect(table.locator(".status-success")).toHaveCount(0);
    await expect(table.getByText("N/A")).toBeVisible();
    await expect(table.getByText("Recorded", { exact: true })).toBeVisible();
  });

  test("positive control: observed receipt_verified and chain_valid light the per-run pills", async ({ page }) => {
    await openWith(page, "/dashboard", {
      cards: [proposalCard()],
      evidenceExtra: { chain_valid: true },
      runs: [{ proposal_id: CANONICAL, state: "CLOSED_FALSE_ALARM", proposal_family: "defi_treasury", receipt_verified: true, chain_valid: true }],
    });
    const table = page.locator(".recent-runs-table");
    await expect(table).toBeVisible();
    await expect(table.getByText("Verified", { exact: true })).toBeVisible();
    await expect(table.getByText("Valid", { exact: true })).toBeVisible();
    await expect(table.locator(".status-success")).toHaveCount(2);
  });

  test("the no-runs fallback is explicitly recorded and dated, never a verified claim", async ({ page }) => {
    await openWith(page, "/dashboard", { cards: [proposalCard()], evidenceExtra: { chain_valid: true }, runs: [] });
    await expect(page.getByText("Recorded Casper run available").first()).toBeVisible();
    await expect(page.getByText("recorded June 2026").first()).toBeVisible();
    await expect(page.getByText("Verified Casper run available")).toHaveCount(0);
  });

  test("replay: handoffs are Recorded when chain validity is not reported", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard()] });
    await expect(page.getByText("Recorded handoff").first()).toBeVisible();
    await expect(page.getByText("Verified handoff")).toHaveCount(0);
    await expect(page.getByText("recorded handoffs").first()).toBeVisible();
  });

  // DELIBERATE MIGRATION (reviewer truth-contract pass): "Verified" replay
  // labels now ALSO require the evidence payload to be bound to the selected
  // proposal (payload proposal_id === selectedId), so the positive control
  // carries the binding and two new negatives isolate the binding dimension.
  test("positive control: replay handoffs are Verified only from chain_valid === true on a BOUND payload", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard()], evidenceExtra: { chain_valid: true, proposal_id: CANONICAL } });
    await expect(page.getByText("Verified handoff").first()).toBeVisible();
    await expect(page.getByText("Recorded handoff")).toHaveCount(0);
    await expect(page.getByText("Runs & Verified Replay")).toBeVisible();
  });

  test("replay: chain_valid without payload proposal binding renders Recorded, never Verified", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard()], evidenceExtra: { chain_valid: true } });
    await expect(page.getByText("Recorded handoff").first()).toBeVisible();
    await expect(page.getByText("Verified handoff")).toHaveCount(0);
    await expect(page.getByText("Runs & Recorded Replay")).toBeVisible();
    await expect(page.getByText("Runs & Verified Replay")).toHaveCount(0);
  });

  test("replay: chain_valid bound to a DIFFERENT proposal renders Recorded, never Verified", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard()], evidenceExtra: { chain_valid: true, proposal_id: "DAO-PROP-UNRELATED" } });
    await expect(page.getByText("Recorded handoff").first()).toBeVisible();
    await expect(page.getByText("Verified handoff")).toHaveCount(0);
  });

  // Reviewer truth pass #2: the recording receipt chip previously rendered
  // the static DEFAULT_CASPER_DEPLOY_HASH literal. It must now carry a
  // validated, payload-derived receipt hash (verified CasperExecutionReceipt
  // with a 64-hex transaction hash) and never the literal.
  const PAYLOAD_RECEIPT_TX = "cafe".repeat(16);
  const boundVerifiedReceipt = (transactionHash = PAYLOAD_RECEIPT_TX, extraData = { receipt_verified: true }) => ({
    card_type: "CasperExecutionReceipt",
    sequence: 6,
    hash: "receipt-hash",
    data: {
      ...extraData,
      actions_taken: [{ action_id: "execute_casper_governance_receipt", status: "success", transaction_hash: transactionHash }],
      timeline: [],
    },
  });

  test("recording mode: unverified replay shows Recorded Run Replay and NO receipt chip", async ({ page }) => {
    await openWith(page, "/dashboard/runs?recording=1", { cards: [proposalCard(), planCard(), boundVerifiedReceipt()], evidenceExtra: { chain_valid: true } });
    await expect(page.getByText("Recorded Run Replay")).toBeVisible();
    await expect(page.getByText("Verified Run Replay")).toHaveCount(0);
    await expect(page.getByText("Casper receipt")).toHaveCount(0);
    await expect(page.getByText("Canonical receipt")).toHaveCount(0);
  });

  test("recording mode (MIGRATED positive control): the receipt chip carries the payload receipt hash, never the static literal", async ({ page }) => {
    await openWith(page, "/dashboard/runs?recording=1", { cards: [proposalCard(), planCard(), boundVerifiedReceipt()], evidenceExtra: { chain_valid: true, proposal_id: CANONICAL } });
    await expect(page.getByText("Verified Run Replay")).toBeVisible();
    await expect(page.locator(`a[href="https://testnet.cspr.live/deploy/${PAYLOAD_RECEIPT_TX}"]`).first()).toBeVisible();
    // The old static literal (constants DEFAULT_CASPER_DEPLOY_HASH) must
    // never appear as a receipt claim again.
    await expect(page.locator('a[href*="e926582f3dacd05d"]')).toHaveCount(0);
    await expect(page.getByText("Canonical receipt")).toHaveCount(0);
  });

  test("recording mode: a verified bound replay WITHOUT a payload receipt shows no receipt chip", async ({ page }) => {
    await openWith(page, "/dashboard/runs?recording=1", { cards: [proposalCard(), planCard()], evidenceExtra: { chain_valid: true, proposal_id: CANONICAL } });
    await expect(page.getByText("Verified Run Replay")).toBeVisible();
    await expect(page.getByText("Casper receipt")).toHaveCount(0);
    await expect(page.locator('a[href*="cspr.live/deploy"]')).toHaveCount(0);
  });

  test("recording mode: an UNVERIFIED payload receipt never renders the receipt chip", async ({ page }) => {
    await openWith(page, "/dashboard/runs?recording=1", { cards: [proposalCard(), planCard(), boundVerifiedReceipt(PAYLOAD_RECEIPT_TX, {})], evidenceExtra: { chain_valid: true, proposal_id: CANONICAL } });
    await expect(page.getByText("Casper receipt")).toHaveCount(0);
  });

  test("recording mode: a verified receipt with a NON-HEX transaction hash never renders the receipt chip", async ({ page }) => {
    await openWith(page, "/dashboard/runs?recording=1", { cards: [proposalCard(), planCard(), boundVerifiedReceipt("tx-hash")], evidenceExtra: { chain_valid: true, proposal_id: CANONICAL } });
    await expect(page.getByText("Casper receipt")).toHaveCount(0);
    await expect(page.locator('a[href*="cspr.live/deploy"]')).toHaveCount(0);
  });

  // Reviewer truth pass #2: execution/anchoring telemetry must use the SAME
  // bound replay predicate — a verified receipt alone (no bound valid chain)
  // must never claim "Execution verified" or "evidence chain valid".
  test("execution telemetry: a verified receipt WITHOUT a bound chain never claims Execution verified", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard(), boundVerifiedReceipt()], evidenceExtra: {} });
    await expect(page.getByText("Execution verified")).toHaveCount(0);
    await expect(page.getByText(/evidence chain valid/)).toHaveCount(0);
    await expect(page.getByText("Receipt recorded")).toBeVisible();
    await expect(page.getByText("Proposal → anchored")).toHaveCount(0);
  });

  test("execution telemetry: chain_valid bound to a DIFFERENT proposal never claims Execution verified", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard(), boundVerifiedReceipt()], evidenceExtra: { chain_valid: true, proposal_id: "DAO-PROP-UNRELATED" } });
    await expect(page.getByText("Execution verified")).toHaveCount(0);
    await expect(page.getByText(/evidence chain valid/)).toHaveCount(0);
  });

  test("positive control: a bound valid chain plus a verified receipt claims Execution verified", async ({ page }) => {
    await openWith(page, "/dashboard/runs", { cards: [proposalCard(), planCard(), boundVerifiedReceipt()], evidenceExtra: { chain_valid: true, proposal_id: CANONICAL } });
    await expect(page.getByText("Execution verified")).toBeVisible();
    await expect(page.getByText(/evidence chain valid/).first()).toBeVisible();
  });
});

test.describe("SOURCE regression: the four fail-open patterns are banned", () => {
  const read = (relative) => fs.readFileSync(path.join(componentsDir, relative), "utf8");

  test("OverviewPage.js has no static positive protocol/health cues", () => {
    const overview = read(path.join("pages", "OverviewPage.js"));
    // Observation-gated pills exist.
    expect(overview).toMatch(/gatewayOperational \? "Operational" : baseObserved \? "Reconnecting" : "Checking"/);
    expect(overview).toMatch(/roomConnected \? "Connected" : data\.roomError \? "Reconnecting" : "Checking"/);
    expect(overview).toMatch(/const gatewayOperational = baseObserved && !data\.baseError/);
    // Banned: the old delayed-flag-driven default-green pills.
    expect(overview).not.toMatch(/showBaseIssue \? "muted" : "success"/);
    expect(overview).not.toContain("showRoomIssue");
    expect(overview).not.toMatch(/tone=\{activeProposal && isActiveProposal\(activeProposal\) \? "warning" : "success"\}/);
    // Banned: the static LIVE chip; the chip must be observation-driven.
    expect(overview).not.toMatch(/\[\s*"CASPER TESTNET LIVE"/);
    expect(overview).toMatch(/casperLiveObserved \? "CASPER TESTNET LIVE"/);
    expect(overview).toMatch(/isCasperLiveReadComplete\(casperLiveRead\)/);
  });

  test("ProofCenterPage.js never falls back to CANONICAL_RECEIPT_FACTS as a verified receipt", () => {
    const proofCenter = read(path.join("pages", "ProofCenterPage.js"));
    // Banned: the old one-line fallback that fed the verified presentation.
    expect(proofCenter).not.toMatch(/const receipt = proof\?\.casper_receipt \|\| data\.evidence\?\.casper_receipt \|\| CANONICAL_RECEIPT_FACTS/);
    expect(proofCenter).not.toMatch(/title="Verified receipts"/);
    // The verified presentation is receiptIsLive-gated with a recorded fallback.
    expect(proofCenter).toMatch(/receiptIsLive \? "Verified receipts" : "Recorded receipts · historical"/);
    expect(proofCenter).toMatch(/const receiptIsLive = Boolean\(liveReceipt\)/);
  });

  test("ProofCenterPage.js compact rows cannot turn green from status === 'verified' alone", () => {
    const proofCenter = read(path.join("pages", "ProofCenterPage.js"));
    expect(proofCenter).not.toMatch(/=== "verified" \? "success"/);
    expect(proofCenter).toMatch(/const compactRowGreen = \(row\) =>/);
    expect(proofCenter).toMatch(/itemGreenVerified\(registryItem\)/);
    expect(proofCenter).toMatch(/findRegistryItemByProofId\(registry, row\?\.proof_id\)/);
  });

  test("presence-derived verified/complete labels are banned across the label families", () => {
    const lib = read("lib.js");
    expect(lib).not.toContain('return "Verified proposal replay"');
    expect(lib).not.toContain('"Verified workflow event"');
    expect(lib).not.toContain('"Safety review completed."');
    expect(lib).toMatch(/export function isDecidedVerdict\(card\)/);
    const overview = read(path.join("pages", "OverviewPage.js"));
    expect(overview).not.toMatch(/activeCandidate \? "Active proposal" : "Verified proposal replay"/);
    expect(overview).toMatch(/chain_valid === true \? "Verified proposal replay" : "Recorded proposal replay"/);
    expect(overview).not.toMatch(/\bverdict \? "Review complete"/);
    expect(overview).toMatch(/isDecidedVerdict\(verdict\) \? "Review complete"/);
    expect(overview).not.toContain('title="Recent verified runs"');
    const agents = read(path.join("pages", "AgentsPage.js"));
    expect(agents).not.toMatch(/getCard\(cards, "Verdict", true\) \? "Independent review complete"/);
    expect(agents).toMatch(/isDecidedVerdict\(verdictCard\) \? "Independent review complete"/);
    const shared = read("shared.js");
    expect(shared).not.toContain("Verified Casper run available");
    expect(shared).not.toContain(': "Verified run"');
    expect(shared).toContain("Recorded Casper run available");
    expect(shared).toContain("recorded June 2026");
    const replay = read(path.join("pages", "ReplayPage.js"));
    expect(replay).not.toContain(">Verified handoff · sequence");
    // Migrated pin: the gate is now replayVerified = chain_valid === true AND
    // payload-to-selected-proposal binding (strictly stronger than chainValid).
    expect(replay).toMatch(/replayVerified \? "Verified handoff" : "Recorded handoff"/);
    expect(replay).toMatch(/replayVerified \? "verified" : "recorded"/);
    expect(replay).toMatch(/replayVerified = chainValid && evidenceBound/);
  });

  test("lib.js isAuthorizedApproval requires the exact action binding on every surface", () => {
    const lib = read("lib.js");
    expect(lib).toMatch(/export function isApprovalBoundToAction\(card, planCard\)/);
    expect(lib).toMatch(/action_binding_hash/);
    expect(lib).toMatch(/isApprovalBoundToPlan\(card, planCard\)\s*&&\s*isApprovalBoundToAction\(card, planCard\)/);
    // The shared predicate remains the single authorization source for all four
    // surfaces (no page-local re-derivation crept back in).
    for (const file of [path.join("pages", "OverviewPage.js"), path.join("pages", "AgentsPage.js"), path.join("pages", "ProposalWorkspacePage.js"), path.join("pages", "ApprovalPage.js")]) {
      expect(read(file)).toContain("isAuthorizedApproval(");
    }
  });
});
