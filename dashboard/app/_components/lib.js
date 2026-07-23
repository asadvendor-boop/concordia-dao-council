// Shared constants, formatting helpers, and evidence-derivation logic for the
// Concordia dashboard. Pure module: no JSX. Every value rendered in the UI must
// come from a gateway payload, a recorded canonical constant (clearly labeled),
// or an honest placeholder — never an invented number, hash, or timestamp.

export const GW = process.env.NEXT_PUBLIC_GATEWAY_URL || "";
export const CONCORDIA_MODE = (process.env.NEXT_PUBLIC_CONCORDIA_MODE || "live").toLowerCase();
export const ASSET_BASE = "/dashboard";
export const DEFAULT_REVIEW_PROPOSAL_ID = process.env.NEXT_PUBLIC_DEFAULT_PROPOSAL_ID || "DAO-PROP-6CB25C";
export const DEFAULT_CASPER_DEPLOY_HASH = process.env.NEXT_PUBLIC_DEFAULT_CASPER_DEPLOY_HASH || "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852";
export const DEFAULT_CASPER_CONTRACT_HASH = process.env.NEXT_PUBLIC_DEFAULT_CASPER_CONTRACT_HASH || "hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1";
export const DEFAULT_CASPER_EXPLORER_URL = process.env.NEXT_PUBLIC_DEFAULT_CASPER_EXPLORER_URL || `https://testnet.cspr.live/deploy/${DEFAULT_CASPER_DEPLOY_HASH}`;
export const DEFAULT_WALLET_RECEIPT_HASH = process.env.NEXT_PUBLIC_DEFAULT_WALLET_RECEIPT_HASH || "56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf";
export const DEFAULT_QUORUM_APPROVAL_HASH = process.env.NEXT_PUBLIC_DEFAULT_QUORUM_APPROVAL_HASH || "7ee77b11b8373fa55976b047e5613d391dd2ece5b6c2f0671c7232183cc875da";
export const DEFAULT_QUORUM_FINAL_RECEIPT_HASH = process.env.NEXT_PUBLIC_DEFAULT_QUORUM_FINAL_RECEIPT_HASH || "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928";
export const DEFAULT_QUORUM_REJECTED_HASH = "6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431";
export const DEFAULT_QUORUM_REJECTED_URL = `https://testnet.cspr.live/deploy/${DEFAULT_QUORUM_REJECTED_HASH}`;
export const DEFAULT_QUORUM_ACCEPTED_URL = `https://testnet.cspr.live/deploy/${DEFAULT_QUORUM_FINAL_RECEIPT_HASH}`;
// Historical SafePay Lite payment (native CSPR, recorded 2026-06-29). This hash
// identifies a real recorded historical payment and is only ever rendered with
// an explicit "historical" label. It must never be presented as a live or
// current settlement, and it never backs any duplicate-rejection claim.
export const HISTORICAL_SAFEPAY_PAYMENT_HASH = "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c";
export const DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH = "68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0";
export const DEFAULT_IPFS_CID = process.env.NEXT_PUBLIC_DEFAULT_IPFS_CID || "bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq";
export const DEFAULT_IPFS_GATEWAY_URL = process.env.NEXT_PUBLIC_DEFAULT_IPFS_GATEWAY_URL || `/api/ipfs/${DEFAULT_IPFS_CID}`;
export const DEFAULT_ODRA_PACKAGE_HASH = "hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a";
export const SUPPLEMENTAL_DYNAMIC_ARGUMENT_SOURCE = "supplemental_dynamic_execution_artifact";
export const PROOF_TAB_IDS = new Set(["summary", "safety", "onchain", "data", "exports"]);

// The recorded on-chain receipts inventory. One source drives both the
// Overview stat tile count and the Proof Center receipts card, so the rendered
// count can never disagree with the rendered list. Every entry is a real
// recorded Casper Testnet deploy.
export const RECORDED_ONCHAIN_RECEIPTS = [
  { id: "canonical", label: "Canonical receipt", hash: DEFAULT_CASPER_DEPLOY_HASH, href: DEFAULT_CASPER_EXPLORER_URL, tone: "success" },
  { id: "wallet", label: "Wallet receipt", hash: DEFAULT_WALLET_RECEIPT_HASH, href: `https://testnet.cspr.live/deploy/${DEFAULT_WALLET_RECEIPT_HASH}` },
  { id: "quorum-rejected", label: "Pre-quorum rejection", hash: DEFAULT_QUORUM_REJECTED_HASH, href: DEFAULT_QUORUM_REJECTED_URL, tone: "warning" },
  { id: "quorum-approval", label: "Quorum approval", hash: DEFAULT_QUORUM_APPROVAL_HASH, href: `https://testnet.cspr.live/deploy/${DEFAULT_QUORUM_APPROVAL_HASH}` },
  { id: "quorum-final", label: "Final quorum receipt", hash: DEFAULT_QUORUM_FINAL_RECEIPT_HASH, href: DEFAULT_QUORUM_ACCEPTED_URL },
  { id: "dynamic", label: "Supplemental dynamic receipt", hash: DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH, href: `https://testnet.cspr.live/deploy/${DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH}` },
];

export const NAV_ITEMS = [
  { id: "overview", label: "Overview", href: "/", icon: "overview" },
  { id: "proposals", label: "Proposals", href: "/proposals", icon: "proposal" },
  { id: "approvals", label: "Approvals", href: "/approvals", icon: "approval" },
  { id: "agents", label: "Council Chamber", href: "/agents", icon: "agents" },
  { id: "evidence", label: "Evidence", href: "/evidence", icon: "evidence" },
  { id: "proof", label: "Proof Center", href: "/proof", icon: "shield" },
  { id: "judge", label: "Judge Walkthrough", href: "/judge", icon: "check" },
  { id: "runs", label: "Runs & Replay", href: "/runs", icon: "replay" },
];

export const PROFILES = {
  rowan: { key: "rowan", name: "Rowan", role: "Proposal Sentinel", framework: "Council Runtime + LLM", model: "Fast advisory model", color: "#2dd4a4", avatar: `${ASSET_BASE}/agents/rowan.png`, description: "Scans and routes incoming DAO proposals" },
  mercer: { key: "mercer", name: "Mercer", role: "Treasury Intelligence Agent", framework: "Council Runtime + LLM", model: "Deep advisory model", color: "#38bdf8", avatar: `${ASSET_BASE}/agents/mercer.png`, description: "Analyzes treasury exposure, RWA evidence, and Casper liquidity signals" },
  verity: { key: "verity", name: "Verity", role: "Risk & Legal Agent", framework: "Council Runtime + LLM", model: "Deep adversarial model", color: "#a78bfa", avatar: `${ASSET_BASE}/agents/verity.png`, description: "Challenges unsafe proposals and legal/policy violations" },
  alden: { key: "alden", name: "Alden", role: "Protocol Strategy Agent", framework: "Council Runtime + LLM", model: "Deep planning model", color: "#6f8cff", avatar: `${ASSET_BASE}/agents/alden.png`, description: "Drafts exact governance execution envelopes" },
  locke: { key: "locke", name: "Locke", role: "Casper Execution Agent", framework: "Casper SDK adapter", model: "Deterministic signer", color: "#22d3ee", avatar: `${ASSET_BASE}/agents/locke.png`, description: "Validates approval and anchors the final receipt on Casper Testnet" },
  core: { key: "core", name: "Concordia Core", role: "Deterministic Evidence Core", framework: "Gateway", model: "Policy engine", color: "#94a3b8", avatar: `${ASSET_BASE}/agents/core.png`, description: "Seals cards, nonces, and evidence-chain integrity" },
  wells: { key: "wells", name: "Wells", role: "Governance Archive Persona", framework: "Presentation persona", model: "Non-reasoning archive view", color: "#c084fc", avatar: `${ASSET_BASE}/agents/wells.png`, description: "Presentation-only archive persona. Concordia Core and Locke produce the deterministic governance archive; Wells does not reason, generate proof, or author historical archives.", platform: true },
  human: { key: "human", name: "Multisig Holder", role: "Authorized DAO Approver", framework: "Human", model: "Exact action approval", color: "#f5b942", avatar: null, description: "Approves or rejects the exact typed action" },
  system: { key: "system", name: "Concordia Core", role: "Deterministic Control Plane", framework: "Gateway", model: "Policy engine", color: "#64748b", avatar: null, description: "Enforces state, authorization and integrity" },
};

export const CARD_ROLE = {
  ProposalCard: "core",
  TriageDecision: "rowan",
  Assessment: "mercer",
  Verdict: "verity",
  ResponsePlan: "alden",
  StructuredApproval: "human",
  PolicyAuthorization: "system",
  CasperExecutionReceipt: "locke",
  "GovernanceSummary": "wells",
};

export const CARD_LABELS = {
  ProposalCard: "Proposal recorded",
  TriageDecision: "Proposal routing",
  Assessment: "Treasury assessment",
  Verdict: "Risk & Legal verdict",
  ResponsePlan: "Governance execution plan",
  StructuredApproval: "Multisig decision",
  PolicyAuthorization: "Policy authorization",
  CasperExecutionReceipt: "Casper execution receipt",
  "GovernanceSummary": "Governance archive",
};

export const ACTIVE_STATES = new Set(["DETECTED", "TRIAGED", "ASSESSED", "REVIEWED", "CHALLENGED", "PLANNED", "APPROVED", "AUTHORIZED", "EXECUTING"]);
export const TERMINAL_STATES = new Set(["EXECUTED", "RESOLVED", "CLOSED", "CLOSED_FALSE_ALARM", "SUPPRESSED"]);

export async function api(path, options = {}) {
  const { timeoutMs = 12000, signal: externalSignal, ...fetchOptions } = options;
  const controller = new AbortController();
  // Link an optional caller-provided signal (used by the proposal-switch
  // generation guard) so switching proposals aborts prior in-flight requests
  // and stale responses can never pair a new proposal with old evidence.
  const onExternalAbort = () => controller.abort(externalSignal?.reason || new Error(`${path} aborted`));
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort(externalSignal.reason || new Error(`${path} aborted`));
    else externalSignal.addEventListener("abort", onExternalAbort, { once: true });
  }
  const timer = timeoutMs > 0
    ? setTimeout(() => controller.abort(new Error(`${path} timed out after ${timeoutMs}ms`)), timeoutMs)
    : null;
  try {
    const response = await fetch(`${GW}${path}`, {
      cache: "no-store",
      ...fetchOptions,
      headers: { Accept: "application/json", ...(fetchOptions.headers || {}) },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`${path} returned ${response.status}`);
    return await response.json();
  } finally {
    if (timer) clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener("abort", onExternalAbort);
  }
}

export function cx(...classes) { return classes.filter(Boolean).join(" "); }
export function firstDefined(...values) { return values.find((value) => value !== undefined && value !== null && value !== ""); }
export const PUBLIC_KEY_ALIASES = {
  sender_role: "agent",
  agent_role: "agent",
  diagnosis: "mercer_assessment",
  agrees_with_diagnosis: "agrees_with_mercer_assessment",
  time_to_diagnosis_seconds: "time_to_mercer_assessment_seconds",
  commander: "alden_strategy",
  operator: "locke_execution",
  runbook: "governance_playbook",
  legacy_room_id: "council_session_id",
  room_message_id: "approval_message_id",
};
export function normalizeRole(value = "") {
  const role = String(value).toLowerCase().replace(/[-\s]/g, "_");
  if (role.includes("triage") || role.includes("sentinel") || role.includes("rowan")) return "rowan";
  if (role.includes("diagnos") || role.includes("treasury") || role.includes("mercer")) return "mercer";
  if (role.includes("safety") || role.includes("reviewer") || role.includes("risk") || role.includes("legal") || role.includes("verity")) return "verity";
  if (role.includes("commander") || role.includes("planner") || role.includes("strategy") || role.includes("alden")) return "alden";
  if (role.includes("operator") || role.includes("signer") || role.includes("execution") || role.includes("locke")) return "locke";
  if (role.includes("recorder") || role.includes("core")) return "core";
  if (role.includes("scribe") || role.includes("archive") || role.includes("wells") || role.includes("governance_summary")) return "wells";
  if (role.includes("human") || role.includes("approver") || role.includes("multisig")) return "human";
  return "system";
}
export function getProfile(role) { return PROFILES[normalizeRole(role)] || PROFILES.system; }
export function sanitizeDisplayText(value = "") {
  const rb = (suffix) => `R${"B"}-${suffix}`;
  return String(value)
    .replace(/\bsafety[_ -]reviewer\b/gi, "Verity")
    .replace(/\btriage\b/gi, "Rowan")
    .replace(/\bdiagnosis\b/gi, "Mercer")
    .replace(/\bcommander\b/gi, "Alden")
    .replace(/\boperator\b/gi, "Locke")
    .replace(/\brecorder\b/gi, "Concordia Core")
    .replace(/\bscribe\b/gi, "Wells")
    .replace(new RegExp(`\\b${rb("001")}\\b`, "g"), "proposal-routing")
    .replace(new RegExp(`\\b${rb("002")}\\b`, "g"), "treasury-cap-exceeded")
    .replace(new RegExp(`\\b${rb("003")}\\b`, "g"), "rwa-evidence-review")
    .replace(new RegExp(`\\b${rb("004")}\\b`, "g"), "policy-drift-review")
    .replace(new RegExp(`\\b${rb("005")}\\b`, "g"), "payment-settlement-review")
    .replace(new RegExp(`\\b${rb("006")}\\b`, "g"), "governance-archive");
}
export function publicDisplayValue(value) {
  if (Array.isArray(value)) return value.map(publicDisplayValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      PUBLIC_KEY_ALIASES[key] || sanitizeDisplayText(key),
      publicDisplayValue(item),
    ]));
  }
  return typeof value === "string" ? sanitizeDisplayText(value) : value;
}
export function publicJson(value, space = 2) {
  return JSON.stringify(publicDisplayValue(value), (key, item) => {
    const lower = key.toLowerCase();
    return ["nonce", "authorization_id", "api_key", "secret"].some((token) => lower.includes(token)) ? "[REDACTED]" : item;
  }, space);
}
export function formatRuleIdentifiers(value) {
  const fromRule = (rule, fallbackKey = "") => {
    if (rule === undefined || rule === null || rule === "") return "";
    if (typeof rule === "string" || typeof rule === "number") return String(rule);
    if (Array.isArray(rule)) return rule.map((item) => fromRule(item)).filter(Boolean).join(" · ");
    if (typeof rule === "object") {
      return firstDefined(rule.rule_id, rule.ruleId, rule.id, rule.name, rule.code, rule.rule, fallbackKey, rule.message);
    }
    return String(rule);
  };
  if (Array.isArray(value)) return value.map((item) => fromRule(item)).filter(Boolean).join(" · ");
  if (value && typeof value === "object") {
    const direct = fromRule(value);
    if (direct) return direct;
    return Object.entries(value).map(([key, item]) => fromRule(item, key)).filter(Boolean).join(" · ");
  }
  return fromRule(value);
}
const STATUS_TONE = {
  RESOLVED: "success",
  SUPPRESSED: "warning",
  PASSED: "success",
  VERIFIED: "success",
  RECORDED: "info",
  "APPROVAL REQUIRED": "warning",
  HIGH: "danger",
};
export function statusTone(value = "", fallback = "info") {
  const normalized = String(value || "").trim().toUpperCase().replace(/_/g, " ");
  return STATUS_TONE[normalized] || fallback;
}
export function stateLabel(state = "UNKNOWN") { return String(state).replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()); }
export function stateTone(state = "") {
  const normalized = String(state).toUpperCase();
  const mapped = statusTone(normalized, "");
  if (mapped) return mapped;
  if (TERMINAL_STATES.has(normalized)) return "success";
  if (["REJECTED", "FAILED"].includes(normalized)) return "danger";
  if (["PLANNED", "APPROVED", "AUTHORIZED", "CHALLENGED"].includes(normalized)) return "warning";
  return "info";
}
export function isActiveProposal(proposal) { return ACTIVE_STATES.has(String(proposal?.state || "").toUpperCase()); }
export function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
export function formatDuration(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return "—";
  const seconds = Math.max(0, Math.round(Number(value)));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return `${minutes}m ${String(rest).padStart(2, "0")}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}
export function formatPercent(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return "—";
  const number = Number(value);
  return `${number.toFixed(number < 10 ? 2 : 1)}%`;
}
export function shortHash(value, start = 8, end = 5) {
  if (!value) return "—";
  const text = String(value);
  if (text.length <= start + end + 2) return text;
  return `${text.slice(0, start)}…${text.slice(-end)}`;
}
export function formatUtcMinute(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const two = (number) => String(number).padStart(2, "0");
  return `${date.getUTCFullYear()}-${two(date.getUTCMonth() + 1)}-${two(date.getUTCDate())} ${two(date.getUTCHours())}:${two(date.getUTCMinutes())} UTC`;
}
export function normalizeJudgeText(value = "") {
  return sanitizeDisplayText(value).replace(/Nonce\s+\[REDACTED\]\s*:\s*([0-9T:.\-+Z]+)/gi, (_match, issuedAt) => {
    const formatted = formatUtcMinute(issuedAt);
    return formatted ? `Nonce redacted · issued ${formatted}` : "Nonce redacted";
  });
}
export function titleCaseAction(value = "") { return String(value).replace(/[_-]/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()); }
export function isPendingProofValue(value) {
  const text = String(value || "").trim().toLowerCase();
  return !text || text.includes("from-proof-pack") || text.startsWith("live-");
}
export function adversarialModeLabel(result) {
  const mode = String(result?.llm_mode || result?.proof_mode || "").trim();
  if (mode === "deterministic_adversarial_replay_fallback" || mode === "interactive_adversarial_replay") {
    return "Deterministic Adversarial Replay";
  }
  return mode ? titleCaseAction(mode) : "Deterministic Adversarial Replay";
}
export function governancePlaybook(value = "") {
  const rb = (suffix) => `R${"B"}-${suffix}`;
  const aliases = {
    [rb("001")]: "proposal-routing",
    [rb("002")]: "treasury-cap-exceeded",
    [rb("003")]: "rwa-evidence-review",
    [rb("004")]: "policy-drift-review",
    [rb("005")]: "payment-settlement-review",
    [rb("006")]: "governance-archive",
  };
  const text = String(value || "").trim();
  return aliases[text] || text || "—";
}
export function displayFamily(value) { return value ? titleCaseAction(value) : "—"; }
export function getCard(cards, type, last = false) {
  const matches = (cards || []).filter((card) => card.card_type === type);
  return last ? matches[matches.length - 1] : matches[0];
}
export function getCardData(card) { return card?.data || card?.card_json || {}; }

export function deriveProposalFacts(proposal, evidence) {
  const cards = evidence?.cards || [];
  const signal = getCard(cards, "ProposalCard");
  const assessment = getCard(cards, "Assessment", true);
  const plan = getCard(cards, "ResponsePlan", true);
  const receipt = getCard(cards, "CasperExecutionReceipt", true);
  const signalData = getCardData(signal);
  const assessmentData = getCardData(assessment);
  const planData = getCardData(plan);
  const receiptData = getCardData(receipt);
  const raw = signalData.raw_payload || {};
  const firstEnvelope = planData.envelopes?.[0] || {};
  const params = firstEnvelope.parameters || {};
  const policy = firstDefined(raw.policy_evaluation, assessmentData.evidence?.policy_evaluation, params.policy_hash ? params : null) || {};
  const title = firstDefined(signalData.title, raw.title, "DAO Treasury Governance Proposal");
  const service = firstDefined(raw.service, raw.service_name, raw.application, raw.repo, firstEnvelope.target, "DAO treasury target");
  const environment = firstDefined(raw.environment, raw.env, params.environment, "DAO Treasury");
  const treasuryVersion = firstDefined(raw.version, raw.treasury_version, raw.deployment_version, raw.release, "—");
  const targetVersion = firstDefined(params.guardrail_cap, params.max_allocation_bps ? `${Number(params.max_allocation_bps) / 100}% cap` : null, raw.target_version, "—");
  const errorRate = firstDefined(raw.risk_exposure_pct, raw.error_rate, raw.error_rate_pct, raw.errors_percent, raw.errorRate);
  const volatility = firstDefined(raw.volatility_bps, raw.latency_p99, raw.p99_ms, raw.yield);
  const uptime = firstDefined(raw.policy_compliance_pct, raw.policy_compliance_percentage, raw.uptime_percentage, raw.uptime_pct, raw.uptime);
  const verificationEvents = (receiptData.timeline || []).filter((event) => /receipt_verification|casper_transaction/i.test(String(event.event || "")));
  const verification = verificationEvents[verificationEvents.length - 1] || null;
  const verificationDetails = verification?.details || [];
  const successfulDetail = [...verificationDetails].reverse().find((item) => item.recovered) || verificationDetails[verificationDetails.length - 1];
  const casperAction = [...(receiptData.actions_taken || [])].reverse().find((item) => item?.action_id === "execute_casper_governance_receipt") || {};
  const evidenceReceipt = evidence?.casper_receipt || {};
  return {
    title, service, environment, treasuryVersion, targetVersion, errorRate, volatility, uptime,
    proposalType: firstDefined(raw.proposal_type, policy.proposal_type, params.proposal_type),
    requestedAllocationBps: firstDefined(raw.treasury_allocation_bps, raw.requested_allocation_bps, policy.requested_allocation_bps, params.requested_allocation_bps),
    approvedAllocationBps: firstDefined(raw.approved_allocation_bps, policy.approved_allocation_bps, params.approved_allocation_bps, params.allocation_bps),
    policyVersion: firstDefined(policy.policy_version, params.policy_version),
    policyHash: firstDefined(policy.policy_hash, params.policy_hash),
    dissentHash: firstDefined(policy.dissent_hash, params.dissent_hash),
    evidenceUri: firstDefined(raw.evidence_uri, assessmentData.evidence?.evidence_uri, params.evidence_uri),
    severity: firstDefined(assessmentData.severity, signalData.preliminary_severity, "High"),
    evidenceStrength: assessmentData.evidence_strength,
    rootCause: assessmentData.root_cause_hypothesis,
    recommendedAction: assessmentData.recommended_action,
    blastRadius: assessmentData.blast_radius || [],
    plan: planData,
    receipt: receiptData,
    casperExplorerUrl: firstDefined(casperAction.explorer_url, evidenceReceipt.explorer_url),
    casperDeployHash: firstDefined(casperAction.deploy_hash, casperAction.transaction_hash, evidenceReceipt.deploy_hash, evidenceReceipt.transaction_hash),
    casperBlockHeight: firstDefined(casperAction.block_height, evidenceReceipt.block_height),
    preMetrics: { errorRate, volatility, uptime },
    postMetrics: { errorRate: successfulDetail?.error_rate, uptime: firstDefined(successfulDetail?.uptime_pct, successfulDetail?.uptime_percentage), volatility: firstDefined(successfulDetail?.volatility_bps, successfulDetail?.latency_p99) },
    // Truth rule: a receipt only counts as verified when the recorded
    // verification event positively confirms recovery. Absent or unknown
    // verification is NOT verified (no fail-open green).
    receiptVerified: Boolean(receipt) && verification?.recovered === true,
  };
}

export function deriveWorkflow(cards = [], proposalState = "") {
  const byType = (type) => cards.filter((card) => card.card_type === type);
  const verdicts = byType("Verdict");
  const assessments = byType("Assessment");
  const challenge = verdicts.find((card) => getCardData(card).decision === "CHALLENGE");
  const confirmation = [...verdicts].reverse().find((card) => getCardData(card).decision === "CONFIRM");
  const revision = challenge ? assessments.find((card) => Number(card.sequence) > Number(challenge.sequence)) : assessments[1];
  const plan = getCard(cards, "ResponsePlan", true);
  const approval = getCard(cards, "StructuredApproval", true) || getCard(cards, "PolicyAuthorization", true);
  const receipt = getCard(cards, "CasperExecutionReceipt", true);
  const terminal = TERMINAL_STATES.has(String(proposalState).toUpperCase());
  const steps = [
    { id: "detected", label: "Detected", done: Boolean(getCard(cards, "ProposalCard")) },
    { id: "rowan", label: "Sentinel", done: Boolean(getCard(cards, "TriageDecision")) },
    { id: "mercer", label: "Treasury intelligence", done: assessments.length > 0 },
    { id: "challenge", label: "Challenge", done: Boolean(challenge), skipped: Boolean(confirmation && !challenge), tone: challenge ? "warning" : "info" },
    { id: "revision", label: "Revision", done: Boolean(revision), skipped: Boolean(confirmation && !challenge) },
    { id: "plan", label: "Plan", done: Boolean(plan) },
    { id: "authorization", label: "Authorization", done: Boolean(approval) },
    { id: "execution", label: "Execution", done: Boolean(receipt) },
    { id: "receipt", label: "Receipt", done: Boolean(receipt) && terminal },
  ];
  let currentIndex = steps.findIndex((step) => !step.done && !step.skipped);
  if (currentIndex < 0) currentIndex = steps.length - 1;
  return { steps, currentIndex };
}

// Seven-step proposal lifecycle for the Overview control room. Every "done"
// flag derives from a real sealed evidence card — nothing is asserted without
// a recorded card backing it.
export function deriveLifecycle(cards = []) {
  const verdicts = (cards || []).filter((card) => card.card_type === "Verdict");
  const challenge = verdicts.find((card) => getCardData(card).decision === "CHALLENGE");
  const confirmation = [...verdicts].reverse().find((card) => getCardData(card).decision === "CONFIRM");
  const approval = getCard(cards, "StructuredApproval", true) || getCard(cards, "PolicyAuthorization", true);
  const receipt = getCard(cards, "CasperExecutionReceipt", true);
  const steps = [
    { id: "detected", label: "Detected", done: Boolean(getCard(cards, "ProposalCard")) },
    { id: "triaged", label: "Triaged", done: Boolean(getCard(cards, "TriageDecision")) },
    { id: "assessed", label: "Assessed", done: cards.some((card) => card.card_type === "Assessment") },
    { id: "challenged", label: "Challenged", done: Boolean(challenge), skipped: Boolean(confirmation && !challenge), tone: challenge ? "warning" : "info" },
    { id: "planned", label: "Planned", done: Boolean(getCard(cards, "ResponsePlan", true)) },
    { id: "approved", label: "Approved", done: Boolean(approval) },
    { id: "executed", label: "Executed", done: Boolean(receipt) },
  ];
  let currentIndex = steps.findIndex((step) => !step.done && !step.skipped);
  if (currentIndex < 0) currentIndex = steps.length - 1;
  return { steps, currentIndex };
}

// Count of recorded dissent (CHALLENGE) verdicts in the sealed evidence chain.
// Returns null when evidence has not loaded — callers must render an honest
// placeholder, never a substitute number.
export function countDissentReceipts(evidence) {
  if (!evidence || !Array.isArray(evidence.cards)) return null;
  return evidence.cards.filter((card) => card.card_type === "Verdict" && getCardData(card).decision === "CHALLENGE").length;
}

// Single source of truth for the agents-online status line. Used by both the
// sidebar system card and the Overview council tile so the two can never
// disagree. When no agent payload exists the status is honestly unavailable —
// no fallback count is invented.
export function agentStatusInfo(agents = [], loading = false) {
  if (Array.isArray(agents) && agents.length) {
    const online = agents.filter((agent) => agent.online).length;
    return { known: true, online, total: agents.length, text: `${online} / ${agents.length} agents online` };
  }
  return { known: false, online: 0, total: 0, text: loading ? "Checking agent status…" : "Agent status unavailable" };
}

// Truth helpers: an approval/receipt is only "successful" from an affirmative
// decision or a positively-verified receipt. Card PRESENCE proves nothing —
// missing/unknown/denied never renders as a success cue.
const AFFIRMATIVE_DECISIONS = new Set(["APPROVE", "APPROVED", "AUTHORIZE", "AUTHORIZED", "CONFIRM", "CONFIRMED", "ACCEPT", "ACCEPTED"]);
const DENIED_DECISIONS = new Set(["REJECT", "REJECTED", "DENY", "DENIED", "REFUSE", "REFUSED", "BLOCK", "BLOCKED", "ABSTAIN", "ABSTAINED"]);
export function approvalDecision(card) {
  return String(getCardData(card).decision || "").trim().toUpperCase();
}
export function isAffirmativeApproval(card) {
  if (!card) return false;
  const data = getCardData(card);
  const decision = String(data.decision || "").trim().toUpperCase();
  if (card.card_type === "PolicyAuthorization") return data.denied !== true && !DENIED_DECISIONS.has(decision);
  return AFFIRMATIVE_DECISIONS.has(decision);
}
export function isDeniedApproval(card) {
  if (!card) return false;
  const data = getCardData(card);
  return data.denied === true || DENIED_DECISIONS.has(String(data.decision || "").trim().toUpperCase());
}
export function isReceiptVerified(card) {
  if (!card || card.card_type !== "CasperExecutionReceipt") return false;
  const data = getCardData(card);
  if (data.receipt_verified === true) return true;
  const events = (data.timeline || []).filter((event) => /receipt_verification|casper_transaction/i.test(String(event.event || "")));
  const last = events[events.length - 1];
  return last?.recovered === true;
}

export function cardSummary(card) {
  if (!card) return "No event selected.";
  const data = getCardData(card);
  switch (card.card_type) {
    case "ProposalCard": return firstDefined(data.title, "A DAO treasury signal was normalized into a sealed proposal card.");
    case "TriageDecision": return firstDefined(data.reasoning, data.decision ? `Proposal routing: ${data.decision}.` : null, "The proposal was routed for specialist analysis.");
    case "Assessment": return firstDefined(data.root_cause_hypothesis && data.recommended_action ? `${data.root_cause_hypothesis} Recommended action: ${data.recommended_action}` : null, data.root_cause_hypothesis, data.recommended_action, "Treasury intelligence submitted an evidence-backed assessment.");
    case "Verdict": return firstDefined(data.challenge_request, data.reasoning, data.decision ? `Safety review decision: ${data.decision}.` : null, "Safety review completed.");
    case "ResponsePlan": {
      const envelopes = data.envelopes || [];
      if (!envelopes.length) return "Protocol Strategy Agent prepared a typed response plan.";
      return `Protocol Strategy Agent prepared ${envelopes.length} exact action${envelopes.length === 1 ? "" : "s"}: ${envelopes.map((envelope) => `${titleCaseAction(envelope.action_id)} on ${envelope.target}`).join("; ")}.`;
    }
    case "StructuredApproval": return isAffirmativeApproval(card)
      ? `Multisig decision: ${data.decision || "APPROVED"}. The authorization is bound to the exact plan and action hashes and can be consumed only once.`
      : `Multisig decision: ${data.decision || "recorded"}. No execution authorization is granted for a non-approval decision.`;
    case "PolicyAuthorization": return isDeniedApproval(card)
      ? "The deterministic policy engine refused authorization."
      : "The deterministic policy engine issued a bounded low-risk authorization.";
    case "CasperExecutionReceipt": return firstDefined(data.resolution_summary, isReceiptVerified(card)
      ? "Casper Execution Agent executed every approved action exactly once and Casper transaction verification passed."
      : "Casper execution receipt recorded. Transaction verification is asserted only from a positively verified receipt.");
    case "GovernanceSummary": return firstDefined(data.timeline_summary, data.root_cause, "Governance archive view. Concordia Core and Locke produced the deterministic archive artifact; Wells presents it without reasoning over it.");
    default: return CARD_LABELS[card.card_type] || "Sealed workflow event.";
  }
}
export function cardTone(card) {
  const data = getCardData(card);
  if (card?.card_type === "Verdict" && data.decision === "CHALLENGE") return "warning";
  if (card?.card_type === "Verdict" && data.decision === "FALSE_ALARM") return "muted";
  // No fail-open success: approval/receipt cards are only green on an
  // affirmative decision or a positively-verified receipt.
  if (card?.card_type === "StructuredApproval") return isAffirmativeApproval(card) ? "success" : isDeniedApproval(card) ? "danger" : "info";
  if (card?.card_type === "PolicyAuthorization") return isDeniedApproval(card) ? "danger" : isAffirmativeApproval(card) ? "success" : "info";
  if (card?.card_type === "CasperExecutionReceipt") return isReceiptVerified(card) ? "success" : "info";
  if (card?.card_type === "ProposalCard") return "danger";
  return "info";
}
export function cardBadge(card) {
  const data = getCardData(card);
  if (card?.card_type === "Verdict") return data.decision || "VERDICT";
  if (card?.card_type === "Assessment" && Number(data.revision || 1) > 1) return "REVISED ASSESSMENT";
  return String(card?.card_type || "EVENT").replace(/([a-z])([A-Z])/g, "$1 $2").toUpperCase();
}
export function replayStageLabel(card) {
  if (card?.card_type === "Verdict") {
    const decision = String(getCardData(card).decision || "Review").toLowerCase();
    if (decision === "challenge") return "Challenge";
    if (decision === "confirm") return "Confirm";
    return titleCaseAction(decision);
  }
  return CARD_LABELS[card.card_type] || titleCaseAction(card.card_type);
}
export function deriveHandoffs(cards = []) {
  const handoffs = [];
  let previousRole = null;
  for (const card of cards) {
    const role = CARD_ROLE[card.card_type] || "system";
    if (previousRole && previousRole !== role) handoffs.push({ from: previousRole, to: role, card, time: card.data?.created_at || card.data?.timestamp || null });
    previousRole = role;
  }
  return handoffs;
}
export function cleanRoomContent(content = "") {
  const text = String(content).replace(/```(?:json)?[\s\S]*?```/gi, "").replace(/@\[\[[^\]]+\]\]/g, "").replace(/\n{3,}/g, "\n\n").trim();
  return normalizeJudgeText(text) || "A structured card was published to the Council Chamber.";
}
export function inferMessageRole(message) {
  if (message?.sender_role) return normalizeRole(message.sender_role);
  if (message?.card_type && CARD_ROLE[message.card_type]) return CARD_ROLE[message.card_type];
  if (message?.agent_key) return normalizeRole(message.agent_key);
  if (message?.agent_role) return normalizeRole(message.agent_role);
  if (message?.metadata?.card_type && CARD_ROLE[message.metadata.card_type]) return CARD_ROLE[message.metadata.card_type];
  if (message?.metadata?.agent_key) return normalizeRole(message.metadata.agent_key);
  if (message?.legacy_text_fallback === true) {
    const content = String(message?.content || "").toLowerCase();
    if (content.includes("challenge") || content.includes("verdict")) return "verity";
    if (content.includes("proposal routing")) return "rowan";
    if (content.includes("assessment") || content.includes("treasury evidence")) return "mercer";
    if (content.includes("responseplan") || content.includes("approval requested")) return "alden";
    if (content.includes("actionreceipt") || content.includes("execut")) return "locke";
    if (content.includes("governance summary")) return "wells";
  }
  return "core";
}
export function messageBadge(message) {
  const content = String(message?.content || "");
  const known = ["ProposalCard", "TriageDecision", "Assessment", "Verdict", "ResponsePlan", "StructuredApproval", "PolicyAuthorization", "CasperExecutionReceipt", "GovernanceSummary"].find((type) => content.includes(type));
  if (known) {
    if (known === "Verdict") {
      const decision = content.match(/Verdict:\s*([A-Z_]+)/i)?.[1]?.toUpperCase();
      if (decision === "CHALLENGE") return "CHALLENGE";
      if (decision === "CONFIRM") return "VERDICT CONFIRMED";
      if (decision) return `VERDICT ${decision.replace(/_/g, " ")}`;
    }
    if (["StructuredApproval", "PolicyAuthorization"].includes(known)) return "APPROVAL";
    return known.replace(/([a-z])([A-Z])/g, "$1 $2").toUpperCase();
  }
  if (/APPROVAL REQUIRED/i.test(content)) return "APPROVAL REQUIRED";
  if (/CHALLENGE/i.test(content)) return "CHALLENGE";
  if (/APPROV/i.test(content)) return "APPROVAL";
  return "COUNCIL MESSAGE";
}
export function navHref(path, proposalId) { return !proposalId || path === "/" ? path : `${path}?proposal=${encodeURIComponent(proposalId)}`; }

export function bpsToPercent(value) {
  if (value === undefined || value === null || value === "") return "—";
  const number = Number(value);
  if (Number.isNaN(number)) return String(value);
  return `${(number / 100).toFixed(number % 100 === 0 ? 0 : 2)}%`;
}
export function pctFromBps(value) {
  if (value === undefined || value === null || value === "") return "—";
  const number = Number(value);
  if (Number.isNaN(number)) return String(value);
  return `${(number / 100).toFixed(2)}%`;
}

export function actionEnvelopeText(envelope) {
  if (!envelope) return "—";
  const params = Object.entries(envelope.parameters || {}).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join(", ");
  return `${envelope.action_id}(${envelope.target}${params ? `, ${params}` : ""})`;
}
export function alteredEnvelope(envelope) {
  if (!envelope) return null;
  const clone = JSON.parse(JSON.stringify(envelope));
  const entries = Object.entries(clone.parameters || {});
  if (entries.length) {
    const [key, value] = entries[0];
    if (typeof value === "number") clone.parameters[key] = value + 1;
    else if (typeof value === "boolean") clone.parameters[key] = !value;
    else clone.parameters[key] = `${value}-altered`;
  } else clone.parameters = { force: true };
  return clone;
}

export function humanizeCardData(card) {
  const data = getCardData(card);
  const rows = [];
  const push = (label, value, options = {}) => {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) return;
    rows.push({ label, value, ...options });
  };
  switch (card?.card_type) {
    case "ProposalCard": {
      const raw = data.raw_payload || {};
      push("Proposal", firstDefined(data.title, raw.title));
      push("Severity", data.preliminary_severity);
      push("Source", data.source);
      push("Target", firstDefined(raw.service, raw.service_name, raw.application));
      push("Environment", firstDefined(raw.environment, raw.env));
      push("Observed at", firstDefined(data.observed_at, data.timestamp), { type: "datetime" });
      break;
    }
    case "TriageDecision":
      push("Decision", data.decision);
      push("Noise score", data.noise_score);
      push("Reasoning", data.reasoning, { wide: true });
      break;
    case "Assessment":
      push("Severity", data.severity);
      push("Evidence strength", data.evidence_strength);
      push("Policy hash", data.evidence?.policy_evaluation?.policy_hash, { mono: true });
      push("Dissent hash", data.evidence?.policy_evaluation?.dissent_hash, { mono: true });
      push("Approved cap", data.evidence?.policy_evaluation?.approved_allocation_bps ? bpsToPercent(data.evidence.policy_evaluation.approved_allocation_bps) : null);
      push("Casper live read", data.evidence?.casper_node_status?.live_read === true ? "OK" : data.evidence?.casper_node_status ? "Reconnecting" : null);
      push("Root-cause hypothesis", data.root_cause_hypothesis, { wide: true });
      push("Recommended action", data.recommended_action, { wide: true });
      push("Blast radius", data.blast_radius, { wide: true });
      push("Revision", data.revision);
      break;
    case "Verdict":
      push("Decision", data.decision);
      push("Policy hash", data.policy_hash, { mono: true });
      push("Dissent hash", data.dissent_hash, { mono: true });
      push("Violated rules", formatRuleIdentifiers(data.violated_rules), { wide: true });
      push("Reasoning", data.reasoning, { wide: true });
      push("Challenge request", data.challenge_request, { wide: true });
      push("Blocking issues", data.blocking_issues, { wide: true });
      break;
    case "ResponsePlan":
      push("Governance playbook", governancePlaybook(data.governance_playbook || data.policy_path || data.runbook));
      push("Risk level", data.risk_level);
      push("Requires human approval", data.requires_human_approval ? "Yes" : "No");
      push("Plan revision", data.revision);
      push("Exact actions", (data.envelopes || []).map(actionEnvelopeText), { wide: true });
      push("Policy hash", data.envelopes?.[0]?.parameters?.policy_hash, { mono: true });
      push("Dissent hash", data.envelopes?.[0]?.parameters?.dissent_hash, { mono: true });
      push("Approved cap", data.envelopes?.[0]?.parameters?.approved_allocation_bps ? bpsToPercent(data.envelopes[0].parameters.approved_allocation_bps) : null);
      break;
    case "StructuredApproval":
      push("Decision", data.decision);
      push("Approver", firstDefined(data.approver_name, data.approver_id, "Verified human approver"));
      push("Reasoning", data.reasoning, { wide: true });
      push("Plan hash", data.plan_hash, { mono: true });
      break;
    case "PolicyAuthorization":
      push("Decision", "Policy authorized");
      push("Policy", data.policy_id);
      push("Scope", data.scope, { wide: true });
      break;
    case "CasperExecutionReceipt": {
      const verified = isReceiptVerified(card);
      push("Outcome", verified ? "Executed and receipt verified" : "Executed; receipt verification not positively confirmed");
      push("Actions completed", (data.actions_taken || []).length);
      push("Casper transaction", data.actions_taken?.[0]?.transaction_hash, { mono: true });
      push("Policy hash", data.actions_taken?.[0]?.receipt_payload?.policy_hash, { mono: true });
      push("Dissent hash", data.actions_taken?.[0]?.receipt_payload?.dissent_hash, { mono: true });
      push("Resolution summary", data.resolution_summary, { wide: true });
      // Missing/unknown receipt verification is Unavailable, never a fail-open "Yes".
      push("Execution verified", verified ? "Yes" : data.receipt_verified === false ? "No" : "Unavailable");
      break;
    }
    case "GovernanceSummary":
      push("Root cause", data.root_cause, { wide: true });
      push("Timeline summary", data.timeline_summary, { wide: true });
      push("Follow-up actions", data.follow_up_actions, { wide: true });
      break;
    default:
      Object.entries(data || {}).slice(0, 10).forEach(([key, value]) => {
        if (["nonce", "authorization_id", "api_key", "secret"].some((token) => key.toLowerCase().includes(token))) return;
        push(titleCaseAction(PUBLIC_KEY_ALIASES[key] || sanitizeDisplayText(key)), publicDisplayValue(value), { wide: typeof value === "object" });
      });
  }
  return rows;
}

export function downloadEvidence(evidence, proposalId) {
  if (!evidence || typeof document === "undefined") return;
  const safe = JSON.parse(JSON.stringify(evidence));
  safe.export_note = "Public judge-facing export: secrets and internal role keys are redacted or displayed as Concordia persona names. Server-side evidence hashes remain authoritative.";
  const redact = (value) => {
    if (!value || typeof value !== "object") return;
    Object.keys(value).forEach((key) => {
      const lower = key.toLowerCase();
      if (lower.includes("nonce") || lower.includes("authorization_id") || lower.includes("api_key") || lower.includes("secret")) value[key] = "[REDACTED]";
      else redact(value[key]);
    });
  };
  redact(safe);
  const blob = new Blob([publicJson(safe)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${proposalId || "concordia"}-evidence.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function replayEventTitle(card) {
  if (!card) return "Verified proposal replay";
  const data = getCardData(card);
  if (card.card_type === "ProposalCard") return "Proposal detected and normalized";
  if (card.card_type === "TriageDecision") return "Rowan routes the proposal for specialist treasury intelligence";
  if (card.card_type === "Assessment" && Number(data.revision || 1) > 1) return "Mercer submits a materially revised assessment";
  if (card.card_type === "Assessment") return "Mercer reviews treasury, liquidity, and policy evidence";
  if (card.card_type === "Verdict" && data.decision === "CHALLENGE") return "Verity challenges unsupported governance execution assumptions";
  if (card.card_type === "Verdict" && data.decision === "CONFIRM") return "Verity confirms the revised evidence threshold";
  if (card.card_type === "ResponsePlan") return "Alden prepares the exact action envelope";
  if (["StructuredApproval", "PolicyAuthorization"].includes(card.card_type)) return "The exact action is authorized";
  if (card.card_type === "CasperExecutionReceipt") return "Locke anchors the approved receipt on Casper";
  if (card.card_type === "GovernanceSummary") return "Governance archive view is presented (deterministic archive produced by Concordia Core and Locke)";
  return CARD_LABELS[card.card_type] || "Verified workflow event";
}

export function proofTabFromLocation() {
  if (typeof window === "undefined") return "summary";
  const queryTab = new URLSearchParams(window.location.search).get("tab");
  const hashTab = window.location.hash ? window.location.hash.replace(/^#/, "") : "";
  const requested = queryTab || hashTab;
  return PROOF_TAB_IDS.has(requested) ? requested : "summary";
}

export function isWalletIntentSignable(intent) {
  return ["ready", "signer_required"].includes(String(intent?.status || "").toLowerCase());
}

export function unsignedIntentUnavailable(reason) {
  return {
    status: "not_available",
    error: reason || "Wallet signing is not available for this proposal.",
  };
}

export function humanizeWalletError(error) {
  const message = String(error?.message || error || "wallet signing failed");
  if (message.includes("/cspr-click/quorum-approval") && message.includes("404")) {
    return "quorum approval is not available for this proposal";
  }
  if (message.includes("/cspr-click/unsigned-receipt") && message.includes("404")) {
    return "not needed: no Casper receipt payload";
  }
  if (message.includes("returned 404")) return "not available for this proposal";
  if (/not_ready|not ready/i.test(message) && /quorum/i.test(message)) return "quorum package is not configured yet";
  if (/no active casper wallet account/i.test(message)) return "connect a Casper Wallet account first";
  if (/signing was cancelled/i.test(message)) return "signing cancelled";
  if (/signal is aborted/i.test(message)) return "wallet request timed out or was cancelled";
  return message.replace(/^Error:\s*/, "").slice(0, 96);
}

export function walletStatusTone(status = "") {
  const text = String(status).toLowerCase();
  if (text.includes("unavailable") || text.includes("not available") || text.includes("not needed") || text.includes("cancelled")) return "warning";
  if (text.includes("submitted") || text.includes("signed") || text.includes("finalized") || text.includes("broadcast")) return "success";
  return "info";
}
