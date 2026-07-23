// Provenance-aware proof registry rendering (G1_INTERFACE_SPEC.md section 13).
//
// Truth rules implemented here:
// - A green verification cue renders ONLY when verification_status=verified,
//   every mapped required check occurs exactly once with required=true and
//   passed=true, every extra required check passes, observation is available,
//   and execution_outcome is accepted / expected_rejection / not_applicable.
// - expected_rejection renders as POSITIVE proof (e.g. QuorumNotMet), never as
//   a failure.
// - unknown / missing / stale / pending / unavailable / invalid never render
//   green. Top-level asserted booleans never become green on their own.
import { cx, shortHash, titleCaseAction } from "./lib";
import { Icon, PendingNote, StatusPill } from "./primitives";

// Required check sets per proof type. These MUST match the current server
// registry (shared/proof_registry.py REQUIRED_CHECKS_BY_PROOF_TYPE). Codex
// renamed several native-treasury and official-x402 check names after the G1
// freeze (handoff/G1_POST_FREEZE_CORRECTIONS.json). Using the OLD frozen names
// here would make genuinely-verified items render pending forever, so these are
// the CURRENT names verified against shared/proof_registry.py.
export const REQUIRED_CHECKS_BY_PROOF_TYPE = {
  historical_odra_receipt_v2: [
    "artifact_hash_recomputed",
    "historical_card_chain_recomputed",
    "deploy_processed_without_execution_error",
    "receipt_arguments_match_historical_artifact",
    "package_and_contract_match_historical_manifest",
    "historical_lineage_matches_frozen_inventory",
  ],
  exact_envelope_v3: [
    "source_tree_sha256_matches_release_manifest",
    "wasm_sha256_matches_release_manifest",
    "generated_schema_sha256_matches_release_manifest",
    "envelope_hash_recomputed_from_typed_fields",
    "proposal_commitment_matches_envelope_hash",
    "signer_set_and_threshold_match_deployment",
    "pre_quorum_finalize_reverted_with_code_8",
    "post_quorum_mutated_envelope_reverted_with_code_10",
    "exact_envelope_finalization_accepted",
    "repeat_finalization_reverted_with_code_12",
    "finalization_deploy_processed_without_execution_error",
    "contract_readback_marks_proposal_finalized",
    "contract_readback_marks_action_authorized",
    "package_contract_and_deployment_domain_match_manifest",
  ],
  native_treasury_execution_v1: [
    "exact_envelope_v3_verified",
    "executor_journal_signed_bytes_hash_matches",
    "single_broadcast_or_reconciled_by_deploy_hash",
    // Renamed post-freeze: ..._are_canonical -> ..._observed_from_casper_rpc
    "snapshot_block_hash_height_and_state_root_observed_from_casper_rpc",
    // Renamed post-freeze: source_balance_at_snapshot_state_root_... ->
    // source_balance_observed_at_snapshot_root_...
    "source_balance_observed_at_snapshot_root_equals_treasury_snapshot_balance_motes",
    "snapshot_precedes_v3_finalization_and_native_execution",
    "transfer_source_exact",
    "transfer_recipient_exact",
    "transfer_amount_exact",
    "transfer_id_exact",
    // Renamed post-freeze: deploy_finalized_without_execution_error ->
    // successful_inclusion_observed_by_two_named_casper_rpc_nodes
    "successful_inclusion_observed_by_two_named_casper_rpc_nodes",
    "post_execution_source_and_recipient_balances_observed",
    // Renamed post-freeze: no_second_native_transaction_for_action_id ->
    // no_second_native_transaction_observed_through_block
    "no_second_native_transaction_observed_through_block",
  ],
  safepay_v2: [
    "quote_hash_recomputed",
    "issued_quote_row_matches_and_survives_restart",
    "per_quote_correlation_id_recomputed_and_equals_native_transfer_id",
    "payment_deploy_finalized_without_execution_error",
    "single_native_transfer_exact",
    "payee_amount_and_transfer_id_exact",
    "proposal_resource_and_correlation_exact",
    "report_hash_recomputed_and_matches_quote",
    "provider_consumption_row_matches_payment_and_binding",
    "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
    "cross_binding_reuse_returned_terminal_409",
  ],
  official_x402_settlement_v1: [
    "exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    "resource_object_equals_configured_resource",
    "accepted_equals_current_payment_requirements",
    "payment_requirements_argument_equals_accepted",
    "eip712_signature_verified",
    "public_key_account_hash_equals_payer",
    "authorization_equals_envelope_payer_payee_value_nonce_and_window",
    "resource_url_hash_matches_envelope",
    "report_hash_matches_envelope",
    "payment_requirements_hash_matches_envelope",
    "signed_payment_payload_hash_matches_envelope",
    "active_wcspr_v8_pre_verify_drift_guard_passed",
    // Renamed post-freeze to satisfy snake-case grammar:
    // facilitator_verify_returned_isValid_true ->
    // facilitator_verify_returned_is_valid_true
    "facilitator_verify_returned_is_valid_true",
    "active_wcspr_v8_pre_settle_drift_guard_passed",
    "facilitator_settlement_response_success_true",
    "settlement_transaction_finalized_without_execution_error",
    "active_wcspr_v8_post_settle_target_and_args_readback_passed",
    "fulfillment_authorization_nonce_unique_binding_matches",
    "fulfillment_restart_reconciliation_passed",
    "exact_retry_returned_stored_fulfillment_without_second_settlement",
    "cross_binding_or_authorization_reuse_returned_terminal_409_before_submission",
    "protected_report_released_only_after_finalized_state",
  ],
  approval_boundary_v1: [
    "caddy_basic_auth_observed",
    "proxy_secret_header_overwritten_by_caddy",
    "gateway_bcrypt_check_passed",
    "approver_allowlist_check_passed",
    "csrf_check_passed",
    "nonce_consumed_exactly_once",
    "trusted_human_message_origin_matches_approval_boundary",
  ],
  demo_capability_v1: [
    "capability_signature_valid",
    "scenario_and_client_binding_exact",
    "capability_unexpired_at_first_consumption",
    "capability_consumed_atomically",
    "demo_run_provenance_present_on_all_created_records",
    "cleanup_scope_exact_demo_run_id",
    "canonical_ids_excluded_from_cleanup",
  ],
  room_identity_v1: [
    "sender_identity_derived_from_authenticated_key",
    "sender_role_derived_from_authenticated_key",
    "agent_sender_type_is_agent",
    "room_membership_enforced",
    "role_operation_matrix_enforced",
    "gateway_secret_fallback_not_used",
  ],
  snapshot: [
    "artifact_sha256_recomputed",
    "capture_time_present",
    "source_https_url_present",
    "staleness_check_passed",
  ],
};

const GREEN_OUTCOMES = new Set(["accepted", "expected_rejection", "not_applicable"]);
const GENERATIONS = new Set(["v1", "v2", "v3", "none"]);
const LINEAGES = new Set(["canonical", "supplemental"]);
const OBSERVATION_MODES = new Set(["live", "snapshot", "unavailable"]);
const TEMPORAL_SCOPES = new Set(["current", "historical"]);
const VERIFICATION_STATUSES = new Set(["verified", "pending", "stale", "unavailable", "invalid"]);
const EXECUTION_OUTCOMES = new Set([
  "accepted",
  "expected_rejection",
  "not_applicable",
  "unexpected_rejection",
  "not_attempted",
  "unknown",
]);

// A proof type is not merely a label for a checklist. Its provenance fields
// define the exact claim that the checklist is allowed to support (G1-C11).
// Mirrors shared/proof_registry.py _PROVENANCE_BY_PROOF_TYPE so a current v3
// proof can never be relabelled canonical/historical (or a v2 SafePay proof
// relabelled v1/v3) while staying green.
const PROVENANCE_BY_PROOF_TYPE = {
  historical_odra_receipt_v2: { generation: new Set(["v1", "v2"]), lineage: new Set(["canonical", "supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["historical"]), execution_outcome: new Set(["accepted", "expected_rejection"]) },
  exact_envelope_v3: { generation: new Set(["v3"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  native_treasury_execution_v1: { generation: new Set(["v3"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  safepay_v2: { generation: new Set(["v2"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  official_x402_settlement_v1: { generation: new Set(["v3"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  approval_boundary_v1: { generation: new Set(["v1"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  demo_capability_v1: { generation: new Set(["v1"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  room_identity_v1: { generation: new Set(["v1"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["live", "snapshot"]), temporal_scope: new Set(["current"]), execution_outcome: new Set(["accepted"]) },
  snapshot: { generation: new Set(["none"]), lineage: new Set(["supplemental"]), observation_mode: new Set(["snapshot"]), temporal_scope: new Set(["current", "historical"]), execution_outcome: new Set(["not_applicable"]) },
};

// 29 required public-item fields (deployment_domain added post-freeze,
// G1-C7). Mirrors shared/proof_registry.py PUBLIC_ITEM_REQUIRED_FIELDS.
export const PUBLIC_ITEM_REQUIRED_FIELDS = [
  "proof_id", "proof_type", "generation", "lineage", "observation_mode",
  "temporal_scope", "verification_status", "execution_outcome", "claim_scope",
  "enforcement_scope", "proposal_id", "action_id", "envelope_hash",
  "artifact_path", "artifact_sha256", "source_commit", "deployment_commit",
  "network", "package_hash", "contract_hash", "deployment_domain",
  "schema_version", "captured_at", "payment_requirements_hash",
  "signed_payment_payload_hash", "report_hash", "settlement_transaction",
  "checks", "links",
];

const HEX32_RE = /^[0-9a-f]{64}$/;
const GIT_SHA_RE = /^[0-9a-f]{40}$/;
const PROPOSAL_RE = /^[A-Z0-9-]{1,64}$/;
const IDENTIFIER_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const CHECK_NAME_RE = /^[a-z][a-z0-9_]{0,127}$/;
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;

function isHex32(value) { return typeof value === "string" && HEX32_RE.test(value); }
function parseRfc3339Utc(value) {
  if (typeof value !== "string" || !RFC3339_UTC_RE.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}
function isRfc3339Utc(value) { return parseRfc3339Utc(value) !== null; }
function safeRepositoryPath(value) {
  if (typeof value !== "string" || !value) return false;
  if (value.includes("://") || value.includes("\\")) return false;
  if (value.startsWith("/")) return false; // absolute
  return !value.split("/").includes("..");
}
function safeCheckSource(value) {
  return typeof value === "string" && (value.startsWith("https://") || safeRepositoryPath(value));
}
function safeLinkHref(value) {
  return typeof value === "string" && (value.startsWith("https://") || (value.startsWith("/") && !value.startsWith("//")));
}

function checkErrors(checks, requiredNames) {
  if (!Array.isArray(checks)) return ["checks_not_array"];
  const errors = [];
  const names = [];
  const allowed = new Set(["name", "required", "passed", "source", "observed_at", "detail_code"]);
  const requiredFields = ["name", "required", "passed", "source", "observed_at"];
  for (const check of checks) {
    if (!check || typeof check !== "object" || Array.isArray(check)) { errors.push("check_not_object"); continue; }
    if (!requiredFields.every((field) => field in check)) { errors.push("check_fields_missing"); continue; }
    if (Object.keys(check).some((key) => !allowed.has(key))) errors.push("check_unknown_fields");
    const name = check.name;
    if (typeof name !== "string" || !CHECK_NAME_RE.test(name)) { errors.push("check_name_invalid"); continue; }
    names.push(name);
    if (typeof check.required !== "boolean" || typeof check.passed !== "boolean") errors.push("check_boolean_invalid");
    if (!safeCheckSource(check.source)) errors.push("check_source_invalid");
    if (!isRfc3339Utc(check.observed_at)) errors.push("check_observed_at_invalid");
  }
  if (names.length !== new Set(names).size) errors.push("duplicate_check_name");
  const byName = new Map(checks.filter((c) => c && typeof c === "object").map((c) => [c.name, c]));
  for (const name of requiredNames) {
    const check = byName.get(name);
    if (!check) errors.push(`required_check_missing:${name}`);
    else if (check.required !== true) errors.push(`required_check_demoted:${name}`);
  }
  return errors;
}

// Full public-item validation mirroring shared/proof_registry.py
// _public_item_errors. Any non-empty result means the item is not well-formed
// and must never render green.
export function registryItemErrors(item) {
  if (!item || typeof item !== "object" || Array.isArray(item)) return ["item_not_object"];
  const errors = [];
  for (const field of PUBLIC_ITEM_REQUIRED_FIELDS) {
    if (!(field in item)) errors.push(`field_missing:${field}`);
  }
  const proofType = item.proof_type;
  let requiredChecks = [];
  if (!(proofType in REQUIRED_CHECKS_BY_PROOF_TYPE)) errors.push("proof_type_invalid");
  else requiredChecks = REQUIRED_CHECKS_BY_PROOF_TYPE[proofType];
  if (typeof item.proof_id !== "string" || !IDENTIFIER_RE.test(item.proof_id || "")) errors.push("proof_id_invalid");
  const proposalId = item.proposal_id;
  if (proposalId != null && (typeof proposalId !== "string" || !PROPOSAL_RE.test(proposalId))) errors.push("proposal_id_invalid");
  const enums = [
    ["generation", GENERATIONS], ["lineage", LINEAGES], ["observation_mode", OBSERVATION_MODES],
    ["temporal_scope", TEMPORAL_SCOPES], ["verification_status", VERIFICATION_STATUSES], ["execution_outcome", EXECUTION_OUTCOMES],
  ];
  for (const [field, allowedSet] of enums) {
    if (!allowedSet.has(item[field])) errors.push(`${field}_invalid`);
  }
  const provenance = PROVENANCE_BY_PROOF_TYPE[proofType];
  if (provenance) {
    for (const [field, allowedSet] of Object.entries(provenance)) {
      if (!allowedSet.has(item[field])) errors.push(`provenance_invalid:${field}`);
    }
  }
  for (const field of ["claim_scope", "enforcement_scope"]) {
    if (typeof item[field] !== "string" || !item[field].trim()) errors.push(`${field}_invalid`);
  }
  if (item.artifact_path != null && !safeRepositoryPath(item.artifact_path)) errors.push("artifact_path_invalid");
  for (const field of ["action_id", "envelope_hash", "artifact_sha256", "package_hash", "contract_hash", "deployment_domain", "payment_requirements_hash", "signed_payment_payload_hash", "report_hash", "settlement_transaction"]) {
    if (item[field] != null && !isHex32(item[field])) errors.push(`${field}_invalid`);
  }
  for (const field of ["source_commit", "deployment_commit"]) {
    const value = item[field];
    if (value != null && (typeof value !== "string" || !GIT_SHA_RE.test(value))) errors.push(`${field}_invalid`);
  }
  if (item.captured_at != null && !isRfc3339Utc(item.captured_at)) errors.push("captured_at_invalid");
  errors.push(...checkErrors(item.checks, requiredChecks));
  const capturedAt = parseRfc3339Utc(item.captured_at);
  if (capturedAt != null && Array.isArray(item.checks)) {
    for (const check of item.checks) {
      if (!check || typeof check !== "object") continue;
      const observedAt = parseRfc3339Utc(check.observed_at);
      if (observedAt != null && observedAt > capturedAt) errors.push("check_observed_after_capture");
    }
  }
  if (!Array.isArray(item.links)) errors.push("links_not_array");
  else {
    for (const link of item.links) {
      if (!link || typeof link !== "object" || Array.isArray(link) || ["rel", "label", "href", "kind"].length !== Object.keys(link).length || !["rel", "label", "href", "kind"].every((k) => k in link)) { errors.push("link_invalid"); continue; }
      if (!["artifact", "chain", "source", "ui", "download"].includes(link.kind)) errors.push("link_kind_invalid");
      if (!safeLinkHref(link.href)) errors.push("link_href_invalid");
    }
  }
  if (item.verification_status === "verified") {
    for (const field of ["artifact_path", "artifact_sha256", "source_commit", "schema_version", "captured_at"]) {
      if (item[field] == null) errors.push(`verified_field_missing:${field}`);
    }
    if (item.observation_mode === "live" && item.temporal_scope === "current" && item.deployment_commit == null) errors.push("verified_live_deployment_commit_missing");
    if (["exact_envelope_v3", "native_treasury_execution_v1", "official_x402_settlement_v1"].includes(proofType)) {
      for (const field of ["proposal_id", "action_id", "envelope_hash", "network", "package_hash", "contract_hash", "deployment_domain"]) {
        if (item[field] == null) errors.push(`execution_identity_missing:${field}`);
      }
    }
    if (proofType === "official_x402_settlement_v1") {
      for (const field of ["payment_requirements_hash", "signed_payment_payload_hash", "report_hash", "settlement_transaction"]) {
        if (item[field] == null) errors.push(`x402_identity_missing:${field}`);
      }
    }
  }
  if (proofType === "snapshot" && item.captured_at == null) errors.push("snapshot_capture_missing");
  return errors;
}

// The exact green predicate from section 13, now enforcing the FULL registry
// schema, enums, proof-type provenance (G1-C11), and per-item chronology
// (G1-C12). Anything malformed, mislabelled, stale, duplicated, or with an
// unknown proof type / empty required checks renders neutral — never green.
export function itemGreenVerified(item) {
  if (!item || item.verification_status !== "verified") return false;
  if (registryItemErrors(item).length) return false;
  if (item.observation_mode === "unavailable") return false;
  if (!GREEN_OUTCOMES.has(item.execution_outcome)) return false;
  const checks = Array.isArray(item.checks) ? item.checks : [];
  const required = REQUIRED_CHECKS_BY_PROOF_TYPE[item.proof_type] || [];
  if (!required.length) return false; // unknown proof type => never green
  const byName = new Map(checks.map((check) => [check?.name, check]));
  for (const name of required) {
    const check = byName.get(name);
    if (!check || check.required !== true || check.passed !== true) return false;
  }
  for (const check of checks) {
    if (check?.required === true && check?.passed !== true) return false;
  }
  return true;
}

// Cross-field normalization at the registry boundary, mirroring the server's
// build_public_registry: an item whose proposal identity does not match the
// registry, or whose capture time is after the registry generation time, or a
// registry generated after the verifier reference time, is stamped invalid so
// no downstream panel can render it green.
function normalizeRegistryItem(item, registry, referenceTime) {
  if (!item || typeof item !== "object") return item;
  const generatedAt = parseRfc3339Utc(registry?.generated_at);
  const capturedAt = parseRfc3339Utc(item.captured_at);
  const reference = parseRfc3339Utc(referenceTime);
  let invalid = registryItemErrors(item).length > 0;
  if (registry?.proposal_id && item.proposal_id != null && item.proposal_id !== registry.proposal_id) invalid = true;
  if (generatedAt != null && capturedAt != null && capturedAt > generatedAt) invalid = true;
  if (generatedAt != null && reference != null && generatedAt > reference) invalid = true;
  return invalid && item.verification_status !== "invalid" ? { ...item, verification_status: "invalid" } : item;
}

export function findRegistryItems(registry, proofType) {
  if (!registry || !Array.isArray(registry.items)) return [];
  const reference = new Date().toISOString();
  return registry.items
    .filter((item) => item?.proof_type === proofType)
    .map((item) => normalizeRegistryItem(item, registry, reference));
}
export function findRegistryItem(registry, proofType) {
  return findRegistryItems(registry, proofType)[0] || null;
}

const STATUS_META = {
  verified: { label: "Verified", tone: "success" },
  pending: { label: "Pending", tone: "warning" },
  stale: { label: "Stale", tone: "warning" },
  unavailable: { label: "Unavailable", tone: "muted" },
  invalid: { label: "Invalid", tone: "danger" },
};
const OUTCOME_META = {
  accepted: { label: "Accepted" },
  expected_rejection: { label: "Expected rejection · proof" },
  not_applicable: { label: "Not applicable" },
  unexpected_rejection: { label: "Unexpected rejection" },
  not_attempted: { label: "Not attempted" },
  unknown: { label: "Unknown" },
};

// Provenance badge: renders the separate registry dimensions without ever
// collapsing them into one status string, and applies the green cue only via
// itemGreenVerified.
export function ProvenanceBadge({ item, compact = false }) {
  if (!item) {
    return <span className="prov-badge prov-unavailable"><Icon name="clock" size={13} />Provenance unavailable</span>;
  }
  const green = itemGreenVerified(item);
  const status = STATUS_META[item.verification_status] || { label: titleCaseAction(item.verification_status || "unknown"), tone: "muted" };
  const outcome = OUTCOME_META[item.execution_outcome] || { label: titleCaseAction(item.execution_outcome || "unknown") };
  const expectedRejectionProof = green && item.execution_outcome === "expected_rejection";
  return <span className={cx("prov-badge", `prov-${item.verification_status || "unknown"}`, green && "prov-verified", compact && "prov-compact")}>
    <Icon name={green ? "check" : status.tone === "danger" ? "signal" : "clock"} size={13} />
    <strong>{status.label}</strong>
    <em className={cx("prov-outcome", expectedRejectionProof && "prov-outcome-proof")}>{outcome.label}</em>
    <small>{item.lineage || "—"} · {item.temporal_scope || "—"} · {item.observation_mode || "—"}</small>
  </span>;
}

function checksSummary(item) {
  const checks = Array.isArray(item?.checks) ? item.checks : [];
  const required = checks.filter((check) => check?.required === true);
  const passed = required.filter((check) => check?.passed === true);
  return { total: checks.length, required: required.length, passed: passed.length };
}

// Full registry listing panel. Renders each item with its provenance badge and
// per-check detail; honest pending state when the registry is not yet served.
export function ProofRegistryPanel({ registry, registryError }) {
  if (!registry) {
    return <div className="registry-pending" data-testid="proof-registry-pending">
      <PendingNote>
        The provenance-aware proof registry (<code>/proof-registry/v1</code>) is not
        available from the gateway yet{registryError ? ` (${registryError})` : ""}. No
        provenance claims are asserted while it is unavailable.
      </PendingNote>
    </div>;
  }
  const rawItems = Array.isArray(registry.items) ? registry.items : [];
  if (!rawItems.length) {
    return <div className="registry-pending" data-testid="proof-registry-empty">
      <PendingNote>The proof registry returned no items for this proposal. Nothing is asserted.</PendingNote>
    </div>;
  }
  const reference = new Date().toISOString();
  const items = rawItems.map((item) => normalizeRegistryItem(item, registry, reference));
  return <div className="registry-list" data-testid="proof-registry-list">
    {items.map((item) => {
      const green = itemGreenVerified(item);
      const summary = checksSummary(item);
      return <article key={item.proof_id} className={cx("registry-item", green && "registry-item-verified")} data-proof-type={item.proof_type}>
        <header>
          <div>
            <strong>{titleCaseAction(item.proof_type)}</strong>
            <small className="mono">{item.proof_id}</small>
          </div>
          <ProvenanceBadge item={item} />
        </header>
        <div className="registry-item-grid">
          <div><span>Generation</span><strong>{item.generation || "—"}</strong></div>
          <div><span>Claim scope</span><strong>{item.claim_scope || "—"}</strong></div>
          <div><span>Enforcement scope</span><strong>{item.enforcement_scope || "—"}</strong></div>
          <div><span>Required checks</span><strong>{summary.required ? `${summary.passed} / ${summary.required} passed` : "none recorded"}</strong></div>
          {item.artifact_sha256 && <div><span>Artifact SHA-256</span><strong className="mono">{shortHash(item.artifact_sha256, 12, 8)}</strong></div>}
          {item.envelope_hash && <div><span>Envelope hash</span><strong className="mono">{shortHash(item.envelope_hash, 12, 8)}</strong></div>}
          {item.captured_at && <div><span>Captured</span><strong>{item.captured_at}</strong></div>}
          {item.source_commit && <div><span>Source commit</span><strong className="mono">{shortHash(item.source_commit, 10, 0)}</strong></div>}
        </div>
        {!green && <p className="registry-item-note">
          {item.verification_status === "verified"
            ? "Marked verified but its required checks do not all pass — rendered without a success cue."
            : "Not verified — rendered without any success cue."}
        </p>}
      </article>;
    })}
  </div>;
}

export function registryStatusPill(item) {
  if (!item) return <StatusPill tone="muted" compact>unavailable</StatusPill>;
  const green = itemGreenVerified(item);
  const meta = STATUS_META[item.verification_status] || { label: item.verification_status || "unknown", tone: "muted" };
  return <StatusPill tone={green ? "success" : meta.tone === "success" ? "info" : meta.tone} compact>{meta.label}</StatusPill>;
}
