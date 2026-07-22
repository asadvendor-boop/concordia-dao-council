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

// Required check sets per proof type, frozen in handoff/G1_CROSS_LANE_SCHEMAS.json
// (public_proof_registry_v1.required_checks_by_proof_type).
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
    "snapshot_block_hash_height_and_state_root_are_canonical",
    "source_balance_at_snapshot_state_root_equals_treasury_snapshot_balance_motes",
    "snapshot_precedes_v3_finalization_and_native_execution",
    "transfer_source_exact",
    "transfer_recipient_exact",
    "transfer_amount_exact",
    "transfer_id_exact",
    "deploy_finalized_without_execution_error",
    "post_execution_source_and_recipient_balances_observed",
    "no_second_native_transaction_for_action_id",
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
    "facilitator_verify_returned_isValid_true",
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

// The exact green predicate from section 13. Anything that fails this renders
// neutral / warned — never green.
export function itemGreenVerified(item) {
  if (!item || item.verification_status !== "verified") return false;
  if (item.observation_mode === "unavailable") return false;
  if (!GREEN_OUTCOMES.has(item.execution_outcome)) return false;
  const checks = Array.isArray(item.checks) ? item.checks : [];
  const names = checks.map((check) => check?.name);
  if (new Set(names).size !== names.length) return false; // duplicate names => invalid item
  const required = REQUIRED_CHECKS_BY_PROOF_TYPE[item.proof_type] || [];
  for (const name of required) {
    const matching = checks.filter((check) => check?.name === name);
    if (matching.length !== 1) return false;
    if (matching[0].required !== true || matching[0].passed !== true) return false;
  }
  for (const check of checks) {
    if (check?.required === true && check?.passed !== true) return false;
  }
  return true;
}

export function findRegistryItems(registry, proofType) {
  if (!registry || !Array.isArray(registry.items)) return [];
  return registry.items.filter((item) => item?.proof_type === proofType);
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
  const items = Array.isArray(registry.items) ? registry.items : [];
  if (!items.length) {
    return <div className="registry-pending" data-testid="proof-registry-empty">
      <PendingNote>The proof registry returned no items for this proposal. Nothing is asserted.</PendingNote>
    </div>;
  }
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
