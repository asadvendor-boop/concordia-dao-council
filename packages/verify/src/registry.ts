import { createHash } from "node:crypto";

import { isRecord } from "./encoders.js";
import { verifyExactEnvelopeV3Artifact, type ExactEnvelopeV3Facts } from "./adapters/exact-envelope-v3.js";
import {
  HistoricalOdraArtifactUnavailableError,
  verifyHistoricalOdraReceiptArtifact,
  type HistoricalOdraReceiptFacts,
} from "./adapters/historical-odra.js";
import { verifyNativeTreasuryExecutionArtifact, type NativeTreasuryExecutionFacts } from "./adapters/native-treasury.js";
import {
  verifyOfficialX402ArtifactEnvelope,
  verifySafePayV2ArtifactEnvelope,
} from "./adapters/payment-envelope.js";
import { parseJsonStrict, StrictJsonError } from "./json.js";

export const EXIT_CODES = Object.freeze({
  VERIFIED: 0,
  INVALID: 2,
  UNAVAILABLE: 3,
  UNKNOWN: 4,
  USAGE: 64,
} as const);

export type ResultStatus = "verified" | "invalid" | "unavailable" | "unknown";
export type VerifiedAspect =
  | "artifact_identity_envelope"
  | "artifact_sha256"
  | "proof_semantics"
  | "proposal_binding";
export type UnsupportedCapability =
  | "official_x402_settlement_v1_semantics"
  | "safepay_v2_semantics";

export type RegistryVerificationOptions = {
  artifacts?: Readonly<Record<string, Uint8Array | string>>;
  now?: string;
};

export type ItemVerificationResult = {
  proofId: string | null;
  proofType: string | null;
  status: ResultStatus;
  green: boolean;
  reasons: string[];
  ignoredAssertions: string[];
  verifiedAspects: VerifiedAspect[];
  unsupportedCapabilities: UnsupportedCapability[];
};

type AdapterFacts = ExactEnvelopeV3Facts | HistoricalOdraReceiptFacts | NativeTreasuryExecutionFacts;
type InternalItemVerificationResult = ItemVerificationResult & {
  adapterFacts?: AdapterFacts;
};

export type RegistryVerificationResult = {
  schemaVersion: 1;
  tool: "@concordia-dao/verify";
  status: ResultStatus;
  valid: boolean;
  exitCode: number;
  proposalId: string | null;
  verificationScope: "none" | "artifact_transcript_consistency" | "live_casper_rpc_corroborated";
  observationSources: string[];
  summary: {
    total: number;
    verified: number;
    invalid: number;
    unavailable: number;
    unknown: number;
  };
  items: ItemVerificationResult[];
  error?: { code: string; message: string };
};

const PROOF_TYPES = new Set([
  "historical_odra_receipt_v2",
  "exact_envelope_v3",
  "native_treasury_execution_v1",
  "safepay_v2",
  "official_x402_settlement_v1",
  "approval_boundary_v1",
  "demo_capability_v1",
  "room_identity_v1",
  "snapshot",
]);

const REQUIRED_CHECKS: Readonly<Record<string, readonly string[]>> = Object.freeze({
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
    "snapshot_block_hash_height_and_state_root_observed_from_casper_rpc",
    "source_balance_observed_at_snapshot_root_equals_treasury_snapshot_balance_motes",
    "snapshot_precedes_v3_finalization_and_native_execution",
    "transfer_source_exact",
    "transfer_recipient_exact",
    "transfer_amount_exact",
    "transfer_id_exact",
    "successful_inclusion_observed_by_two_named_casper_rpc_nodes",
    "post_execution_source_and_recipient_balances_observed",
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
});

const ITEM_REQUIRED_FIELDS = [
  "proof_id",
  "proof_type",
  "generation",
  "lineage",
  "observation_mode",
  "temporal_scope",
  "verification_status",
  "execution_outcome",
  "claim_scope",
  "enforcement_scope",
  "proposal_id",
  "action_id",
  "envelope_hash",
  "artifact_path",
  "artifact_sha256",
  "source_commit",
  "deployment_commit",
  "network",
  "package_hash",
  "contract_hash",
  "deployment_domain",
  "schema_version",
  "captured_at",
  "payment_requirements_hash",
  "signed_payment_payload_hash",
  "report_hash",
  "settlement_transaction",
  "checks",
  "links",
] as const;

const FORGED_BOOLEAN_FIELDS = [
  "chain_valid",
  "duplicate_proof_rejected",
  "passed",
  "verified",
] as const;

const ALLOWED_ITEM_FIELDS = new Set<string>([
  ...ITEM_REQUIRED_FIELDS,
  ...FORGED_BOOLEAN_FIELDS,
]);
const ALLOWED_CHECK_FIELDS = new Set(["name", "required", "passed", "source", "observed_at", "detail_code"]);
const REQUIRED_LINK_FIELDS = new Set(["rel", "label", "href", "kind"]);

const ALLOWED_OUTCOMES = new Set(["accepted", "expected_rejection", "not_applicable"]);
type VerifiedProofSemantics = {
  generation: ReadonlySet<string>;
  lineage: ReadonlySet<string>;
  observationMode: ReadonlySet<string>;
  temporalScope?: ReadonlySet<string>;
  executionOutcome: ReadonlySet<string>;
};
const VERIFIED_PROOF_SEMANTICS: Readonly<Record<string, VerifiedProofSemantics>> = Object.freeze({
  exact_envelope_v3: {
    generation: new Set(["v3"]),
    lineage: new Set(["supplemental"]),
    observationMode: new Set(["live", "snapshot"]),
    temporalScope: new Set(["current"]),
    executionOutcome: new Set(["accepted"]),
  },
  native_treasury_execution_v1: {
    generation: new Set(["v3"]),
    lineage: new Set(["supplemental"]),
    observationMode: new Set(["live", "snapshot"]),
    temporalScope: new Set(["current"]),
    executionOutcome: new Set(["accepted"]),
  },
  safepay_v2: {
    generation: new Set(["v2"]),
    lineage: new Set(["supplemental"]),
    observationMode: new Set(["live", "snapshot"]),
    temporalScope: new Set(["current"]),
    executionOutcome: new Set(["accepted"]),
  },
  official_x402_settlement_v1: {
    generation: new Set(["v3"]),
    lineage: new Set(["supplemental"]),
    observationMode: new Set(["live", "snapshot"]),
    temporalScope: new Set(["current"]),
    executionOutcome: new Set(["accepted"]),
  },
  historical_odra_receipt_v2: {
    generation: new Set(["v1", "v2"]),
    lineage: new Set(["canonical", "supplemental"]),
    observationMode: new Set(["live", "snapshot"]),
    temporalScope: new Set(["historical"]),
    executionOutcome: new Set(["accepted", "expected_rejection"]),
  },
  snapshot: {
    generation: new Set(["none"]),
    lineage: new Set(["supplemental"]),
    observationMode: new Set(["snapshot"]),
    executionOutcome: new Set(["not_applicable"]),
  },
});
const HEX64 = /^[0-9a-f]{64}$/;
const GIT40 = /^[0-9a-f]{40}$/;
const MACHINE_ID = /^[a-z][a-z0-9_]{0,63}$/;
// Frozen observed-check names are intentionally descriptive and include names
// longer than the 64-character identifier ceiling (the longest current name is
// 79 characters). Keep proof/link identifiers constrained separately.
const CHECK_NAME = /^[a-z][a-z0-9_]{0,95}$/;
const PROPOSAL_ID = /^[A-Z0-9-]{1,64}$/;
const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/;
const SNAPSHOT_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_REGISTRY_ITEMS = 128;

export function verifyProofRegistry(
  input: unknown,
  options: RegistryVerificationOptions = {},
): RegistryVerificationResult {
  if (options.now !== undefined && !isRfc3339(options.now)) {
    return topLevelError("invalid_reference_time", "now must be RFC3339 UTC");
  }
  if (!isRecord(input)) return topLevelError("invalid_registry", "registry must be an object");
  const expectedTopLevel = new Set(["schema_version", "generated_at", "proposal_id", "items"]);
  const missingTopLevel = [...expectedTopLevel].filter((key) => !Object.hasOwn(input, key));
  if (missingTopLevel.length > 0) {
    return topLevelError(
      "missing_registry_fields",
      `required top-level fields must be own properties: ${missingTopLevel.sort().join(",")}`,
    );
  }
  const unknown = Object.keys(input).filter((key) => !expectedTopLevel.has(key));
  if (unknown.length > 0) {
    return topLevelError("unknown_registry_fields", `unknown top-level fields: ${unknown.sort().join(",")}`);
  }
  if (input.schema_version !== 1) return topLevelError("invalid_schema_version", "schema_version must equal 1");
  if (!isRfc3339(input.generated_at)) return topLevelError("invalid_generated_at", "generated_at must be RFC3339 UTC");
  if (typeof input.proposal_id !== "string" || !PROPOSAL_ID.test(input.proposal_id)) {
    return topLevelError("invalid_proposal_id", "proposal_id is not canonical");
  }
  if (!Array.isArray(input.items)) return topLevelError("invalid_items", "items must be an array");
  if (input.items.length > MAX_REGISTRY_ITEMS) {
    return topLevelError("too_many_items", `registry exceeds the ${MAX_REGISTRY_ITEMS}-item limit`);
  }

  const proofIds = new Set<string>();
  for (const raw of input.items) {
    if (!isRecord(raw) || typeof raw.proof_id !== "string") continue;
    if (proofIds.has(raw.proof_id)) {
      return topLevelError("duplicate_proof_id", `duplicate proof_id ${raw.proof_id}`);
    }
    proofIds.add(raw.proof_id);
  }

  const artifacts = options.artifacts ?? {};
  // Freshness is a verifier observation, never a claim the registry may set by
  // choosing its own generated_at. Tests and reproducible replays can pin now;
  // ordinary callers use the local wall clock.
  const referenceTime = options.now ?? new Date().toISOString();
  if (Date.parse(input.generated_at as string) > Date.parse(referenceTime)) {
    return topLevelError("future_generated_at", "generated_at cannot be in the verifier's future");
  }
  const internalItems = input.items.map((item) =>
    verifyItem(
      item,
      input.proposal_id as string,
      artifacts,
      input.generated_at as string,
      referenceTime,
    ),
  );
  applyCrossProofBindings(internalItems);
  const items = internalItems.map(({ adapterFacts: _adapterFacts, ...item }) => item);
  const summary = summarize(items);
  const status = overallStatus(items);
  return {
    schemaVersion: 1,
    tool: "@concordia-dao/verify",
    status,
    valid: status === "verified",
    exitCode: exitCodeFor(status),
    proposalId: input.proposal_id,
    verificationScope: "artifact_transcript_consistency",
    observationSources: [],
    summary,
    items,
  };
}

function verifyItem(
  input: unknown,
  registryProposalId: string,
  artifacts: Readonly<Record<string, Uint8Array | string>>,
  registryGeneratedAt: string,
  referenceTime: string,
): InternalItemVerificationResult {
  if (!isRecord(input)) {
    return itemResult(null, null, "invalid", ["proof item must be an object"], [], [], []);
  }
  const proofId = typeof input.proof_id === "string" ? input.proof_id : null;
  const proofType = typeof input.proof_type === "string" ? input.proof_type : null;
  const reasons: string[] = [];
  const unavailableReasons: string[] = [];
  const unknownReasons: string[] = [];
  const ignoredAssertions = FORGED_BOOLEAN_FIELDS.filter((field) => Object.hasOwn(input, field)).sort();
  const verifiedAspects = new Set<VerifiedAspect>();
  const unsupportedCapabilities = new Set<UnsupportedCapability>();
  let artifactHashVerified = false;
  let independentlyVerified = false;
  let adapterFacts: AdapterFacts | undefined;

  const unknownFields = Object.keys(input).filter((field) => !ALLOWED_ITEM_FIELDS.has(field));
  if (unknownFields.length > 0) reasons.push(`unknown proof item fields: ${unknownFields.sort().join(",")}`);

  for (const field of ITEM_REQUIRED_FIELDS) {
    if (!Object.hasOwn(input, field)) reasons.push(`missing required field ${field}`);
  }
  if (proofId === null || !MACHINE_ID.test(proofId)) reasons.push("proof_id is not canonical");
  if (proofType === null || !PROOF_TYPES.has(proofType)) reasons.push("proof_type is not recognized");
  validateEnum(input.generation, ["v1", "v2", "v3", "none"], "generation", reasons);
  validateEnum(input.lineage, ["canonical", "supplemental"], "lineage", reasons);
  validateEnum(input.observation_mode, ["live", "snapshot", "unavailable"], "observation_mode", reasons);
  validateEnum(input.temporal_scope, ["current", "historical"], "temporal_scope", reasons);
  validateEnum(
    input.verification_status,
    ["verified", "pending", "stale", "unavailable", "invalid"],
    "verification_status",
    reasons,
  );
  validateEnum(
    input.execution_outcome,
    ["accepted", "expected_rejection", "not_applicable", "unexpected_rejection", "not_attempted", "unknown"],
    "execution_outcome",
    reasons,
  );
  validateVerifiedProofSemantics(input, proofType, reasons);
  if (!isNonemptyAscii(input.claim_scope)) reasons.push("claim_scope must be nonempty ASCII");
  if (!isNonemptyAscii(input.enforcement_scope)) reasons.push("enforcement_scope must be nonempty ASCII");
  if (input.proposal_id !== null && (!isStringMatching(input.proposal_id, PROPOSAL_ID) || input.proposal_id !== registryProposalId)) {
    reasons.push("proposal_id must be null or equal the registry proposal");
  } else if (input.proposal_id === registryProposalId) {
    verifiedAspects.add("proposal_binding");
  }
  for (const field of [
    "action_id",
    "envelope_hash",
    "artifact_sha256",
    "package_hash",
    "contract_hash",
    "deployment_domain",
    "payment_requirements_hash",
    "signed_payment_payload_hash",
    "report_hash",
    "settlement_transaction",
  ]) {
    if (!isNullableMatch(input[field], HEX64)) reasons.push(`${field} must be null or lowercase hex32`);
  }
  for (const field of ["source_commit", "deployment_commit"]) {
    if (!isNullableMatch(input[field], GIT40)) reasons.push(`${field} must be null or lowercase git SHA`);
  }
  if (input.artifact_path !== null && !isRepositoryRelativePath(input.artifact_path)) {
    reasons.push("artifact_path must be a safe repository-relative path or null");
  }
  if (input.network !== null && !isNonemptyAscii(input.network)) reasons.push("network must be ASCII or null");
  if (input.schema_version !== null && !isNonemptyAscii(input.schema_version)) {
    reasons.push("schema_version must be ASCII or null");
  }
  if (input.captured_at !== null && !isRfc3339(input.captured_at)) reasons.push("captured_at must be RFC3339 UTC or null");
  if (
    typeof input.captured_at === "string" &&
    isRfc3339(input.captured_at) &&
    Date.parse(input.captured_at) > Date.parse(referenceTime)
  ) {
    reasons.push("captured_at is in the verifier's future");
  }
  if (
    input.verification_status === "verified" &&
    typeof input.captured_at === "string" &&
    isRfc3339(input.captured_at) &&
    Date.parse(input.captured_at) > Date.parse(registryGeneratedAt)
  ) {
    reasons.push("verified proof captured_at is after registry generated_at");
  }

  validateLinks(input.links, reasons);
  validateChecks(input.checks, proofType, input.captured_at, referenceTime, reasons);
  validateNullability(input, proofType, reasons);

  if (input.verification_status === "invalid" || input.execution_outcome === "unexpected_rejection") {
    reasons.push("proof explicitly reports an invalid or unexpected outcome");
  }
  if (input.verification_status === "unavailable" || input.verification_status === "stale" || input.observation_mode === "unavailable") {
    unavailableReasons.push("proof observation is unavailable or stale");
  }
  if (input.verification_status === "pending" || input.execution_outcome === "not_attempted" || input.execution_outcome === "unknown") {
    unknownReasons.push("proof has not reached an observed terminal outcome");
  }
  const unsupportedPaymentCapability = paymentSemanticCapability(proofType);
  if (input.verification_status === "verified" && unsupportedPaymentCapability !== undefined) {
    unsupportedCapabilities.add(unsupportedPaymentCapability);
  }

  if (input.verification_status === "verified" && typeof input.artifact_path === "string") {
    const artifact = Object.hasOwn(artifacts, input.artifact_path)
      ? artifacts[input.artifact_path]
      : undefined;
    if (artifact === undefined) {
      unavailableReasons.push(`artifact bytes unavailable for ${input.artifact_path}`);
    } else {
      const bytes = typeof artifact === "string" ? Buffer.from(artifact, "utf8") : artifact;
      const digest = createHash("sha256").update(bytes).digest("hex");
      if (digest !== input.artifact_sha256) reasons.push("artifact SHA-256 mismatch");
      else {
        artifactHashVerified = true;
        verifiedAspects.add("artifact_sha256");
      }
    }
  }

  if (input.verification_status === "verified") {
    if (proofType === "snapshot") {
      const sourcePresent = Array.isArray(input.links) && input.links.some(
        (raw) =>
          isRecord(raw) &&
          raw.rel === "source" &&
          raw.kind === "source" &&
          isHttpsUrl(raw.href),
      );
      if (!sourcePresent) reasons.push("snapshot requires an explicit HTTPS source link");
      if (typeof input.captured_at === "string" && isRfc3339(input.captured_at)) {
        const capturedMs = Date.parse(input.captured_at);
        const referenceMs = Date.parse(referenceTime);
        if (
          capturedMs <= referenceMs &&
          input.temporal_scope === "current" &&
          referenceMs - capturedMs > SNAPSHOT_MAX_AGE_MS
        ) {
          unavailableReasons.push("current snapshot is older than 24 hours");
        }
      }
      independentlyVerified = artifactHashVerified && sourcePresent;
      if (independentlyVerified) verifiedAspects.add("proof_semantics");
    } else if (
      artifactHashVerified &&
      (
        proofType === "exact_envelope_v3" ||
        proofType === "historical_odra_receipt_v2" ||
        proofType === "native_treasury_execution_v1" ||
        proofType === "safepay_v2" ||
        proofType === "official_x402_settlement_v1"
      ) &&
      typeof input.artifact_path === "string"
    ) {
      const artifact = Object.hasOwn(artifacts, input.artifact_path)
        ? artifacts[input.artifact_path]
        : undefined;
      if (artifact !== undefined) {
        try {
          const bytes = typeof artifact === "string" ? Buffer.from(artifact, "utf8") : artifact;
          const parsed = parseJsonStrict(Buffer.from(bytes).toString("utf8"));
          if (proofType === "exact_envelope_v3") {
            const facts = verifyExactEnvelopeV3Artifact(parsed);
            if (validateAdapterClaims(input, {
              proposal_id: facts.proposalId,
              action_id: facts.actionId,
              envelope_hash: facts.envelopeHash,
              network: facts.network,
              package_hash: facts.packageHash,
              contract_hash: facts.contractHash,
              deployment_domain: facts.deploymentDomain,
              source_commit: facts.sourceCommit,
              deployment_commit: facts.deploymentCommit,
              schema_version: "concordia.v3-proof.v1",
            }, reasons)) verifiedAspects.add("artifact_identity_envelope");
            adapterFacts = facts;
          } else if (proofType === "historical_odra_receipt_v2") {
            const facts = verifyHistoricalOdraReceiptArtifact(parsed);
            if (validateAdapterClaims(input, {
              proposal_id: facts.proposalId,
              generation: facts.generation,
              network: "casper-test",
              package_hash: facts.packageHash,
              contract_hash: facts.contractHash,
              source_commit: facts.sourceCommit,
              deployment_commit: facts.deploymentCommit,
              schema_version: facts.schemaVersion,
              captured_at: facts.capturedAt,
            }, reasons)) verifiedAspects.add("artifact_identity_envelope");
            if (facts.generation === "v1" && input.lineage !== "canonical") {
              reasons.push("the currently publishable historical v1 combined proof must use canonical lineage");
            }
            adapterFacts = facts;
          } else if (proofType === "native_treasury_execution_v1") {
            const facts = verifyNativeTreasuryExecutionArtifact(parsed);
            if (validateAdapterClaims(input, {
              proposal_id: facts.proposalId,
              action_id: facts.actionId,
              envelope_hash: facts.envelopeHash,
              network: facts.network,
              package_hash: facts.packageHash,
              contract_hash: facts.contractHash,
              deployment_domain: facts.deploymentDomain,
              source_commit: facts.sourceCommit,
              deployment_commit: facts.deploymentCommit,
              schema_version: facts.schemaVersion,
              captured_at: facts.capturedAt,
            }, reasons)) verifiedAspects.add("artifact_identity_envelope");
            adapterFacts = facts;
          } else if (proofType === "safepay_v2") {
            const facts = verifySafePayV2ArtifactEnvelope(parsed);
            if (validateAdapterClaims(input, {
              proposal_id: facts.proposalId,
              network: facts.network,
              report_hash: facts.reportHash,
              settlement_transaction: facts.settlementTransaction,
              source_commit: facts.sourceCommit,
              deployment_commit: facts.deploymentCommit,
              schema_version: facts.schemaVersion,
              captured_at: facts.capturedAt,
            }, reasons)) verifiedAspects.add("artifact_identity_envelope");
          } else {
            const facts = verifyOfficialX402ArtifactEnvelope(parsed);
            if (validateAdapterClaims(input, {
              proposal_id: facts.proposalId,
              action_id: facts.actionId,
              envelope_hash: facts.envelopeHash,
              network: facts.network,
              package_hash: facts.packageHash,
              contract_hash: facts.contractHash,
              deployment_domain: facts.deploymentDomain,
              payment_requirements_hash: facts.paymentRequirementsHash,
              signed_payment_payload_hash: facts.signedPaymentPayloadHash,
              report_hash: facts.reportHash,
              settlement_transaction: facts.settlementTransaction,
              source_commit: facts.sourceCommit,
              deployment_commit: facts.deploymentCommit,
              schema_version: facts.schemaVersion,
              captured_at: facts.capturedAt,
            }, reasons)) verifiedAspects.add("artifact_identity_envelope");
          }
          if (
            proofType === "exact_envelope_v3" ||
            proofType === "historical_odra_receipt_v2" ||
            proofType === "native_treasury_execution_v1"
          ) {
            independentlyVerified = true;
            verifiedAspects.add("proof_semantics");
          }
        } catch (error) {
          if (error instanceof HistoricalOdraArtifactUnavailableError) {
            unavailableReasons.push(`independent ${proofType} verification unavailable: ${error.message}`);
          } else if (error instanceof StrictJsonError) reasons.push(`artifact strict JSON is invalid: ${error.message}`);
          else reasons.push(`independent ${proofType} verification failed: ${safeErrorMessage(error)}`);
        }
      }
    } else if (unsupportedPaymentCapability === undefined) {
      unavailableReasons.push(
        `independent ${proofType ?? "unknown"} proof adapter has not verified the artifact`,
      );
    }
    if (unsupportedPaymentCapability !== undefined) {
      const verifiedEnvelope = verifiedAspects.has("artifact_identity_envelope");
      unavailableReasons.push(
        `${proofType} payment semantic verification is unsupported by this package; ${
          verifiedEnvelope
            ? "artifact SHA-256 and proposal/identity envelope were independently verified"
            : "a dedicated raw-evidence semantic adapter is required"
        }`,
      );
    }
  }

  let status: ResultStatus;
  if (reasons.length > 0) status = "invalid";
  else if (unavailableReasons.length > 0) status = "unavailable";
  else if (unknownReasons.length > 0) status = "unknown";
  else if (
    input.verification_status === "verified" &&
    independentlyVerified &&
    input.observation_mode !== "unavailable" &&
    ALLOWED_OUTCOMES.has(String(input.execution_outcome))
  ) {
    status = "verified";
  } else {
    status = "unknown";
    unknownReasons.push("proof does not satisfy the frozen green predicate");
  }
  const result: InternalItemVerificationResult = itemResult(
    proofId,
    proofType,
    status,
    [...reasons, ...unavailableReasons, ...unknownReasons],
    ignoredAssertions,
    [...verifiedAspects],
    [...unsupportedCapabilities],
  );
  if (adapterFacts !== undefined) result.adapterFacts = adapterFacts;
  return result;
}

function validateVerifiedProofSemantics(
  item: Record<string, unknown>,
  proofType: string | null,
  reasons: string[],
): void {
  if (item.verification_status !== "verified" || proofType === null) return;
  const contract = VERIFIED_PROOF_SEMANTICS[proofType];
  if (contract === undefined) return;
  const dimensions: [string, ReadonlySet<string>][] = [
    ["generation", contract.generation],
    ["lineage", contract.lineage],
    ["observation_mode", contract.observationMode],
    ["execution_outcome", contract.executionOutcome],
  ];
  if (contract.temporalScope !== undefined) {
    dimensions.push(["temporal_scope", contract.temporalScope]);
  }
  for (const [field, allowed] of dimensions) {
    if (typeof item[field] !== "string" || !allowed.has(item[field] as string)) {
      reasons.push(
        `verified ${proofType} ${field} must be one of ${[...allowed].sort().join("|")}`,
      );
    }
  }
}

function validateAdapterClaims(
  item: Record<string, unknown>,
  expected: Readonly<Record<string, unknown>>,
  reasons: string[],
): boolean {
  let matches = true;
  for (const [field, value] of Object.entries(expected)) {
    if (item[field] !== value) {
      matches = false;
      reasons.push(`${field} differs from independently verified artifact`);
    }
  }
  return matches;
}

function paymentSemanticCapability(
  proofType: string | null,
): UnsupportedCapability | undefined {
  if (proofType === "safepay_v2") return "safepay_v2_semantics";
  if (proofType === "official_x402_settlement_v1") {
    return "official_x402_settlement_v1_semantics";
  }
  return undefined;
}

function applyCrossProofBindings(items: InternalItemVerificationResult[]): void {
  const exactItems = items.filter(
    (item): item is InternalItemVerificationResult & { adapterFacts: ExactEnvelopeV3Facts } =>
      item.proofType === "exact_envelope_v3" &&
      item.status === "verified" &&
      isExactEnvelopeFacts(item.adapterFacts),
  );
  for (const treasury of items) {
    if (
      treasury.proofType !== "native_treasury_execution_v1" ||
      treasury.status !== "verified" ||
      !isNativeTreasuryFacts(treasury.adapterFacts)
    ) {
      continue;
    }
    const facts = treasury.adapterFacts;
    const matches = exactItems.filter((candidate) => {
      const exact = candidate.adapterFacts;
      return (
        exact.proposalId === facts.proposalId &&
        exact.actionId === facts.actionId &&
        exact.envelopeHash === facts.envelopeHash &&
        exact.network === facts.network &&
        exact.packageHash === facts.packageHash &&
        exact.contractHash === facts.contractHash &&
        exact.deploymentDomain === facts.deploymentDomain
      );
    });
    if (matches.length !== 1) {
      invalidateItem(treasury, "native treasury execution requires exactly one independently verified, identity-matched exact-envelope v3 proof");
      continue;
    }
    const exact = matches[0]?.adapterFacts;
    if (
      exact === undefined ||
      !(facts.snapshotBlockHeight < exact.finalizationBlockHeight) ||
      facts.authorizationBlockHeight !== exact.finalizationBlockHeight ||
      facts.authorizationBlockHash !== exact.finalizationBlockHash ||
      exact.finalizationBlockHeight > facts.nativeBlockHeight
    ) {
      invalidateItem(
        treasury,
        "native treasury ordering must satisfy snapshot < v3 finalization = exact scan-start block <= native execution",
      );
    }
  }
}

function isExactEnvelopeFacts(value: AdapterFacts | undefined): value is ExactEnvelopeV3Facts {
  return value !== undefined && "schemaId" in value && value.schemaId === "concordia.v3-proof-verification.v1";
}

function isNativeTreasuryFacts(value: AdapterFacts | undefined): value is NativeTreasuryExecutionFacts {
  return value !== undefined && "schemaVersion" in value && value.schemaVersion === "concordia.native_treasury_execution.v1";
}

function invalidateItem(item: InternalItemVerificationResult, reason: string): void {
  item.status = "invalid";
  item.green = false;
  item.reasons.push(reason);
}

function safeErrorMessage(value: unknown): string {
  return value instanceof Error ? value.message : "unknown adapter error";
}

function validateChecks(
  input: unknown,
  proofType: string | null,
  capturedAt: unknown,
  referenceTime: string,
  reasons: string[],
): void {
  if (!Array.isArray(input)) {
    reasons.push("checks must be an array");
    return;
  }
  const seen = new Set<string>();
  const checks = new Map<string, Record<string, unknown>>();
  for (const raw of input) {
    if (!isRecord(raw)) {
      reasons.push("observed check must be an object");
      continue;
    }
    const unknownFields = Object.keys(raw).filter((field) => !ALLOWED_CHECK_FIELDS.has(field));
    if (unknownFields.length > 0) {
      reasons.push(`observed check has unknown fields: ${unknownFields.sort().join(",")}`);
    }
    const name = Object.hasOwn(raw, "name") && typeof raw.name === "string" ? raw.name : "";
    if (!CHECK_NAME.test(name)) reasons.push("observed check name is not canonical");
    if (seen.has(name)) reasons.push(`duplicate observed check name ${name}`);
    seen.add(name);
    checks.set(name, raw);
    if (
      !Object.hasOwn(raw, "required") ||
      !Object.hasOwn(raw, "passed") ||
      typeof raw.required !== "boolean" ||
      typeof raw.passed !== "boolean"
    ) {
      reasons.push(`observed check ${name || "<unknown>"} requires boolean required/passed`);
    }
    if (!Object.hasOwn(raw, "source") || !isCheckSource(raw.source)) {
      reasons.push(`observed check ${name || "<unknown>"} has invalid source`);
    }
    if (!Object.hasOwn(raw, "observed_at") || !isRfc3339(raw.observed_at)) {
      reasons.push(`observed check ${name || "<unknown>"} has invalid observed_at`);
    } else {
      const observedMs = Date.parse(raw.observed_at as string);
      if (observedMs > Date.parse(referenceTime)) {
        reasons.push(`observed check ${name || "<unknown>"} observed_at is in the verifier's future`);
      }
      if (isRfc3339(capturedAt) && observedMs > Date.parse(capturedAt)) {
        reasons.push(`observed check ${name || "<unknown>"} observed_at is after item captured_at`);
      }
    }
    if (
      Object.hasOwn(raw, "detail_code") &&
      raw.detail_code !== undefined &&
      raw.detail_code !== null &&
      !isStringMatching(raw.detail_code, MACHINE_ID)
    ) {
      reasons.push(`observed check ${name || "<unknown>"} has invalid detail_code`);
    }
  }
  const required = proofType === null ? undefined : REQUIRED_CHECKS[proofType];
  if (!required) return;
  for (const name of required) {
    const check = checks.get(name);
    if (!check) {
      reasons.push(`missing required observed check ${name}`);
    } else if (check.required !== true) {
      reasons.push(`mapped check ${name} must set required=true`);
    } else if (check.passed !== true) {
      reasons.push(`required check ${name} did not pass`);
    }
  }
  for (const [name, check] of checks) {
    if (!required.includes(name) && check.required === true && check.passed !== true) {
      reasons.push(`extra required check ${name} did not pass`);
    }
  }
}

function validateNullability(
  item: Record<string, unknown>,
  proofType: string | null,
  reasons: string[],
): void {
  if (item.verification_status === "verified") {
    for (const field of ["artifact_path", "artifact_sha256", "source_commit", "schema_version", "captured_at"]) {
      if (item[field] === null || item[field] === undefined) reasons.push(`verified proof requires ${field}`);
    }
    if (item.observation_mode === "live" && item.temporal_scope === "current" && item.deployment_commit === null) {
      reasons.push("verified live current proof requires deployment_commit");
    }
  }
  if (proofType === "exact_envelope_v3" || proofType === "native_treasury_execution_v1") {
    for (const field of ["proposal_id", "action_id", "envelope_hash", "network", "package_hash", "contract_hash", "deployment_domain"]) {
      if (item[field] === null || item[field] === undefined) reasons.push(`${proofType} requires ${field}`);
    }
  }
  if (proofType === "historical_odra_receipt_v2" && item.verification_status === "verified") {
    for (const field of [
      "proposal_id",
      "network",
      "package_hash",
      "contract_hash",
      "source_commit",
      "deployment_commit",
    ]) {
      if (item[field] === null || item[field] === undefined) {
        reasons.push(`verified historical Odra proof requires ${field}`);
      }
    }
  }
  if (proofType === "safepay_v2" && item.verification_status === "verified") {
    for (const field of [
      "proposal_id",
      "network",
      "report_hash",
      "settlement_transaction",
    ]) {
      if (item[field] === null || item[field] === undefined) {
        reasons.push(`verified SafePay proof requires ${field}`);
      }
    }
  }
  if (proofType === "official_x402_settlement_v1" && item.verification_status === "verified") {
    for (const field of [
      "proposal_id",
      "action_id",
      "envelope_hash",
      "network",
      "package_hash",
      "contract_hash",
      "deployment_domain",
    ]) {
      if (item[field] === null || item[field] === undefined) {
        reasons.push(`verified official x402 proof requires ${field}`);
      }
    }
    for (const field of [
      "payment_requirements_hash",
      "signed_payment_payload_hash",
      "report_hash",
      "settlement_transaction",
    ]) {
      if (item[field] === null || item[field] === undefined) reasons.push(`verified official x402 proof requires ${field}`);
    }
  }
}

function validateLinks(input: unknown, reasons: string[]): void {
  if (!Array.isArray(input)) {
    reasons.push("links must be an array");
    return;
  }
  for (const raw of input) {
    if (!isRecord(raw)) {
      reasons.push("typed link must be an object");
      continue;
    }
    const fields = Object.keys(raw);
    const unknownFields = fields.filter((field) => !REQUIRED_LINK_FIELDS.has(field));
    const missingFields = [...REQUIRED_LINK_FIELDS].filter((field) => !Object.hasOwn(raw, field));
    if (unknownFields.length > 0) reasons.push(`typed link has unknown fields: ${unknownFields.sort().join(",")}`);
    if (missingFields.length > 0) reasons.push(`typed link is missing fields: ${missingFields.sort().join(",")}`);
    if (!isStringMatching(raw.rel, MACHINE_ID)) reasons.push("typed link rel is invalid");
    if (!isNonemptyAscii(raw.label)) reasons.push("typed link label is invalid");
    if (!isAllowedHref(raw.href)) reasons.push("typed link href is invalid");
    if (!isStringIn(raw.kind, ["artifact", "chain", "source", "ui", "download"])) {
      reasons.push("typed link kind is invalid");
    }
  }
}

function summarize(items: ItemVerificationResult[]): RegistryVerificationResult["summary"] {
  return {
    total: items.length,
    verified: items.filter((item) => item.status === "verified").length,
    invalid: items.filter((item) => item.status === "invalid").length,
    unavailable: items.filter((item) => item.status === "unavailable").length,
    unknown: items.filter((item) => item.status === "unknown").length,
  };
}

function overallStatus(items: ItemVerificationResult[]): ResultStatus {
  if (items.length === 0) return "unknown";
  if (items.some((item) => item.status === "invalid")) return "invalid";
  if (items.some((item) => item.status === "unavailable")) return "unavailable";
  if (items.some((item) => item.status === "unknown")) return "unknown";
  return "verified";
}

function itemResult(
  proofId: string | null,
  proofType: string | null,
  status: ResultStatus,
  reasons: string[],
  ignoredAssertions: string[],
  verifiedAspects: VerifiedAspect[],
  unsupportedCapabilities: UnsupportedCapability[],
): ItemVerificationResult {
  return {
    proofId,
    proofType,
    status,
    green: status === "verified",
    reasons,
    ignoredAssertions,
    verifiedAspects: verifiedAspects.sort(),
    unsupportedCapabilities: unsupportedCapabilities.sort(),
  };
}

function topLevelError(code: string, message: string): RegistryVerificationResult {
  return {
    schemaVersion: 1,
    tool: "@concordia-dao/verify",
    status: "invalid",
    valid: false,
    exitCode: EXIT_CODES.INVALID,
    proposalId: null,
    verificationScope: "none",
    observationSources: [],
    summary: { total: 0, verified: 0, invalid: 0, unavailable: 0, unknown: 0 },
    items: [],
    error: { code, message },
  };
}

function exitCodeFor(status: ResultStatus): number {
  if (status === "verified") return EXIT_CODES.VERIFIED;
  if (status === "invalid") return EXIT_CODES.INVALID;
  if (status === "unavailable") return EXIT_CODES.UNAVAILABLE;
  return EXIT_CODES.UNKNOWN;
}

function validateEnum(value: unknown, allowed: readonly string[], label: string, reasons: string[]): void {
  if (!isStringIn(value, allowed)) reasons.push(`${label} is invalid`);
}

function isStringIn(value: unknown, allowed: readonly string[]): value is string {
  return typeof value === "string" && allowed.includes(value);
}

function isStringMatching(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function isNullableMatch(value: unknown, pattern: RegExp): boolean {
  return value === null || isStringMatching(value, pattern);
}

function isNonemptyAscii(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && /^[\x20-\x7e]+$/.test(value);
}

function isRfc3339(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = RFC3339_UTC.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  if (!yearText || !monthText || !dayText || !hourText || !minuteText || !secondText) return false;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthLengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= (monthLengths[month - 1] ?? 0);
}

function isCheckSource(value: unknown): boolean {
  return isRepositoryRelativePath(value) || isHttpsUrl(value);
}

function isAllowedHref(value: unknown): boolean {
  return (
    isHttpsUrl(value) ||
    (typeof value === "string" &&
      (value === "/dashboard" || value.startsWith("/dashboard/") || value.startsWith("/dashboard?")))
  );
}

function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}

function isRepositoryRelativePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.startsWith("/") || value.includes("\\")) return false;
  const segments = value.split("/");
  return !segments.some((segment) => segment === "" || segment === "." || segment === "..");
}
