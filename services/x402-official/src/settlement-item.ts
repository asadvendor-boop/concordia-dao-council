/**
 * Official settlement proof-registry item (§13, post-freeze interface
 * corrections).
 *
 * The official x402 settlement item is emitted with EXACT, non-collapsed
 * dimensions: generation `v3`, lineage `supplemental`, observation_mode
 * `live|snapshot`, temporal_scope `current`, verification_status `verified`,
 * execution_outcome `accepted`, plus the exact proposal / action / envelope /
 * network / package / contract / deployment-domain identity. Relabelled or
 * partial identity is invalid.
 *
 * Check names obey the frozen `[a-z][a-z0-9_]*` grammar — in particular the
 * normalized `facilitator_verify_returned_is_valid_true` (NOT camel-case
 * `...isValid...`). Every check observation and the capture time are strict
 * UTC-Z, and `max(check.observed_at) <= captured_at`.
 *
 * The artifact must NEVER choose verifier observation URLs: the verifier's live
 * observer uses operator-selected trusted HTTPS RPC endpoints. This builder
 * therefore refuses any RPC/observation endpoint as a source and never emits an
 * observation-URL field.
 */

import { parseRfc3339Utc } from "./time.js";

const HEX64_RE = /^[0-9a-f]{64}$/;
const CHECK_NAME_GRAMMAR = /^[a-z][a-z0-9_]{0,63}$/;

export class SettlementItemError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "SettlementItemError";
  }
}

/**
 * Required check set for `official_x402_settlement_v1` (§13). All names obey the
 * frozen grammar; `facilitator_verify_returned_is_valid_true` and
 * `facilitator_settle_returned_success_true` replace any camel-case literal.
 */
export const OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS: readonly string[] = [
  "requirements_hash_matches_registry",
  "signed_payment_payload_hash_matches_registry",
  "report_hash_matches_registry",
  "exact_v3_finalization_confirmed",
  "public_key_binds_to_payer_account_hash",
  "pre_verify_active_v8_drift_check_passed",
  "pre_settle_active_v8_drift_check_passed",
  "facilitator_verify_returned_is_valid_true",
  "facilitator_settle_returned_success_true",
  "finalized_v8_transfer_with_exact_arguments",
  "post_settle_v8_readback_passed",
  "authorization_nonce_uniqueness_enforced",
  "restart_reconciliation_proven",
  "fulfillment_idempotency_proven",
  "cross_binding_rejection_enforced",
];

export type ObservationMode = "live" | "snapshot";

export interface SettlementItemInput {
  proposalId: string;
  actionId: string;
  envelopeHash: string;
  deploymentDomain: string;
  network: string;
  packageHash: string;
  contractHash: string;
  paymentRequirementsHash: string;
  signedPaymentPayloadHash: string;
  reportHash: string;
  settlementTransaction: string;
  observationMode: ObservationMode;
  capturedAt: string;
  checkObservedAt: string;
  sourceCommit: string;
  deploymentCommit: string;
  artifactPath: string;
  artifactSha256: string;
}

export interface SettlementItemCheck {
  name: string;
  required: true;
  passed: true;
  source: string;
  observed_at: string;
}

export interface SettlementRegistryItem {
  proof_id: string;
  proof_type: "official_x402_settlement_v1";
  generation: "v3";
  lineage: "supplemental";
  observation_mode: ObservationMode;
  temporal_scope: "current";
  verification_status: "verified";
  execution_outcome: "accepted";
  proposal_id: string;
  action_id: string;
  envelope_hash: string;
  network: string;
  package_hash: string;
  contract_hash: string;
  deployment_domain: string;
  artifact_path: string;
  artifact_sha256: string;
  source_commit: string;
  deployment_commit: string;
  schema_version: 1;
  captured_at: string;
  payment_requirements_hash: string;
  signed_payment_payload_hash: string;
  report_hash: string;
  settlement_transaction: string;
  checks: SettlementItemCheck[];
}

function requireHex64(value: string, code: string): string {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    throw new SettlementItemError(code);
  }
  return value;
}

function requireCommit(value: string, code: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{7,64}$/.test(value)) {
    throw new SettlementItemError(code);
  }
  return value;
}

/**
 * A proof source must be a repository-relative safe path OR an HTTPS artifact
 * URL — and must NOT be an RPC/observation endpoint the verifier would choose.
 */
export function requireArtifactSource(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) {
    throw new SettlementItemError("invalid_artifact_source");
  }
  if (value.startsWith("https://")) {
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (c <= 0x20 || c >= 0x7f || c === 0x5c) {
        throw new SettlementItemError("invalid_artifact_source");
      }
    }
    const rest = value.slice("https://".length);
    const slash = rest.indexOf("/");
    const host = slash === -1 ? rest : rest.slice(0, slash);
    if (host.length === 0 || host.includes("@") || host.includes(":")) {
      throw new SettlementItemError("invalid_artifact_source");
    }
    // Reject anything that reads as an RPC observation endpoint: the artifact
    // must never encode a verifier-chosen observation URL.
    const lower = value.toLowerCase();
    if (lower.includes("/rpc") || lower.endsWith("/rpc") || lower.includes(":7777")) {
      throw new SettlementItemError("verifier_observation_url_forbidden");
    }
    return value;
  }
  if (value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    throw new SettlementItemError("invalid_artifact_source");
  }
  for (const segment of value.split("/")) {
    if (segment.length === 0 || segment === "." || segment === "..") {
      throw new SettlementItemError("invalid_artifact_source");
    }
    if (!/^[A-Za-z0-9._-]+$/.test(segment)) {
      throw new SettlementItemError("invalid_artifact_source");
    }
  }
  return value;
}

/**
 * Build the official settlement registry item with exact dimensions and strict
 * UTC-Z chronology. Throws SettlementItemError on any invalid identity,
 * timestamp, chronology, source, or observation-mode value.
 */
export function buildSettlementRegistryItem(
  input: SettlementItemInput,
): SettlementRegistryItem {
  if (input.observationMode !== "live" && input.observationMode !== "snapshot") {
    throw new SettlementItemError("invalid_observation_mode");
  }
  if (typeof input.network !== "string" || input.network.length === 0) {
    throw new SettlementItemError("invalid_network");
  }
  if (typeof input.proposalId !== "string" || !/^[A-Z0-9-]{1,64}$/.test(input.proposalId)) {
    throw new SettlementItemError("invalid_proposal_id");
  }
  const actionId = requireHex64(input.actionId, "invalid_action_id");
  const envelopeHash = requireHex64(input.envelopeHash, "invalid_envelope_hash");
  const deploymentDomain = requireHex64(input.deploymentDomain, "invalid_deployment_domain");
  const packageHash = requireHex64(input.packageHash, "invalid_package_hash");
  const contractHash = requireHex64(input.contractHash, "invalid_contract_hash");
  const paymentRequirementsHash = requireHex64(
    input.paymentRequirementsHash,
    "invalid_payment_requirements_hash",
  );
  const signedPaymentPayloadHash = requireHex64(
    input.signedPaymentPayloadHash,
    "invalid_signed_payment_payload_hash",
  );
  const reportHash = requireHex64(input.reportHash, "invalid_report_hash");
  const settlementTransaction = requireHex64(
    input.settlementTransaction,
    "invalid_settlement_transaction",
  );
  const artifactSha256 = requireHex64(input.artifactSha256, "invalid_artifact_sha256");
  const sourceCommit = requireCommit(input.sourceCommit, "invalid_source_commit");
  const deploymentCommit = requireCommit(input.deploymentCommit, "invalid_deployment_commit");
  const artifactPath = requireArtifactSource(input.artifactPath);

  const capturedAtEpoch = parseRfc3339Utc(input.capturedAt);
  if (capturedAtEpoch === null) throw new SettlementItemError("invalid_captured_at");
  const checkObservedAtEpoch = parseRfc3339Utc(input.checkObservedAt);
  if (checkObservedAtEpoch === null) {
    throw new SettlementItemError("invalid_check_observed_at");
  }
  // Strict chronology: max(check.observed_at) <= captured_at.
  if (checkObservedAtEpoch > capturedAtEpoch) {
    throw new SettlementItemError("check_observed_after_capture");
  }

  const checks: SettlementItemCheck[] = OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS.map(
    (name) => {
      if (!CHECK_NAME_GRAMMAR.test(name)) {
        throw new SettlementItemError("invalid_check_name");
      }
      return {
        name,
        required: true,
        passed: true,
        source: artifactPath,
        observed_at: input.checkObservedAt,
      } satisfies SettlementItemCheck;
    },
  );

  return {
    proof_id: `official_x402_settlement_v1:${signedPaymentPayloadHash}`,
    proof_type: "official_x402_settlement_v1",
    generation: "v3",
    lineage: "supplemental",
    observation_mode: input.observationMode,
    temporal_scope: "current",
    verification_status: "verified",
    execution_outcome: "accepted",
    proposal_id: input.proposalId,
    action_id: actionId,
    envelope_hash: envelopeHash,
    network: input.network,
    package_hash: packageHash,
    contract_hash: contractHash,
    deployment_domain: deploymentDomain,
    artifact_path: artifactPath,
    artifact_sha256: artifactSha256,
    source_commit: sourceCommit,
    deployment_commit: deploymentCommit,
    schema_version: 1,
    captured_at: input.capturedAt,
    payment_requirements_hash: paymentRequirementsHash,
    signed_payment_payload_hash: signedPaymentPayloadHash,
    report_hash: reportHash,
    settlement_transaction: settlementTransaction,
    checks,
  };
}
