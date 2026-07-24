/**
 * Official settlement proof-registry item (§13, current registry authority).
 *
 * SCHEMA-DRIVEN CONTRACT — this module is NOT self-referential. The required
 * check list (22 names) and the public item shape (29 fields) are exact copies
 * of the current cross-lane authority:
 *
 *   - shared/proof_registry.py
 *       REQUIRED_CHECKS_BY_PROOF_TYPE["official_x402_settlement_v1"] (22)
 *       PUBLIC_ITEM_REQUIRED_FIELDS (29)
 *   - handoff/G1_CROSS_LANE_SCHEMAS.json  public_proof_registry_v1
 *       (one post-freeze rename is normative in the registry:
 *        facilitator_verify_returned_isValid_true ->
 *        facilitator_verify_returned_is_valid_true, snake-case grammar)
 *   - dashboard/app/_components/provenance-pure.js (re-exported by
 *       provenance.js) REQUIRED_CHECKS_BY_PROOF_TYPE /
 *       PUBLIC_ITEM_REQUIRED_FIELDS
 *
 * Cross-language drift between these constants and the two consumers is pinned
 * by test/settlement-item-cross-language.test.ts, which pipes ONE real builder
 * output through Python `shared.proof_registry.normalize_proof_item` and the
 * dashboard's `registryItemErrors` / `itemGreenVerified`.
 *
 * The item is emitted with EXACT, non-collapsed dimensions: generation `v3`,
 * lineage `supplemental`, observation_mode `live|snapshot`, temporal_scope
 * `current`, verification_status `verified`, execution_outcome `accepted`,
 * network exactly `casper:casper-test`, schema_version exactly
 * `concordia.official_x402_settlement.v1`, SHA-40 source/deployment commits,
 * plus the exact proposal / action / envelope / package / contract /
 * deployment-domain / x402 identity, `claim_scope`, `enforcement_scope`, and
 * typed `links`.
 *
 * Independent-observation semantics (security addendum item 3) are retained:
 * the caller must supply one independently observed receipt PER required check
 * (name, passed, source, observed_at, evidence, optional detail_code) and the
 * builder validates the complete set — every required name exactly once, no
 * extras, no unknown receipt fields, every receipt passed, well-sourced, and
 * strictly UTC-Z timestamped no later than captured_at. It REFUSES to build
 * otherwise: minting `verification_status: "verified"` from identity fields
 * alone is impossible.
 *
 * FORBIDDEN EVIDENCE ON EMISSION (§13): emitted check objects carry ONLY
 * {name, required, passed, source, observed_at, detail_code?}. The caller's
 * `evidence` receipt field is validated as supporting input and then STRIPPED —
 * it never appears in the emitted item; any other field would make the item
 * invalid under shared/proof_registry.py (`check_unknown_fields`).
 *
 * The artifact must NEVER choose verifier observation URLs: the verifier's live
 * observer uses operator-selected trusted HTTPS RPC endpoints. This builder
 * therefore refuses any RPC/observation endpoint as a source and never emits an
 * observation-URL field.
 */

import { rfc3339UtcOrdinal } from "./time.js";

const HEX64_RE = /^[0-9a-f]{64}$/;
const GIT_SHA40_RE = /^[0-9a-f]{40}$/;
// Current registry grammar (shared/proof_registry.py _CHECK_NAME_RE).
const CHECK_NAME_GRAMMAR = /^[a-z][a-z0-9_]{0,95}$/;
// shared/proof_registry.py _IDENTIFIER_RE (proof_id) — also the
// ascii_machine_identifier_1_to_64 grammar for link rel / detail_code.
const IDENTIFIER_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const PROPOSAL_RE = /^[A-Z0-9-]{1,64}$/;
// nonempty_ascii_string (printable ASCII, bounded, not blank).
const ASCII_TEXT_RE = /^[\x20-\x7e]{1,256}$/;
// Registry-compatible UTC-Z instant: shared/proof_registry.py accepts at most
// six fractional digits and no leap second (datetime.fromisoformat rejects
// second 60).
//
// This is now REDUNDANT defence-in-depth, not an added constraint: since the
// exact-chronology pass, src/time.ts enforces BOTH itself (its grammar caps
// the fraction at six digits and it rejects second > 59), and a differential
// check found no input the ordinal parser accepts that this pattern rejects.
// It is retained deliberately so the emission grammar stays legible and
// locally enforced at the registry boundary — do NOT read it as licence to
// relax src/time.ts, whose consumers (registry.ts in particular) have no
// grammar guard of their own.
const REGISTRY_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:(\d{2})(?:\.\d{1,6})?Z$/;
const EVIDENCE_RE = /^[\x20-\x7e]{1,1024}$/;

export class SettlementItemError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "SettlementItemError";
  }
}

/** Exact §13 network for OfficialX402SettlementV1 (G1 spec + internal record). */
export const OFFICIAL_X402_SETTLEMENT_NETWORK = "casper:casper-test";

/**
 * Exact current proof-artifact schema/version identifier for this proof type
 * (shared/release_manifest.py artifact binding for official_x402_settlement_v1).
 */
export const OFFICIAL_X402_SETTLEMENT_SCHEMA_VERSION =
  "concordia.official_x402_settlement.v1";

/**
 * Required check set for `official_x402_settlement_v1` — EXACT copy of
 * shared/proof_registry.py REQUIRED_CHECKS_BY_PROOF_TYPE (22 checks), in the
 * registry's canonical order. Cross-checked against
 * handoff/G1_CROSS_LANE_SCHEMAS.json (whose sole divergence is the pre-rename
 * camel-case `facilitator_verify_returned_isValid_true`; the registry and the
 * dashboard both use the snake-case name below).
 */
export const OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS: readonly string[] = [
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
];

/**
 * The 29 required public-item fields — EXACT copy (name and order) of
 * shared/proof_registry.py PUBLIC_ITEM_REQUIRED_FIELDS. The emitted item
 * carries exactly these keys, in exactly this order, and nothing else.
 */
export const PUBLIC_ITEM_REQUIRED_FIELDS: readonly string[] = [
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
];

/** §13 emitted-check shape: any other key is forbidden evidence. */
const ALLOWED_EMITTED_CHECK_FIELDS: readonly string[] = [
  "name",
  "required",
  "passed",
  "source",
  "observed_at",
  "detail_code",
];

const ALLOWED_RECEIPT_INPUT_FIELDS = new Set([
  "name",
  "passed",
  "source",
  "observed_at",
  "evidence",
  "detail_code",
]);

const LINK_FIELDS: readonly string[] = ["rel", "label", "href", "kind"];
const LINK_KINDS = new Set(["artifact", "chain", "source", "ui", "download"]);

export type ObservationMode = "live" | "snapshot";
export type SettlementLinkKind = "artifact" | "chain" | "source" | "ui" | "download";

/**
 * One independently observed receipt for one required check. The caller (the
 * canary operator) captures these from the actual artifacts — the builder only
 * validates and carries them; it never asserts a check on its own. `evidence`
 * is validated as supporting input and NEVER emitted.
 */
export interface SettlementCheckObservationInput {
  name: string;
  passed: boolean;
  source: string;
  observed_at: string;
  /** Non-empty supporting evidence reference (printable, bounded). INPUT ONLY. */
  evidence: string;
  /** Optional machine detail code, emitted verbatim when present. */
  detail_code?: string;
}

/** Typed §13 link: exactly {rel, label, href, kind}. */
export interface SettlementItemLink {
  rel: string;
  label: string;
  href: string;
  kind: SettlementLinkKind;
}

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
  /** One receipt per required check — validated, never synthesized. */
  checks: SettlementCheckObservationInput[];
  sourceCommit: string;
  deploymentCommit: string;
  artifactPath: string;
  artifactSha256: string;
  claimScope: string;
  enforcementScope: string;
  links: SettlementItemLink[];
}

/** §13 emitted check: ONLY name/required/passed/source/observed_at(/detail_code). */
export interface SettlementItemCheck {
  name: string;
  required: true;
  passed: true;
  source: string;
  observed_at: string;
  detail_code?: string;
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
  claim_scope: string;
  enforcement_scope: string;
  proposal_id: string;
  action_id: string;
  envelope_hash: string;
  artifact_path: string;
  artifact_sha256: string;
  source_commit: string;
  deployment_commit: string;
  network: typeof OFFICIAL_X402_SETTLEMENT_NETWORK;
  package_hash: string;
  contract_hash: string;
  deployment_domain: string;
  schema_version: typeof OFFICIAL_X402_SETTLEMENT_SCHEMA_VERSION;
  captured_at: string;
  payment_requirements_hash: string;
  signed_payment_payload_hash: string;
  report_hash: string;
  settlement_transaction: string;
  checks: SettlementItemCheck[];
  links: SettlementItemLink[];
}

function requireHex64(value: string, code: string): string {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    throw new SettlementItemError(code);
  }
  return value;
}

/** Exact SHA-40 git commit — abbreviated or 64-hex values are rejected. */
function requireCommit40(value: string, code: string): string {
  if (typeof value !== "string" || !GIT_SHA40_RE.test(value)) {
    throw new SettlementItemError(code);
  }
  return value;
}

/**
 * Registry-compatible strict UTC-Z instant. Returns the EXACT microsecond
 * ordinal (BigInt) so chronology matches Python to the microsecond; throws
 * with the caller's code otherwise.
 *
 * The local grammar check below now duplicates rather than tightens
 * src/time.ts (which itself caps the fraction at six digits and rejects
 * second 60) — see the REGISTRY_UTC_RE comment. It stays as a boundary-local
 * restatement of shared/proof_registry.py's rules.
 */
function requireRegistryUtc(value: unknown, code: string): bigint {
  if (typeof value !== "string") throw new SettlementItemError(code);
  const m = REGISTRY_UTC_RE.exec(value);
  if (m === null || m[1] === "60") throw new SettlementItemError(code);
  const epoch = rfc3339UtcOrdinal(value);
  if (epoch === null) throw new SettlementItemError(code);
  return epoch;
}

function requireScope(value: unknown, code: string): string {
  if (
    typeof value !== "string" ||
    !ASCII_TEXT_RE.test(value) ||
    value.trim().length === 0
  ) {
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
 * Validate one typed §13 link: exactly {rel, label, href, kind}, kind from the
 * frozen enum, href an HTTPS artifact URL (never an RPC observation endpoint)
 * or a dashboard-basepath-relative `/...` path.
 */
function requireLink(value: unknown): SettlementItemLink {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SettlementItemError("invalid_link");
  }
  const link = value as Record<string, unknown>;
  const keys = Object.keys(link);
  if (
    keys.length !== LINK_FIELDS.length ||
    !LINK_FIELDS.every((field) => Object.prototype.hasOwnProperty.call(link, field))
  ) {
    throw new SettlementItemError("invalid_link");
  }
  const rel = link["rel"];
  if (typeof rel !== "string" || !IDENTIFIER_RE.test(rel)) {
    throw new SettlementItemError("invalid_link_rel");
  }
  const label = link["label"];
  if (
    typeof label !== "string" ||
    !ASCII_TEXT_RE.test(label) ||
    label.trim().length === 0
  ) {
    throw new SettlementItemError("invalid_link_label");
  }
  const kind = link["kind"];
  if (typeof kind !== "string" || !LINK_KINDS.has(kind)) {
    throw new SettlementItemError("invalid_link_kind");
  }
  const href = link["href"];
  if (typeof href !== "string" || href.length === 0 || href.length > 512) {
    throw new SettlementItemError("invalid_link_href");
  }
  if (href.startsWith("https://")) {
    requireArtifactSource(href);
  } else if (
    !href.startsWith("/") ||
    href.startsWith("//") ||
    !/^[\x21-\x7e]+$/.test(href)
  ) {
    throw new SettlementItemError("invalid_link_href");
  }
  return { rel, label, href, kind: kind as SettlementLinkKind };
}

/**
 * Validate the complete per-check receipt set: every required check name
 * exactly once, no extras, no unknown receipt fields, every receipt passed
 * with a valid source, strict UTC-Z chronology against captured_at, and
 * non-empty supporting evidence. Returns the checks in the canonical required
 * order — WITHOUT the evidence field, which is input-only (§13 permits only
 * name/required/passed/source/observed_at/detail_code on emission). Refuses
 * (throws) on any missing, duplicate, unexpected, unpassed, or malformed
 * observation — the builder never fabricates a check.
 */
function validateCheckObservations(
  checks: unknown,
  capturedAtEpoch: bigint,
): SettlementItemCheck[] {
  if (!Array.isArray(checks)) {
    throw new SettlementItemError("invalid_check_observations");
  }
  const required = new Set(OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS);
  const observed = new Map<string, SettlementItemCheck>();
  for (const entry of checks) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new SettlementItemError("invalid_check_observation");
    }
    const check = entry as Record<string, unknown>;
    for (const key of Object.keys(check)) {
      if (!ALLOWED_RECEIPT_INPUT_FIELDS.has(key)) {
        throw new SettlementItemError("unexpected_check_field");
      }
    }
    const name = check["name"];
    if (typeof name !== "string" || !CHECK_NAME_GRAMMAR.test(name)) {
      throw new SettlementItemError("invalid_check_name");
    }
    if (!required.has(name)) {
      throw new SettlementItemError("unexpected_check");
    }
    if (observed.has(name)) {
      throw new SettlementItemError("duplicate_check_observation");
    }
    if (check["passed"] !== true) {
      throw new SettlementItemError("check_not_passed");
    }
    const source = check["source"];
    if (typeof source !== "string") {
      throw new SettlementItemError("invalid_artifact_source");
    }
    requireArtifactSource(source);
    const observedAt = check["observed_at"];
    const observedAtEpoch = requireRegistryUtc(observedAt, "invalid_check_observed_at");
    // Strict per-check chronology: max(check.observed_at) <= captured_at.
    if (observedAtEpoch > capturedAtEpoch) {
      throw new SettlementItemError("check_observed_after_capture");
    }
    const evidence = check["evidence"];
    if (typeof evidence !== "string" || !EVIDENCE_RE.test(evidence)) {
      throw new SettlementItemError("invalid_check_evidence");
    }
    const detailCode = check["detail_code"];
    if (detailCode !== undefined) {
      if (typeof detailCode !== "string" || !IDENTIFIER_RE.test(detailCode)) {
        throw new SettlementItemError("invalid_check_detail_code");
      }
    }
    // Emission strips the input-only evidence field: the emitted check carries
    // ONLY the §13-permitted fields, constructed literally — never spread.
    observed.set(
      name,
      detailCode === undefined
        ? {
            name,
            required: true,
            passed: true,
            source,
            observed_at: observedAt as string,
          }
        : {
            name,
            required: true,
            passed: true,
            source,
            observed_at: observedAt as string,
            detail_code: detailCode,
          },
    );
  }
  const emitted = OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS.map((name) => {
    const receipt = observed.get(name);
    if (receipt === undefined) {
      throw new SettlementItemError("missing_check_observation");
    }
    return receipt;
  });
  // Defensive shape guard: no emitted check may carry a field outside the §13
  // set — in particular never the input-only `evidence`.
  for (const check of emitted) {
    for (const key of Object.keys(check)) {
      if (!ALLOWED_EMITTED_CHECK_FIELDS.includes(key)) {
        throw new SettlementItemError("forbidden_check_field_emitted");
      }
    }
  }
  return emitted;
}

/**
 * Build the official settlement registry item with exact dimensions, strict
 * UTC-Z chronology, and one validated independently observed receipt per
 * required check (22 checks, 29 public fields). Throws SettlementItemError on
 * any invalid identity, network, commit, timestamp, chronology, source, scope,
 * link, observation-mode, or check-receipt value — it is impossible to obtain
 * `verification_status: "verified"` without every required observation.
 */
export function buildSettlementRegistryItem(
  input: SettlementItemInput,
): SettlementRegistryItem {
  if (input.observationMode !== "live" && input.observationMode !== "snapshot") {
    throw new SettlementItemError("invalid_observation_mode");
  }
  // Exact §13 network binding — any other CAIP-2 value is a different claim.
  if (input.network !== OFFICIAL_X402_SETTLEMENT_NETWORK) {
    throw new SettlementItemError("invalid_network");
  }
  if (typeof input.proposalId !== "string" || !PROPOSAL_RE.test(input.proposalId)) {
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
  const sourceCommit = requireCommit40(input.sourceCommit, "invalid_source_commit");
  const deploymentCommit = requireCommit40(
    input.deploymentCommit,
    "invalid_deployment_commit",
  );
  const artifactPath = requireArtifactSource(input.artifactPath);
  const claimScope = requireScope(input.claimScope, "invalid_claim_scope");
  const enforcementScope = requireScope(
    input.enforcementScope,
    "invalid_enforcement_scope",
  );
  if (!Array.isArray(input.links)) {
    throw new SettlementItemError("invalid_links");
  }
  const links = input.links.map((link) => requireLink(link));

  const capturedAtEpoch = requireRegistryUtc(input.capturedAt, "invalid_captured_at");

  // One independently observed, validated receipt per required check. The
  // builder refuses to construct ANY check itself.
  const checks = validateCheckObservations(input.checks, capturedAtEpoch);

  // proof_id must satisfy the registry identifier grammar
  // ([a-zA-Z0-9_-]{1,64}) — derived deterministically from the signed payload
  // hash that keys this settlement.
  const proofId = `official-x402-${signedPaymentPayloadHash.slice(0, 48)}`;
  if (!IDENTIFIER_RE.test(proofId)) {
    throw new SettlementItemError("invalid_proof_id");
  }

  const item: SettlementRegistryItem = {
    proof_id: proofId,
    proof_type: "official_x402_settlement_v1",
    generation: "v3",
    lineage: "supplemental",
    observation_mode: input.observationMode,
    temporal_scope: "current",
    verification_status: "verified",
    execution_outcome: "accepted",
    claim_scope: claimScope,
    enforcement_scope: enforcementScope,
    proposal_id: input.proposalId,
    action_id: actionId,
    envelope_hash: envelopeHash,
    artifact_path: artifactPath,
    artifact_sha256: artifactSha256,
    source_commit: sourceCommit,
    deployment_commit: deploymentCommit,
    network: OFFICIAL_X402_SETTLEMENT_NETWORK,
    package_hash: packageHash,
    contract_hash: contractHash,
    deployment_domain: deploymentDomain,
    schema_version: OFFICIAL_X402_SETTLEMENT_SCHEMA_VERSION,
    captured_at: input.capturedAt,
    payment_requirements_hash: paymentRequirementsHash,
    signed_payment_payload_hash: signedPaymentPayloadHash,
    report_hash: reportHash,
    settlement_transaction: settlementTransaction,
    checks,
    links,
  };

  // Defensive shape guard: the emitted item carries exactly the 29 required
  // public fields, in the registry's canonical order, and nothing else.
  const emittedFields = Object.keys(item);
  if (
    emittedFields.length !== PUBLIC_ITEM_REQUIRED_FIELDS.length ||
    !PUBLIC_ITEM_REQUIRED_FIELDS.every((field, index) => emittedFields[index] === field)
  ) {
    throw new SettlementItemError("forbidden_item_field_emitted");
  }
  return item;
}
