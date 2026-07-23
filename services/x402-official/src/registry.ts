/**
 * Governance interlock: internal proof-registry read model (§13).
 *
 * The ONLY lookup this service performs is
 * GET {gateway}/internal/proof-registry/v1/x402/{signed_payment_payload_hash}
 * with X-Concordia-Service-Token. The hash is computed from the validated
 * request — a caller-supplied action_id or envelope hash is never accepted.
 *
 * The success record is validated with unknown-field REJECTION (frozen
 * internal_proof_registry_v1 schema — unlike facilitator responses, unknown
 * fields here are a fail-closed condition), exact identity/hash equality, and
 * the full required exact-envelope check set. The top-level boolean is never
 * trusted alone.
 */

import {
  ServiceRefusal,
  upstreamUnavailable,
  REFUSAL_CODES,
} from "./errors.js";
import { readBoundedJson } from "./http.js";
import { rfc3339UtcOrdinal } from "./time.js";
import type { ServiceConfig } from "./config.js";
import type {
  GovernanceBinding,
  RegistryLookupResult,
  RegistryTransport,
  ValidatedPayment,
} from "./types.js";

/** Frozen internal Gateway origin — no environment-proxy override (WP5-4). */
export const FROZEN_GATEWAY_ORIGIN = "http://gateway:8000";

const CREDENTIALED_FETCH_TIMEOUT_MS = 15_000;
const MAX_REGISTRY_RESPONSE_BYTES = 65_536;

/** Frozen exact_envelope_v3 required check names (G1 schemas §13). */
export const EXACT_ENVELOPE_V3_REQUIRED_CHECKS: readonly string[] = [
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
];

const RECORD_FIELDS = [
  "schema_version",
  "proposal_id",
  "proposal_hash",
  "proposal_nonce",
  "action_id",
  "action_kind",
  "action_version",
  "envelope_hash",
  "deployment_domain",
  "network",
  "package_hash",
  "contract_hash",
  "v3_finalized_exact",
  "finalization_transaction",
  "finalized_at",
  "resource_url_hash",
  "report_hash",
  "payment_requirements_hash",
  "signed_payment_payload_hash",
  "verification_status",
  "observed_at",
  "checks",
] as const;

const CHECK_FIELDS = ["name", "required", "passed", "source", "observed_at"] as const;
const CHECK_OPTIONAL_FIELDS = ["detail_code"] as const;

const HEX64_RE = /^[0-9a-f]{64}$/;

export interface RegistryTransportTestOptions {
  allowUnfrozenOriginForTest?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export class HttpRegistryTransport implements RegistryTransport {
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(
    private readonly gatewayInternalUrl: string,
    private readonly tokenProvider: () => string,
    options: RegistryTransportTestOptions = {},
  ) {
    // Freeze the credentialed internal origin: a redirected env must never be
    // able to send the service token to an attacker-chosen host (WP5-4).
    if (
      options.allowUnfrozenOriginForTest !== true &&
      gatewayInternalUrl !== FROZEN_GATEWAY_ORIGIN
    ) {
      throw new ServiceRefusal(500, "gateway_origin_not_frozen", "internal");
    }
    this.timeoutMs = options.timeoutMs ?? CREDENTIALED_FETCH_TIMEOUT_MS;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_REGISTRY_RESPONSE_BYTES;
  }

  async getBySignedPaymentPayloadHash(hashHex: string): Promise<RegistryLookupResult> {
    if (!HEX64_RE.test(hashHex)) {
      // Defense in depth; the pipeline always passes a computed hash.
      throw upstreamUnavailable(REFUSAL_CODES.REGISTRY_UNAVAILABLE);
    }
    const token = this.tokenProvider();
    let response: Response;
    try {
      response = await fetch(
        `${this.gatewayInternalUrl}/internal/proof-registry/v1/x402/${hashHex}`,
        {
          headers: { "x-concordia-service-token": token },
          // Credentialed request: never follow a redirect, always bounded.
          redirect: "error",
          signal: AbortSignal.timeout(this.timeoutMs),
        },
      );
    } catch {
      throw upstreamUnavailable(REFUSAL_CODES.REGISTRY_UNAVAILABLE);
    }
    if (response.status === 404) {
      try {
        await response.body?.cancel();
      } catch {
        /* discarded */
      }
      return { outcome: "not_found" };
    }
    if (response.status === 409) {
      try {
        await response.body?.cancel();
      } catch {
        /* discarded */
      }
      return { outcome: "ambiguous" };
    }
    if (!response.ok) {
      // 403 (auth) and 5xx: fail closed, never log the body.
      try {
        await response.body?.cancel();
      } catch {
        /* discarded */
      }
      throw upstreamUnavailable(REFUSAL_CODES.REGISTRY_UNAVAILABLE);
    }
    let record: unknown;
    try {
      record = await readBoundedJson(response, this.maxResponseBytes);
    } catch {
      throw new ServiceRefusal(
        502,
        REFUSAL_CODES.GOVERNANCE_RECORD_INVALID,
        "upstream_malformed",
      );
    }
    return { outcome: "found", record };
  }
}

function fail(code: string): never {
  throw new ServiceRefusal(502, code, "upstream_malformed");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireHex64(value: unknown): string {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  return value;
}

function requireNonEmptyString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  return value;
}

/**
 * Strict RFC3339 UTC timestamp → EXACT microsecond ordinal (BigInt); anything
 * else fails closed (WP5-6). The ordinal, not milliseconds, is what makes
 * these chronology comparisons agree with Python to the microsecond.
 */
function requireRfc3339Utc(value: unknown): bigint {
  const epoch = rfc3339UtcOrdinal(value);
  if (epoch === null) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  return epoch;
}

/**
 * A proof `source` must be either a repository-relative safe path or an HTTPS
 * URL — never an absolute filesystem path, a parent-traversal, a backslash/NUL,
 * or an opaque unbounded string (WP5-6).
 */
export function validateProofSource(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (value.startsWith("https://")) {
    // Reject control/backslash/whitespace; require a plausible HTTPS URL.
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (c <= 0x20 || c >= 0x7f || c === 0x5c) {
        fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
      }
    }
    const rest = value.slice("https://".length);
    const slash = rest.indexOf("/");
    const host = slash === -1 ? rest : rest.slice(0, slash);
    if (host.length === 0 || host.includes("@") || host.includes(":")) {
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    return value;
  }
  // Repository-relative safe path.
  if (value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  for (const segment of value.split("/")) {
    if (segment.length === 0 || segment === "." || segment === "..") {
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    if (!/^[A-Za-z0-9._-]+$/.test(segment)) {
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
  }
  return value;
}

interface ValidatedChecks {
  names: Set<string>;
  /**
   * Latest check observation as an exact microsecond ordinal, or null when
   * there were no checks. BigInt has no -Infinity, so absence is an explicit
   * null rather than a sentinel value.
   */
  maxObservedAtEpoch: bigint | null;
}

const CHECK_NAME_GRAMMAR = /^[a-z][a-z0-9_]{0,63}$/;

function validateChecks(value: unknown): ValidatedChecks {
  if (!Array.isArray(value)) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  const names = new Set<string>();
  const allowed = new Set<string>([...CHECK_FIELDS, ...CHECK_OPTIONAL_FIELDS]);
  let maxObservedAtEpoch: bigint | null = null;
  for (const check of value) {
    if (!isPlainObject(check)) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    for (const key of Object.keys(check)) {
      if (!allowed.has(key)) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    const name = requireNonEmptyString(check["name"]);
    if (!CHECK_NAME_GRAMMAR.test(name)) {
      // Frozen check-name grammar: lowercase snake_case only (§13).
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    if (names.has(name)) {
      // Duplicate check names make the record invalid (§13).
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    names.add(name);
    if (typeof check["required"] !== "boolean" || typeof check["passed"] !== "boolean") {
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    validateProofSource(check["source"]);
    const checkEpoch = requireRfc3339Utc(check["observed_at"]);
    if (maxObservedAtEpoch === null || checkEpoch > maxObservedAtEpoch) {
      maxObservedAtEpoch = checkEpoch;
    }
    if (
      "detail_code" in check &&
      check["detail_code"] !== undefined &&
      typeof check["detail_code"] !== "string"
    ) {
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    const isMappedRequired = EXACT_ENVELOPE_V3_REQUIRED_CHECKS.includes(name);
    if (isMappedRequired && check["required"] !== true) {
      // A mapped required name may never be demoted to required=false.
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
    if (check["required"] === true && check["passed"] !== true) {
      // Any failed required check blocks authorization, mapped or extra.
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
  }
  for (const requiredName of EXACT_ENVELOPE_V3_REQUIRED_CHECKS) {
    if (!names.has(requiredName)) {
      fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
    }
  }
  return { names, maxObservedAtEpoch };
}

/**
 * Validate the registry record against the frozen schema AND require exact
 * equality with every identity/hash derived from the validated request and
 * frozen configuration. Returns the governance binding stored in the ledger.
 */
export function validateGovernanceRecord(
  record: unknown,
  payment: ValidatedPayment,
  config: ServiceConfig,
): GovernanceBinding {
  if (!isPlainObject(record)) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  const allowed = new Set<string>(RECORD_FIELDS);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  for (const key of RECORD_FIELDS) {
    if (!(key in record)) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (record["schema_version"] !== 1) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  const proposalId = requireNonEmptyString(record["proposal_id"]);
  if (!/^[A-Z0-9-]{1,64}$/.test(proposalId)) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  requireHex64(record["proposal_hash"]);
  requireHex64(record["proposal_nonce"]);
  const actionId = requireHex64(record["action_id"]);
  if (record["action_kind"] !== "OfficialX402SettlementV1") {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (record["action_version"] !== 1) fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  const envelopeHash = requireHex64(record["envelope_hash"]);
  requireHex64(record["deployment_domain"]);
  if (record["network"] !== config.network) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (requireHex64(record["package_hash"]) !== config.wcsprPackageHash) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (requireHex64(record["contract_hash"]) !== config.wcsprContractHash) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  // The top-level boolean is necessary but never sufficient.
  if (record["v3_finalized_exact"] !== true) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (record["verification_status"] !== "verified") {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  const finalizationTransaction = requireHex64(record["finalization_transaction"]);
  const finalizedAtEpoch = requireRfc3339Utc(record["finalized_at"]);
  const finalizedAt = record["finalized_at"] as string;
  const observedAtEpoch = requireRfc3339Utc(record["observed_at"]);
  // Chronology: finalization is observed at or before the record observation.
  if (finalizedAtEpoch > observedAtEpoch) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }

  // Exact equality of every x402 binding hash with values computed locally
  // from the validated request and frozen resource configuration.
  if (requireHex64(record["resource_url_hash"]) !== payment.resource.resourceUrlHashHex) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (requireHex64(record["report_hash"]) !== payment.resource.reportHashHex) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (
    requireHex64(record["payment_requirements_hash"]) !==
    payment.paymentRequirementsHashHex
  ) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  if (
    requireHex64(record["signed_payment_payload_hash"]) !==
    payment.signedPaymentPayloadHashHex
  ) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  const { maxObservedAtEpoch } = validateChecks(record["checks"]);
  // Chronology: no check may claim an observation after the record itself was
  // observed (forged future-dated checks fail closed, WP5-6).
  if (maxObservedAtEpoch !== null && maxObservedAtEpoch > observedAtEpoch) {
    fail(REFUSAL_CODES.GOVERNANCE_RECORD_INVALID);
  }
  return {
    proposalId,
    actionId,
    envelopeHash,
    finalizationTransaction,
    finalizedAt,
  };
}
