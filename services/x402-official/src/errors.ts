/**
 * Sanitized error model.
 *
 * Every error that can cross a module boundary carries only a stable machine
 * code, an HTTP status, and a retryability flag. No error in this service ever
 * carries request bodies, headers, tokens, or upstream response bodies —
 * constructing one with free-form interpolated context is forbidden by design
 * (the CSPR.cloud facilitator 401 reflects the supplied Authorization value,
 * so even exception text is a leak channel).
 */

export type RefusalKind =
  | "invalid_request"
  | "verify_refusal"
  | "settle_refusal"
  | "terminal_conflict"
  | "upstream_unavailable"
  | "upstream_malformed"
  | "internal";

export class ServiceRefusal extends Error {
  readonly httpStatus: number;
  readonly code: string;
  readonly kind: RefusalKind;
  readonly retryable: boolean;

  constructor(
    httpStatus: number,
    code: string,
    kind: RefusalKind,
    retryable = false,
  ) {
    // The message is exactly the machine code — never interpolated context.
    super(code);
    this.name = "ServiceRefusal";
    this.httpStatus = httpStatus;
    this.code = code;
    this.kind = kind;
    this.retryable = retryable;
  }
}

export function invalidRequest(code: string): ServiceRefusal {
  return new ServiceRefusal(400, code, "invalid_request");
}

export function terminalConflict(code: string): ServiceRefusal {
  return new ServiceRefusal(409, code, "terminal_conflict");
}

export function upstreamUnavailable(code: string): ServiceRefusal {
  return new ServiceRefusal(503, code, "upstream_unavailable", true);
}

export function upstreamMalformed(code: string): ServiceRefusal {
  return new ServiceRefusal(502, code, "upstream_malformed");
}

/** Refusals that surface as {isValid:false}/{success:false} bodies. */
export const REFUSAL_CODES = {
  UNGOVERNED_PAYLOAD: "ungoverned_payload",
  AMBIGUOUS_GOVERNANCE_BINDING: "ambiguous_governance_binding",
  GOVERNANCE_RECORD_INVALID: "governance_record_invalid",
  BLOCKED_UPGRADE_DRIFT: "blocked_upgrade_drift",
  CROSS_BINDING_REJECTED: "cross_binding_rejected",
  AUTHORIZATION_NONCE_REUSED: "authorization_nonce_reused",
  RECONCILIATION_PENDING: "reconciliation_pending",
  MALFORMED_FACILITATOR_RESPONSE: "malformed_facilitator_response",
  FACILITATOR_UNREACHABLE: "facilitator_unreachable",
  REGISTRY_UNAVAILABLE: "registry_unavailable",
  CHAIN_OBSERVATION_UNAVAILABLE: "chain_observation_unavailable",
  SECRET_UNAVAILABLE: "secret_unavailable",
  SETTLEMENT_NOT_FINALIZED: "settlement_not_finalized",
  POST_SETTLE_READBACK_FAILED: "post_settle_readback_failed",
  FACILITATOR_REPORTED_FAILURE: "facilitator_reported_failure",
} as const;
