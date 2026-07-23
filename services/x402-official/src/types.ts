/**
 * Wire and internal types for the official x402 settlement service.
 *
 * Wire shapes follow handoff/G1_CROSS_LANE_SCHEMAS.json → official_x402_service_v1
 * and the pinned @x402/core 2.15.0 protocol types.
 */

export interface ResourceInfoWire {
  url: string;
  description: string;
  mimeType: string;
}

export interface PaymentRequirementsWire {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: Record<string, string>;
}

export interface AuthorizationWire {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

export interface ExactPayloadWire {
  signature: string;
  publicKey: string;
  authorization: AuthorizationWire;
}

export interface PaymentPayloadWire {
  x402Version: number;
  resource: ResourceInfoWire;
  accepted: PaymentRequirementsWire;
  payload: ExactPayloadWire;
  extensions?: Record<string, never>;
}

export interface VerifySettleRequestWire {
  x402Version: number;
  paymentPayload: PaymentPayloadWire;
  paymentRequirements: PaymentRequirementsWire;
}

/** A resource this service protects, from validated local configuration. */
export interface ConfiguredResource {
  id: string;
  url: string;
  description: string;
  mimeType: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  reportBytes: Buffer;
  reportHashHex: string;
  resourceUrlHashHex: string;
}

/** Result of full local validation of a verify/settle request. */
export interface ValidatedPayment {
  resource: ConfiguredResource;
  requirements: PaymentRequirementsWire;
  paymentPayload: PaymentPayloadWire;
  valueAtomic: bigint;
  payerAccountHash: Buffer;
  payeeAccountHash: Buffer;
  signature: Buffer;
  publicKeyBytes: Buffer;
  nonce: Buffer;
  validAfter: bigint;
  validBefore: bigint;
  paymentRequirementsHashHex: string;
  signedPaymentPayloadHashHex: string;
}

/** Verified governance facts read from the internal proof registry. */
export interface GovernanceBinding {
  proposalId: string;
  actionId: string;
  envelopeHash: string;
  finalizationTransaction: string;
  finalizedAt: string;
}

/** Chain state of the WCSPR package as independently observed. */
export interface PackageState {
  lockStatus: string;
  enabledVersion: number;
  enabledContractHash: string;
}

/**
 * One typed runtime argument as read back from the finalized deploy. Both the
 * exact Casper CL type and the canonical value string are verified — a value
 * match with the wrong CL type (or the wrong Key/account variant) is a hard
 * readback failure (§11, WP5-1).
 */
export interface ReadbackArg {
  clType: string;
  value: string;
}

/**
 * Readback of a finalized settlement transaction. `args` is MANDATORY and must
 * carry all eight frozen `transfer_with_authorization` arguments with their
 * exact CL types; a missing, empty, or partial `args` map is a hard readback
 * failure (never fail-open). `transactionHash` binds the readback to the exact
 * submitted deploy identity.
 */
export interface TransactionReadback {
  transactionHash: string;
  finalized: boolean;
  executionSuccess: boolean;
  targetContractHash: string;
  contractVersion: number | null;
  entryPoint: string;
  argNames: string[];
  args: Record<string, ReadbackArg>;
}

/**
 * Exact authorization identity used to recover an already-submitted settlement
 * after a lost `/settle` response, without ever issuing a second settlement
 * (§11, WP5-3). The WCSPR contract enforces single-use nonces, so this tuple
 * uniquely identifies at most one on-chain transfer.
 */
export interface AuthorizationLocatorQuery {
  packageHashHex: string;
  contractHashHex: string;
  payerAccountHashHex: string;
  payerPublicKeyHex: string;
  authorizationNonceHex: string;
}

/**
 * Authoritative result of locating a settlement by authorization identity.
 * `found:false` means the observer PROVED the nonce is unconsumed at the
 * observed finalized state (safe to submit exactly once). An indeterminate
 * observer must throw instead of returning `found:false`.
 */
export type SettlementLocator =
  | { found: true; transactionHash: string }
  | { found: false };

export interface FacilitatorTransport {
  /** GET /supported — parsed 2xx JSON body. */
  supported(): Promise<unknown>;
  /** POST /verify — parsed 2xx JSON body. Throws sanitized errors otherwise. */
  verify(body: unknown): Promise<unknown>;
  /** POST /settle — parsed 2xx JSON body. Throws sanitized errors otherwise. */
  settle(body: unknown): Promise<unknown>;
}

export type RegistryLookupResult =
  | { outcome: "found"; record: unknown }
  | { outcome: "not_found" }
  | { outcome: "ambiguous" };

export interface RegistryTransport {
  getBySignedPaymentPayloadHash(hashHex: string): Promise<RegistryLookupResult>;
}

export interface ChainTransport {
  resolveActivePackage(packageHashHex: string): Promise<PackageState>;
  getFinalizedTransaction(txHashHex: string): Promise<TransactionReadback>;
  /**
   * Recover an already-submitted settlement by exact authorization identity
   * (payer + package + contract + nonce). Used only for lost-response recovery;
   * never issues a settlement itself.
   */
  locateSettlementByAuthorization(
    query: AuthorizationLocatorQuery,
  ): Promise<SettlementLocator>;
}

export interface VerifyResponseWire {
  isValid: boolean;
  invalidReason?: string;
  invalidMessage?: string;
  payer?: string;
  extensions?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface SettleResponseWire {
  success: boolean;
  errorReason?: string;
  errorMessage?: string;
  payer?: string;
  transaction: string;
  network: string;
  amount?: string;
  extensions?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface SupportedKindWire {
  x402Version: number;
  scheme: string;
  network: string;
  [extraKey: string]: unknown;
}

export interface SupportedDocumentWire {
  kinds: SupportedKindWire[];
  extensions: Record<string, unknown>;
  signers: Record<string, unknown> | unknown[];
}
