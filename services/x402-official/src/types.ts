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

/** Readback of a finalized settlement transaction. */
export interface TransactionReadback {
  finalized: boolean;
  executionSuccess: boolean;
  targetContractHash: string;
  contractVersion: number | null;
  entryPoint: string;
  argNames: string[];
  args?: Record<string, string>;
}

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
