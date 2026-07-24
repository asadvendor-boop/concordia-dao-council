/**
 * Independent chain observation: active-v8 drift guards and post-settle
 * transaction readback (§11).
 *
 * The WCSPR package is UNLOCKED on Testnet, so every verify attempt and every
 * settlement attempt must independently re-resolve the package's currently
 * enabled contract and require version 8, the exact frozen hash, AND
 * lockStatus == "Unlocked". The check is repeated immediately before
 * settlement — a cached read is never sufficient — and again after settlement
 * via full transaction readback.
 *
 * The runtime argument set is the frozen live v8 ABI: the value argument is
 * named `value`, NEVER `amount`, and this module never "tries both". The
 * readback verifies all eight typed arguments (exact CL type + canonical value
 * + account-only Key variant), the exact package/contract identity, and the
 * exact transaction identity. A `finalized:false` readback is PENDING, not a
 * terminal failure.
 *
 * `FailClosedChainTransport` remains the explicit offline/test fallback. The
 * production entrypoint wires `CasperRpcChainTransport`, whose observations
 * remain fail-closed on any unavailable, malformed, ambiguous, or drifting
 * state.
 */

import {
  ServiceRefusal,
  PendingFinalityError,
  upstreamUnavailable,
  REFUSAL_CODES,
} from "./errors.js";
import type { ServiceConfig } from "./config.js";
import type {
  AuthorizationLocatorQuery,
  ChainTransport,
  PackageState,
  ReadbackArg,
  SettlementLocator,
  TransactionReadback,
} from "./types.js";

/** Frozen live v8 transfer_with_authorization runtime argument names, in ABI order. */
export const TRANSFER_WITH_AUTHORIZATION_ARGS: readonly string[] = [
  "from",
  "to",
  "value",
  "valid_after",
  "valid_before",
  "nonce",
  "public_key",
  "signature",
];

/** Frozen live v8 CL type for every argument, in ABI order (§11). */
export const TRANSFER_WITH_AUTHORIZATION_ARG_TYPES: Readonly<
  Record<string, string>
> = {
  from: "Key",
  to: "Key",
  value: "U256",
  valid_after: "U64",
  valid_before: "U64",
  nonce: "List<U8>",
  public_key: "PublicKey",
  signature: "List<U8>",
};

export const SETTLEMENT_ENTRY_POINT = "transfer_with_authorization";
export const REQUIRED_PACKAGE_LOCK_STATUS = "Unlocked";

const HEX64_RE = /^[0-9a-f]{64}$/;

export class DriftError extends ServiceRefusal {
  constructor() {
    super(200, REFUSAL_CODES.BLOCKED_UPGRADE_DRIFT, "settle_refusal");
    this.name = "DriftError";
  }
}

/** Fail-closed default: every observation attempt refuses. */
export class FailClosedChainTransport implements ChainTransport {
  resolveActivePackage(): Promise<PackageState> {
    return Promise.reject(
      upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE),
    );
  }

  getFinalizedTransaction(): Promise<TransactionReadback> {
    return Promise.reject(
      upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE),
    );
  }

  locateSettlementByAuthorization(): Promise<SettlementLocator> {
    return Promise.reject(
      upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE),
    );
  }
}

/**
 * Fresh (uncached) resolution of the package's enabled contract; requires
 * exactly the frozen version, contract hash, AND lockStatus "Unlocked".
 * Mismatch → blocked_upgrade_drift (§11, WP5-6).
 */
export async function requireActiveV8(
  chain: ChainTransport,
  config: ServiceConfig,
): Promise<void> {
  let state: PackageState;
  try {
    state = await chain.resolveActivePackage(config.wcsprPackageHash);
  } catch (error) {
    if (error instanceof ServiceRefusal) throw error;
    throw upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE);
  }
  if (
    state.lockStatus !== REQUIRED_PACKAGE_LOCK_STATUS ||
    state.enabledVersion !== config.wcsprContractVersion ||
    state.enabledContractHash !== config.wcsprContractHash
  ) {
    throw new DriftError();
  }
}

export interface ExpectedSettlement {
  transactionHashHex: string;
  payerAccountHashHex: string;
  payeeAccountHashHex: string;
  valueAtomic: string;
  validAfter: string;
  validBefore: string;
  nonceHex: string;
  publicKeyHex: string;
  signatureHex: string;
}

function readbackFail(code: string): never {
  throw new ServiceRefusal(200, code, "settle_refusal");
}

/**
 * Verify one typed readback argument: exact CL type AND exact canonical value.
 * A value match under the wrong CL type is a hard failure.
 */
function requireArg(
  args: Record<string, ReadbackArg>,
  name: string,
  expectedValue: string,
): void {
  const arg = args[name];
  if (arg === undefined || typeof arg !== "object" || arg === null) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }
  const expectedType = TRANSFER_WITH_AUTHORIZATION_ARG_TYPES[name];
  if (arg.clType !== expectedType) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }
  if (arg.value !== expectedValue) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }
}

/**
 * Post-settle readback proof (§11, WP5-1/WP5-2): the finalized transaction must
 * prove the exact v8 target, entry point, transaction identity, and every one
 * of the eight typed arguments (CL type + value + account-only Key variant)
 * before any protected report is released.
 *
 * Outcomes:
 *  - `finalized:false` → PendingFinalityError (retryable; resumable; NOT terminal).
 *  - `finalized:true` + executionSuccess:false → terminal settlement_execution_failed.
 *  - `finalized:true` + any identity/type/value mismatch → terminal (drift or
 *    post_settle_readback_failed).
 *  - all exact → returns normally (safe to finalize).
 */
export function validateSettlementReadback(
  readback: TransactionReadback,
  config: ServiceConfig,
  expected: ExpectedSettlement,
): void {
  // Exact transaction identity: the readback must be for the deploy we recorded.
  if (
    typeof readback.transactionHash !== "string" ||
    readback.transactionHash !== expected.transactionHashHex
  ) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }

  // Pending finality is never terminal (WP5-2): resolve later.
  if (readback.finalized !== true) {
    throw new PendingFinalityError();
  }

  // Finalized execution failure is a defined terminal chain error.
  if (readback.executionSuccess !== true) {
    readbackFail(REFUSAL_CODES.SETTLEMENT_EXECUTION_FAILED);
  }

  // Exact package/contract identity.
  if (readback.targetContractHash !== config.wcsprContractHash) {
    throw new DriftError();
  }
  if (readback.contractVersion !== config.wcsprContractVersion) {
    throw new DriftError();
  }
  if (readback.entryPoint !== SETTLEMENT_ENTRY_POINT) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }

  // Exact argument set, in exact ABI order (rejects the amount-vs-value trap,
  // reordering, and any missing/extra argument).
  if (
    !Array.isArray(readback.argNames) ||
    readback.argNames.length !== TRANSFER_WITH_AUTHORIZATION_ARGS.length ||
    readback.argNames.some((name, i) => name !== TRANSFER_WITH_AUTHORIZATION_ARGS[i])
  ) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }

  // Mandatory typed args map — never optional, empty, or partial (WP5-1).
  const args = readback.args;
  if (typeof args !== "object" || args === null) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }
  const argKeys = Object.keys(args).sort();
  const expectedKeys = [...TRANSFER_WITH_AUTHORIZATION_ARGS].sort();
  if (
    argKeys.length !== expectedKeys.length ||
    argKeys.some((k, i) => k !== expectedKeys[i])
  ) {
    readbackFail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }

  // Account-only Key variant for from/to: the canonical Casper account-hash Key
  // string. A Hash/URef/other Key variant (or a bare account hash) fails.
  requireArg(args, "from", `account-hash-${expected.payerAccountHashHex}`);
  requireArg(args, "to", `account-hash-${expected.payeeAccountHashHex}`);
  requireArg(args, "value", expected.valueAtomic);
  requireArg(args, "valid_after", expected.validAfter);
  requireArg(args, "valid_before", expected.validBefore);
  requireArg(args, "nonce", expected.nonceHex);
  requireArg(args, "public_key", expected.publicKeyHex);
  requireArg(args, "signature", expected.signatureHex);
}

/** Structural guard for the values passed to the authorization locator. */
export function assertLocatorQuery(query: AuthorizationLocatorQuery): void {
  for (const value of [
    query.packageHashHex,
    query.contractHashHex,
    query.payerAccountHashHex,
    query.authorizationNonceHex,
  ]) {
    if (typeof value !== "string" || !HEX64_RE.test(value)) {
      throw upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE);
    }
  }
  if (
    typeof query.payerPublicKeyHex !== "string" ||
    !/^[0-9a-f]+$/.test(query.payerPublicKeyHex)
  ) {
    throw upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE);
  }
}
