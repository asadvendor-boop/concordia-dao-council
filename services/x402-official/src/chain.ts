/**
 * Independent chain observation: active-v8 drift guards and post-settle
 * transaction readback (§11).
 *
 * The WCSPR package is UNLOCKED on Testnet, so every verify attempt and every
 * settlement attempt must independently re-resolve the package's currently
 * enabled contract and require version 8 plus the exact frozen hash. The
 * check is repeated immediately before settlement — a cached read is never
 * sufficient — and again after settlement via full transaction readback.
 *
 * The runtime argument set is the frozen live v8 ABI: the value argument is
 * named `value`, NEVER `amount`, and this module never "tries both".
 *
 * The default production transport is fail-closed: with no chain observer
 * wired, every drift guard fails and no credentialed facilitator call can
 * happen. The live RPC transport is Codex-owned wiring for the canary.
 */

import { ServiceRefusal, upstreamUnavailable, REFUSAL_CODES } from "./errors.js";
import type { ServiceConfig } from "./config.js";
import type { ChainTransport, PackageState, TransactionReadback } from "./types.js";

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

export const SETTLEMENT_ENTRY_POINT = "transfer_with_authorization";

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
}

/**
 * Fresh (uncached) resolution of the package's enabled contract; requires
 * exactly the frozen version and contract hash. Mismatch → blocked_upgrade_drift.
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
    state.enabledVersion !== config.wcsprContractVersion ||
    state.enabledContractHash !== config.wcsprContractHash
  ) {
    throw new DriftError();
  }
}

export interface ExpectedSettlement {
  payerAccountHashHex: string;
  payeeAccountHashHex: string;
  valueAtomic: string;
  nonceHex: string;
}

/**
 * Post-settle readback proof (§11): the finalized transaction must prove the
 * exact v8 target, entry point, argument set, and execution success before
 * any protected report is released. Rejects an `amount` argument outright.
 */
export function validateSettlementReadback(
  readback: TransactionReadback,
  config: ServiceConfig,
  expected: ExpectedSettlement,
): void {
  const fail = (code: string): never => {
    throw new ServiceRefusal(200, code, "settle_refusal");
  };
  if (readback.finalized !== true) {
    fail(REFUSAL_CODES.SETTLEMENT_NOT_FINALIZED);
  }
  if (readback.executionSuccess !== true) {
    fail(REFUSAL_CODES.SETTLEMENT_NOT_FINALIZED);
  }
  if (readback.targetContractHash !== config.wcsprContractHash) {
    throw new DriftError();
  }
  if (readback.contractVersion !== config.wcsprContractVersion) {
    throw new DriftError();
  }
  if (readback.entryPoint !== SETTLEMENT_ENTRY_POINT) {
    fail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }
  const argNames = [...readback.argNames].sort();
  const expectedArgs = [...TRANSFER_WITH_AUTHORIZATION_ARGS].sort();
  if (
    argNames.length !== expectedArgs.length ||
    argNames.some((name, i) => name !== expectedArgs[i])
  ) {
    // Includes the amount-vs-value ABI trap: an `amount` argument or a
    // missing `value` argument is a hard readback failure.
    fail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
  }
  if (readback.args !== undefined) {
    const { args } = readback;
    if (
      (args["from"] !== undefined && args["from"] !== expected.payerAccountHashHex) ||
      (args["to"] !== undefined && args["to"] !== expected.payeeAccountHashHex) ||
      (args["value"] !== undefined && args["value"] !== expected.valueAtomic) ||
      (args["nonce"] !== undefined && args["nonce"] !== expected.nonceHex)
    ) {
      fail(REFUSAL_CODES.POST_SETTLE_READBACK_FAILED);
    }
  }
}
