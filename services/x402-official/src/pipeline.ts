/**
 * Verify/settle pipelines (§11, §12).
 *
 * Frozen processing order for both endpoints:
 *   1. local shape / canonical-number / account / signature validation
 *   2. offline official EIP-712 verification (pinned scheme, stub signer)
 *   3. signed_payment_payload_hash computed from the validated request
 *   4. unique verified v3 registry lookup (governance interlock)
 *   5. fresh active-v8 drift guard
 *   6. credentialed hosted facilitator call
 *
 * An ungoverned, ambiguous, stale, or invalid payload causes ZERO upstream
 * facilitator calls. Settlement additionally claims the durable ledger before
 * any submission, journals submission_started BEFORE the facilitator settle
 * call, and releases nothing until the on-chain readback proves the exact v8
 * transfer. HTTP 200 from the facilitator is never success by itself.
 */

import { ServiceRefusal, upstreamUnavailable, REFUSAL_CODES } from "./errors.js";
import { SETTLEMENT_STATES, type ServiceConfig } from "./config.js";
import { validateVerifySettleRequest } from "./validation.js";
import {
  validateVerifyResponse,
  validateSettleResponse,
  type LocalVerifier,
} from "./facilitator.js";
import { validateGovernanceRecord } from "./registry.js";
import {
  DriftError,
  requireActiveV8,
  validateSettlementReadback,
  type ExpectedSettlement,
} from "./chain.js";
import { responseHash, type FulfillmentLedger, type FulfillmentRow } from "./ledger.js";
import type {
  ChainTransport,
  ConfiguredResource,
  FacilitatorTransport,
  GovernanceBinding,
  PaymentRequirementsWire,
  RegistryTransport,
  SettleResponseWire,
  ValidatedPayment,
  VerifyResponseWire,
} from "./types.js";

export interface PipelineDeps {
  config: ServiceConfig;
  ledger: FulfillmentLedger;
  facilitator: FacilitatorTransport;
  registry: RegistryTransport;
  chain: ChainTransport;
  localVerifier: LocalVerifier;
}

export function buildPaymentRequirements(
  resource: ConfiguredResource,
  config: ServiceConfig,
): PaymentRequirementsWire {
  return {
    scheme: "exact",
    network: config.network,
    asset: config.wcsprPackageHash,
    amount: resource.amount,
    payTo: resource.payTo,
    maxTimeoutSeconds: resource.maxTimeoutSeconds,
    extra: {
      name: config.tokenName,
      version: config.tokenDomainVersion,
      decimals: String(config.tokenDecimals),
      symbol: config.tokenSymbol,
    },
  };
}

export function buildPaymentRequired(
  resource: ConfiguredResource,
  config: ServiceConfig,
): Record<string, unknown> {
  return {
    x402Version: 2,
    resource: {
      url: resource.url,
      description: resource.description,
      mimeType: resource.mimeType,
    },
    accepts: [buildPaymentRequirements(resource, config)],
  };
}

function markDrift(deps: PipelineDeps, error: unknown): void {
  if (error instanceof DriftError) {
    deps.ledger.setSettlementState(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
  }
}

/**
 * Local gates shared by verify and settle: strict validation, offline
 * official EIP-712 verification, and the governance interlock. Zero
 * facilitator calls happen inside this function.
 */
async function runLocalGates(
  body: unknown,
  deps: PipelineDeps,
): Promise<{ payment: ValidatedPayment; governance: GovernanceBinding }> {
  const payment = validateVerifySettleRequest(body, deps.config);
  const local = await deps.localVerifier.verify(
    payment.paymentPayload,
    payment.requirements,
  );
  if (local.isValid !== true) {
    throw new ServiceRefusal(
      200,
      local.invalidReason ?? "invalid_payment_payload",
      "verify_refusal",
    );
  }
  const lookup = await deps.registry.getBySignedPaymentPayloadHash(
    payment.signedPaymentPayloadHashHex,
  );
  if (lookup.outcome === "not_found") {
    throw new ServiceRefusal(200, REFUSAL_CODES.UNGOVERNED_PAYLOAD, "verify_refusal");
  }
  if (lookup.outcome === "ambiguous") {
    throw new ServiceRefusal(
      409,
      REFUSAL_CODES.AMBIGUOUS_GOVERNANCE_BINDING,
      "terminal_conflict",
    );
  }
  const governance = validateGovernanceRecord(lookup.record, payment, deps.config);
  return { payment, governance };
}

export async function runVerify(
  body: unknown,
  deps: PipelineDeps,
): Promise<VerifyResponseWire> {
  const { payment } = await runLocalGates(body, deps);
  try {
    await requireActiveV8(deps.chain, deps.config);
  } catch (error) {
    markDrift(deps, error);
    throw error;
  }
  const raw = await deps.facilitator.verify({
    x402Version: 2,
    paymentPayload: payment.paymentPayload,
    paymentRequirements: payment.requirements,
  });
  return validateVerifyResponse(raw);
}

function settleSuccessResponse(
  payment: { payerAccountHash: Buffer },
  transaction: string,
  network: string,
): SettleResponseWire {
  return {
    success: true,
    transaction,
    network,
    payer: `00${payment.payerAccountHash.toString("hex")}`,
  };
}

function storedResponse(row: FulfillmentRow): SettleResponseWire | undefined {
  if (row.responseJson === null) return undefined;
  try {
    return JSON.parse(row.responseJson) as SettleResponseWire;
  } catch {
    return undefined;
  }
}

function expectedFromRow(row: FulfillmentRow): ExpectedSettlement {
  return {
    payerAccountHashHex: row.payerAccountHash,
    payeeAccountHashHex: row.payeeAccountHash,
    valueAtomic: row.valueAtomic,
    nonceHex: row.authorizationNonce,
  };
}

/**
 * Reconcile one in-flight row against the chain by its recorded transaction
 * hash. Never issues a facilitator call. Returns the final row when the row
 * reached a terminal state, undefined when observation is unavailable.
 */
async function reconcileRow(
  row: FulfillmentRow,
  deps: PipelineDeps,
): Promise<FulfillmentRow | undefined> {
  if (row.settlementTransactionHash === null) return undefined;
  let readback;
  try {
    readback = await deps.chain.getFinalizedTransaction(row.settlementTransactionHash);
  } catch {
    return undefined;
  }
  try {
    validateSettlementReadback(readback, deps.config, expectedFromRow(row));
  } catch (error) {
    markDrift(deps, error);
    const code =
      error instanceof ServiceRefusal ? error.code : REFUSAL_CODES.POST_SETTLE_READBACK_FAILED;
    const body: SettleResponseWire = {
      success: false,
      errorReason: code,
      transaction: row.settlementTransactionHash,
      network: row.network,
    };
    return deps.ledger.transition(
      row.network,
      row.signedPaymentPayloadHash,
      ["submission_started", "transaction_observed"],
      "failed_terminal",
      {
        failureReason: code,
        responseJson: JSON.stringify(body),
        settlementResponseHash: responseHash(JSON.stringify(body)),
      },
    );
  }
  const body = settleSuccessResponse(
    { payerAccountHash: Buffer.from(row.payerAccountHash, "hex") },
    row.settlementTransactionHash,
    row.network,
  );
  const json = JSON.stringify(body);
  const finalized = deps.ledger.transition(
    row.network,
    row.signedPaymentPayloadHash,
    ["submission_started", "transaction_observed"],
    "finalized",
    {
      responseJson: json,
      settlementResponseHash: responseHash(json),
      settledAt: new Date().toISOString(),
    },
  );
  deps.ledger.setSettlementState(SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE);
  return finalized;
}

/**
 * Startup crash-safety: reconcile every journaled in-flight settlement so an
 * authorization nonce can never be reused (or resubmitted) through a crash
 * gap. Rows without a recorded transaction hash stay reserved, fail closed.
 */
export async function reconcileLedgerOnStartup(
  deps: PipelineDeps,
): Promise<{ finalized: number; failed: number; pending: number }> {
  let finalized = 0;
  let failed = 0;
  let pending = 0;
  for (const row of deps.ledger.pendingRows()) {
    const result = await reconcileRow(row, deps);
    if (result === undefined) pending += 1;
    else if (result.state === "finalized") finalized += 1;
    else failed += 1;
  }
  return { finalized, failed, pending };
}

export async function runSettle(
  body: unknown,
  deps: PipelineDeps,
): Promise<SettleResponseWire> {
  const { config, ledger } = deps;
  const { payment, governance } = await runLocalGates(body, deps);

  const claim = ledger.claim({
    network: config.network,
    signedPaymentPayloadHash: payment.signedPaymentPayloadHashHex,
    resourceId: payment.resource.id,
    actionId: governance.actionId,
    envelopeHash: governance.envelopeHash,
    resourceUrlHash: payment.resource.resourceUrlHashHex,
    reportHash: payment.resource.reportHashHex,
    paymentRequirementsHash: payment.paymentRequirementsHashHex,
    payerAccountHash: payment.payerAccountHash.toString("hex"),
    payeeAccountHash: payment.payeeAccountHash.toString("hex"),
    valueAtomic: payment.valueAtomic.toString(10),
    authorizationNonce: payment.nonce.toString("hex"),
    wcsprContract: config.wcsprContractHash,
  });

  let row = claim.row;
  if (claim.outcome === "existing") {
    if (row.state === "finalized" || row.state === "failed_terminal") {
      // Exact same-binding retry: idempotent stored response, no upstream calls.
      const stored = storedResponse(row);
      if (stored !== undefined) return stored;
      return {
        success: row.state === "finalized",
        ...(row.state === "finalized"
          ? {}
          : { errorReason: row.failureReason ?? "failed_terminal" }),
        transaction: row.settlementTransactionHash ?? "",
        network: row.network,
      };
    }
    if (row.state === "submission_started" || row.state === "transaction_observed") {
      const reconciled = await reconcileRow(row, deps);
      if (reconciled === undefined) {
        // In-flight and unobservable: never a blind second settlement.
        throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
      }
      const stored = storedResponse(reconciled);
      if (stored !== undefined) return stored;
      throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
    }
    // claimed/verified: continue the pipeline from the journaled state.
  }

  // Fresh pre-verify drift guard (§11: uncached, per attempt).
  try {
    await requireActiveV8(deps.chain, config);
  } catch (error) {
    markDrift(deps, error);
    throw error;
  }

  const rawVerify = await deps.facilitator.verify({
    x402Version: 2,
    paymentPayload: payment.paymentPayload,
    paymentRequirements: payment.requirements,
  });
  const verifyResponse = validateVerifyResponse(rawVerify);
  if (verifyResponse.isValid !== true) {
    const code = verifyResponse.invalidReason ?? "facilitator_verify_invalid";
    const bodyOut: SettleResponseWire = {
      success: false,
      errorReason: code,
      transaction: "",
      network: config.network,
    };
    const json = JSON.stringify(bodyOut);
    ledger.transition(
      config.network,
      payment.signedPaymentPayloadHashHex,
      ["claimed", "verified"],
      "failed_terminal",
      {
        failureReason: code,
        responseJson: json,
        settlementResponseHash: responseHash(json),
      },
    );
    return bodyOut;
  }
  if (row.state === "claimed") {
    row = ledger.transition(
      config.network,
      payment.signedPaymentPayloadHashHex,
      ["claimed"],
      "verified",
    );
  }

  // Fresh pre-settle drift guard, immediately before submission (§11 TOCTOU).
  try {
    await requireActiveV8(deps.chain, config);
  } catch (error) {
    markDrift(deps, error);
    throw error;
  }

  // Durable journal BEFORE the credentialed settle call.
  row = ledger.transition(
    config.network,
    payment.signedPaymentPayloadHashHex,
    ["verified"],
    "submission_started",
  );

  let rawSettle: unknown;
  try {
    rawSettle = await deps.facilitator.settle({
      x402Version: 2,
      paymentPayload: payment.paymentPayload,
      paymentRequirements: payment.requirements,
    });
  } catch (error) {
    // Response lost or refused after journaling: the nonce stays reserved and
    // later retries go through reconciliation. Never resubmit blindly.
    if (error instanceof ServiceRefusal) throw error;
    throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
  }
  const settleResponse = validateSettleResponse(rawSettle, config.network);

  if (settleResponse.success !== true) {
    const code = settleResponse.errorReason ?? REFUSAL_CODES.FACILITATOR_REPORTED_FAILURE;
    const bodyOut: SettleResponseWire = {
      success: false,
      errorReason: code,
      transaction: settleResponse.transaction,
      network: config.network,
    };
    const json = JSON.stringify(bodyOut);
    ledger.transition(
      config.network,
      payment.signedPaymentPayloadHashHex,
      ["submission_started"],
      "failed_terminal",
      {
        failureReason: code,
        responseJson: json,
        settlementResponseHash: responseHash(json),
      },
    );
    return bodyOut;
  }

  row = ledger.transition(
    config.network,
    payment.signedPaymentPayloadHashHex,
    ["submission_started"],
    "transaction_observed",
    { settlementTransactionHash: settleResponse.transaction },
  );

  // Post-settle proof: fresh drift guard + full transaction readback. HTTP
  // 200 + success:true is still not success until this passes.
  let readback;
  try {
    await requireActiveV8(deps.chain, config);
    readback = await deps.chain.getFinalizedTransaction(settleResponse.transaction);
  } catch (error) {
    markDrift(deps, error);
    if (error instanceof DriftError) {
      // TOCTOU drift between submission and readback: terminal, no release.
      const bodyOut: SettleResponseWire = {
        success: false,
        errorReason: error.code,
        transaction: settleResponse.transaction,
        network: config.network,
      };
      const json = JSON.stringify(bodyOut);
      ledger.transition(
        config.network,
        payment.signedPaymentPayloadHashHex,
        ["transaction_observed"],
        "failed_terminal",
        {
          failureReason: error.code,
          responseJson: json,
          settlementResponseHash: responseHash(json),
        },
      );
      return bodyOut;
    }
    // Observation unavailable: stay in transaction_observed; reconcile later.
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }
  try {
    validateSettlementReadback(readback, config, {
      payerAccountHashHex: payment.payerAccountHash.toString("hex"),
      payeeAccountHashHex: payment.payeeAccountHash.toString("hex"),
      valueAtomic: payment.valueAtomic.toString(10),
      nonceHex: payment.nonce.toString("hex"),
    });
  } catch (error) {
    markDrift(deps, error);
    const code =
      error instanceof ServiceRefusal
        ? error.code
        : REFUSAL_CODES.POST_SETTLE_READBACK_FAILED;
    const bodyOut: SettleResponseWire = {
      success: false,
      errorReason: code,
      transaction: settleResponse.transaction,
      network: config.network,
    };
    const json = JSON.stringify(bodyOut);
    ledger.transition(
      config.network,
      payment.signedPaymentPayloadHashHex,
      ["transaction_observed"],
      "failed_terminal",
      {
        failureReason: code,
        responseJson: json,
        settlementResponseHash: responseHash(json),
      },
    );
    return bodyOut;
  }

  const bodyOut = settleSuccessResponse(payment, settleResponse.transaction, config.network);
  const json = JSON.stringify(bodyOut);
  ledger.transition(
    config.network,
    payment.signedPaymentPayloadHashHex,
    ["transaction_observed"],
    "finalized",
    {
      responseJson: json,
      settlementResponseHash: responseHash(json),
      settledAt: new Date().toISOString(),
    },
  );
  ledger.setSettlementState(SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE);
  return bodyOut;
}

/**
 * Protected-report release: only a finalized fulfillment row bound to this
 * exact resource releases bytes (§11 "report_release_state: finalized_only").
 */
export function reportReleasableRow(
  deps: PipelineDeps,
  resource: ConfiguredResource,
  payloadHashHex: string,
): FulfillmentRow | undefined {
  const row = deps.ledger.get(deps.config.network, payloadHashHex);
  if (row === undefined) return undefined;
  if (row.state !== "finalized") return undefined;
  if (row.resourceId !== resource.id) return undefined;
  if (row.reportHash !== resource.reportHashHex) return undefined;
  return row;
}
