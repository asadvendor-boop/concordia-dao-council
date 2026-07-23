/**
 * Verify/settle pipelines (§11, §12).
 *
 * Settlement processing order (WP5-5 durable idempotency):
 *   1. strict parse + canonical validation + signed_payment_payload_hash
 *   2. ledger consult BEFORE any volatile gate:
 *        - terminal row  → validated stored response (survives expiry/outage)
 *        - in-flight row → reconcile/recover, never a second settlement
 *   3. NEW claim only: current-time official EIP-712 verify, unique verified v3
 *      registry binding, atomic ledger claim
 *   4. fresh pre-verify + pre-settle active-v8 drift guards (lockStatus+version)
 *   5. credentialed hosted facilitator verify + settle
 *   6. post-settle readback of all eight typed args + exact transaction identity
 *
 * A `finalized:false` readback is PENDING, resumable, never terminal (WP5-2).
 * A lost `/settle` response is recovered by exact payer/package/nonce identity
 * without ever issuing a second settlement (WP5-3). Untrusted upstream reason
 * strings are mapped to bounded local codes and never echoed or logged.
 */

import {
  ServiceRefusal,
  PendingFinalityError,
  upstreamUnavailable,
  REFUSAL_CODES,
} from "./errors.js";
import { SETTLEMENT_STATES, type ServiceConfig } from "./config.js";
import { validateVerifySettleRequest } from "./validation.js";
import {
  validateVerifyResponse,
  validateSettleResponse,
  boundFacilitatorReason,
  type LocalVerifier,
} from "./facilitator.js";
import { validateGovernanceRecord } from "./registry.js";
import {
  DriftError,
  requireActiveV8,
  validateSettlementReadback,
  type ExpectedSettlement,
} from "./chain.js";
import {
  responseHash,
  type FulfillmentBinding,
  type FulfillmentLedger,
  type FulfillmentRow,
  type RowState,
} from "./ledger.js";
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

/** Readiness (distinct from liveness): only a proven live gate is "ready". */
export function isSettlementReady(deps: PipelineDeps): boolean {
  return (
    deps.ledger.getSettlementState() ===
    SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE
  );
}

function expectedFromPayment(
  payment: ValidatedPayment,
  transactionHashHex: string,
): ExpectedSettlement {
  return {
    transactionHashHex,
    payerAccountHashHex: payment.payerAccountHash.toString("hex"),
    payeeAccountHashHex: payment.payeeAccountHash.toString("hex"),
    valueAtomic: payment.valueAtomic.toString(10),
    validAfter: payment.validAfter.toString(10),
    validBefore: payment.validBefore.toString(10),
    nonceHex: payment.nonce.toString("hex"),
    publicKeyHex: payment.publicKeyBytes.toString("hex"),
    signatureHex: payment.signature.toString("hex"),
  };
}

function expectedFromRow(row: FulfillmentRow): ExpectedSettlement {
  return {
    transactionHashHex: row.settlementTransactionHash ?? "",
    payerAccountHashHex: row.payerAccountHash,
    payeeAccountHashHex: row.payeeAccountHash,
    valueAtomic: row.valueAtomic,
    validAfter: row.validAfter,
    validBefore: row.validBefore,
    nonceHex: row.authorizationNonce,
    publicKeyHex: row.publicKey,
    signatureHex: row.signature,
  };
}

function bindingFrom(
  payment: ValidatedPayment,
  governance: GovernanceBinding,
  config: ServiceConfig,
): FulfillmentBinding {
  return {
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
    validAfter: payment.validAfter.toString(10),
    validBefore: payment.validBefore.toString(10),
    authorizationNonce: payment.nonce.toString("hex"),
    publicKey: payment.publicKeyBytes.toString("hex"),
    signature: payment.signature.toString("hex"),
    wcsprContract: config.wcsprContractHash,
  };
}

function settleSuccessResponse(
  payerAccountHashHex: string,
  transaction: string,
  network: string,
): SettleResponseWire {
  return {
    success: true,
    transaction,
    network,
    payer: `00${payerAccountHashHex}`,
  };
}

/** Exact terminal retry: re-validate and return the stored response (WP5-5). */
function validatedStoredResponse(
  row: FulfillmentRow,
  config: ServiceConfig,
): SettleResponseWire {
  if (row.responseJson !== null) {
    try {
      return validateSettleResponse(JSON.parse(row.responseJson), config.network);
    } catch {
      /* corrupt stored body: fall through to deterministic derivation */
    }
  }
  if (row.state === "finalized") {
    return settleSuccessResponse(
      row.payerAccountHash,
      row.settlementTransactionHash ?? "",
      row.network,
    );
  }
  return {
    success: false,
    errorReason: row.failureReason ?? "failed_terminal",
    transaction: row.settlementTransactionHash ?? "",
    network: row.network,
  };
}

function writeTerminalFailure(
  deps: PipelineDeps,
  hash: string,
  from: RowState[],
  code: string,
  transaction: string,
): SettleResponseWire {
  const body: SettleResponseWire = {
    success: false,
    errorReason: code,
    transaction,
    network: deps.config.network,
  };
  const json = JSON.stringify(body);
  deps.ledger.transition(deps.config.network, hash, from, "failed_terminal", {
    failureReason: code,
    responseJson: json,
    settlementResponseHash: responseHash(json),
  });
  return body;
}

function writeFinalized(
  deps: PipelineDeps,
  hash: string,
  payerAccountHashHex: string,
  transaction: string,
): SettleResponseWire {
  const body = settleSuccessResponse(payerAccountHashHex, transaction, deps.config.network);
  const json = JSON.stringify(body);
  deps.ledger.transition(deps.config.network, hash, ["transaction_observed"], "finalized", {
    responseJson: json,
    settlementResponseHash: responseHash(json),
    settledAt: new Date().toISOString(),
  });
  deps.ledger.setSettlementState(SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE);
  return body;
}

type Recovery =
  | { status: "finalized"; response: SettleResponseWire }
  | { status: "failed"; response: SettleResponseWire }
  | { status: "pending" }
  | { status: "unconsumed" };

/**
 * Apply a chain readback to an observed row. A pending readback leaves the row
 * resumable in transaction_observed (WP5-2); a terminal mismatch writes
 * failed_terminal; an exact match finalizes.
 */
function applyReadback(
  deps: PipelineDeps,
  ctx: { hash: string; payerAccountHashHex: string },
  expected: ExpectedSettlement,
  readback: Parameters<typeof validateSettlementReadback>[0],
): Recovery {
  try {
    validateSettlementReadback(readback, deps.config, expected);
  } catch (error) {
    if (error instanceof PendingFinalityError) return { status: "pending" };
    markDrift(deps, error);
    const code =
      error instanceof ServiceRefusal ? error.code : REFUSAL_CODES.POST_SETTLE_READBACK_FAILED;
    const response = writeTerminalFailure(
      deps,
      ctx.hash,
      ["transaction_observed"],
      code,
      expected.transactionHashHex,
    );
    return { status: "failed", response };
  }
  const response = writeFinalized(
    deps,
    ctx.hash,
    ctx.payerAccountHashHex,
    expected.transactionHashHex,
  );
  return { status: "finalized", response };
}

/**
 * Reconcile one in-flight row against the chain. For a row with a recorded
 * deploy hash, read it back. For a row whose `/settle` response was lost (no
 * recorded hash), recover the deploy by exact authorization identity — adopting
 * an already-submitted transaction WITHOUT a second settlement, or proving the
 * nonce is unconsumed so the caller may submit exactly once (WP5-3). Never
 * issues a facilitator call.
 */
async function recoverInFlightRow(
  deps: PipelineDeps,
  row: FulfillmentRow,
): Promise<Recovery> {
  let current = row;
  if (current.settlementTransactionHash === null) {
    let locator;
    try {
      locator = await deps.chain.locateSettlementByAuthorization({
        packageHashHex: deps.config.wcsprPackageHash,
        contractHashHex: current.wcsprContract,
        payerAccountHashHex: current.payerAccountHash,
        payerPublicKeyHex: current.publicKey,
        authorizationNonceHex: current.authorizationNonce,
      });
    } catch {
      return { status: "pending" };
    }
    if (!locator.found) {
      // Authoritatively unconsumed: no settlement happened.
      return { status: "unconsumed" };
    }
    current = deps.ledger.transition(
      current.network,
      current.signedPaymentPayloadHash,
      ["submission_started"],
      "transaction_observed",
      { settlementTransactionHash: locator.transactionHash },
    );
  }
  const txHash = current.settlementTransactionHash;
  if (txHash === null) return { status: "pending" };
  let readback;
  try {
    readback = await deps.chain.getFinalizedTransaction(txHash);
  } catch {
    return { status: "pending" };
  }
  return applyReadback(
    deps,
    { hash: current.signedPaymentPayloadHash, payerAccountHashHex: current.payerAccountHash },
    expectedFromRow(current),
    readback,
  );
}

/**
 * Current-time governance/signature gates. Runs the offline official EIP-712
 * verification (validity window vs the current clock) and the unique verified
 * v3 registry lookup. Only ever runs for a NEW claim (WP5-5). Zero facilitator
 * calls happen here.
 */
async function runCurrentTimeGates(
  payment: ValidatedPayment,
  deps: PipelineDeps,
): Promise<GovernanceBinding> {
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
  return validateGovernanceRecord(lookup.record, payment, deps.config);
}

export async function runVerify(
  body: unknown,
  deps: PipelineDeps,
): Promise<VerifyResponseWire> {
  const payment = validateVerifySettleRequest(body, deps.config);
  await runCurrentTimeGates(payment, deps);
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
  const resp = validateVerifyResponse(raw);
  if (resp.isValid !== true) {
    // The remote facilitator reason is untrusted: bound and map it.
    resp.invalidReason = boundFacilitatorReason(
      resp.invalidReason,
      REFUSAL_CODES.FACILITATOR_DECLINED,
    );
  }
  return resp;
}

/**
 * Submit a settlement exactly once. `freshVerify` runs the credentialed verify
 * + claimed→verified transition for a genuinely new claim; a proven-unconsumed
 * lost-response resubmission skips it (the payload was already verified) and
 * resubmits from the reserved `submission_started` row without a second
 * governance lookup.
 */
async function submitSettlement(
  deps: PipelineDeps,
  initialRow: FulfillmentRow,
  payment: ValidatedPayment,
  freshVerify: boolean,
): Promise<SettleResponseWire> {
  const { config } = deps;
  const hash = payment.signedPaymentPayloadHashHex;
  let row = initialRow;

  if (freshVerify) {
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
      const code = boundFacilitatorReason(
        verifyResponse.invalidReason,
        REFUSAL_CODES.FACILITATOR_DECLINED,
      );
      return writeTerminalFailure(deps, hash, ["claimed", "verified"], code, "");
    }
    if (row.state === "claimed") {
      row = deps.ledger.transition(config.network, hash, ["claimed"], "verified");
    }
  }

  // Fresh pre-settle drift guard, immediately before submission (§11 TOCTOU).
  try {
    await requireActiveV8(deps.chain, config);
  } catch (error) {
    markDrift(deps, error);
    throw error;
  }

  if (row.state === "verified") {
    row = deps.ledger.transition(config.network, hash, ["verified"], "submission_started");
  }

  let rawSettle: unknown;
  try {
    rawSettle = await deps.facilitator.settle({
      x402Version: 2,
      paymentPayload: payment.paymentPayload,
      paymentRequirements: payment.requirements,
    });
  } catch (error) {
    // Response lost or refused after journaling: the nonce stays reserved and
    // later retries recover by authorization identity. Never resubmit blindly.
    if (error instanceof ServiceRefusal) throw error;
    throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
  }
  const settleResponse = validateSettleResponse(rawSettle, config.network);
  if (settleResponse.success !== true) {
    const code = boundFacilitatorReason(
      settleResponse.errorReason,
      REFUSAL_CODES.FACILITATOR_SETTLEMENT_DECLINED,
    );
    return writeTerminalFailure(
      deps,
      hash,
      ["submission_started"],
      code,
      settleResponse.transaction,
    );
  }

  deps.ledger.transition(config.network, hash, ["submission_started"], "transaction_observed", {
    settlementTransactionHash: settleResponse.transaction,
  });

  // Post-settle proof: fresh drift guard + full transaction readback.
  let readback;
  try {
    await requireActiveV8(deps.chain, config);
    readback = await deps.chain.getFinalizedTransaction(settleResponse.transaction);
  } catch (error) {
    markDrift(deps, error);
    if (error instanceof DriftError) {
      return writeTerminalFailure(
        deps,
        hash,
        ["transaction_observed"],
        error.code,
        settleResponse.transaction,
      );
    }
    // Observation unavailable: stay transaction_observed; reconcile later.
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }
  const recovery = applyReadback(
    deps,
    { hash, payerAccountHashHex: payment.payerAccountHash.toString("hex") },
    expectedFromPayment(payment, settleResponse.transaction),
    readback,
  );
  if (recovery.status === "finalized" || recovery.status === "failed") {
    return recovery.response;
  }
  // Pending finality: resumable, retryable, row stays transaction_observed.
  throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
}

/** Resolve an already-existing ledger row; returns a response or falls through. */
async function resolveExistingRow(
  deps: PipelineDeps,
  row: FulfillmentRow,
  payment: ValidatedPayment,
): Promise<SettleResponseWire | "resume_new" | "resubmit_from_reserved"> {
  if (row.state === "finalized" || row.state === "failed_terminal") {
    // Exact terminal idempotent retry — BEFORE any volatile gate (WP5-5).
    return validatedStoredResponse(row, deps.config);
  }
  if (row.state === "submission_started" || row.state === "transaction_observed") {
    const recovery = await recoverInFlightRow(deps, row);
    if (recovery.status === "finalized" || recovery.status === "failed") {
      return recovery.response;
    }
    if (recovery.status === "pending") {
      throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
    }
    return "resubmit_from_reserved";
  }
  // claimed / verified: resume the pipeline using the STORED binding.
  return "resume_new";
}

export async function runSettle(
  body: unknown,
  deps: PipelineDeps,
): Promise<SettleResponseWire> {
  const { config, ledger } = deps;
  // 1. Strict parse + hash FIRST — no current-time, no network (WP5-5).
  const payment = validateVerifySettleRequest(body, config);
  const hash = payment.signedPaymentPayloadHashHex;

  // 2. Consult the ledger BEFORE any volatile gate (WP5-5).
  const existing = ledger.get(config.network, hash);
  if (existing !== undefined) {
    const resolved = await resolveExistingRow(deps, existing, payment);
    if (resolved === "resubmit_from_reserved") {
      return submitSettlement(deps, existing, payment, false);
    }
    if (resolved === "resume_new") {
      return submitSettlement(deps, existing, payment, true);
    }
    return resolved;
  }

  // 3. NEW claim: all current-time governance/signature gates run only here.
  const governance = await runCurrentTimeGates(payment, deps);
  const claim = ledger.claim(bindingFrom(payment, governance, config));
  if (claim.outcome === "existing") {
    // Concurrent claim raced us: resolve the now-existing row.
    const resolved = await resolveExistingRow(deps, claim.row, payment);
    if (resolved === "resubmit_from_reserved") {
      return submitSettlement(deps, claim.row, payment, false);
    }
    if (resolved === "resume_new") {
      return submitSettlement(deps, claim.row, payment, true);
    }
    return resolved;
  }
  return submitSettlement(deps, claim.row, payment, true);
}

/**
 * Startup crash-safety: reconcile every journaled in-flight settlement so an
 * authorization nonce can never be reused (or resubmitted) through a crash gap.
 * A lost-response row with no recorded hash is recovered by authorization
 * identity when the observer can prove it; otherwise it stays reserved and a
 * later retry (with request context) submits exactly once.
 */
export async function reconcileLedgerOnStartup(
  deps: PipelineDeps,
): Promise<{ finalized: number; failed: number; pending: number }> {
  let finalized = 0;
  let failed = 0;
  let pending = 0;
  for (const row of deps.ledger.pendingRows()) {
    const recovery = await recoverInFlightRow(deps, row);
    if (recovery.status === "finalized") finalized += 1;
    else if (recovery.status === "failed") failed += 1;
    else pending += 1; // pending or provably-unconsumed both await a retry
  }
  return { finalized, failed, pending };
}

/**
 * Startup readiness probe (WP5-6): current package drift or unavailability must
 * never leave the operational settlement state green. Drift is persisted as
 * blocked_upgrade_drift; an unavailable observer leaves the default
 * blocked_fail_closed state.
 */
export async function probePackageHealthOnStartup(
  deps: PipelineDeps,
): Promise<boolean> {
  try {
    await requireActiveV8(deps.chain, deps.config);
    return true;
  } catch (error) {
    if (error instanceof DriftError) {
      deps.ledger.setSettlementState(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
    }
    return false;
  }
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
