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
 *
 * Security addendum:
 *  - Exactly-one-submission is enforced under CONCURRENCY: every path to a
 *    facilitator `/settle` call first takes durable exclusive ownership in the
 *    ledger (the verified→submission_started CAS for a fresh submission, the
 *    atomic recovery lease for a lost-response resubmission) BEFORE any
 *    settlement network I/O. A caller that loses any ownership CAS returns a
 *    bounded retryable pending refusal and never submits.
 *  - A negative authorization lookup is proof of non-submission ONLY when it
 *    asserts an explicit finalized observation boundary; anything weaker is
 *    indeterminate and stays pending.
 *  - Every stored-response replay is integrity-verified (canonical digest of
 *    the stored bytes + terminal-field binding to the row); a mismatch is a
 *    fail-closed integrity refusal, never a synthesized fallback.
 */

import { randomUUID } from "node:crypto";

import {
  ServiceRefusal,
  PendingFinalityError,
  integrityRefusal,
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
  SettlementLocator,
  ValidatedPayment,
  VerifyResponseWire,
} from "./types.js";

/**
 * Exclusive submission/recovery ownership window (security addendum, item 1).
 * Long enough to cover the credentialed settle + readback round trips; short
 * enough that a crashed owner's lease expires and recovery can proceed.
 */
const SUBMISSION_LEASE_TTL_MS = 120_000;

const HEX64_RE = /^[0-9a-f]{64}$/;

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

function storedIntegrityFailure(): never {
  throw integrityRefusal(REFUSAL_CODES.STORED_RESPONSE_INTEGRITY_FAILURE);
}

/**
 * Exact terminal retry (WP5-5; security addendum, item 2). Every stored-
 * response replay recomputes the canonical SHA-256 digest of the stored
 * response bytes and requires it to equal the stored digest column, then binds
 * the response's terminal fields to the row: a finalized replay must carry the
 * row's exact 64-hex transaction and payer binding with `settled_at` present
 * and no failure reason; a failed replay must carry the row's bounded failure
 * code and recorded transaction. Any missing or mismatched value is a
 * fail-closed integrity refusal — a fallback response is NEVER synthesized.
 */
export function validatedStoredResponse(
  row: FulfillmentRow,
  config: ServiceConfig,
): SettleResponseWire {
  if (row.state !== "finalized" && row.state !== "failed_terminal") {
    storedIntegrityFailure();
  }
  if (row.responseJson === null || row.settlementResponseHash === null) {
    storedIntegrityFailure();
  }
  if (responseHash(row.responseJson) !== row.settlementResponseHash) {
    storedIntegrityFailure();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.responseJson);
  } catch {
    storedIntegrityFailure();
  }
  let response: SettleResponseWire;
  try {
    response = validateSettleResponse(parsed, config.network);
  } catch {
    // Locally stored bytes failing wire validation are corrupt local state.
    storedIntegrityFailure();
  }
  if (row.state === "finalized") {
    if (response.success !== true) storedIntegrityFailure();
    if (
      row.settlementTransactionHash === null ||
      !HEX64_RE.test(row.settlementTransactionHash) ||
      response.transaction !== row.settlementTransactionHash
    ) {
      storedIntegrityFailure();
    }
    if (response.payer !== `00${row.payerAccountHash}`) storedIntegrityFailure();
    if (row.settledAt === null || row.failureReason !== null) {
      storedIntegrityFailure();
    }
  } else {
    if (response.success !== false) storedIntegrityFailure();
    if (
      row.failureReason === null ||
      response.errorReason !== row.failureReason
    ) {
      storedIntegrityFailure();
    }
    if (response.transaction !== (row.settlementTransactionHash ?? "")) {
      storedIntegrityFailure();
    }
    if (row.settledAt !== null) storedIntegrityFailure();
  }
  return response;
}

/**
 * Re-read the durable row after losing a terminal write race: if another
 * caller already recorded a terminal outcome, adopt (and integrity-verify)
 * THAT response — the ledger, not the in-memory caller, is the source of
 * truth. Integrity refusals from the read propagate (fail closed).
 */
function adoptTerminalOutcome(
  deps: PipelineDeps,
  hash: string,
): SettleResponseWire | undefined {
  const row = deps.ledger.get(deps.config.network, hash);
  if (row === undefined) return undefined;
  if (row.state === "finalized" || row.state === "failed_terminal") {
    return validatedStoredResponse(row, deps.config);
  }
  return undefined;
}

function writeTerminalFailure(
  deps: PipelineDeps,
  hash: string,
  from: RowState[],
  code: string,
  transaction: string,
): SettleResponseWire {
  // Terminal invariant (item 4): the stored body's transaction must match the
  // row's transaction column exactly. Only a 64-hex deploy hash is recordable;
  // anything else is stored as the empty placeholder.
  const boundTransaction = HEX64_RE.test(transaction) ? transaction : "";
  const body: SettleResponseWire = {
    success: false,
    errorReason: code,
    transaction: boundTransaction,
    network: deps.config.network,
  };
  const json = JSON.stringify(body);
  try {
    deps.ledger.transition(deps.config.network, hash, from, "failed_terminal", {
      failureReason: code,
      responseJson: json,
      settlementResponseHash: responseHash(json),
      ...(boundTransaction === ""
        ? {}
        : { settlementTransactionHash: boundTransaction }),
    });
  } catch (error) {
    if (error instanceof ServiceRefusal) throw error;
    // Lost a terminal write race: adopt the durable outcome, never overwrite.
    const adopted = adoptTerminalOutcome(deps, hash);
    if (adopted !== undefined) return adopted;
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }
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
  try {
    deps.ledger.transition(deps.config.network, hash, ["transaction_observed"], "finalized", {
      responseJson: json,
      settlementResponseHash: responseHash(json),
      settledAt: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof ServiceRefusal) throw error;
    // Lost a finalize race: adopt the durable, integrity-verified outcome.
    const adopted = adoptTerminalOutcome(deps, hash);
    if (adopted !== undefined) return adopted;
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }
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
 * A negative chain lookup (`found:false`) is proof of non-submission ONLY when
 * the observer explicitly asserts the finalized observation boundary it
 * queried: the literal `finalized:true`, a non-negative integer finalized
 * block height, and the 64-hex state root actually queried. Ordinary indexer
 * absence — or any weaker/malformed assertion — is NOT proof and is treated as
 * indeterminate (pending; never a resubmission).
 */
function isProvedUnconsumed(locator: SettlementLocator): boolean {
  if (locator.found !== false) return false;
  const observed: unknown = (locator as { observed?: unknown }).observed;
  if (typeof observed !== "object" || observed === null) return false;
  const boundary = observed as Record<string, unknown>;
  const height = boundary["blockHeight"];
  const stateRoot = boundary["stateRootHash"];
  return (
    boundary["finalized"] === true &&
    typeof height === "number" &&
    Number.isInteger(height) &&
    height >= 0 &&
    typeof stateRoot === "string" &&
    HEX64_RE.test(stateRoot)
  );
}

/**
 * Reconcile one in-flight row against the chain. For a row with a recorded
 * deploy hash, read it back. For a row whose `/settle` response was lost (no
 * recorded hash), recover the deploy by exact authorization identity — adopting
 * an already-submitted transaction WITHOUT a second settlement, or proving the
 * nonce is unconsumed at an explicit finalized observation boundary so that
 * exactly one lease-holding caller may resubmit (WP5-3, security addendum
 * item 1). Never issues a facilitator call.
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
    if (locator.found !== true) {
      if (!isProvedUnconsumed(locator)) {
        // Weaker than a finalized-boundary proof: indeterminate → pending.
        return { status: "pending" };
      }
      // Provably unconsumed at an explicit finalized observation boundary.
      return { status: "unconsumed" };
    }
    try {
      current = deps.ledger.transition(
        current.network,
        current.signedPaymentPayloadHash,
        ["submission_started"],
        "transaction_observed",
        { settlementTransactionHash: locator.transactionHash },
      );
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      // Lost an adoption race: the durable row is the source of truth.
      const fresh = deps.ledger.get(
        current.network,
        current.signedPaymentPayloadHash,
      );
      if (fresh === undefined) return { status: "pending" };
      if (fresh.state === "finalized") {
        return {
          status: "finalized",
          response: validatedStoredResponse(fresh, deps.config),
        };
      }
      if (fresh.state === "failed_terminal") {
        return {
          status: "failed",
          response: validatedStoredResponse(fresh, deps.config),
        };
      }
      if (fresh.settlementTransactionHash === null) return { status: "pending" };
      current = fresh;
    }
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
 * CAS a durable transition. Losing the race to another concurrent caller is a
 * bounded, retryable pending refusal — the loser must never continue toward a
 * facilitator submission. Integrity refusals propagate unchanged.
 */
function transitionOrPending(
  deps: PipelineDeps,
  hash: string,
  from: RowState[],
  to: RowState,
  extra?: {
    recoveryLeaseId?: string;
    recoveryLeaseExpiresAt?: string;
  },
): FulfillmentRow {
  try {
    return deps.ledger.transition(deps.config.network, hash, from, to, extra);
  } catch (error) {
    if (error instanceof ServiceRefusal) throw error;
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }
}

type SubmissionMode =
  | { freshVerify: true }
  | { freshVerify: false; leaseId: string };

/**
 * Submit a settlement exactly once, under concurrency (security addendum,
 * item 1). `freshVerify` runs the credentialed verify + claimed→verified CAS
 * for a genuinely new claim and takes the durable submission lease inside the
 * verified→submission_started CAS; a proven-unconsumed lost-response
 * resubmission arrives already holding the recovery lease. Either way, the
 * caller owns durable exclusive submission rights BEFORE the `/settle` network
 * I/O — a caller that loses any CAS returns pending and never submits.
 */
async function submitSettlement(
  deps: PipelineDeps,
  initialRow: FulfillmentRow,
  payment: ValidatedPayment,
  mode: SubmissionMode,
): Promise<SettleResponseWire> {
  const { config } = deps;
  const hash = payment.signedPaymentPayloadHashHex;
  let row = initialRow;
  let leaseId: string;

  if (mode.freshVerify) {
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
      row = transitionOrPending(deps, hash, ["claimed"], "verified");
    }
  }

  // Fresh pre-settle drift guard, immediately before submission (§11 TOCTOU).
  try {
    await requireActiveV8(deps.chain, config);
  } catch (error) {
    markDrift(deps, error);
    throw error;
  }

  if (mode.freshVerify) {
    // Exclusive-ownership CAS: exactly one caller journals submission_started,
    // taking the durable submission lease in the same atomic write.
    leaseId = randomUUID();
    row = transitionOrPending(deps, hash, ["verified"], "submission_started", {
      recoveryLeaseId: leaseId,
      recoveryLeaseExpiresAt: new Date(
        Date.now() + SUBMISSION_LEASE_TTL_MS,
      ).toISOString(),
    });
  } else {
    // Lost-response resubmission: the recovery lease was claimed atomically
    // before this call.
    leaseId = mode.leaseId;
  }
  if (row.state !== "submission_started") {
    // Never submit without durable exclusive ownership.
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }

  let settleResponse: SettleResponseWire;
  try {
    const rawSettle = await deps.facilitator.settle({
      x402Version: 2,
      paymentPayload: payment.paymentPayload,
      paymentRequirements: payment.requirements,
    });
    settleResponse = validateSettleResponse(rawSettle, config.network);
  } catch (error) {
    // Response lost/malformed after journaling: the attempt is over but its
    // outcome is unrecorded. Release the exclusive lease (owner-checked); the
    // nonce stays reserved by the durable submission_started row, and any
    // resubmission must first re-prove the nonce unconsumed at a finalized
    // observation boundary AND win the recovery lease. Never resubmit blindly.
    deps.ledger.releaseRecoveryLease(config.network, hash, leaseId);
    if (error instanceof ServiceRefusal) throw error;
    throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
  }
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

  try {
    deps.ledger.transition(config.network, hash, ["submission_started"], "transaction_observed", {
      settlementTransactionHash: settleResponse.transaction,
    });
  } catch (error) {
    if (error instanceof ServiceRefusal) throw error;
    // A concurrent recovery adopted an observation for this row first. The
    // durable record wins; if it names a different transaction, reconcile from
    // the recorded identity later — never trust our in-memory copy.
    const adopted = adoptTerminalOutcome(deps, hash);
    if (adopted !== undefined) return adopted;
    const fresh = deps.ledger.get(config.network, hash);
    if (
      fresh === undefined ||
      fresh.settlementTransactionHash !== settleResponse.transaction
    ) {
      throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
    }
  }

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

type ExistingResolution =
  | { kind: "response"; response: SettleResponseWire }
  | { kind: "resume_new" }
  | { kind: "resubmit_from_reserved"; leaseId: string };

/** Resolve an already-existing ledger row; returns a response or falls through. */
async function resolveExistingRow(
  deps: PipelineDeps,
  row: FulfillmentRow,
): Promise<ExistingResolution> {
  if (row.state === "finalized" || row.state === "failed_terminal") {
    // Exact terminal idempotent retry — BEFORE any volatile gate (WP5-5),
    // integrity-verified against the stored digest and terminal columns.
    return { kind: "response", response: validatedStoredResponse(row, deps.config) };
  }
  if (row.state === "submission_started" || row.state === "transaction_observed") {
    const recovery = await recoverInFlightRow(deps, row);
    if (recovery.status === "finalized" || recovery.status === "failed") {
      return { kind: "response", response: recovery.response };
    }
    if (recovery.status === "pending") {
      throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
    }
    // Provably unconsumed. Exactly ONE caller may own resubmission: take the
    // durable atomic recovery lease BEFORE any resubmission network I/O
    // (item 1). Every loser stays pending and never resubmits.
    const leaseId = randomUUID();
    const now = Date.now();
    const claimed = deps.ledger.claimRecoveryLease(
      deps.config.network,
      row.signedPaymentPayloadHash,
      leaseId,
      new Date(now).toISOString(),
      new Date(now + SUBMISSION_LEASE_TTL_MS).toISOString(),
    );
    if (!claimed) {
      throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
    }
    return { kind: "resubmit_from_reserved", leaseId };
  }
  // claimed / verified: resume the pipeline using the STORED binding.
  return { kind: "resume_new" };
}

async function settleExistingRow(
  deps: PipelineDeps,
  row: FulfillmentRow,
  payment: ValidatedPayment,
): Promise<SettleResponseWire> {
  const resolved = await resolveExistingRow(deps, row);
  if (resolved.kind === "response") return resolved.response;
  if (resolved.kind === "resubmit_from_reserved") {
    return submitSettlement(deps, row, payment, {
      freshVerify: false,
      leaseId: resolved.leaseId,
    });
  }
  return submitSettlement(deps, row, payment, { freshVerify: true });
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
    return settleExistingRow(deps, existing, payment);
  }

  // 3. NEW claim: all current-time governance/signature gates run only here.
  const governance = await runCurrentTimeGates(payment, deps);
  const claim = ledger.claim(bindingFrom(payment, governance, config));
  if (claim.outcome === "existing") {
    // Concurrent claim raced us: resolve the now-existing row.
    return settleExistingRow(deps, claim.row, payment);
  }
  return submitSettlement(deps, claim.row, payment, { freshVerify: true });
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
