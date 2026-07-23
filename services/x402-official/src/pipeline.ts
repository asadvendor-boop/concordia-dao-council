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
 * ONE HARD INVARIANT (protocol-safety blocker): AT MOST ONE facilitator
 * `/settle` request per authorization, EVER — across retries, concurrency,
 * restarts, lost responses, negative locator results, and elapsed time. The
 * durable verified→submission_started CAS is the single exclusive-submission
 * gate, taken BEFORE any settlement network I/O; states are monotonic, so once
 * `submission_started` is journaled no code path can reach `/settle` for that
 * authorization again. There is NO automatic resubmission: a `found:false`
 * authorization lookup — even at a finalized observation boundary — proves
 * only "not consumed yet", NOT "the first submission never happened" (a
 * pending first transaction can still land later). A reserved lost-response
 * row is resolved only by (a) adopting the exact original transaction when
 * `found:true`, or (b) proven-expiry terminalization: once `valid_before` has
 * passed AND a finalized observation strictly after `valid_before` shows the
 * nonce unconsumed, the contract can no longer accept the original
 * transaction, and the row terminalizes as `authorization_expired_unrecovered`
 * (manual reauthorization with a FRESH authorization/nonce — never the old
 * one). Anything weaker stays pending. New settlements for a NEW authorization
 * are unaffected.
 *
 * Security addendum:
 *  - Every stored-response replay is integrity-verified (canonical digest of
 *    the stored bytes + terminal-field binding to the row); a mismatch is a
 *    fail-closed integrity refusal, never a synthesized fallback.
 */

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
import { parseRfc3339Utc } from "./time.js";
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
  | { status: "pending" };

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
 * Extract the finalized observation boundary's block timestamp (epoch ms) from
 * a NEGATIVE locator result. Returns a number ONLY when the whole boundary is
 * well-formed: the literal `finalized:true`, a non-negative integer finalized
 * block height, the 64-hex state root actually queried, and a strict RFC3339
 * UTC block timestamp. Anything weaker or malformed is indeterminate (null).
 *
 * NOTE what even a well-formed boundary proves: ONLY "the nonce was not
 * consumed as of that finalized snapshot" — NEVER "the original facilitator
 * submission did not happen". No negative observation ever justifies a second
 * `/settle` call; its only affirmative use is proven-expiry terminalization.
 */
function finalizedBoundaryTimestampMs(locator: SettlementLocator): number | null {
  if (locator.found !== false) return null;
  const observed: unknown = (locator as { observed?: unknown }).observed;
  if (typeof observed !== "object" || observed === null) return null;
  const boundary = observed as Record<string, unknown>;
  const height = boundary["blockHeight"];
  const stateRoot = boundary["stateRootHash"];
  if (
    boundary["finalized"] !== true ||
    typeof height !== "number" ||
    !Number.isInteger(height) ||
    height < 0 ||
    typeof stateRoot !== "string" ||
    !HEX64_RE.test(stateRoot)
  ) {
    return null;
  }
  return parseRfc3339Utc(boundary["blockTimestamp"]);
}

/** Maximum epoch seconds still exactly representable after ×1000 (Date range). */
const MAX_EPOCH_SECONDS = 8_640_000_000_000;

/**
 * The row's persisted `valid_before` (canonical U64 epoch seconds) as epoch
 * milliseconds. Returns null (fail-safe: never terminalize) for any value that
 * is not a safely representable epoch.
 */
function validBeforeEpochMs(row: FulfillmentRow): number | null {
  if (!/^\d+$/.test(row.validBefore)) return null;
  const seconds = Number(row.validBefore);
  if (!Number.isSafeInteger(seconds) || seconds > MAX_EPOCH_SECONDS) return null;
  return seconds * 1000;
}

/**
 * Reconcile one in-flight row against the chain. For a row with a recorded
 * deploy hash, read it back. For a row whose `/settle` response was lost (no
 * recorded hash), poll for the EXACT original transaction by authorization
 * identity (WP5-3):
 *  - `found:true`  → adopt the original transaction and reconcile through the
 *    readback path — never a second settlement.
 *  - `found:false` — even at a finalized observation boundary — proves only
 *    "not consumed yet": the row stays PENDING (the pending first transaction
 *    can still land later). The ONLY exception is proven expiry: when
 *    `valid_before` has passed on the local clock AND the finalized boundary's
 *    block timestamp is strictly after `valid_before`, the on-chain contract
 *    can no longer accept the original transaction, so the row terminalizes as
 *    `authorization_expired_unrecovered` (manual reauthorization required)
 *    through the ledger's terminal CAS — exactly one caller writes it.
 *  - observer unavailable/indeterminate → pending.
 * NEVER issues a facilitator call (hard invariant: at most one `/settle` per
 * authorization, ever).
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
      const boundaryMs = finalizedBoundaryTimestampMs(locator);
      const expiryMs = validBeforeEpochMs(current);
      if (
        boundaryMs !== null &&
        expiryMs !== null &&
        Date.now() > expiryMs &&
        boundaryMs > expiryMs
      ) {
        // Proven expiry: the authorization's own validity window has passed
        // AND a finalized observation strictly after valid_before shows the
        // nonce unconsumed — the contract can no longer accept the original
        // transaction. Terminalize (bounded code, replayable stored failure)
        // via the existing terminal CAS: exactly one caller writes it, every
        // racer adopts the durable outcome. Recovery now requires MANUAL
        // reauthorization with a FRESH authorization/nonce — the old
        // authorization is never resubmitted.
        const response = writeTerminalFailure(
          deps,
          current.signedPaymentPayloadHash,
          ["submission_started"],
          REFUSAL_CODES.AUTHORIZATION_EXPIRED_UNRECOVERED,
          "",
        );
        return { status: "failed", response };
      }
      // Not provably expired: keep waiting. A negative lookup — finalized
      // boundary or not — never proves the first submission didn't happen,
      // so it must never trigger another one.
      return { status: "pending" };
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
): FulfillmentRow {
  try {
    return deps.ledger.transition(deps.config.network, hash, from, to);
  } catch (error) {
    if (error instanceof ServiceRefusal) throw error;
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
  }
}

/**
 * Submit a settlement for a genuinely NEW claim (or a resumed claimed/verified
 * row that has never been submitted). This is the ONLY function that calls
 * `facilitator.settle`, and the durable verified→submission_started CAS taken
 * here — BEFORE the `/settle` network I/O — is the single exclusive-submission
 * gate: exactly one caller (across processes and restarts) can ever journal
 * `submission_started` for an authorization, states are monotonic, and no
 * recovery path re-enters this function. That is the hard invariant: at most
 * ONE facilitator `/settle` request per authorization, EVER. A caller that
 * loses any CAS returns a bounded retryable pending refusal and never submits.
 */
async function submitSettlement(
  deps: PipelineDeps,
  initialRow: FulfillmentRow,
  payment: ValidatedPayment,
): Promise<SettleResponseWire> {
  const { config } = deps;
  const hash = payment.signedPaymentPayloadHashHex;
  let row = initialRow;

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

  // Fresh pre-settle drift guard, immediately before submission (§11 TOCTOU).
  try {
    await requireActiveV8(deps.chain, config);
  } catch (error) {
    markDrift(deps, error);
    throw error;
  }

  // Exclusive-ownership CAS: exactly one caller, ever, journals
  // submission_started for this authorization. Once this durable write lands,
  // the row can never return to a submittable state.
  row = transitionOrPending(deps, hash, ["verified"], "submission_started");
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
    // outcome is unrecorded. The durable submission_started row keeps the
    // authorization reserved FOREVER against another submission: every retry
    // and startup reconciliation only polls for the exact original
    // transaction (adopt on found:true) or terminalizes on proven expiry.
    // There is no resubmission path — this `/settle` call was this
    // authorization's one and only.
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
  | { kind: "resume_new" };

/**
 * Resolve an already-existing ledger row; returns a response or falls through
 * to the fresh pipeline ONLY for a never-submitted claimed/verified row. A row
 * that has reached submission_started can NEVER route back to a facilitator
 * submission (hard invariant): its only exits are adopting the exact original
 * transaction, proven-expiry terminalization, or staying pending.
 */
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
    // Pending: the original submission's outcome is still unknown — keep the
    // durable row reserved and retry reconciliation later. NEVER submit again.
    throw upstreamUnavailable(REFUSAL_CODES.RECONCILIATION_PENDING);
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
  return submitSettlement(deps, row, payment);
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
  return submitSettlement(deps, claim.row, payment);
}

/**
 * Startup crash-safety: reconcile every journaled in-flight settlement so an
 * authorization nonce can never be reused — or submitted a second time —
 * through a crash gap. A lost-response row with no recorded hash is resolved
 * ONLY by adopting the exact original transaction (`found:true`) or by
 * proven-expiry terminalization; anything else stays reserved and pending.
 * Startup reconciliation never issues a facilitator call.
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
    else pending += 1; // outcome still unknown: reserved, awaiting evidence
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
