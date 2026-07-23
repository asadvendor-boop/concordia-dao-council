/**
 * /settle pipeline: governance interlock, atomic ledger claim, fresh
 * pre-verify + pre-settle drift guards, journaled submission, success:true
 * discipline, post-settle TOCTOU readback, idempotent retry, and
 * cross-binding / nonce-reuse terminal 409s.
 */

import { describe, expect, it } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import { SETTLEMENT_STATES } from "../src/config.js";
import { runSettle } from "../src/pipeline.js";
import {
  buildRegistryRecord,
  readbackFor,
  makeDeps,
  makeSignedRequest,
  type TestHarness,
} from "./helpers.js";

const TX = "cc".repeat(32);

async function refusal(fn: () => Promise<unknown>): Promise<ServiceRefusal> {
  try {
    await fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

async function governedRequest(h: TestHarness) {
  const made = await makeSignedRequest(h.config);
  h.registry.result = {
    outcome: "found",
    record: buildRegistryRecord(made.payment, h.config),
  };
  return made;
}

describe("runSettle", () => {
  it("happy path: three fresh drift checks, journal before settle, finalized only after readback", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
    expect(response.network).toBe("casper:casper-test");
    expect(response.payer).toBe(`00${payment.payerAccountHash.toString("hex")}`);
    // §11: pre-verify, pre-settle, and post-settle drift checks are all
    // independent uncached package resolutions.
    expect(h.chain.resolveCalls).toBe(3);
    expect(h.chain.txCalls).toEqual([TX]);
    expect(h.facilitator.verifyCalls).toHaveLength(1);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");
    expect(row?.settlementTransactionHash).toBe(TX);
    expect(h.ledger.getSettlementState()).toBe(
      SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE,
    );
  });

  it("ungoverned payload: zero facilitator calls and zero ledger rows", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const error = await refusal(() => runSettle(request, h.deps));
    expect(error.code).toBe("ungoverned_payload");
    expect(h.facilitator.verifyCalls).toHaveLength(0);
    expect(h.facilitator.settleCalls).toHaveLength(0);
    expect(
      h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex),
    ).toBeUndefined();
  });

  it("pre-settle drift (after clean pre-verify): no settle submission", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.packageStates = [
      { lockStatus: "Unlocked", enabledVersion: 8, enabledContractHash: h.config.wcsprContractHash },
      { lockStatus: "Unlocked", enabledVersion: 9, enabledContractHash: "ee".repeat(32) },
    ];
    const error = await refusal(() => runSettle(request, h.deps));
    expect(error.code).toBe("blocked_upgrade_drift");
    expect(h.facilitator.verifyCalls).toHaveLength(1);
    expect(h.facilitator.settleCalls).toHaveLength(0);
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("verified"); // journaled, never submitted
    expect(h.ledger.getSettlementState()).toBe(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
  });

  it("post-settle TOCTOU drift: terminal failure, report never releasable", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.packageStates = [
      { lockStatus: "Unlocked", enabledVersion: 8, enabledContractHash: h.config.wcsprContractHash },
      { lockStatus: "Unlocked", enabledVersion: 8, enabledContractHash: h.config.wcsprContractHash },
      { lockStatus: "Unlocked", enabledVersion: 9, enabledContractHash: "ee".repeat(32) },
    ];
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(false);
    expect(response.errorReason).toBe("blocked_upgrade_drift");
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("failed_terminal");
    expect(h.ledger.getSettlementState()).toBe(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
  });

  it("wrong-contract transaction readback: terminal failure", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(
      TX,
      readbackFor(payment, TX, { targetContractHash: "ee".repeat(32), contractVersion: 7 }),
    );
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(false);
    expect(response.errorReason).toBe("blocked_upgrade_drift");
    expect(
      h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("failed_terminal");
  });

  it("readback with an `amount` runtime argument (published-SDK trap): terminal failure", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(
      TX,
      readbackFor(payment, TX, {
        argNames: [
          "from",
          "to",
          "amount", // the pinned 1.0.0 builder bug — must never pass readback
          "valid_after",
          "valid_before",
          "nonce",
          "public_key",
          "signature",
        ],
      }),
    );
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(false);
    expect(response.errorReason).toBe("post_settle_readback_failed");
    expect(
      h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("failed_terminal");
  });

  it("readback finalized:false is PENDING, not terminal: row stays resumable, later finalizes (WP5-2)", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    // Not yet final on chain: this is a retryable pending state, never a
    // terminal failure. The row must remain resumable in transaction_observed.
    h.chain.transactions.set(TX, readbackFor(payment, TX, { finalized: false }));
    const pending = await refusal(() => runSettle(request, h.deps));
    expect(pending.code).toBe("reconciliation_pending");
    expect(pending.retryable).toBe(true);
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("transaction_observed");
    expect(row?.settlementTransactionHash).toBe(TX);
    expect(h.ledger.getSettlementState()).not.toBe(SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE);
    // Finality arrives; the retry reconciles from chain with NO second settle.
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const done = await runSettle(request, h.deps);
    expect(done.success).toBe(true);
    expect(done.transaction).toBe(TX);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex)?.state).toBe(
      "finalized",
    );
  });

  it("readback finalized:true but executionSuccess:false is terminal (defined chain failure)", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(TX, readbackFor(payment, TX, { executionSuccess: false }));
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(false);
    expect(response.errorReason).toBe("settlement_execution_failed");
    expect(h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex)?.state).toBe(
      "failed_terminal",
    );
  });

  it("HTTP 200 with success:false is NOT success and is terminal", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.facilitator.settleResponse = {
      success: false,
      errorReason: "facilitator_says_no",
      transaction: "",
      network: h.config.network,
    };
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(false);
    // Untrusted upstream reason is mapped to a bounded local code, never echoed.
    expect(response.errorReason).toBe("facilitator_settlement_declined");
    // No chain readback for a non-submitted settlement.
    expect(h.chain.txCalls).toHaveLength(0);
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("failed_terminal");
    // The gate still starts and stays fail-closed.
    expect(h.ledger.getSettlementState()).toBe(SETTLEMENT_STATES.BLOCKED_FAIL_CLOSED);
  });

  it("HTTP 200 with success:true but missing transaction/network: malformed, nonce stays reserved", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.facilitator.settleResponse = { success: true };
    const error = await refusal(() => runSettle(request, h.deps));
    expect(error.code).toBe("malformed_facilitator_response");
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("submission_started");
    // Retry does NOT resubmit: it lands in reconciliation.
    const again = await refusal(() => runSettle(request, h.deps));
    expect(again.code).toBe("reconciliation_pending");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("facilitator verify isValid:false during settle: terminal, no submission", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.facilitator.verifyResponse = { isValid: false, invalidReason: "bad_payload" };
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(false);
    // Untrusted upstream reason mapped to a bounded local code.
    expect(response.errorReason).toBe("facilitator_declined");
    expect(h.facilitator.settleCalls).toHaveLength(0);
    expect(
      h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("failed_terminal");
  });

  it("exact same-binding retry is idempotent with exactly one settlement", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const first = await runSettle(request, h.deps);
    expect(first.success).toBe(true);
    const second = await runSettle(request, h.deps);
    expect(second).toEqual(first);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(h.facilitator.verifyCalls).toHaveLength(1);
  });

  it("exact terminal retry is resolved from the ledger BEFORE registry/expiry gates (WP5-5)", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const first = await runSettle(request, h.deps);
    expect(first.success).toBe(true);
    const registryCallsAfterFirst = h.registry.calls.length;
    // Volatile downstreams now all fail: registry outage, chain observer down.
    h.registry.result = { outcome: "not_found" };
    h.chain.packageStates = [new Error("chain down")];
    h.chain.transactions.clear();
    // The exact same request must still return the stored valid response,
    // never re-consulting the registry or the chain (idempotency survives).
    const retry = await runSettle(request, h.deps);
    expect(retry).toEqual(first);
    expect(h.registry.calls).toHaveLength(registryCallsAfterFirst);
    expect(h.chain.resolveCalls).toBe(3); // only the original settlement's three
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("distinct payload hash reusing the same authorization nonce: terminal 409", async () => {
    // Cross-binding / nonce-reuse rejection is enforced at atomic ledger claim
    // time. A genuinely new payload that reuses a consumed nonce fails closed
    // BEFORE any settlement (a same-body retry, by contrast, is idempotent).
    const h = makeDeps();
    const nonceHex = "5b".repeat(32);
    const first = await makeSignedRequest(h.config, { nonceHex });
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(first.payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(first.payment, TX));
    const ok = await runSettle(first.request, h.deps);
    expect(ok.success).toBe(true);
    const settleCallsBefore = h.facilitator.settleCalls.length;
    const now = Math.floor(Date.now() / 1000);
    const second = await makeSignedRequest(
      h.config,
      { nonceHex, validAfter: now - 450, validBefore: now + 650 },
      first.signer,
    );
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(second.payment, h.config),
    };
    const error = await refusal(() => runSettle(second.request, h.deps));
    expect(error.httpStatus).toBe(409);
    expect(error.code).toBe("authorization_nonce_reused");
    expect(h.facilitator.settleCalls).toHaveLength(settleCallsBefore);
  });

  it("authorization-nonce reuse across different payloads: terminal 409 before submission", async () => {
    const h = makeDeps();
    const nonceHex = "9a".repeat(32);
    const first = await makeSignedRequest(h.config, { nonceHex });
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(first.payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(first.payment, TX));
    const ok = await runSettle(first.request, h.deps);
    expect(ok.success).toBe(true);
    // Same signer, same nonce, different window → different payload hash.
    const now = Math.floor(Date.now() / 1000);
    const second = await makeSignedRequest(
      h.config,
      { nonceHex, validAfter: now - 500, validBefore: now + 700 },
      first.signer,
    );
    expect(second.payment.signedPaymentPayloadHashHex).not.toBe(
      first.payment.signedPaymentPayloadHashHex,
    );
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(second.payment, h.config),
    };
    const error = await refusal(() => runSettle(second.request, h.deps));
    expect(error.httpStatus).toBe(409);
    expect(error.code).toBe("authorization_nonce_reused");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("facilitator transport failure after journaling: nonce reserved, reconciliation path", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.facilitator.settleError = new Error("socket reset");
    const error = await refusal(() => runSettle(request, h.deps));
    expect(error.code).toBe("facilitator_unreachable");
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("submission_started");
    // A retry while unobservable never resubmits.
    h.facilitator.settleError = undefined;
    const retry = await refusal(() => runSettle(request, h.deps));
    expect(retry.code).toBe("reconciliation_pending");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("post-settle observation unavailable: row stays transaction_observed, later retry finalizes from chain", async () => {
    const h = makeDeps();
    const { request, payment } = await governedRequest(h);
    h.chain.transactions.set(TX, new Error("observer down"));
    const error = await refusal(() => runSettle(request, h.deps));
    expect(error.code).toBe("reconciliation_pending");
    const row = h.ledger.get(h.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("transaction_observed");
    expect(row?.settlementTransactionHash).toBe(TX);
    // Observer recovers; the retry reconciles by recorded transaction hash
    // without a second facilitator settle call.
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const response = await runSettle(request, h.deps);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });
});
