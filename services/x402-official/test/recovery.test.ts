/**
 * Lost-response recovery (§11, WP5-3). A `/settle` whose response is lost leaves
 * a reserved row with no recorded deploy hash. Recovery is by exact
 * payer/package/nonce authorization identity:
 *   - observer finds the deploy  → adopt it, reconcile, finalize, ZERO 2nd settle
 *   - observer PROVES unconsumed at an explicit finalized observation boundary
 *     → resubmit exactly once (under the durable recovery lease)
 *   - observer unavailable       → stay pending (retryable), never resubmit blind
 * The authorization nonce can never be reused through the crash gap.
 */

import { describe, expect, it } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import { reconcileLedgerOnStartup, runSettle } from "../src/pipeline.js";
import {
  buildRegistryRecord,
  provedUnconsumed,
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

/** Journal a settle whose response is "lost" (row reserved, no deploy hash). */
async function lostResponse(h: TestHarness) {
  const made = await makeSignedRequest(h.config);
  h.registry.result = {
    outcome: "found",
    record: buildRegistryRecord(made.payment, h.config),
  };
  h.facilitator.settleError = new Error("response lost in transit");
  const err = await refusal(() => runSettle(made.request, h.deps));
  expect(err.code).toBe("facilitator_unreachable");
  const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
  expect(row?.state).toBe("submission_started");
  expect(row?.settlementTransactionHash).toBeNull();
  expect(h.facilitator.settleCalls).toHaveLength(1);
  h.facilitator.settleError = undefined;
  return made;
}

describe("lost /settle response recovery", () => {
  it("observer finds the already-submitted deploy: adopt + finalize with ZERO second settle", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    // The facilitator DID submit before the response was lost.
    h.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const response = await runSettle(made.request, h.deps);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
    // Recovered by authorization identity — no blind second settlement.
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(h.chain.locateCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");
    expect(row?.settlementTransactionHash).toBe(TX);
  });

  it("observer proves the nonce unconsumed at a finalized boundary: resubmit EXACTLY once and finalize", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    // The lost attempt never reached the chain; the nonce is provably unused
    // at an explicit finalized observation boundary (a bare miss would NOT be
    // proof and would stay pending — see concurrency.test.ts).
    h.chain.locators.set(nonceHex, provedUnconsumed());
    h.facilitator.settleResponse = {
      success: true,
      transaction: TX,
      network: h.config.network,
    };
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const response = await runSettle(made.request, h.deps);
    expect(response.success).toBe(true);
    // Exactly one real settlement reached the chain (1 lost attempt + 1 real).
    expect(h.facilitator.settleCalls).toHaveLength(2);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");
  });

  it("observer unavailable: stays pending and never resubmits blindly", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    // No locator entry → the observer cannot determine the outcome.
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("reconciliation_pending");
    expect(err.retryable).toBe(true);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("submission_started");
  });

  it("startup reconciliation adopts a recovered deploy with ZERO second settle and keeps the nonce unique", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    h.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const summary = await reconcileLedgerOnStartup(h.deps);
    expect(summary).toEqual({ finalized: 1, failed: 0, pending: 0 });
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");

    // The nonce can never be reused through the crash gap.
    const now = Math.floor(Date.now() / 1000);
    const second = await makeSignedRequest(
      h.config,
      { nonceHex, validAfter: now - 300, validBefore: now + 900 },
      made.signer,
    );
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(second.payment, h.config),
    };
    const err = await refusal(() => runSettle(second.request, h.deps));
    expect(err.code).toBe("authorization_nonce_reused");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });
});
