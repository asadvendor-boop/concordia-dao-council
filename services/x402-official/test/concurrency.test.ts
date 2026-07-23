/**
 * Adversarial concurrency (protocol-safety blocker).
 *
 * The reviewer's original race: two concurrent lost-response retries both
 * observed `found:false`, both received a resubmission path, and both called
 * `/settle` (3 total calls including the lost original). The first fix
 * serialized resubmission behind a lease — but the reviewer's follow-up
 * blocker is stronger: a finalized `used_nonces=false` observation proves only
 * "not consumed yet", NOT "the first submission never happened", so ANY
 * automatic resubmission is unsafe. These tests pin the corrected invariant:
 * once submission_started is durably written, that authorization causes AT
 * MOST ONE LIFETIME facilitator `/settle` call — across N concurrent callers,
 * process restarts on the same volume, and any sequence of negative locator
 * observations. Losers get a bounded retryable refusal (never a crash, never
 * another settle call).
 */

import { describe, expect, it } from "vitest";

import { ServiceRefusal, upstreamUnavailable } from "../src/errors.js";
import { runSettle } from "../src/pipeline.js";
import type { SettleResponseWire, SettlementLocator } from "../src/types.js";
import { join } from "node:path";
import {
  buildRegistryRecord,
  goodPackageState,
  makeDeps,
  makeSignedRequest,
  unconsumedAtFinalizedBoundary,
  readbackFor,
  tempDir,
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

/** Journal a settle whose response is "lost" (row reserved, no deploy hash). */
async function lostResponse(h: TestHarness) {
  const made = await governedRequest(h);
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

/**
 * Every concurrent outcome must be bounded: a fulfilled result is the exact
 * finalized success; a rejection is a retryable ServiceRefusal — never a raw
 * Error escaping a lost ledger CAS.
 */
function expectBoundedOutcomes(
  results: PromiseSettledResult<SettleResponseWire>[],
  expectedTx: string,
): { fulfilled: number; rejected: number } {
  let fulfilled = 0;
  let rejected = 0;
  for (const result of results) {
    if (result.status === "fulfilled") {
      fulfilled += 1;
      expect(result.value.success).toBe(true);
      expect(result.value.transaction).toBe(expectedTx);
    } else {
      rejected += 1;
      expect(result.reason).toBeInstanceOf(ServiceRefusal);
      const refused = result.reason as ServiceRefusal;
      expect(refused.code).toBe("reconciliation_pending");
      expect(refused.retryable).toBe(true);
    }
  }
  return { fulfilled, rejected };
}

describe("concurrent lost-response recovery (reviewer race)", () => {
  it("N concurrent retries observing finalized found:false: ALL pending, ONE lifetime settle call, no resubmission", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    // Every concurrent retry sees the nonce unconsumed at a finalized
    // observation boundary. Under the superseded design this admitted one
    // "safe" resubmission; the corrected invariant is that it admits NONE —
    // the pending original can still land later.
    h.chain.locators.set(nonceHex, unconsumedAtFinalizedBoundary());
    h.facilitator.settleResponse = {
      success: true,
      transaction: TX,
      network: h.config.network,
    };
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const results = await Promise.allSettled([
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
    ]);

    // The reviewer's original failure was 3 total settle calls; the first fix
    // allowed 2 (lost original + one leased resubmission). The corrected
    // invariant: the lost original was this authorization's ONE lifetime call.
    expect(h.facilitator.settleCalls).toHaveLength(1);
    for (const result of results) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") {
        expect(result.reason).toBeInstanceOf(ServiceRefusal);
        const refused = result.reason as ServiceRefusal;
        expect(refused.code).toBe("reconciliation_pending");
        expect(refused.retryable).toBe(true);
      }
    }
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("submission_started");
    expect(row?.settlementTransactionHash).toBeNull();

    // The original transaction eventually lands: adoption reconciles it with
    // the lifetime settle-call count still exactly one.
    h.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    const adopted = await runSettle(made.request, h.deps);
    expect(adopted.success).toBe(true);
    expect(adopted.transaction).toBe(TX);
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("restart on the same durable volume: a second process observing finalized found:false stays pending — the reservation, not a lease, forbids submission", async () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");
    const h1 = makeDeps({}, path);
    const made = await lostResponse(h1);
    const nonceHex = made.payment.nonce.toString("hex");
    h1.ledger.close();

    // A fresh process on the same volume (its own transports, zero calls yet).
    const h2 = makeDeps({}, path);
    h2.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(made.payment, h2.config),
    };
    h2.chain.locators.set(nonceHex, unconsumedAtFinalizedBoundary());
    h2.facilitator.settleResponse = {
      success: true,
      transaction: TX,
      network: h2.config.network,
    };
    const err = await refusal(() => runSettle(made.request, h2.deps));
    expect(err.code).toBe("reconciliation_pending");
    // ZERO settle calls from the new process: one lifetime call total.
    expect(h2.facilitator.settleCalls).toHaveLength(0);
    expect(
      h2.ledger.get(h2.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("submission_started");

    // found:true in the new process adopts the ORIGINAL transaction only.
    h2.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    h2.chain.transactions.set(TX, readbackFor(made.payment, TX));
    const adopted = await runSettle(made.request, h2.deps);
    expect(adopted.success).toBe(true);
    expect(adopted.transaction).toBe(TX);
    expect(h2.facilitator.settleCalls).toHaveLength(0);
    h2.ledger.close();
  });
});

describe("indeterminate negative locator results (no finalized boundary)", () => {
  it("a bare found:false with NO observation boundary is indeterminate: pending, never submits again", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    // An ordinary indexer miss — absence asserted with no finalized boundary.
    h.chain.locators.set(nonceHex, { found: false } as unknown as SettlementLocator);
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("reconciliation_pending");
    expect(err.retryable).toBe(true);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("submission_started");
  });

  it("a negative result observed at a NON-finalized boundary is indeterminate: pending, never submits again", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    h.chain.locators.set(
      nonceHex,
      {
        found: false,
        observed: { finalized: false, blockHeight: 424242, stateRootHash: "ee".repeat(32) },
      } as unknown as SettlementLocator,
    );
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("reconciliation_pending");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it.each([
    ["non-integer height", { finalized: true, blockHeight: 1.5, stateRootHash: "ee".repeat(32) }],
    ["negative height", { finalized: true, blockHeight: -1, stateRootHash: "ee".repeat(32) }],
    ["malformed state root", { finalized: true, blockHeight: 7, stateRootHash: "not-hex" }],
    ["missing state root", { finalized: true, blockHeight: 7 }],
    ["boundary not an object", "finalized"],
  ])("a malformed observation boundary (%s) is indeterminate: pending, never submits again", async (_n, observed) => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    h.chain.locators.set(nonceHex, { found: false, observed } as unknown as SettlementLocator);
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("reconciliation_pending");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });
});

describe("concurrent new claims and resumes", () => {
  it("concurrent brand-new claims: exactly one settlement, losers get a bounded retryable refusal", async () => {
    const h = makeDeps();
    const made = await governedRequest(h);
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const results = await Promise.allSettled([
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
    ]);

    expect(h.facilitator.settleCalls).toHaveLength(1);
    const { fulfilled } = expectBoundedOutcomes(results, TX);
    expect(fulfilled).toBeGreaterThanOrEqual(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("finalized");

    const replay = await runSettle(made.request, h.deps);
    expect(replay.success).toBe(true);
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("concurrent resumes from a durable claimed row: exactly one settlement", async () => {
    const h = makeDeps();
    const made = await governedRequest(h);
    // First attempt dies at the credentialed verify: the row stays claimed.
    h.facilitator.verifyError = upstreamUnavailable("facilitator_unreachable");
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("facilitator_unreachable");
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("claimed");
    h.facilitator.verifyError = undefined;
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const results = await Promise.allSettled([
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
    ]);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const { fulfilled } = expectBoundedOutcomes(results, TX);
    expect(fulfilled).toBeGreaterThanOrEqual(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("finalized");
  });

  it("concurrent resumes from a durable verified row: exactly one settlement", async () => {
    const h = makeDeps();
    const made = await governedRequest(h);
    // First attempt dies at the pre-settle drift guard: the row stays verified.
    h.chain.packageStates = [
      goodPackageState(),
      { lockStatus: "Unlocked", enabledVersion: 9, enabledContractHash: "ee".repeat(32) },
      goodPackageState(),
    ];
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("blocked_upgrade_drift");
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("verified");
    h.chain.packageStates = [goodPackageState()];
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const results = await Promise.allSettled([
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
    ]);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const { fulfilled } = expectBoundedOutcomes(results, TX);
    expect(fulfilled).toBeGreaterThanOrEqual(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("finalized");
  });
});
