/**
 * Lost-response recovery (§11, WP5-3; protocol-safety blocker). A `/settle`
 * whose response is lost leaves a reserved row with no recorded deploy hash.
 * HARD INVARIANT under test: once submission_started is durably written, that
 * authorization causes AT MOST ONE LIFETIME facilitator `/settle` call —
 * regardless of response loss, restart, concurrency, negative locator results,
 * or elapsed time. Recovery is by exact payer/package/nonce authorization
 * identity:
 *   - observer finds the deploy → adopt the EXACT original transaction,
 *     reconcile, finalize — ZERO additional settle calls
 *   - observer reports found:false — even at a finalized boundary — that
 *     proves only "not consumed yet": stay PENDING, never submit again
 *   - observer unavailable/indeterminate → stay pending (retryable)
 *   - valid_before passed AND a finalized observation strictly after
 *     valid_before shows the nonce unused → terminalize
 *     authorization_expired_unrecovered (manual reauthorization with a FRESH
 *     authorization/nonce; the old authorization is never resubmitted)
 * The authorization nonce can never be reused through the crash gap.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import { reconcileLedgerOnStartup, runSettle } from "../src/pipeline.js";
import {
  buildRegistryRecord,
  unconsumedAtFinalizedBoundary,
  readbackFor,
  makeDeps,
  makeSignedRequest,
  type TestHarness,
} from "./helpers.js";

const TX = "cc".repeat(32);

afterEach(() => {
  vi.restoreAllMocks();
});

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
  it("observer finds the already-submitted deploy: adopt + finalize with ZERO additional settle calls", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    // The facilitator DID submit before the response was lost.
    h.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const response = await runSettle(made.request, h.deps);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
    // Recovered by authorization identity — never a second settlement.
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(h.chain.locateCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");
    expect(row?.settlementTransactionHash).toBe(TX);
  });

  it("found:false at a finalized boundary proves only 'not consumed yet': stays pending, ZERO additional settle calls, and the pending original can still land", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    // The nonce is unconsumed at an explicit finalized observation boundary.
    // That does NOT prove the first facilitator submission never happened — a
    // pending first transaction can still land later. The service must keep
    // waiting and must NEVER call /settle again, even though the facilitator
    // stands ready to answer.
    h.chain.locators.set(nonceHex, unconsumedAtFinalizedBoundary());
    h.facilitator.settleResponse = {
      success: true,
      transaction: TX,
      network: h.config.network,
    };
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    // Repeated retries: every one is pending; the settle-call count never moves.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const err = await refusal(() => runSettle(made.request, h.deps));
      expect(err.code).toBe("reconciliation_pending");
      expect(err.retryable).toBe(true);
    }
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("submission_started");

    // The reviewer's scenario: the "provably unconsumed" first transaction now
    // LANDS. Because nothing was resubmitted, adoption is clean and the
    // lifetime settle-call count is still exactly one.
    h.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    const response = await runSettle(made.request, h.deps);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("finalized");
  });

  it("locator alternates false / unavailable / true across retries: zero new calls, true adopts only the ORIGINAL transaction", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    h.facilitator.settleResponse = {
      success: true,
      transaction: "dd".repeat(32), // would be a DIFFERENT tx if ever resubmitted
      network: h.config.network,
    };
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    // Retry 1: finalized found:false → pending.
    h.chain.locators.set(nonceHex, unconsumedAtFinalizedBoundary());
    expect((await refusal(() => runSettle(made.request, h.deps))).code).toBe(
      "reconciliation_pending",
    );
    // Retry 2: observer unavailable → pending.
    h.chain.locators.set(nonceHex, new Error("observer down"));
    expect((await refusal(() => runSettle(made.request, h.deps))).code).toBe(
      "reconciliation_pending",
    );
    // Retry 3: finalized found:false again → still pending.
    h.chain.locators.set(nonceHex, unconsumedAtFinalizedBoundary());
    expect((await refusal(() => runSettle(made.request, h.deps))).code).toBe(
      "reconciliation_pending",
    );
    expect(h.facilitator.settleCalls).toHaveLength(1);

    // Retry 4: found:true → adopt exactly the original transaction.
    h.chain.locators.set(nonceHex, { found: true, transactionHash: TX });
    const response = await runSettle(made.request, h.deps);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");
    expect(row?.settlementTransactionHash).toBe(TX);
  });

  it("observer unavailable: stays pending and never submits again", async () => {
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

  it("startup reconciliation adopts a recovered deploy with ZERO additional settle calls and keeps the nonce unique", async () => {
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

describe("expiry terminalization (authorization_expired_unrecovered)", () => {
  /** Epoch ms of the payment's own valid_before (persisted on the row). */
  function expiryMsOf(made: Awaited<ReturnType<typeof lostResponse>>): number {
    return Number(made.payment.validBefore) * 1000;
  }

  it("valid_before passed + finalized observation strictly after expiry shows the nonce unused: terminalize with the bounded code, zero additional settle calls, replayable stored failure", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    const expiryMs = expiryMsOf(made);
    // Finalized snapshot taken strictly AFTER the authorization expired: the
    // contract can no longer accept the original transaction.
    h.chain.locators.set(
      nonceHex,
      unconsumedAtFinalizedBoundary({
        blockTimestamp: new Date(expiryMs + 50_000).toISOString(),
      }),
    );
    // Even now, a facilitator standing ready must never be asked again.
    h.facilitator.settleResponse = {
      success: true,
      transaction: "dd".repeat(32),
      network: h.config.network,
    };
    vi.spyOn(Date, "now").mockReturnValue(expiryMs + 100_000);

    const response = await runSettle(made.request, h.deps);
    expect(response.success).toBe(false);
    expect(response.errorReason).toBe("authorization_expired_unrecovered");
    expect(response.transaction).toBe("");
    // Expiry does NOT permit a second call (lifetime count stays 1).
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("failed_terminal");
    expect(row?.failureReason).toBe("authorization_expired_unrecovered");
    expect(row?.settledAt).toBeNull();
    expect(row?.settlementTransactionHash).toBeNull();

    // The stored failure replays idempotently (integrity-verified), with no
    // registry, chain, or facilitator traffic — manual reauthorization means a
    // FRESH authorization/nonce, never this one again.
    const locateCallsBefore = h.chain.locateCalls.length;
    const replay = await runSettle(made.request, h.deps);
    expect(replay).toEqual(response);
    expect(h.facilitator.settleCalls).toHaveLength(1);
    expect(h.chain.locateCalls).toHaveLength(locateCallsBefore);
  });

  it("N concurrent retries at proven expiry: EXACTLY ONE CAS terminalize, every caller gets the same stored failure, zero additional settle calls", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    const expiryMs = expiryMsOf(made);
    h.chain.locators.set(
      nonceHex,
      unconsumedAtFinalizedBoundary({
        blockTimestamp: new Date(expiryMs + 50_000).toISOString(),
      }),
    );
    vi.spyOn(Date, "now").mockReturnValue(expiryMs + 100_000);
    const transitionSpy = vi.spyOn(h.ledger, "transition");

    const results = await Promise.allSettled([
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
      runSettle(made.request, h.deps),
    ]);
    for (const result of results) {
      expect(result.status).toBe("fulfilled");
      if (result.status === "fulfilled") {
        expect(result.value.success).toBe(false);
        expect(result.value.errorReason).toBe("authorization_expired_unrecovered");
      }
    }
    expect(h.facilitator.settleCalls).toHaveLength(1);
    // Exactly one caller's terminal CAS write succeeded; every racer adopted
    // the durable outcome instead of writing (or submitting) anything.
    const successfulTerminalWrites = transitionSpy.mock.calls
      .map((call, index) => ({
        to: call[3],
        result: transitionSpy.mock.results[index],
      }))
      .filter((x) => x.to === "failed_terminal" && x.result?.type === "return");
    expect(successfulTerminalWrites).toHaveLength(1);
    expect(
      h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("failed_terminal");
  });

  it("startup reconciliation applies proven-expiry terminalization with zero facilitator calls", async () => {
    const h = makeDeps();
    const made = await lostResponse(h);
    const nonceHex = made.payment.nonce.toString("hex");
    const expiryMs = expiryMsOf(made);
    h.chain.locators.set(
      nonceHex,
      unconsumedAtFinalizedBoundary({
        blockTimestamp: new Date(expiryMs + 50_000).toISOString(),
      }),
    );
    vi.spyOn(Date, "now").mockReturnValue(expiryMs + 100_000);

    const summary = await reconcileLedgerOnStartup(h.deps);
    expect(summary).toEqual({ finalized: 0, failed: 1, pending: 0 });
    expect(h.facilitator.settleCalls).toHaveLength(1);
    const row = h.ledger.get(h.config.network, made.payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("failed_terminal");
    expect(row?.failureReason).toBe("authorization_expired_unrecovered");
  });

  it.each([
    [
      "finalized boundary timestamp BEFORE valid_before (stale snapshot), clock past expiry",
      (expiryMs: number) =>
        unconsumedAtFinalizedBoundary({
          blockTimestamp: new Date(expiryMs - 50_000).toISOString(),
        }),
      true,
    ],
    [
      "finalized boundary timestamp EXACTLY valid_before (not strictly after), clock past expiry",
      (expiryMs: number) =>
        unconsumedAtFinalizedBoundary({
          blockTimestamp: new Date(expiryMs).toISOString(),
        }),
      true,
    ],
    [
      "finalized boundary missing its block timestamp, clock past expiry",
      (expiryMs: number) => {
        void expiryMs;
        const locator = unconsumedAtFinalizedBoundary() as {
          found: false;
          observed: Record<string, unknown>;
        };
        delete locator.observed["blockTimestamp"];
        return locator;
      },
      true,
    ],
    [
      "finalized boundary with a non-UTC block timestamp, clock past expiry",
      (expiryMs: number) => {
        void expiryMs;
        return unconsumedAtFinalizedBoundary({
          blockTimestamp: "2026-07-23T12:00:00+05:00",
        });
      },
      true,
    ],
    [
      "bare found:false with no boundary at all, clock past expiry",
      (expiryMs: number) => {
        void expiryMs;
        return { found: false } as unknown as ReturnType<
          typeof unconsumedAtFinalizedBoundary
        >;
      },
      true,
    ],
    [
      "finalized boundary after valid_before but the local clock is still inside the window",
      (expiryMs: number) =>
        unconsumedAtFinalizedBoundary({
          blockTimestamp: new Date(expiryMs + 50_000).toISOString(),
        }),
      false,
    ],
  ])(
    "expiry NOT provable (%s): stays pending, never terminalizes, never submits again",
    async (_name, locatorFor, clockPastExpiry) => {
      const h = makeDeps();
      const made = await lostResponse(h);
      const nonceHex = made.payment.nonce.toString("hex");
      const expiryMs = Number(made.payment.validBefore) * 1000;
      h.chain.locators.set(nonceHex, locatorFor(expiryMs));
      if (clockPastExpiry) {
        vi.spyOn(Date, "now").mockReturnValue(expiryMs + 100_000);
      }

      const err = await refusal(() => runSettle(made.request, h.deps));
      expect(err.code).toBe("reconciliation_pending");
      expect(err.retryable).toBe(true);
      expect(h.facilitator.settleCalls).toHaveLength(1);
      const row = h.ledger.get(
        h.config.network,
        made.payment.signedPaymentPayloadHashHex,
      );
      expect(row?.state).toBe("submission_started");
      expect(row?.failureReason).toBeNull();
    },
  );
});
