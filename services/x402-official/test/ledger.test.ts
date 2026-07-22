/**
 * Durable ledger: monotonic transitions, restart persistence, and
 * crash-safe authorization-nonce reconciliation (kill mid-journal).
 */

import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import { FulfillmentLedger, type FulfillmentBinding } from "../src/ledger.js";
import { reconcileLedgerOnStartup, runSettle } from "../src/pipeline.js";
import { SETTLEMENT_STATES } from "../src/config.js";
import {
  buildRegistryRecord,
  goodReadback,
  makeDeps,
  makeSignedRequest,
  tempDir,
} from "./helpers.js";

const TX = "cc".repeat(32);

function makeBinding(overrides: Partial<FulfillmentBinding> = {}): FulfillmentBinding {
  return {
    network: "casper:casper-test",
    signedPaymentPayloadHash: "aa".repeat(32),
    resourceId: "finals-report-001",
    actionId: "33".repeat(32),
    envelopeHash: "44".repeat(32),
    resourceUrlHash: "55".repeat(32),
    reportHash: "66".repeat(32),
    paymentRequirementsHash: "77".repeat(32),
    payerAccountHash: "88".repeat(32),
    payeeAccountHash: "ab".repeat(32),
    valueAtomic: "1000000000",
    authorizationNonce: "99".repeat(32),
    wcsprContract: "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
    ...overrides,
  };
}

describe("FulfillmentLedger", () => {
  it("claims once, is idempotent for the same binding, 409 for a changed binding", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const binding = makeBinding();
    expect(ledger.claim(binding).outcome).toBe("new");
    expect(ledger.claim(binding).outcome).toBe("existing");
    try {
      ledger.claim(makeBinding({ actionId: "ff".repeat(32) }));
      throw new Error("expected 409");
    } catch (error) {
      expect(error).toBeInstanceOf(ServiceRefusal);
      expect((error as ServiceRefusal).code).toBe("cross_binding_rejected");
    }
  });

  it("rejects nonce reuse across different payload hashes (unique authorization key)", () => {
    const ledger = new FulfillmentLedger(":memory:");
    ledger.claim(makeBinding());
    try {
      ledger.claim(makeBinding({ signedPaymentPayloadHash: "bb".repeat(32) }));
      throw new Error("expected 409");
    } catch (error) {
      expect((error as ServiceRefusal).code).toBe("authorization_nonce_reused");
    }
  });

  it("enforces monotonic durable transitions", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = makeBinding();
    ledger.claim(b);
    ledger.transition(b.network, b.signedPaymentPayloadHash, ["claimed"], "verified");
    ledger.transition(
      b.network,
      b.signedPaymentPayloadHash,
      ["verified"],
      "submission_started",
    );
    expect(() =>
      ledger.transition(
        b.network,
        b.signedPaymentPayloadHash,
        ["submission_started"],
        "verified" as never,
      ),
    ).toThrow();
    ledger.transition(
      b.network,
      b.signedPaymentPayloadHash,
      ["submission_started"],
      "transaction_observed",
      { settlementTransactionHash: TX },
    );
    ledger.transition(
      b.network,
      b.signedPaymentPayloadHash,
      ["transaction_observed"],
      "finalized",
      { responseJson: "{}", settledAt: new Date().toISOString() },
    );
    expect(() =>
      ledger.transition(
        b.network,
        b.signedPaymentPayloadHash,
        ["finalized"],
        "failed_terminal",
      ),
    ).toThrow();
  });

  it("persists consumed state across reopen from the same volume path", () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");
    const first = new FulfillmentLedger(path);
    const b = makeBinding();
    first.claim(b);
    first.transition(b.network, b.signedPaymentPayloadHash, ["claimed"], "verified");
    first.setSettlementState(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
    first.close();
    const second = new FulfillmentLedger(path);
    const row = second.get(b.network, b.signedPaymentPayloadHash);
    expect(row?.state).toBe("verified");
    expect(second.getSettlementState()).toBe(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
    second.close();
  });
});

describe("crash-safe reconciliation (kill mid-journal)", () => {
  it("crash after journal + submission with recorded tx: startup reconciles to finalized, nonce still unique", async () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");

    // Session 1: journal a submission then "crash" (close without resolving).
    const h1 = makeDeps({}, path);
    const { request, payment, signer } = await makeSignedRequest(h1.config);
    h1.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h1.config),
    };
    h1.chain.transactions.set(TX, new Error("crash before observation"));
    try {
      await runSettle(request, h1.deps);
    } catch {
      /* reconciliation_pending — the process now "dies" */
    }
    const journaled = h1.ledger.get(h1.config.network, payment.signedPaymentPayloadHashHex);
    expect(journaled?.state).toBe("transaction_observed");
    expect(journaled?.settlementTransactionHash).toBe(TX);
    h1.ledger.close();

    // Session 2: fresh process, same volume. Startup reconciliation must
    // resolve the in-flight row from the chain, never resubmit.
    const h2 = makeDeps({}, path);
    h2.chain.transactions.set(TX, goodReadback());
    const summary = await reconcileLedgerOnStartup(h2.deps);
    expect(summary).toEqual({ finalized: 1, failed: 0, pending: 0 });
    const row = h2.ledger.get(h2.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("finalized");

    // Same-binding retry now returns the stored response with zero new
    // facilitator traffic.
    h2.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h2.config),
    };
    const replay = await runSettle(request, h2.deps);
    expect(replay.success).toBe(true);
    expect(replay.transaction).toBe(TX);
    expect(h2.facilitator.settleCalls).toHaveLength(0);
    expect(h2.facilitator.verifyCalls).toHaveLength(0);

    // The authorization nonce can never be reused through the crash gap.
    const now = Math.floor(Date.now() / 1000);
    const nonceHex = payment.nonce.toString("hex");
    const second = await makeSignedRequest(
      h2.config,
      { nonceHex, validAfter: now - 400, validBefore: now + 800 },
      signer,
    );
    h2.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(second.payment, h2.config),
    };
    try {
      await runSettle(second.request, h2.deps);
      throw new Error("expected 409");
    } catch (error) {
      expect((error as ServiceRefusal).code).toBe("authorization_nonce_reused");
    }
    expect(h2.facilitator.settleCalls).toHaveLength(0);
    h2.ledger.close();
  });

  it("crash mid-journal WITHOUT a recorded tx: row stays reserved, retry never resubmits", async () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");

    const h1 = makeDeps({}, path);
    const { request, payment } = await makeSignedRequest(h1.config);
    h1.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h1.config),
    };
    h1.facilitator.settleError = new Error("crash: response lost");
    try {
      await runSettle(request, h1.deps);
    } catch {
      /* facilitator_unreachable — process "dies" mid-flight */
    }
    expect(
      h1.ledger.get(h1.config.network, payment.signedPaymentPayloadHashHex)?.state,
    ).toBe("submission_started");
    h1.ledger.close();

    const h2 = makeDeps({}, path);
    const summary = await reconcileLedgerOnStartup(h2.deps);
    expect(summary).toEqual({ finalized: 0, failed: 0, pending: 1 });
    h2.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h2.config),
    };
    try {
      await runSettle(request, h2.deps);
      throw new Error("expected reconciliation_pending");
    } catch (error) {
      expect((error as ServiceRefusal).code).toBe("reconciliation_pending");
    }
    expect(h2.facilitator.settleCalls).toHaveLength(0);
    h2.ledger.close();
  });

  it("startup reconciliation marks a wrong-contract transaction failed_terminal", async () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");
    const h1 = makeDeps({}, path);
    const { request, payment } = await makeSignedRequest(h1.config);
    h1.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h1.config),
    };
    h1.chain.transactions.set(TX, new Error("crash"));
    try {
      await runSettle(request, h1.deps);
    } catch {
      /* crash */
    }
    h1.ledger.close();

    const h2 = makeDeps({}, path);
    h2.chain.transactions.set(TX, goodReadback({ targetContractHash: "ee".repeat(32) }));
    const summary = await reconcileLedgerOnStartup(h2.deps);
    expect(summary).toEqual({ finalized: 0, failed: 1, pending: 0 });
    const row = h2.ledger.get(h2.config.network, payment.signedPaymentPayloadHashHex);
    expect(row?.state).toBe("failed_terminal");
    expect(row?.failureReason).toBe("blocked_upgrade_drift");
    h2.ledger.close();
  });
});
