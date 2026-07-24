/**
 * Stored-response integrity + database terminal invariants (security addendum,
 * reviewer items 2 + 4 + 5).
 *
 * The reviewer changed a stored response's transaction while leaving the digest
 * unchanged and an idempotent retry returned the forged transaction. These
 * tests pin the fixed invariants: every stored-response replay recomputes the
 * canonical digest of the stored bytes and binds the response's terminal fields
 * to the row's columns; the ledger refuses to WRITE a terminal row violating
 * the invariants and refuses to READ (replay) a corrupt one. Fail closed —
 * an integrity refusal, never a synthesized fallback response.
 */

import DatabaseConstructor from "better-sqlite3";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import {
  FulfillmentLedger,
  responseHash,
  type FulfillmentBinding,
  type FulfillmentRow,
} from "../src/ledger.js";
import { runSettle, validatedStoredResponse } from "../src/pipeline.js";
import {
  buildRegistryRecord,
  makeConfig,
  makeDeps,
  makeSignedRequest,
  readbackFor,
  tempDir,
  type TestHarness,
} from "./helpers.js";

const TX = "cc".repeat(32);
const FORGED_TX = "dd".repeat(32);

async function refusal(fn: () => Promise<unknown>): Promise<ServiceRefusal> {
  try {
    await fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

function refusalSync(fn: () => unknown): ServiceRefusal {
  try {
    fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

/** Finalize one settlement on a durable on-disk ledger. */
async function finalizedOnDisk(): Promise<{
  h: TestHarness;
  path: string;
  made: Awaited<ReturnType<typeof makeSignedRequest>>;
  first: { success: boolean; transaction: string };
}> {
  const dir = tempDir();
  const path = join(dir, "x402-official.db");
  const h = makeDeps({}, path);
  const made = await makeSignedRequest(h.config);
  h.registry.result = {
    outcome: "found",
    record: buildRegistryRecord(made.payment, h.config),
  };
  h.chain.transactions.set(TX, readbackFor(made.payment, TX));
  const first = await runSettle(made.request, h.deps);
  expect(first.success).toBe(true);
  expect(first.transaction).toBe(TX);
  return { h, path, made, first };
}

/** Tamper with the durable row through an independent SQLite connection. */
function corrupt(path: string, hash: string, sets: Record<string, string | null>): void {
  const db = new DatabaseConstructor(path);
  const assignments = Object.keys(sets)
    .map((column) => `${column} = ?`)
    .join(", ");
  db.prepare(
    `UPDATE x402_fulfillments SET ${assignments} WHERE signed_payment_payload_hash = ?`,
  ).run(...Object.values(sets), hash);
  db.close();
}

function readStoredJson(path: string, hash: string): string {
  const db = new DatabaseConstructor(path);
  const row = db
    .prepare(
      `SELECT response_json FROM x402_fulfillments WHERE signed_payment_payload_hash = ?`,
    )
    .get(hash) as { response_json: string };
  db.close();
  return row.response_json;
}

describe("stored-response tampering fails closed on replay (reviewer item 2)", () => {
  it("response-byte tampering (forged transaction, digest unchanged): replay refuses, forged transaction is NEVER returned", async () => {
    const { h, path, made } = await finalizedOnDisk();
    const hash = made.payment.signedPaymentPayloadHashHex;
    const stored = JSON.parse(readStoredJson(path, hash)) as Record<string, unknown>;
    stored["transaction"] = FORGED_TX; // digest column left untouched
    corrupt(path, hash, { response_json: JSON.stringify(stored) });

    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("ledger_terminal_invariant_violated");
    // Fail closed: no fallback response is synthesized, no new settlement.
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("digest-column tampering: replay refuses", async () => {
    const { h, path, made } = await finalizedOnDisk();
    const hash = made.payment.signedPaymentPayloadHashHex;
    corrupt(path, hash, { settlement_response_hash: "11".repeat(32) });
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("ledger_terminal_invariant_violated");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("consistently forged bytes+digest still fail: the transaction column binds the row", async () => {
    const { h, path, made } = await finalizedOnDisk();
    const hash = made.payment.signedPaymentPayloadHashHex;
    const stored = JSON.parse(readStoredJson(path, hash)) as Record<string, unknown>;
    stored["transaction"] = FORGED_TX;
    const forgedJson = JSON.stringify(stored);
    // The attacker recomputes a matching digest — the row's transaction column
    // must still refuse the swap.
    corrupt(path, hash, {
      response_json: forgedJson,
      settlement_response_hash: responseHash(forgedJson),
    });
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("ledger_terminal_invariant_violated");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });
});

describe("terminal rows with missing/impossible fields fail closed on read (reviewer item 4)", () => {
  it.each([
    ["missing settled_at", { settled_at: null }],
    ["missing response_json", { response_json: null }],
    ["missing response digest", { settlement_response_hash: null }],
    ["non-64-hex transaction hash", { settlement_transaction_hash: "abc123" }],
    ["failure reason on a finalized row", { failure_reason: "blocked_upgrade_drift" }],
  ])("finalized row with %s refuses (never replayed as success)", async (_n, sets) => {
    const { h, path, made } = await finalizedOnDisk();
    const hash = made.payment.signedPaymentPayloadHashHex;
    corrupt(path, hash, sets as Record<string, string | null>);
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("ledger_terminal_invariant_violated");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("failed-terminal row whose failure code does not match its stored response refuses", async () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");
    const h = makeDeps({}, path);
    const made = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(made.payment, h.config),
    };
    h.facilitator.settleResponse = {
      success: false,
      errorReason: "insufficient_funds",
      transaction: "",
      network: h.config.network,
    };
    const failed = await runSettle(made.request, h.deps);
    expect(failed.success).toBe(false);
    expect(failed.errorReason).toBe("insufficient_funds");

    const hash = made.payment.signedPaymentPayloadHashHex;
    corrupt(path, hash, { failure_reason: "expired" });
    const err = await refusal(() => runSettle(made.request, h.deps));
    expect(err.code).toBe("ledger_terminal_invariant_violated");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });
});

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
    validAfter: "1753142400",
    validBefore: "1753146000",
    authorizationNonce: "99".repeat(32),
    publicKey: `01${"22".repeat(32)}`,
    signature: `01${"33".repeat(64)}`,
    wcsprContract: "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
    ...overrides,
  };
}

function observedRow(ledger: FulfillmentLedger): FulfillmentBinding {
  const b = makeBinding();
  ledger.claim(b);
  ledger.transition(b.network, b.signedPaymentPayloadHash, ["claimed"], "verified");
  ledger.transition(b.network, b.signedPaymentPayloadHash, ["verified"], "submission_started");
  ledger.transition(
    b.network,
    b.signedPaymentPayloadHash,
    ["submission_started"],
    "transaction_observed",
    { settlementTransactionHash: TX },
  );
  return b;
}

function validSuccessJson(b: FulfillmentBinding): string {
  return JSON.stringify({
    success: true,
    transaction: TX,
    network: b.network,
    payer: `00${b.payerAccountHash}`,
  });
}

describe("ledger write-time terminal invariants (reviewer item 4)", () => {
  it("refuses to finalize without a response digest, and rolls the write back", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = observedRow(ledger);
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["transaction_observed"], "finalized", {
        responseJson: validSuccessJson(b),
        settledAt: new Date().toISOString(),
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
    // The refused write must not commit.
    expect(ledger.get(b.network, b.signedPaymentPayloadHash)?.state).toBe("transaction_observed");
  });

  it("refuses to finalize with a digest that does not match the response bytes", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = observedRow(ledger);
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["transaction_observed"], "finalized", {
        responseJson: validSuccessJson(b),
        settlementResponseHash: "11".repeat(32),
        settledAt: new Date().toISOString(),
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
  });

  it("refuses to finalize without settled_at", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = observedRow(ledger);
    const json = validSuccessJson(b);
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["transaction_observed"], "finalized", {
        responseJson: json,
        settlementResponseHash: responseHash(json),
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
  });

  it("refuses to finalize when the stored response's transaction differs from the row's", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = observedRow(ledger);
    const forged = JSON.stringify({
      success: true,
      transaction: FORGED_TX,
      network: b.network,
      payer: `00${b.payerAccountHash}`,
    });
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["transaction_observed"], "finalized", {
        responseJson: forged,
        settlementResponseHash: responseHash(forged),
        settledAt: new Date().toISOString(),
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
  });

  it("accepts a fully consistent finalized write", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = observedRow(ledger);
    const json = validSuccessJson(b);
    const row = ledger.transition(
      b.network,
      b.signedPaymentPayloadHash,
      ["transaction_observed"],
      "finalized",
      {
        responseJson: json,
        settlementResponseHash: responseHash(json),
        settledAt: new Date().toISOString(),
      },
    );
    expect(row.state).toBe("finalized");
  });

  it("refuses a failed-terminal write with an unbounded failure code", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = makeBinding();
    ledger.claim(b);
    const code = "Not A Bounded Code!";
    const json = JSON.stringify({
      success: false,
      errorReason: code,
      transaction: "",
      network: b.network,
    });
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["claimed"], "failed_terminal", {
        failureReason: code,
        responseJson: json,
        settlementResponseHash: responseHash(json),
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
  });

  it("refuses a failed-terminal write whose response does not carry the failure code", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = makeBinding();
    ledger.claim(b);
    const json = JSON.stringify({
      success: false,
      errorReason: "expired",
      transaction: "",
      network: b.network,
    });
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["claimed"], "failed_terminal", {
        failureReason: "insufficient_funds",
        responseJson: json,
        settlementResponseHash: responseHash(json),
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
  });

  it("refuses a failed-terminal write with no stored failure response", () => {
    const ledger = new FulfillmentLedger(":memory:");
    const b = makeBinding();
    ledger.claim(b);
    const err = refusalSync(() =>
      ledger.transition(b.network, b.signedPaymentPayloadHash, ["claimed"], "failed_terminal", {
        failureReason: "insufficient_funds",
      }),
    );
    expect(err.code).toBe("ledger_terminal_invariant_violated");
  });
});

describe("validatedStoredResponse replay verification (reviewer item 2, pipeline layer)", () => {
  const config = makeConfig();

  function terminalRow(overrides: Partial<FulfillmentRow> = {}): FulfillmentRow {
    const b = makeBinding();
    const json = validSuccessJson(b);
    return {
      ...b,
      state: "finalized",
      settlementTransactionHash: TX,
      settlementResponseHash: responseHash(json),
      responseJson: json,
      settledAt: "2026-07-22T20:00:00.000Z",
      failureReason: null,
      recoveryLeaseId: null,
      recoveryLeaseExpiresAt: null,
      createdAt: "2026-07-22T19:59:00.000Z",
      updatedAt: "2026-07-22T20:00:00.000Z",
      ...overrides,
    };
  }

  it("accepts a consistent stored finalized response", () => {
    const response = validatedStoredResponse(terminalRow(), config);
    expect(response.success).toBe(true);
    expect(response.transaction).toBe(TX);
  });

  it("refuses a digest mismatch", () => {
    const err = refusalSync(() =>
      validatedStoredResponse(terminalRow({ settlementResponseHash: "11".repeat(32) }), config),
    );
    expect(err.code).toBe("stored_response_integrity_failure");
  });

  it("refuses when the response transaction does not equal the row's transaction column", () => {
    const b = makeBinding();
    const forged = JSON.stringify({
      success: true,
      transaction: FORGED_TX,
      network: b.network,
      payer: `00${b.payerAccountHash}`,
    });
    const err = refusalSync(() =>
      validatedStoredResponse(
        terminalRow({ responseJson: forged, settlementResponseHash: responseHash(forged) }),
        config,
      ),
    );
    expect(err.code).toBe("stored_response_integrity_failure");
  });

  it("refuses a payer that does not bind to the row's payer account hash", () => {
    const b = makeBinding();
    const forged = JSON.stringify({
      success: true,
      transaction: TX,
      network: b.network,
      payer: `00${"ff".repeat(32)}`,
    });
    const err = refusalSync(() =>
      validatedStoredResponse(
        terminalRow({ responseJson: forged, settlementResponseHash: responseHash(forged) }),
        config,
      ),
    );
    expect(err.code).toBe("stored_response_integrity_failure");
  });

  it("refuses a missing stored response instead of synthesizing a fallback", () => {
    const err = refusalSync(() =>
      validatedStoredResponse(
        terminalRow({ responseJson: null, settlementResponseHash: null }),
        config,
      ),
    );
    expect(err.code).toBe("stored_response_integrity_failure");
  });

  it("refuses a non-terminal row outright", () => {
    const err = refusalSync(() =>
      validatedStoredResponse(terminalRow({ state: "transaction_observed" }), config),
    );
    expect(err.code).toBe("stored_response_integrity_failure");
  });
});
