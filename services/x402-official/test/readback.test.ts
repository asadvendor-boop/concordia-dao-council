/**
 * Exact WCSPR post-settle readback (§11, WP5-1). The readback is FAIL-CLOSED:
 * `args` is mandatory and every one of the eight frozen typed arguments is
 * checked for exact CL type, canonical value, and account-only Key variant, plus
 * exact transaction identity. A `finalized:false` readback is PENDING, not
 * terminal (WP5-2). The active-package guard also requires lockStatus Unlocked
 * (WP5-6).
 */

import { describe, expect, it } from "vitest";

import { ServiceRefusal, PendingFinalityError } from "../src/errors.js";
import {
  DriftError,
  requireActiveV8,
  validateSettlementReadback,
  TRANSFER_WITH_AUTHORIZATION_ARGS,
  type ExpectedSettlement,
} from "../src/chain.js";
import type { ReadbackArg, ValidatedPayment } from "../src/types.js";
import {
  MockChain,
  makeConfig,
  makeSignedRequest,
  readbackArgsFor,
  readbackFor,
} from "./helpers.js";

const TX = "cc".repeat(32);

function expectedFor(payment: ValidatedPayment): ExpectedSettlement {
  return {
    transactionHashHex: TX,
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

async function validated() {
  const config = makeConfig();
  const { payment } = await makeSignedRequest(config);
  return { config, payment, expected: expectedFor(payment) };
}

function codeOf(fn: () => void): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error.code;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("validateSettlementReadback — mandatory exact typed args", () => {
  it("accepts a fully exact eight-argument readback", async () => {
    const { config, payment, expected } = await validated();
    expect(() =>
      validateSettlementReadback(readbackFor(payment, TX), config, expected),
    ).not.toThrow();
  });

  it("rejects an absent args map (never fail-open)", async () => {
    const { config, payment, expected } = await validated();
    const rb = readbackFor(payment, TX);
    (rb as { args?: unknown }).args = undefined;
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it("rejects an empty args map", async () => {
    const { config, payment, expected } = await validated();
    const rb = readbackFor(payment, TX, { args: {} });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it.each(TRANSFER_WITH_AUTHORIZATION_ARGS)(
    "rejects a partial args map missing %s",
    async (missing) => {
      const { config, payment, expected } = await validated();
      const args = readbackArgsFor(payment);
      delete (args as Record<string, ReadbackArg>)[missing];
      const rb = readbackFor(payment, TX, { args });
      expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
        "post_settle_readback_failed",
      );
    },
  );

  it("rejects a wrong CL type on the value argument (value match, type mismatch)", async () => {
    const { config, payment, expected } = await validated();
    const args = readbackArgsFor(payment);
    args["value"] = { clType: "U512", value: payment.valueAtomic.toString(10) };
    const rb = readbackFor(payment, TX, { args });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it.each([
    ["bare account hash, no variant", (hex: string) => hex],
    ["hash- (contract) variant", (hex: string) => `hash-${hex}`],
    ["uref- variant", (hex: string) => `uref-${hex}-007`],
  ])("rejects a wrong account variant on from (%s)", async (_n, mutate) => {
    const { config, payment, expected } = await validated();
    const args = readbackArgsFor(payment);
    args["from"] = { clType: "Key", value: mutate(payment.payerAccountHash.toString("hex")) };
    const rb = readbackFor(payment, TX, { args });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it("rejects a readback for a different transaction identity", async () => {
    const { config, payment, expected } = await validated();
    const rb = readbackFor(payment, "dd".repeat(32));
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it("rejects argNames in the wrong order", async () => {
    const { config, payment, expected } = await validated();
    const rb = readbackFor(payment, TX, {
      argNames: ["to", "from", "value", "valid_after", "valid_before", "nonce", "public_key", "signature"],
    });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it.each([
    ["value", (p: ValidatedPayment) => ({ clType: "U256", value: (p.valueAtomic + 1n).toString(10) })],
    ["valid_after", (p: ValidatedPayment) => ({ clType: "U64", value: (p.validAfter + 1n).toString(10) })],
    ["valid_before", (p: ValidatedPayment) => ({ clType: "U64", value: (p.validBefore + 1n).toString(10) })],
    ["nonce", () => ({ clType: "List<U8>", value: "ab".repeat(32) })],
    ["public_key", () => ({ clType: "PublicKey", value: `01${"99".repeat(32)}` })],
    ["signature", () => ({ clType: "List<U8>", value: `01${"77".repeat(64)}` })],
  ])("rejects a per-field value mutation of %s", async (field, make) => {
    const { config, payment, expected } = await validated();
    const args = readbackArgsFor(payment);
    args[field] = make(payment) as ReadbackArg;
    const rb = readbackFor(payment, TX, { args });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });

  it("treats finalized:false as PENDING, never terminal (WP5-2)", async () => {
    const { config, payment, expected } = await validated();
    const rb = readbackFor(payment, TX, { finalized: false });
    expect(() => validateSettlementReadback(rb, config, expected)).toThrow(
      PendingFinalityError,
    );
  });

  it("treats finalized:true + executionSuccess:false as a terminal chain failure", async () => {
    const { config, payment, expected } = await validated();
    const rb = readbackFor(payment, TX, { executionSuccess: false });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "settlement_execution_failed",
    );
  });

  it("rejects an extra unexpected argument in the args map", async () => {
    const { config, payment, expected } = await validated();
    const args = readbackArgsFor(payment);
    (args as Record<string, ReadbackArg>)["amount"] = { clType: "U256", value: "1" };
    const rb = readbackFor(payment, TX, {
      argNames: [...TRANSFER_WITH_AUTHORIZATION_ARGS, "amount"],
      args,
    });
    expect(codeOf(() => validateSettlementReadback(rb, config, expected))).toBe(
      "post_settle_readback_failed",
    );
  });
});

describe("requireActiveV8 — package lock/version/contract identity (WP5-6)", () => {
  it("rejects a locked package as drift even at the exact v8 contract", async () => {
    const config = makeConfig();
    const chain = new MockChain();
    chain.packageStates = [
      { lockStatus: "Locked", enabledVersion: 8, enabledContractHash: config.wcsprContractHash },
    ];
    await expect(requireActiveV8(chain, config)).rejects.toBeInstanceOf(DriftError);
  });

  it("rejects a version drift", async () => {
    const config = makeConfig();
    const chain = new MockChain();
    chain.packageStates = [
      { lockStatus: "Unlocked", enabledVersion: 9, enabledContractHash: config.wcsprContractHash },
    ];
    await expect(requireActiveV8(chain, config)).rejects.toBeInstanceOf(DriftError);
  });

  it("accepts the exact unlocked v8 package", async () => {
    const config = makeConfig();
    const chain = new MockChain();
    await expect(requireActiveV8(chain, config)).resolves.toBeUndefined();
  });
});
