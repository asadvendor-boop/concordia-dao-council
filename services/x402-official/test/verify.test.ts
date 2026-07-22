/**
 * /verify pipeline: local official EIP-712 verification, governance
 * interlock (404 ungoverned / 409 ambiguous / invalid record), and the fresh
 * pre-verify v8 drift guard — each proving ZERO credentialed facilitator
 * calls on refusal.
 */

import { describe, expect, it } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import { SETTLEMENT_STATES } from "../src/config.js";
import { runVerify } from "../src/pipeline.js";
import { buildRegistryRecord, makeDeps, makeSignedRequest } from "./helpers.js";

async function refusal(fn: () => Promise<unknown>): Promise<ServiceRefusal> {
  try {
    await fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("runVerify", () => {
  it("happy path: governed + v8 + facilitator isValid", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    const response = await runVerify(request, h.deps);
    expect(response.isValid).toBe(true);
    expect(h.registry.calls).toEqual([payment.signedPaymentPayloadHashHex]);
    expect(h.chain.resolveCalls).toBe(1);
    expect(h.facilitator.verifyCalls).toHaveLength(1);
    const sent = h.facilitator.verifyCalls[0] as Record<string, unknown>;
    expect(sent["x402Version"]).toBe(2);
    expect(sent["paymentPayload"]).toBeDefined();
    expect(sent["paymentRequirements"]).toBeDefined();
  });

  it("locally-invalid signature: zero registry and zero facilitator calls", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    const tampered = structuredClone(request) as never as {
      paymentPayload: { payload: { signature: string } };
    };
    // Flip the last signature byte: still canonical encoding, wrong digest.
    const sig = tampered.paymentPayload.payload.signature;
    const last = sig.slice(-2) === "00" ? "01" : "00";
    tampered.paymentPayload.payload.signature = sig.slice(0, -2) + last;
    const error = await refusal(() => runVerify(tampered, h.deps));
    expect(error.httpStatus).toBe(200);
    expect(error.code).toBe("invalid_exact_casper_facilitator_invalid_signature");
    expect(h.registry.calls).toHaveLength(0);
    expect(h.facilitator.verifyCalls).toHaveLength(0);
    expect(h.chain.resolveCalls).toBe(0);
  });

  it("stale payload (expired window, validly signed): zero upstream calls", async () => {
    const h = makeDeps();
    const now = Math.floor(Date.now() / 1000);
    const { request } = await makeSignedRequest(h.config, {
      validAfter: now - 7200,
      validBefore: now - 3600,
    });
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("invalid_exact_casper_facilitator_expired");
    expect(h.registry.calls).toHaveLength(0);
    expect(h.facilitator.verifyCalls).toHaveLength(0);
  });

  it("ungoverned payload (registry 404): refusal with zero facilitator calls", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("ungoverned_payload");
    expect(h.registry.calls).toHaveLength(1);
    expect(h.facilitator.verifyCalls).toHaveLength(0);
    expect(h.chain.resolveCalls).toBe(0);
  });

  it("ambiguous governance binding (registry 409): terminal, zero facilitator calls", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "ambiguous" };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.httpStatus).toBe(409);
    expect(error.code).toBe("ambiguous_governance_binding");
    expect(h.facilitator.verifyCalls).toHaveLength(0);
  });

  it.each([
    ["v3_finalized_exact false", { v3_finalized_exact: false }],
    ["verification_status pending", { verification_status: "pending" }],
    ["unknown extra field", { surprise: true }],
    ["wrong network", { network: "casper:casper" }],
    ["wrong package hash", { package_hash: "ee".repeat(32) }],
    ["wrong contract hash", { contract_hash: "ee".repeat(32) }],
    ["null finalization transaction", { finalization_transaction: null }],
    ["wrong action kind", { action_kind: "NativeTransferV1" }],
  ])("invalid registry record (%s): fail closed, zero facilitator calls", async (_n, overrides) => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config, overrides as never),
    };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("governance_record_invalid");
    expect(h.facilitator.verifyCalls).toHaveLength(0);
  });

  it("registry record with a mismatching bound hash: fail closed", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config, {
        payment_requirements_hash: "ee".repeat(32),
      }),
    };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("governance_record_invalid");
    expect(h.facilitator.verifyCalls).toHaveLength(0);
  });

  it("registry record missing one required exact-envelope check: fail closed", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    const record = buildRegistryRecord(payment, h.config);
    (record["checks"] as unknown[]).pop();
    h.registry.result = { outcome: "found", record };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("governance_record_invalid");
  });

  it("registry record with a duplicated check name: fail closed", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    const record = buildRegistryRecord(payment, h.config);
    const checks = record["checks"] as Record<string, unknown>[];
    checks.push({ ...(checks[0] as Record<string, unknown>) });
    h.registry.result = { outcome: "found", record };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("governance_record_invalid");
  });

  it("registry record with a failed extra required check: fail closed", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    const record = buildRegistryRecord(payment, h.config);
    (record["checks"] as unknown[]).push({
      name: "extra_operator_check",
      required: true,
      passed: false,
      source: "artifacts/live/x.json",
      observed_at: "2026-07-22T20:00:00Z",
    });
    h.registry.result = { outcome: "found", record };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("governance_record_invalid");
  });

  it("pre-verify drift: blocked_upgrade_drift, zero facilitator calls, state recorded", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.packageStates = [
      { lockStatus: "Unlocked", enabledVersion: 9, enabledContractHash: "ee".repeat(32) },
    ];
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("blocked_upgrade_drift");
    expect(h.facilitator.verifyCalls).toHaveLength(0);
    expect(h.ledger.getSettlementState()).toBe(SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT);
  });

  it("chain observation unavailable: fail closed before any facilitator call", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.packageStates = [new Error("offline")];
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("chain_observation_unavailable");
    expect(error.retryable).toBe(true);
    expect(h.facilitator.verifyCalls).toHaveLength(0);
  });

  it("malformed facilitator verify 2xx: terminal safe failure", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.facilitator.verifyResponse = { valid: true };
    const error = await refusal(() => runVerify(request, h.deps));
    expect(error.code).toBe("malformed_facilitator_response");
    expect(error.httpStatus).toBe(502);
  });

  it("passes facilitator isValid:false through unchanged", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.facilitator.verifyResponse = { isValid: false, invalidReason: "nope" };
    const response = await runVerify(request, h.deps);
    expect(response.isValid).toBe(false);
    expect(response.invalidReason).toBe("nope");
  });
});
