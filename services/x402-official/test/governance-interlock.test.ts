/**
 * Governance interlock record validation (§13, WP5-6). Beyond the frozen schema
 * and exact identity/hash equality, timestamps must be strict RFC3339 UTC,
 * chronology must hold (no forged future-dated observations), and every proof
 * `source` must be a repository-relative safe path or an HTTPS URL. Duplicate or
 * grammar-violating check names, and any failed required check, fail closed.
 */

import { describe, expect, it } from "vitest";

import { ServiceRefusal } from "../src/errors.js";
import { validateGovernanceRecord, validateProofSource } from "../src/registry.js";
import type { ValidatedPayment } from "../src/types.js";
import type { ServiceConfig } from "../src/config.js";
import { buildRegistryRecord, makeConfig, makeSignedRequest } from "./helpers.js";

async function fixture(): Promise<{ config: ServiceConfig; payment: ValidatedPayment }> {
  const config = makeConfig();
  const { payment } = await makeSignedRequest(config);
  return { config, payment };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error.code;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("validateGovernanceRecord — timestamps and chronology", () => {
  it("accepts a fully valid record and returns the binding", async () => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config);
    const binding = validateGovernanceRecord(record, payment, config);
    expect(binding.actionId).toMatch(/^[0-9a-f]{64}$/);
    expect(binding.finalizedAt).toBe("2026-07-22T20:00:00Z");
  });

  it.each([
    ["local time, no zone", "2026-07-22T20:00:00"],
    ["space separator", "2026-07-22 20:00:00Z"],
    ["explicit +00:00 offset (not UTC-Z)", "2026-07-22T20:00:00+00:00"],
    ["non-Z offset", "2026-07-22T20:00:00+05:00"],
    ["calendar-invalid month", "2026-13-01T00:00:00Z"],
    ["calendar-invalid day", "2026-02-30T00:00:00Z"],
    ["not a timestamp", "yesterday"],
  ])("rejects a non-strict-UTC finalized_at (%s)", async (_n, ts) => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config, { finalized_at: ts });
    expect(codeOf(() => validateGovernanceRecord(record, payment, config))).toBe(
      "governance_record_invalid",
    );
  });

  it("rejects finalized_at chronologically after observed_at", async () => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config, {
      finalized_at: "2026-07-22T21:00:00Z",
      observed_at: "2026-07-22T20:00:00Z",
    });
    expect(codeOf(() => validateGovernanceRecord(record, payment, config))).toBe(
      "governance_record_invalid",
    );
  });

  it("rejects a forged future-dated check observation (after observed_at)", async () => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config);
    (record["checks"] as Record<string, unknown>[])[0]!["observed_at"] =
      "2030-01-01T00:00:00Z";
    expect(codeOf(() => validateGovernanceRecord(record, payment, config))).toBe(
      "governance_record_invalid",
    );
  });

  it("rejects a non-UTC check observed_at", async () => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config);
    (record["checks"] as Record<string, unknown>[])[0]!["observed_at"] = "not-a-time";
    expect(codeOf(() => validateGovernanceRecord(record, payment, config))).toBe(
      "governance_record_invalid",
    );
  });
});

describe("validateGovernanceRecord — proof source identity", () => {
  it.each([
    ["absolute filesystem path", "/etc/passwd"],
    ["parent traversal", "artifacts/../../etc/shadow"],
    ["backslash path", "artifacts\\live\\x.json"],
    ["http (not https) url", "http://evil.example/x.json"],
    ["url with userinfo", "https://user:pw@evil.example/x.json"],
  ])("rejects an unsafe check source (%s)", async (_n, source) => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config);
    (record["checks"] as Record<string, unknown>[])[0]!["source"] = source;
    expect(codeOf(() => validateGovernanceRecord(record, payment, config))).toBe(
      "governance_record_invalid",
    );
  });

  it("accepts a repo-relative path and an HTTPS url as sources", () => {
    expect(validateProofSource("artifacts/live/exact-envelope-v3.json")).toBeTruthy();
    expect(validateProofSource("https://x402.concordiadao.xyz/proofs/x.json")).toBeTruthy();
  });
});

describe("validateGovernanceRecord — check-name grammar", () => {
  it("rejects an extra check whose name violates [a-z][a-z0-9_]* grammar", async () => {
    const { config, payment } = await fixture();
    const record = buildRegistryRecord(payment, config);
    (record["checks"] as unknown[]).push({
      name: "Operator-Check", // uppercase + hyphen violate the grammar
      required: false,
      passed: true,
      source: "artifacts/live/x.json",
      observed_at: "2026-07-22T20:00:00Z",
    });
    expect(codeOf(() => validateGovernanceRecord(record, payment, config))).toBe(
      "governance_record_invalid",
    );
  });
});
