/**
 * Proof-item builder receipts (security addendum, reviewer items 3 + 5).
 *
 * The reviewer showed buildSettlementRegistryItem() fabricating its own
 * passing evidence: identity fields plus one timestamp minted every required
 * check with passed:true. These tests pin the fixed contract: the caller must
 * supply one independently observed receipt PER required check (name, passed,
 * source, observed_at, evidence), and the builder validates the complete set —
 * refusing on any missing, duplicate, extra, unpassed, or malformed
 * observation. It must be impossible to mint verification_status "verified"
 * from identity fields alone.
 */

import { describe, expect, it } from "vitest";

import {
  buildSettlementRegistryItem,
  OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
  SettlementItemError,
  type SettlementCheckObservationInput,
  type SettlementItemInput,
} from "../src/settlement-item.js";

const SOURCE = "artifacts/live/official-x402-settlement-v1.json";
const OBSERVED_AT = "2026-07-22T20:00:00Z";

export function validChecks(
  observedAt = OBSERVED_AT,
): SettlementCheckObservationInput[] {
  return OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS.map((name) => ({
    name,
    passed: true,
    source: SOURCE,
    observed_at: observedAt,
    evidence: `independently captured artifact record for ${name}`,
  }));
}

function validInput(overrides: Partial<SettlementItemInput> = {}): SettlementItemInput {
  return {
    proposalId: "FINALS-X402-001",
    actionId: "33".repeat(32),
    envelopeHash: "44".repeat(32),
    deploymentDomain: "55".repeat(32),
    network: "casper:casper-test",
    packageHash: "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e",
    contractHash: "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
    paymentRequirementsHash: "ab".repeat(32),
    signedPaymentPayloadHash: "cd".repeat(32),
    reportHash: "ef".repeat(32),
    settlementTransaction: "66".repeat(32),
    observationMode: "live",
    capturedAt: "2026-07-22T20:05:00Z",
    checks: validChecks(),
    sourceCommit: "abcdef1",
    deploymentCommit: "1234567",
    artifactPath: SOURCE,
    artifactSha256: "77".repeat(32),
    ...overrides,
  };
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof SettlementItemError) return error.message;
    throw error;
  }
  throw new Error("expected a SettlementItemError");
}

describe("the builder cannot fabricate evidence (reviewer item 3)", () => {
  it("REFUSES to mint verified from identity fields alone (the reviewer's reproduction)", () => {
    const identityOnly = { ...validInput() } as Record<string, unknown>;
    delete identityOnly["checks"];
    // The pre-fix API shape: identity fields + one generic timestamp.
    identityOnly["checkObservedAt"] = OBSERVED_AT;
    expect(() =>
      buildSettlementRegistryItem(identityOnly as unknown as SettlementItemInput),
    ).toThrow(SettlementItemError);
  });

  it("builds only from a complete set of per-check receipts, carrying each receipt through", () => {
    const item = buildSettlementRegistryItem(validInput());
    expect(item.verification_status).toBe("verified");
    expect(item.checks.map((c) => c.name)).toEqual([
      ...OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
    ]);
    for (const check of item.checks) {
      expect(check.required).toBe(true);
      expect(check.passed).toBe(true);
      expect(check.source).toBe(SOURCE);
      expect(check.observed_at).toBe(OBSERVED_AT);
      expect(check.evidence).toContain(check.name);
    }
  });

  it("refuses EACH required check when its observation is missing", () => {
    for (const name of OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS) {
      const checks = validChecks().filter((c) => c.name !== name);
      expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
        "missing_check_observation",
      );
    }
  });

  it("refuses EACH required check when its observation is not passed", () => {
    for (const name of OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS) {
      const checks = validChecks().map((c) =>
        c.name === name ? { ...c, passed: false } : c,
      );
      expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
        "check_not_passed",
      );
    }
  });

  it("refuses a duplicated check observation", () => {
    const checks = [...validChecks(), validChecks()[0]!];
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "duplicate_check_observation",
    );
  });

  it("refuses an extra check outside the required set", () => {
    const checks = [
      ...validChecks(),
      {
        name: "self_asserted_extra_check",
        passed: true,
        source: SOURCE,
        observed_at: OBSERVED_AT,
        evidence: "not part of the frozen required set",
      },
    ];
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "unexpected_check",
    );
  });

  it("refuses an empty or non-array check set", () => {
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks: [] })))).toBe(
      "missing_check_observation",
    );
    expect(
      codeOf(() =>
        buildSettlementRegistryItem(
          validInput({ checks: "all-passed" as unknown as SettlementCheckObservationInput[] }),
        ),
      ),
    ).toBe("invalid_check_observations");
  });

  it("refuses a malformed observation object", () => {
    const checks = validChecks();
    checks[0] = null as unknown as SettlementCheckObservationInput;
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "invalid_check_observation",
    );
  });

  it("refuses a check whose observed_at is not strict UTC-Z", () => {
    const checks = validChecks();
    checks[2] = { ...checks[2]!, observed_at: "2026-07-22T20:00:00+00:00" };
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "invalid_check_observed_at",
    );
  });

  it("refuses a check observed after captured_at (per-check chronology)", () => {
    const checks = validChecks();
    checks[5] = { ...checks[5]!, observed_at: "2026-07-22T20:10:00Z" };
    expect(
      codeOf(() =>
        buildSettlementRegistryItem(
          validInput({ checks, capturedAt: "2026-07-22T20:05:00Z" }),
        ),
      ),
    ).toBe("check_observed_after_capture");
  });

  it("refuses a check sourced from a verifier-chosen RPC observation endpoint", () => {
    const checks = validChecks();
    checks[1] = { ...checks[1]!, source: "https://node.testnet.casper.network/rpc" };
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "verifier_observation_url_forbidden",
    );
  });

  it("refuses a check without supporting evidence", () => {
    const empty = validChecks();
    empty[3] = { ...empty[3]!, evidence: "" };
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks: empty })))).toBe(
      "invalid_check_evidence",
    );
    const missing = validChecks();
    delete (missing[3] as unknown as Record<string, unknown>)["evidence"];
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks: missing })))).toBe(
      "invalid_check_evidence",
    );
  });

  it("refuses a check name violating the frozen grammar", () => {
    const checks = validChecks();
    checks[0] = { ...checks[0]!, name: "FacilitatorVerifyReturnedIsValidTrue" };
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "invalid_check_name",
    );
  });
});
