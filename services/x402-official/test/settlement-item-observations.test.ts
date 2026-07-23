/**
 * Proof-item builder receipts (security addendum, reviewer items 3 + 5;
 * migrated to the current 22-check registry set).
 *
 * The reviewer showed buildSettlementRegistryItem() fabricating its own
 * passing evidence: identity fields plus one timestamp minted every required
 * check with passed:true. These tests pin the fixed contract: the caller must
 * supply one independently observed receipt PER required check (name, passed,
 * source, observed_at, evidence, optional detail_code), and the builder
 * validates the complete set — refusing on any missing, duplicate, extra,
 * unpassed, unknown-field, or malformed observation. It must be impossible to
 * mint verification_status "verified" from identity fields alone.
 *
 * §13 emission rule: the validated `evidence` receipt field is INPUT ONLY —
 * emitted checks carry only {name, required, passed, source, observed_at,
 * detail_code?}; anything else would invalidate the item in the shared
 * registry and the dashboard.
 */

import { describe, expect, it } from "vitest";

import {
  buildSettlementRegistryItem,
  OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
  SettlementItemError,
  type SettlementCheckObservationInput,
  type SettlementItemInput,
} from "../src/settlement-item.js";
import {
  FIXTURE_OBSERVED_AT as OBSERVED_AT,
  FIXTURE_SOURCE as SOURCE,
  validChecks,
  validInput,
} from "./settlement-item-fixture.js";

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

  it("builds only from a complete set of per-check receipts, emitting the §13 shape", () => {
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
      // §13: the supporting evidence receipt is validated but NEVER emitted.
      expect(Object.keys(check)).toEqual([
        "name",
        "required",
        "passed",
        "source",
        "observed_at",
      ]);
      expect(check).not.toHaveProperty("evidence");
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
        evidence: "not part of the current required set",
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

  it("refuses a receipt carrying a field outside the receipt contract", () => {
    const checks = validChecks();
    checks[4] = {
      ...checks[4]!,
      required: true,
    } as unknown as SettlementCheckObservationInput;
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "unexpected_check_field",
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

  it("refuses a check without supporting evidence (input contract unchanged)", () => {
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

  it("refuses a malformed detail_code but carries a valid one through", () => {
    const bad = validChecks();
    bad[6] = { ...bad[6]!, detail_code: "not a code!" };
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks: bad })))).toBe(
      "invalid_check_detail_code",
    );
    const good = validChecks();
    good[6] = { ...good[6]!, detail_code: "readback_exact" };
    const item = buildSettlementRegistryItem(validInput({ checks: good }));
    expect(item.checks[6]?.detail_code).toBe("readback_exact");
    expect(Object.keys(item.checks[6]!)).toEqual([
      "name",
      "required",
      "passed",
      "source",
      "observed_at",
      "detail_code",
    ]);
  });

  it("refuses a check name violating the frozen grammar", () => {
    const checks = validChecks();
    checks[0] = { ...checks[0]!, name: "FacilitatorVerifyReturnedIsValidTrue" };
    expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "invalid_check_name",
    );
  });
});
