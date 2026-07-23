/**
 * Official settlement registry item (§13, post-freeze interface corrections).
 * Exact non-collapsed dimensions, frozen check-name grammar (including
 * facilitator_verify_returned_is_valid_true), strict UTC-Z chronology
 * (max(check.observed_at) <= captured_at), and no verifier-chosen observation
 * URL anywhere in the artifact.
 */

import { describe, expect, it } from "vitest";

import {
  buildSettlementRegistryItem,
  requireArtifactSource,
  OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
  SettlementItemError,
  type SettlementCheckObservationInput,
  type SettlementItemInput,
} from "../src/settlement-item.js";

function checksObservedAt(observedAt: string): SettlementCheckObservationInput[] {
  return OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS.map((name) => ({
    name,
    passed: true,
    source: "artifacts/live/official-x402-settlement-v1.json",
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
    checks: checksObservedAt("2026-07-22T20:00:00Z"),
    sourceCommit: "abcdef1",
    deploymentCommit: "1234567",
    artifactPath: "artifacts/live/official-x402-settlement-v1.json",
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

describe("buildSettlementRegistryItem — exact dimensions", () => {
  it("emits the exact non-collapsed proof dimensions and full identity", () => {
    const item = buildSettlementRegistryItem(validInput());
    expect(item.proof_type).toBe("official_x402_settlement_v1");
    expect(item.generation).toBe("v3");
    expect(item.lineage).toBe("supplemental");
    expect(item.observation_mode).toBe("live");
    expect(item.temporal_scope).toBe("current");
    expect(item.verification_status).toBe("verified");
    expect(item.execution_outcome).toBe("accepted");
    // Exact identity — never relabelled or partial.
    expect(item.proposal_id).toBe("FINALS-X402-001");
    expect(item.action_id).toBe("33".repeat(32));
    expect(item.envelope_hash).toBe("44".repeat(32));
    expect(item.deployment_domain).toBe("55".repeat(32));
    expect(item.network).toBe("casper:casper-test");
    expect(item.package_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(item.contract_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("accepts the snapshot observation mode", () => {
    expect(buildSettlementRegistryItem(validInput({ observationMode: "snapshot" })).observation_mode).toBe(
      "snapshot",
    );
  });

  it("rejects an invalid observation mode", () => {
    expect(
      codeOf(() =>
        buildSettlementRegistryItem(
          validInput({ observationMode: "guess" as unknown as "live" }),
        ),
      ),
    ).toBe("invalid_observation_mode");
  });
});

describe("check-name grammar (frozen [a-z][a-z0-9_]*)", () => {
  it("uses the normalized facilitator_verify_returned_is_valid_true, never camel-case", () => {
    const item = buildSettlementRegistryItem(validInput());
    const names = item.checks.map((c) => c.name);
    expect(names).toContain("facilitator_verify_returned_is_valid_true");
    expect(names).toContain("facilitator_settle_returned_success_true");
    for (const name of names) expect(name).toMatch(/^[a-z][a-z0-9_]*$/);
    expect(names).toEqual([...OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS]);
    expect(names.join(",")).not.toMatch(/isValid/i);
  });

  it("marks every required check required:true and passed:true", () => {
    const item = buildSettlementRegistryItem(validInput());
    for (const check of item.checks) {
      expect(check.required).toBe(true);
      expect(check.passed).toBe(true);
    }
  });
});

describe("strict UTC-Z chronology", () => {
  it("requires max(check.observed_at) <= captured_at", () => {
    expect(
      codeOf(() =>
        buildSettlementRegistryItem(
          validInput({
            checks: checksObservedAt("2026-07-22T20:10:00Z"),
            capturedAt: "2026-07-22T20:05:00Z",
          }),
        ),
      ),
    ).toBe("check_observed_after_capture");
  });

  it.each([
    ["captured_at not UTC-Z", { capturedAt: "2026-07-22T20:05:00+00:00" }],
    ["check observed_at local", { checks: checksObservedAt("2026-07-22T20:00:00") }],
  ])("rejects non-UTC-Z timestamps (%s)", (_n, overrides) => {
    expect(() => buildSettlementRegistryItem(validInput(overrides))).toThrow(SettlementItemError);
  });
});

describe("no verifier-chosen observation URL", () => {
  it("rejects an RPC endpoint as an artifact source", () => {
    expect(codeOf(() => requireArtifactSource("https://node.testnet.casper.network/rpc"))).toBe(
      "verifier_observation_url_forbidden",
    );
  });

  it("accepts a repo-relative artifact path and an HTTPS artifact URL", () => {
    expect(requireArtifactSource("artifacts/live/x.json")).toBeTruthy();
    expect(requireArtifactSource("https://x402.concordiadao.xyz/proofs/x.json")).toBeTruthy();
  });

  it("the emitted item embeds no rpc/endpoint/observation-url field or value", () => {
    const item = buildSettlementRegistryItem(validInput());
    const json = JSON.stringify(item);
    expect(json.toLowerCase()).not.toContain("/rpc");
    expect(json.toLowerCase()).not.toContain("rpc_url");
    expect(json.toLowerCase()).not.toContain("observation_url");
    expect(json.toLowerCase()).not.toContain("endpoint");
  });
});

describe("identity validation", () => {
  it.each([
    ["actionId", { actionId: "zz".repeat(32) }, "invalid_action_id"],
    ["deploymentDomain", { deploymentDomain: "abc" }, "invalid_deployment_domain"],
    ["settlementTransaction", { settlementTransaction: "1234" }, "invalid_settlement_transaction"],
    ["proposalId", { proposalId: "lower-case" }, "invalid_proposal_id"],
  ])("rejects malformed %s", (_n, overrides, expected) => {
    expect(codeOf(() => buildSettlementRegistryItem(validInput(overrides)))).toBe(expected);
  });
});
