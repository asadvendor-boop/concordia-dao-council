/**
 * Official settlement registry item (§13, current registry authority).
 * Exact non-collapsed dimensions, the CURRENT 22-check required set copied
 * from shared/proof_registry.py (including the post-freeze snake-case
 * facilitator_verify_returned_is_valid_true), all 29 public fields, exact
 * casper:casper-test network, exact SHA-40 commits, the exact
 * concordia.official_x402_settlement.v1 schema identity, strict UTC-Z
 * chronology (max(check.observed_at) <= captured_at), and no verifier-chosen
 * observation URL anywhere in the artifact.
 *
 * DELIBERATE MIGRATION from the obsolete 15-check WP5 set: every assertion
 * that named an old check now pins its current registry replacement — nothing
 * was weakened. Cross-language agreement with Python and the dashboard is
 * pinned separately in settlement-item-cross-language.test.ts.
 */

import { describe, expect, it } from "vitest";

import {
  buildSettlementRegistryItem,
  requireArtifactSource,
  OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
  PUBLIC_ITEM_REQUIRED_FIELDS,
  SettlementItemError,
} from "../src/settlement-item.js";
import { validChecks, validInput } from "./settlement-item-fixture.js";

function checksObservedAt(observedAt: string) {
  return validChecks(observedAt);
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
    // Mandatory scope + link fields (registry: 29 required public fields).
    expect(item.claim_scope).toBe("official x402 WCSPR settlement for FINALS-X402-001");
    expect(item.enforcement_scope).toBe("governance-bound facilitator settlement gate");
    expect(item.links.length).toBeGreaterThan(0);
    // Exact schema identity for this proof type.
    expect(item.schema_version).toBe("concordia.official_x402_settlement.v1");
  });

  it("emits exactly the 29 required public fields in the registry's canonical order", () => {
    const item = buildSettlementRegistryItem(validInput());
    expect(Object.keys(item)).toEqual([...PUBLIC_ITEM_REQUIRED_FIELDS]);
    expect(Object.keys(item)).toHaveLength(29);
  });

  it("emits a proof_id that satisfies the registry identifier grammar", () => {
    const item = buildSettlementRegistryItem(validInput());
    expect(item.proof_id).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
    // Deterministic binding to the settlement's signed payload hash.
    expect(item.proof_id).toBe(`official-x402-${"cd".repeat(24)}`);
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

describe("current registry check set (22 checks, frozen [a-z][a-z0-9_]* grammar)", () => {
  it("emits exactly the 22 current required checks, in registry order", () => {
    const item = buildSettlementRegistryItem(validInput());
    expect(item.checks).toHaveLength(22);
    expect(item.checks.map((c) => c.name)).toEqual([
      ...OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
    ]);
  });

  it("uses the normalized snake-case facilitator names, never camel-case", () => {
    const item = buildSettlementRegistryItem(validInput());
    const names = item.checks.map((c) => c.name);
    expect(names).toContain("facilitator_verify_returned_is_valid_true");
    expect(names).toContain("facilitator_settlement_response_success_true");
    for (const name of names) expect(name).toMatch(/^[a-z][a-z0-9_]*$/);
    expect(names.join(",")).not.toMatch(/isValid/i);
  });

  it("refuses every obsolete WP5-era check name as an unexpected check", () => {
    const obsolete = [
      "requirements_hash_matches_registry",
      "exact_v3_finalization_confirmed",
      "facilitator_settle_returned_success_true",
      "fulfillment_idempotency_proven",
    ];
    for (const name of obsolete) {
      expect(OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS).not.toContain(name);
      const checks = validChecks();
      checks[0] = { ...checks[0]!, name };
      expect(codeOf(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
        "unexpected_check",
      );
    }
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
    // The registry (shared/proof_registry.py) allows at most 6 fractional
    // digits and no leap second — emission must be registry-compatible.
    ["captured_at 9 fractional digits", { capturedAt: "2026-07-22T20:05:00.123456789Z" }],
    ["captured_at leap second", { capturedAt: "2026-07-22T20:05:60Z" }],
  ])("rejects registry-incompatible timestamps (%s)", (_n, overrides) => {
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

  it("rejects an RPC endpoint smuggled through a link href", () => {
    expect(
      codeOf(() =>
        buildSettlementRegistryItem(
          validInput({
            links: [
              {
                rel: "observer",
                label: "node",
                href: "https://node.testnet.casper.network/rpc",
                kind: "chain",
              },
            ],
          }),
        ),
      ),
    ).toBe("verifier_observation_url_forbidden");
  });
});

describe("identity validation", () => {
  it.each([
    ["actionId", { actionId: "zz".repeat(32) }, "invalid_action_id"],
    ["deploymentDomain", { deploymentDomain: "abc" }, "invalid_deployment_domain"],
    ["settlementTransaction", { settlementTransaction: "1234" }, "invalid_settlement_transaction"],
    ["proposalId", { proposalId: "lower-case" }, "invalid_proposal_id"],
    // Exact network binding — no other CAIP-2 value, no empty string.
    ["network (mainnet)", { network: "casper:mainnet" }, "invalid_network"],
    ["network (empty)", { network: "" }, "invalid_network"],
    // Exact SHA-40 commits — abbreviated and 64-hex forms are both rejected.
    ["sourceCommit (short)", { sourceCommit: "abcdef1" }, "invalid_source_commit"],
    ["sourceCommit (64-hex)", { sourceCommit: "ab".repeat(32) }, "invalid_source_commit"],
    ["deploymentCommit (short)", { deploymentCommit: "1234567" }, "invalid_deployment_commit"],
    ["claimScope (blank)", { claimScope: "   " }, "invalid_claim_scope"],
    ["enforcementScope (empty)", { enforcementScope: "" }, "invalid_enforcement_scope"],
  ])("rejects malformed %s", (_n, overrides, expected) => {
    expect(codeOf(() => buildSettlementRegistryItem(validInput(overrides)))).toBe(expected);
  });

  it.each([
    ["missing field", { rel: "a", label: "b", kind: "ui" }, "invalid_link"],
    ["extra field", { rel: "a", label: "b", href: "/x", kind: "ui", note: "n" }, "invalid_link"],
    ["bad rel", { rel: "bad rel!", label: "b", href: "/x", kind: "ui" }, "invalid_link_rel"],
    ["blank label", { rel: "a", label: "  ", href: "/x", kind: "ui" }, "invalid_link_label"],
    ["bad kind", { rel: "a", label: "b", href: "/x", kind: "portal" }, "invalid_link_kind"],
    ["protocol-relative href", { rel: "a", label: "b", href: "//evil", kind: "ui" }, "invalid_link_href"],
    ["http href", { rel: "a", label: "b", href: "http://x/y", kind: "ui" }, "invalid_link_href"],
  ])("rejects a malformed link (%s)", (_n, link, expected) => {
    expect(
      codeOf(() =>
        buildSettlementRegistryItem(
          validInput({ links: [link as never] }),
        ),
      ),
    ).toBe(expected);
  });
});
