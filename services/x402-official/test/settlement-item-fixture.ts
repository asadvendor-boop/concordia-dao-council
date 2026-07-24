/**
 * Shared fixture for the settlement proof-registry item suites: one realistic,
 * fully valid builder input (22 per-check receipts, 40-hex commits, exact
 * casper:casper-test network, claim/enforcement scopes, typed links). Kept
 * separate from test/helpers.ts so the cross-language suite stays light — no
 * SDK imports.
 */

import {
  OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
  type SettlementCheckObservationInput,
  type SettlementItemInput,
  type SettlementItemLink,
} from "../src/settlement-item.js";

export const FIXTURE_SOURCE = "artifacts/live/official-x402-settlement-v1.json";
export const FIXTURE_OBSERVED_AT = "2026-07-22T20:00:00Z";
export const FIXTURE_CAPTURED_AT = "2026-07-22T20:05:00Z";

export function validChecks(
  observedAt = FIXTURE_OBSERVED_AT,
): SettlementCheckObservationInput[] {
  return OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS.map((name) => ({
    name,
    passed: true,
    source: FIXTURE_SOURCE,
    observed_at: observedAt,
    evidence: `independently captured artifact record for ${name}`,
  }));
}

export function validLinks(): SettlementItemLink[] {
  return [
    {
      rel: "proof_center",
      label: "Concordia proof center",
      href: "/dashboard/proof",
      kind: "ui",
    },
    {
      rel: "settlement_artifact",
      label: "Official x402 settlement artifact",
      href: "https://x402.concordiadao.xyz/proofs/official-x402-settlement-v1.json",
      kind: "artifact",
    },
  ];
}

export function validInput(
  overrides: Partial<SettlementItemInput> = {},
): SettlementItemInput {
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
    capturedAt: FIXTURE_CAPTURED_AT,
    checks: validChecks(),
    sourceCommit: "0f".repeat(20),
    deploymentCommit: "1e".repeat(20),
    artifactPath: FIXTURE_SOURCE,
    artifactSha256: "77".repeat(32),
    claimScope: "official x402 WCSPR settlement for FINALS-X402-001",
    enforcementScope: "governance-bound facilitator settlement gate",
    links: validLinks(),
    ...overrides,
  };
}
