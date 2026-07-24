import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { EXIT_CODES, parseJsonStrict, verifyProofRegistry } from "../dist/index.js";

const CAPTURED_AT = "2026-07-23T00:00:00Z";
const GENERATED_AT = "2026-07-23T00:01:00Z";
const ARTIFACT = Buffer.from('{"proof":"observed"}\n', "utf8");
const ARTIFACT_SHA = createHash("sha256").update(ARTIFACT).digest("hex");

function check(name, passed = true) {
  return {
    name,
    required: true,
    passed,
    source: "artifact.json",
    observed_at: CAPTURED_AT,
  };
}

function snapshotItem(overrides = {}) {
  return {
    proof_id: "snapshot_fixture",
    proof_type: "snapshot",
    generation: "none",
    lineage: "supplemental",
    observation_mode: "snapshot",
    temporal_scope: "current",
    verification_status: "verified",
    execution_outcome: "not_applicable",
    claim_scope: "A captured, content-addressed test artifact.",
    enforcement_scope: "Read-only local verification.",
    proposal_id: "DAO-PROP-VERIFY-001",
    action_id: null,
    envelope_hash: null,
    artifact_path: "artifact.json",
    artifact_sha256: ARTIFACT_SHA,
    source_commit: "1".repeat(40),
    deployment_commit: "2".repeat(40),
    network: "casper:casper-test",
    package_hash: null,
    contract_hash: null,
    deployment_domain: null,
    schema_version: "snapshot-v1",
    captured_at: CAPTURED_AT,
    payment_requirements_hash: null,
    signed_payment_payload_hash: null,
    report_hash: null,
    settlement_transaction: null,
    checks: [
      check("artifact_sha256_recomputed"),
      check("capture_time_present"),
      check("source_https_url_present"),
      check("staleness_check_passed"),
    ],
    links: [
      {
        rel: "source",
        label: "Frozen source",
        href: "https://example.invalid/artifact.json",
        kind: "source",
      },
    ],
    ...overrides,
  };
}

function registry(item = snapshotItem()) {
  return {
    schema_version: 1,
    generated_at: GENERATED_AT,
    proposal_id: "DAO-PROP-VERIFY-001",
    items: [item],
  };
}

const options = {
  artifacts: { "artifact.json": ARTIFACT },
  now: GENERATED_AT,
};

test("a fully observed snapshot verifies from provenance and artifact bytes", () => {
  const result = verifyProofRegistry(registry(), options);
  assert.equal(result.status, "verified");
  assert.equal(result.valid, true);
  assert.equal(result.exitCode, EXIT_CODES.VERIFIED);
});

test("passed staleness assertion cannot make an actually stale current snapshot green", () => {
  const stale = snapshotItem({ captured_at: "2026-07-20T00:00:00Z" });
  for (const observed of stale.checks) observed.observed_at = "2026-07-20T00:00:00Z";
  const result = verifyProofRegistry(registry(stale), options);
  assert.equal(result.status, "unavailable");
  assert.equal(result.valid, false);
  assert.match(result.items[0].reasons.join(" "), /older than 24 hours/i);
});

test("default freshness uses verifier wall time rather than registry generated_at", () => {
  const stale = snapshotItem({ captured_at: "2020-01-01T00:00:00Z" });
  for (const observed of stale.checks) observed.observed_at = "2020-01-01T00:00:00Z";
  const oldRegistry = registry(stale);
  oldRegistry.generated_at = "2020-01-01T00:01:00Z";
  const result = verifyProofRegistry(oldRegistry, { artifacts: options.artifacts });
  assert.equal(result.status, "unavailable");
  assert.match(result.items[0].reasons.join(" "), /older than 24 hours/i);
});

test("registry generation and proof capture cannot be in the verifier's future", () => {
  const futureRegistry = registry();
  futureRegistry.generated_at = "2026-07-23T00:02:00Z";
  const generated = verifyProofRegistry(futureRegistry, options);
  assert.equal(generated.status, "invalid");
  assert.equal(generated.error.code, "future_generated_at");

  const futureCapture = snapshotItem({ captured_at: "2026-07-23T00:02:00Z" });
  const captured = verifyProofRegistry(registry(futureCapture), options);
  assert.equal(captured.status, "invalid");
  assert.match(captured.items[0].reasons.join(" "), /captured_at.*future/i);
});

test("check observation timestamps cannot be future-dated or occur after artifact capture", () => {
  const futureObserved = snapshotItem();
  for (const observed of futureObserved.checks) observed.observed_at = "2099-01-01T00:00:00Z";
  const future = verifyProofRegistry(registry(futureObserved), options);
  assert.equal(future.status, "invalid");
  assert.match(future.items[0].reasons.join(" "), /observed_at.*future/i);

  const reversed = snapshotItem();
  reversed.checks[0].observed_at = "2026-07-23T00:00:30Z";
  const outOfOrder = verifyProofRegistry(registry(reversed), options);
  assert.equal(outOfOrder.status, "invalid");
  assert.match(outOfOrder.items[0].reasons.join(" "), /observed_at.*after.*captured_at/i);
});

test("verified item capture cannot occur after registry generation", () => {
  const lateCapture = snapshotItem({ captured_at: "2026-07-23T00:00:30Z" });
  for (const observed of lateCapture.checks) observed.observed_at = "2026-07-23T00:00:30Z";
  const earlyRegistry = registry(lateCapture);
  earlyRegistry.generated_at = "2026-07-23T00:00:15Z";
  const result = verifyProofRegistry(earlyRegistry, options);
  assert.equal(result.status, "invalid");
  assert.match(result.items[0].reasons.join(" "), /captured_at.*after.*generated_at/i);
});

test("forged summary booleans never override a failed observed check", () => {
  const forged = snapshotItem({
    passed: true,
    chain_valid: true,
    verified: true,
    duplicate_proof_rejected: true,
  });
  forged.checks[0].passed = false;

  const result = verifyProofRegistry(registry(forged), options);
  assert.equal(result.status, "invalid");
  assert.equal(result.valid, false);
  assert.equal(result.exitCode, EXIT_CODES.INVALID);
  assert.deepEqual(result.items[0].ignoredAssertions, [
    "chain_valid",
    "duplicate_proof_rejected",
    "passed",
    "verified",
  ]);
});

test("duplicate required-check names invalidate an otherwise green item", () => {
  const duplicate = snapshotItem();
  duplicate.checks.push(check("artifact_sha256_recomputed"));
  const result = verifyProofRegistry(registry(duplicate), options);
  assert.equal(result.status, "invalid");
  assert.match(result.items[0].reasons.join(" "), /duplicate/i);
});

test("duplicate proof IDs invalidate the registry identity map", () => {
  const duplicated = registry();
  duplicated.items.push(structuredClone(duplicated.items[0]));
  const result = verifyProofRegistry(duplicated, options);
  assert.equal(result.status, "invalid");
  assert.equal(result.error.code, "duplicate_proof_id");
});

test("registry item count is bounded before item verification", () => {
  const oversized = registry();
  oversized.items = Array.from({ length: 129 }, (_, index) => snapshotItem({
    proof_id: `snapshot_${String(index).padStart(3, "0")}`,
  }));
  const result = verifyProofRegistry(oversized, options);
  assert.equal(result.status, "invalid");
  assert.equal(result.error.code, "too_many_items");
});

test("unavailable observation stays unavailable despite forged green booleans", () => {
  const unavailable = snapshotItem({
    observation_mode: "unavailable",
    verification_status: "unavailable",
    passed: true,
    verified: true,
  });
  const result = verifyProofRegistry(registry(unavailable), options);
  assert.equal(result.status, "unavailable");
  assert.equal(result.exitCode, EXIT_CODES.UNAVAILABLE);
  assert.equal(result.valid, false);
});

test("missing evidence cannot pass vacuously", () => {
  const result = verifyProofRegistry(registry(snapshotItem({ checks: [] })), options);
  assert.equal(result.status, "invalid");
  assert.equal(result.valid, false);
});

test("unknown item, check, and link fields cannot smuggle an assertion", () => {
  const smuggled = snapshotItem({ green: true });
  smuggled.checks[0].attested = true;
  smuggled.links[0].trusted = true;

  const result = verifyProofRegistry(registry(smuggled), options);
  assert.equal(result.status, "invalid");
  assert.match(result.items[0].reasons.join(" "), /unknown/i);
});

test("dashboard links are base-path relative, not prefix lookalikes", () => {
  const lookalike = snapshotItem();
  lookalike.links[0] = {
    rel: "source",
    label: "Lookalike",
    href: "/dashboardevil/proof",
    kind: "ui",
  };

  const result = verifyProofRegistry(registry(lookalike), options);
  assert.equal(result.status, "invalid");
  assert.match(result.items[0].reasons.join(" "), /href/i);
});

test("reference and evidence timestamps reject impossible UTC calendar dates", () => {
  const impossible = snapshotItem({ captured_at: "2026-02-31T00:00:00Z" });
  const badEvidenceTime = verifyProofRegistry(registry(impossible), options);
  assert.equal(badEvidenceTime.status, "invalid");

  const badReferenceTime = verifyProofRegistry(registry(), {
    artifacts: options.artifacts,
    now: "not-a-time",
  });
  assert.equal(badReferenceTime.status, "invalid");
  assert.equal(badReferenceTime.error.code, "invalid_reference_time");
});

test("strict JSON objects cannot inherit forged proof-check fields through __proto__", () => {
  const parsed = parseJsonStrict(
    '{"name":"mapped_check","source":"artifact.json","observed_at":"2026-07-23T00:00:00Z","__proto__":{"required":true,"passed":true}}',
  );

  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(Object.hasOwn(parsed, "required"), false);
  assert.equal(Object.hasOwn(parsed, "passed"), false);
  assert.equal(parsed.required, undefined);
  assert.equal(parsed.passed, undefined);

  const poisonedRegistry = JSON.stringify(registry()).replace(
    '"required":true,"passed":true',
    '"__proto__":{"required":true,"passed":true}',
  );
  const result = verifyProofRegistry(parseJsonStrict(poisonedRegistry), options);
  assert.equal(result.status, "invalid");
  assert.match(result.items[0].reasons.join(" "), /required\/passed/);
});

test("direct library callers cannot satisfy registry or check contracts through inheritance", () => {
  const inheritedRegistry = Object.create(registry());
  const topLevel = verifyProofRegistry(inheritedRegistry, options);
  assert.equal(topLevel.status, "invalid");
  assert.equal(topLevel.valid, false);
  assert.match(topLevel.error.message, /own|required|missing/i);

  const inheritedName = snapshotItem();
  inheritedName.checks[0] = Object.assign(
    Object.create({ name: "artifact_sha256_recomputed" }),
    {
      required: true,
      passed: true,
      source: "artifact.json",
      observed_at: CAPTURED_AT,
    },
  );
  const check = verifyProofRegistry(registry(inheritedName), options);
  assert.equal(check.status, "invalid");
  assert.match(check.items[0].reasons.join(" "), /name/i);
});

test("artifact lookup requires an own property and cannot fall through Object.prototype", () => {
  const prototypeNamed = snapshotItem({ artifact_path: "toString" });
  const inheritedArtifacts = Object.create({ toString: ARTIFACT });
  const result = verifyProofRegistry(registry(prototypeNamed), {
    artifacts: inheritedArtifacts,
    now: GENERATED_AT,
  });
  assert.equal(result.status, "unavailable");
  assert.match(result.items[0].reasons.join(" "), /artifact bytes unavailable/i);
});

test("verified official x402 identity cannot omit any exact-v3 or settlement binding", () => {
  const requiredChecks = [
    "exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    "resource_object_equals_configured_resource",
    "accepted_equals_current_payment_requirements",
    "payment_requirements_argument_equals_accepted",
    "eip712_signature_verified",
    "public_key_account_hash_equals_payer",
    "authorization_equals_envelope_payer_payee_value_nonce_and_window",
    "resource_url_hash_matches_envelope",
    "report_hash_matches_envelope",
    "payment_requirements_hash_matches_envelope",
    "signed_payment_payload_hash_matches_envelope",
    "active_wcspr_v8_pre_verify_drift_guard_passed",
    "facilitator_verify_returned_is_valid_true",
    "active_wcspr_v8_pre_settle_drift_guard_passed",
    "facilitator_settlement_response_success_true",
    "settlement_transaction_finalized_without_execution_error",
    "active_wcspr_v8_post_settle_target_and_args_readback_passed",
    "fulfillment_authorization_nonce_unique_binding_matches",
    "fulfillment_restart_reconciliation_passed",
    "exact_retry_returned_stored_fulfillment_without_second_settlement",
    "cross_binding_or_authorization_reuse_returned_terminal_409_before_submission",
    "protected_report_released_only_after_finalized_state",
  ];
  const baseline = snapshotItem({
    proof_id: "official_x402_settlement_v1",
    proof_type: "official_x402_settlement_v1",
    generation: "v3",
    observation_mode: "live",
    temporal_scope: "current",
    execution_outcome: "accepted",
    proposal_id: "DAO-PROP-VERIFY-001",
    action_id: "10".repeat(32),
    envelope_hash: "11".repeat(32),
    network: "casper:casper-test",
    package_hash: "12".repeat(32),
    contract_hash: "13".repeat(32),
    deployment_domain: "14".repeat(32),
    payment_requirements_hash: "15".repeat(32),
    signed_payment_payload_hash: "16".repeat(32),
    report_hash: "17".repeat(32),
    settlement_transaction: "18".repeat(32),
    checks: requiredChecks.map((name) => check(name)),
  });
  for (const field of [
    "proposal_id",
    "action_id",
    "envelope_hash",
    "network",
    "package_hash",
    "contract_hash",
    "deployment_domain",
    "payment_requirements_hash",
    "signed_payment_payload_hash",
    "report_hash",
    "settlement_transaction",
  ]) {
    const item = structuredClone(baseline);
    item[field] = null;
    const result = verifyProofRegistry(registry(item), options);
    assert.equal(result.status, "invalid", field);
    assert.match(result.items[0].reasons.join(" "), new RegExp(field), field);
  }
});
