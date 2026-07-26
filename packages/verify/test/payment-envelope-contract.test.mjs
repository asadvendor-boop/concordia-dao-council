import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  verifyProofRegistry,
  verifySafePayV2ArtifactEnvelope,
} from "../dist/index.js";

const CAPTURED_AT = "2026-07-23T00:00:00Z";
const SOURCE_COMMIT = "ab".repeat(20);
const DEPLOYMENT_COMMIT = "cd".repeat(20);
const NETWORK = "casper:casper-test";
const PRIMARY_PROPOSAL = "DAO-PROP-RELEASE-ROOTS";
const OFFICIAL_PROPOSAL = "DAO-PROP-OFFICIAL-X402";
const REPORT_HASH = "11".repeat(32);
const PAYMENT_HASH = "22".repeat(32);
const ACTION_ID = "33".repeat(32);
const ENVELOPE_HASH = "44".repeat(32);
const PACKAGE_HASH = "55".repeat(32);
const CONTRACT_HASH = "66".repeat(32);
const DEPLOYMENT_DOMAIN = "77".repeat(32);
const PAYMENT_REQUIREMENTS_HASH = "88".repeat(32);
const SIGNED_PAYMENT_PAYLOAD_HASH = "99".repeat(32);

const SAFEPAY_CHECKS = [
  "quote_hash_recomputed",
  "issued_quote_row_matches_and_survives_restart",
  "per_quote_correlation_id_recomputed_and_equals_native_transfer_id",
  "payment_deploy_finalized_without_execution_error",
  "single_native_transfer_exact",
  "payee_amount_and_transfer_id_exact",
  "proposal_resource_and_correlation_exact",
  "report_hash_recomputed_and_matches_quote",
  "provider_consumption_row_matches_payment_and_binding",
  "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
  "cross_binding_reuse_returned_terminal_409",
];

const OFFICIAL_CHECKS = [
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

const SNAPSHOT_CHECKS = [
  "artifact_sha256_recomputed",
  "capture_time_present",
  "source_https_url_present",
  "staleness_check_passed",
];

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function artifactBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function checks(names, source) {
  return names.map((name) => ({
    name,
    required: true,
    passed: true,
    source,
    observed_at: CAPTURED_AT,
  }));
}

function commonItem({
  proofId,
  proofType,
  proposalId,
  artifactPath,
  artifact,
  checkNames,
}) {
  return {
    proof_id: proofId,
    proof_type: proofType,
    generation: proofType === "safepay_v2" ? "v2" : "v3",
    lineage: "supplemental",
    observation_mode: "live",
    temporal_scope: "current",
    verification_status: "verified",
    execution_outcome: "accepted",
    claim_scope: "Frozen release evidence.",
    enforcement_scope: "The exact content-addressed producer artifact.",
    proposal_id: proposalId,
    action_id: null,
    envelope_hash: null,
    artifact_path: artifactPath,
    artifact_sha256: sha256(artifact),
    source_commit: SOURCE_COMMIT,
    deployment_commit: DEPLOYMENT_COMMIT,
    network: NETWORK,
    package_hash: null,
    contract_hash: null,
    deployment_domain: null,
    schema_version: proofType === "safepay_v2"
      ? "safepay-v2"
      : "concordia.official_x402_settlement.v2",
    captured_at: CAPTURED_AT,
    payment_requirements_hash: null,
    signed_payment_payload_hash: null,
    report_hash: REPORT_HASH,
    settlement_transaction: PAYMENT_HASH,
    checks: checks(checkNames, artifactPath),
    links: [{
      rel: "artifact",
      label: "Content-addressed producer artifact",
      href: `https://concordiadao.xyz/${artifactPath}`,
      kind: "artifact",
    }],
  };
}

function safepayArtifact(proposalId = PRIMARY_PROPOSAL) {
  return {
    schema_version: "safepay-v2",
    captured_at: CAPTURED_AT,
    source_commit: SOURCE_COMMIT,
    deployment_commit: DEPLOYMENT_COMMIT,
    capture_identity: {},
    quote: {
      schema_version: "safepay-v2",
      quote_id: "123e4567-e89b-42d3-a456-426614174000",
      proposal_id: proposalId,
      resource_id: "release-report",
      network: NETWORK,
      payee_account_hash: "aa".repeat(32),
      amount_motes: "100",
      correlation_id: "42",
      report_version: "safepay-report-v2",
      report_hash: REPORT_HASH,
      expires_at: 1_900_000_000,
      quote_nonce: "bb".repeat(32),
      quote_hash: "cc".repeat(32),
    },
    issued_quote_rows: {},
    chain_evidence: {
      network: NETWORK,
      payment_hash: PAYMENT_HASH,
      providers: [],
      parsed_transfer: {
        network: NETWORK,
        payment_hash: PAYMENT_HASH,
        block_hash: "dd".repeat(32),
        block_height: 10,
        state_root_hash: "ee".repeat(32),
        block_timestamp: CAPTURED_AT,
        execution_status: "processed",
        finality_status: "finalized",
        execution_error: null,
        native_transfer_count: 1,
        source_account_hash: "ff".repeat(32),
        payee_account_hash: "aa".repeat(32),
        amount_motes: "100",
        transfer_id: "42",
      },
    },
    consumption_rows: {},
    ledger_evidence: {},
    redemption_observations: {},
    protected_report: {
      report_version: "safepay-report-v2",
      proposal_id: proposalId,
      resource_id: "release-report",
      correlation_id: "42",
      media_type: "application/json",
      content_base64: "e30=",
      decoded_length: 2,
      report_hash: REPORT_HASH,
      response_hash: "12".repeat(32),
      persisted_at: CAPTURED_AT,
      released_at: CAPTURED_AT,
    },
  };
}

function officialArtifact(proposalId = OFFICIAL_PROPOSAL) {
  return {
    schema_version: "concordia.official_x402_settlement.v2",
    captured_at: CAPTURED_AT,
    source_commit: SOURCE_COMMIT,
    deployment_commit: DEPLOYMENT_COMMIT,
    capture_identity: {},
    governance_binding: {
      proposal_id: proposalId,
      proposal_hash: "13".repeat(32),
      proposal_nonce: "14".repeat(32),
      action_id: ACTION_ID,
      action_kind: "OfficialX402SettlementV1",
      action_version: 1,
      envelope_hash: ENVELOPE_HASH,
      deployment_domain: DEPLOYMENT_DOMAIN,
      network: NETWORK,
      package_hash: PACKAGE_HASH,
      contract_hash: CONTRACT_HASH,
      finalization_transaction: "15".repeat(32),
      finalized_at: CAPTURED_AT,
      observed_at: CAPTURED_AT,
      resource_url_hash: "16".repeat(32),
      payment_requirements_hash: PAYMENT_REQUIREMENTS_HASH,
      signed_payment_payload_hash: SIGNED_PAYMENT_PAYLOAD_HASH,
      report_hash: REPORT_HASH,
      v3_proof_sha256: sha256(Buffer.from("{}", "utf8")),
      v3_proof_bytes_base64: "e30=",
    },
    resource_and_payment: {},
    authorization: {},
    facilitator: {},
    wcspr_readbacks: {},
    settlement_chain_evidence: {
      network: NETWORK,
      settlement_transaction: PAYMENT_HASH,
      providers: [],
      parsed_settlement: {},
    },
    fulfillment: {},
    protected_report: {},
    release_order: {},
  };
}

function safepayCase(proposalId = PRIMARY_PROPOSAL) {
  const path = "artifacts/live/safepay-lite-replaysafe-v2.json";
  const artifact = artifactBytes(safepayArtifact(proposalId));
  const item = commonItem({
    proofId: "safepay_v2",
    proofType: "safepay_v2",
    proposalId,
    artifactPath: path,
    artifact,
    checkNames: SAFEPAY_CHECKS,
  });
  return { path, artifact, item };
}

function officialCase(proposalId = OFFICIAL_PROPOSAL) {
  const path = "artifacts/live/official-x402-settlement-v1.json";
  const artifact = artifactBytes(officialArtifact(proposalId));
  const item = commonItem({
    proofId: "official_x402_settlement_v1",
    proofType: "official_x402_settlement_v1",
    proposalId,
    artifactPath: path,
    artifact,
    checkNames: OFFICIAL_CHECKS,
  });
  item.action_id = ACTION_ID;
  item.envelope_hash = ENVELOPE_HASH;
  item.package_hash = PACKAGE_HASH;
  item.contract_hash = CONTRACT_HASH;
  item.deployment_domain = DEPLOYMENT_DOMAIN;
  item.payment_requirements_hash = PAYMENT_REQUIREMENTS_HASH;
  item.signed_payment_payload_hash = SIGNED_PAYMENT_PAYLOAD_HASH;
  return { path, artifact, item };
}

function snapshotCase(index) {
  const path = `artifacts/live/supported-${index}.json`;
  const artifact = artifactBytes({ observed: index });
  return {
    path,
    artifact,
    item: {
      ...commonItem({
        proofId: `supported_${index}`,
        proofType: "snapshot",
        proposalId: PRIMARY_PROPOSAL,
        artifactPath: path,
        artifact,
        checkNames: SNAPSHOT_CHECKS,
      }),
      generation: "none",
      observation_mode: "snapshot",
      execution_outcome: "not_applicable",
      schema_version: "snapshot-v1",
      action_id: null,
      envelope_hash: null,
      package_hash: null,
      contract_hash: null,
      deployment_domain: null,
      payment_requirements_hash: null,
      signed_payment_payload_hash: null,
      report_hash: null,
      settlement_transaction: null,
      links: [{
        rel: "source",
        label: "Frozen source",
        href: `https://concordiadao.xyz/${path}`,
        kind: "source",
      }],
    },
  };
}

test("SafePay verifies its artifact identity envelope but unsupported semantics never become green", () => {
  const fixture = safepayCase();
  fixture.item.passed = true;
  fixture.item.verified = true;
  const result = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: PRIMARY_PROPOSAL,
    items: [fixture.item],
  }, {
    artifacts: { [fixture.path]: fixture.artifact },
    now: CAPTURED_AT,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.exitCode, 3);
  assert.equal(result.valid, false);
  assert.equal(result.items[0].green, false);
  assert.deepEqual(result.items[0].verifiedAspects, [
    "artifact_identity_envelope",
    "artifact_sha256",
    "proposal_binding",
  ]);
  assert.deepEqual(result.items[0].unsupportedCapabilities, [
    "safepay_v2_semantics",
  ]);
  assert.match(result.items[0].reasons.join(" "), /semantic verification is unsupported/i);
  assert.deepEqual(result.items[0].ignoredAssertions, ["passed", "verified"]);
});

test("official x402 verifies its artifact identity envelope but unsupported semantics never become green", () => {
  const fixture = officialCase();
  const result = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: OFFICIAL_PROPOSAL,
    items: [fixture.item],
  }, {
    artifacts: { [fixture.path]: fixture.artifact },
    now: CAPTURED_AT,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.exitCode, 3);
  assert.equal(result.valid, false);
  assert.equal(result.items[0].green, false);
  assert.deepEqual(result.items[0].verifiedAspects, [
    "artifact_identity_envelope",
    "artifact_sha256",
    "proposal_binding",
  ]);
  assert.deepEqual(result.items[0].unsupportedCapabilities, [
    "official_x402_settlement_v1_semantics",
  ]);
  assert.match(result.items[0].reasons.join(" "), /semantic verification is unsupported/i);
});

test("payment artifact proposal-envelope contradictions are invalid, not merely unsupported", () => {
  const safepay = safepayCase();
  const contradictory = artifactBytes(safepayArtifact("DAO-PROP-OTHER"));
  safepay.item.artifact_sha256 = sha256(contradictory);
  const safeResult = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: PRIMARY_PROPOSAL,
    items: [safepay.item],
  }, {
    artifacts: { [safepay.path]: contradictory },
    now: CAPTURED_AT,
  });
  assert.equal(safeResult.status, "invalid");
  assert.equal(safeResult.items[0].green, false);
  assert.doesNotMatch(
    safeResult.items[0].verifiedAspects.join(" "),
    /artifact_identity_envelope/,
  );
  assert.match(safeResult.items[0].reasons.join(" "), /proposal_id/i);

  const official = officialCase();
  const contradictoryOfficial = artifactBytes(officialArtifact(PRIMARY_PROPOSAL));
  official.item.artifact_sha256 = sha256(contradictoryOfficial);
  const officialResult = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: OFFICIAL_PROPOSAL,
    items: [official.item],
  }, {
    artifacts: { [official.path]: contradictoryOfficial },
    now: CAPTURED_AT,
  });
  assert.equal(officialResult.status, "invalid");
  assert.equal(officialResult.items[0].green, false);
  assert.doesNotMatch(
    officialResult.items[0].verifiedAspects.join(" "),
    /artifact_identity_envelope/,
  );
  assert.match(officialResult.items[0].reasons.join(" "), /proposal_id/i);
});

test("payment identity envelopes cannot relabel a non-Testnet artifact as supported", () => {
  const safeDocument = safepayArtifact();
  safeDocument.quote.network = "casper:mainnet";
  safeDocument.chain_evidence.network = "casper:mainnet";
  safeDocument.chain_evidence.parsed_transfer.network = "casper:mainnet";
  const safeBytes = artifactBytes(safeDocument);
  const safepay = safepayCase();
  safepay.item.network = "casper:mainnet";
  safepay.item.artifact_sha256 = sha256(safeBytes);
  const safeResult = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: PRIMARY_PROPOSAL,
    items: [safepay.item],
  }, {
    artifacts: { [safepay.path]: safeBytes },
    now: CAPTURED_AT,
  });
  assert.equal(safeResult.status, "invalid");
  assert.match(safeResult.items[0].reasons.join(" "), /network/i);

  const officialDocument = officialArtifact();
  officialDocument.governance_binding.network = "casper:mainnet";
  officialDocument.settlement_chain_evidence.network = "casper:mainnet";
  const officialBytes = artifactBytes(officialDocument);
  const official = officialCase();
  official.item.network = "casper:mainnet";
  official.item.artifact_sha256 = sha256(officialBytes);
  const officialResult = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: OFFICIAL_PROPOSAL,
    items: [official.item],
  }, {
    artifacts: { [official.path]: officialBytes },
    now: CAPTURED_AT,
  });
  assert.equal(officialResult.status, "invalid");
  assert.match(officialResult.items[0].reasons.join(" "), /network/i);
});

test("direct payment-envelope callers cannot inherit parsed transfer identity fields", () => {
  const document = safepayArtifact();
  document.chain_evidence.parsed_transfer = Object.create({
    network: NETWORK,
    payment_hash: PAYMENT_HASH,
  });

  assert.throws(
    () => verifySafePayV2ArtifactEnvelope(document),
    /parsed_transfer|fields differ/i,
  );
});

test("the four-item primary and one-item official proposal documents are verified independently", () => {
  const safepay = safepayCase();
  const snapshots = [1, 2, 3].map(snapshotCase);
  const primaryArtifacts = Object.fromEntries(
    [...snapshots, safepay].map(({ path, artifact }) => [path, artifact]),
  );
  const primary = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: PRIMARY_PROPOSAL,
    items: [...snapshots.map(({ item }) => item), safepay.item],
  }, {
    artifacts: primaryArtifacts,
    now: CAPTURED_AT,
  });

  const official = officialCase();
  const officialResult = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: OFFICIAL_PROPOSAL,
    items: [official.item],
  }, {
    artifacts: { [official.path]: official.artifact },
    now: CAPTURED_AT,
  });

  assert.equal(primary.proposalId, PRIMARY_PROPOSAL);
  assert.deepEqual(primary.summary, {
    total: 4,
    verified: 3,
    invalid: 0,
    unavailable: 1,
    unknown: 0,
  });
  assert.equal(primary.status, "unavailable");
  assert.equal(officialResult.proposalId, OFFICIAL_PROPOSAL);
  assert.deepEqual(officialResult.summary, {
    total: 1,
    verified: 0,
    invalid: 0,
    unavailable: 1,
    unknown: 0,
  });
  assert.equal(officialResult.status, "unavailable");

  const crossed = structuredClone(official.item);
  crossed.proposal_id = PRIMARY_PROPOSAL;
  const crossedResult = verifyProofRegistry({
    schema_version: 1,
    generated_at: CAPTURED_AT,
    proposal_id: OFFICIAL_PROPOSAL,
    items: [crossed],
  }, {
    artifacts: { [official.path]: official.artifact },
    now: CAPTURED_AT,
  });
  assert.equal(crossedResult.status, "invalid");
  assert.equal(primary.summary.verified, 3);
  assert.equal(primary.items[3].status, "unavailable");
});
