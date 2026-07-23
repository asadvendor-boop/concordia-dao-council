import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { before, test } from "node:test";

import {
  canonicalTranscriptJson,
  parseJsonStrict,
  verifyExactEnvelopeV3Artifact,
  verifyNativeTreasuryExecutionArtifact,
  verifyProofRegistry,
} from "../dist/index.js";
import { buildNativeTreasuryArtifact } from "./helpers/native-treasury-artifact.mjs";

const REPOSITORY = fileURLToPath(new URL("../../../", import.meta.url));
const OBSERVED_AT = "2026-07-23T00:00:00Z";
let exactBytes;
let exactFacts;
let matchedExactProof;

const EXACT_CHECKS = [
  "source_tree_sha256_matches_release_manifest",
  "wasm_sha256_matches_release_manifest",
  "generated_schema_sha256_matches_release_manifest",
  "envelope_hash_recomputed_from_typed_fields",
  "proposal_commitment_matches_envelope_hash",
  "signer_set_and_threshold_match_deployment",
  "pre_quorum_finalize_reverted_with_code_8",
  "post_quorum_mutated_envelope_reverted_with_code_10",
  "exact_envelope_finalization_accepted",
  "repeat_finalization_reverted_with_code_12",
  "finalization_deploy_processed_without_execution_error",
  "contract_readback_marks_proposal_finalized",
  "contract_readback_marks_action_authorized",
  "package_contract_and_deployment_domain_match_manifest",
];

const TREASURY_CHECKS = [
  "exact_envelope_v3_verified",
  "executor_journal_signed_bytes_hash_matches",
  "single_broadcast_or_reconciled_by_deploy_hash",
  "snapshot_block_hash_height_and_state_root_observed_from_casper_rpc",
  "source_balance_observed_at_snapshot_root_equals_treasury_snapshot_balance_motes",
  "snapshot_precedes_v3_finalization_and_native_execution",
  "transfer_source_exact",
  "transfer_recipient_exact",
  "transfer_amount_exact",
  "transfer_id_exact",
  "successful_inclusion_observed_by_two_named_casper_rpc_nodes",
  "post_execution_source_and_recipient_balances_observed",
  "no_second_native_transaction_observed_through_block",
];

function generateExactProofScript(useTreasuryDocument = false) {
  return [
    "import json",
    ...(useTreasuryDocument
      ? [
          "from pathlib import Path",
          "import tests.test_clvalue_roundtrip as fixtures",
          "core = json.loads(Path('packages/verify/test/fixtures/native-treasury-core.json').read_text())",
          "document = {'schema_id': 'concordia.exact-envelope-v3.input.v1', 'action': 'NativeTransferV1', 'header': core['authorization']['typed_header'], 'body': core['authorization']['typed_body']}",
          "fixtures._native_document = lambda: document",
          "proof, _, _ = fixtures._bound_v3_proof()",
        ]
      : [
          "from tests.test_clvalue_roundtrip import _bound_v3_proof",
          "proof, _, _ = _bound_v3_proof()",
        ]),
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ].join("\n");
}

function generateExactProof(useTreasuryDocument = false) {
  const raw = execFileSync("uv", ["run", "--frozen", "python", "-c", generateExactProofScript(useTreasuryDocument)], {
    cwd: REPOSITORY,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return { raw, proof: parseJsonStrict(raw) };
}

function resealExactTemporalEvidence(proof, finalizationBlockHeight, finalizationBlockHash) {
  const canonicalStep = proof.run.steps.find((step) => step.name === "finalize_exact");
  const blockHash = finalizationBlockHash ?? canonicalStep.finality_block_evidence.block_hash;
  const stateRootHash = canonicalStep.finality_block_evidence.state_root_hash;
  const blockTimestamp = canonicalStep.finality_block_evidence.block_timestamp;
  const transactions = {
    "0": proof.run.steps.map((step) => ({ Deploy: step.deploy_hash })),
  };
  for (const step of proof.run.steps) {
    const transcript = step.finality_transcript;
    transcript.response.result.execution_info.block_height = finalizationBlockHeight;
    transcript.response.result.execution_info.block_hash = blockHash;
    transcript.canonical_sha256 = sha256Canonical({
      request: transcript.request,
      response: transcript.response,
    });
    const evidence = step.finality_block_evidence;
    evidence.block_hash = blockHash;
    evidence.block_height = finalizationBlockHeight;
    evidence.state_root_hash = stateRootHash;
    evidence.block_timestamp = blockTimestamp;
    evidence.finalized_at = blockTimestamp;
    for (const node of evidence.node_observations) {
      node.deploy_response.result.execution_info.block_hash = blockHash;
      node.deploy_response.result.execution_info.block_height = finalizationBlockHeight;
      node.block_request.params.block_identifier.Hash = blockHash;
      const block = node.block_response.result.block_with_signatures.block.Version2;
      block.hash = blockHash;
      block.header.height = finalizationBlockHeight;
      block.header.state_root_hash = stateRootHash;
      block.header.timestamp = blockTimestamp;
      block.body.transactions = structuredClone(transactions);
    }
  }
  const observedBlockHeight = finalizationBlockHeight + 1;
  const blockTranscript = proof.readback.transcripts.find((item) => item.method === "chain_get_block");
  blockTranscript.response.result.block_with_signatures.block.Version2.header.height = observedBlockHeight;
  blockTranscript.canonical_sha256 = sha256Canonical({
    request: blockTranscript.request,
    response: blockTranscript.response,
  });
  proof.readback.facts.observed_block_height = observedBlockHeight;
  const readbackWithoutHash = structuredClone(proof.readback);
  delete readbackWithoutHash.artifact_sha256;
  proof.readback.artifact_sha256 = sha256Canonical(readbackWithoutHash);
  proof.run.readback = structuredClone(proof.readback);
}

before(() => {
  const generated = generateExactProof();
  const raw = generated.raw;
  exactBytes = Buffer.from(raw, "utf8");
  exactFacts = verifyExactEnvelopeV3Artifact(parseJsonStrict(raw));
  matchedExactProof = generateExactProof(true).proof;
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256Canonical(value) {
  return sha256(Buffer.from(canonicalTranscriptJson(value, "registry adapter transcript"), "ascii"));
}

function checks(names, source) {
  return names.map((name) => ({
    name,
    required: true,
    passed: true,
    source,
    observed_at: OBSERVED_AT,
  }));
}

function commonItem({ proofId, proofType, proposalId, actionId, envelopeHash, artifactPath, artifactBytes, facts, schemaVersion, checkNames }) {
  return {
    proof_id: proofId,
    proof_type: proofType,
    generation: "v3",
    lineage: "supplemental",
    observation_mode: "live",
    temporal_scope: "current",
    verification_status: "verified",
    execution_outcome: "accepted",
    claim_scope: "Independently recomputed typed and raw chain evidence.",
    enforcement_scope: "Casper Testnet and the exact versioned proof artifact.",
    proposal_id: proposalId,
    action_id: actionId,
    envelope_hash: envelopeHash,
    artifact_path: artifactPath,
    artifact_sha256: sha256(artifactBytes),
    source_commit: facts.sourceCommit,
    deployment_commit: facts.deploymentCommit,
    network: facts.network,
    package_hash: facts.packageHash,
    contract_hash: facts.contractHash,
    deployment_domain: facts.deploymentDomain,
    schema_version: schemaVersion,
    captured_at: OBSERVED_AT,
    payment_requirements_hash: null,
    signed_payment_payload_hash: null,
    report_hash: null,
    settlement_transaction: null,
    checks: checks(checkNames, artifactPath),
    links: [{
      rel: "artifact",
      label: "Versioned proof artifact",
      href: `https://example.invalid/${artifactPath}`,
      kind: "artifact",
    }],
  };
}

test("registry green for exact-envelope v3 comes from the strict adapter, not passed booleans", () => {
  const item = commonItem({
    proofId: "exact_envelope_v3",
    proofType: "exact_envelope_v3",
    proposalId: exactFacts.proposalId,
    actionId: exactFacts.actionId,
    envelopeHash: exactFacts.envelopeHash,
    artifactPath: "exact-v3.json",
    artifactBytes: exactBytes,
    facts: exactFacts,
    schemaVersion: "concordia.v3-proof.v1",
    checkNames: EXACT_CHECKS,
  });
  item.passed = true;
  const result = verifyProofRegistry(
    { schema_version: 1, generated_at: OBSERVED_AT, proposal_id: exactFacts.proposalId, items: [item] },
    { artifacts: { "exact-v3.json": exactBytes }, now: OBSERVED_AT },
  );
  assert.equal(result.status, "verified");
  assert.equal(result.items[0].green, true);
  assert.deepEqual(result.items[0].ignoredAssertions, ["passed"]);

  const tampered = Buffer.from(exactBytes);
  tampered[tampered.length - 2] ^= 1;
  const invalid = verifyProofRegistry(
    { schema_version: 1, generated_at: OBSERVED_AT, proposal_id: exactFacts.proposalId, items: [item] },
    { artifacts: { "exact-v3.json": tampered }, now: OBSERVED_AT },
  );
  assert.equal(invalid.status, "invalid");
  assert.match(invalid.items[0].reasons.join(" "), /SHA-256/i);
});

test("registry rejects false provenance or outcome labels on exact-envelope v3 evidence", () => {
  const baseline = commonItem({
    proofId: "exact_envelope_v3",
    proofType: "exact_envelope_v3",
    proposalId: exactFacts.proposalId,
    actionId: exactFacts.actionId,
    envelopeHash: exactFacts.envelopeHash,
    artifactPath: "exact-v3.json",
    artifactBytes: exactBytes,
    facts: exactFacts,
    schemaVersion: "concordia.v3-proof.v1",
    checkNames: EXACT_CHECKS,
  });
  const mutations = [
    ["generation", "v1"],
    ["lineage", "canonical"],
    ["observation_mode", "unavailable"],
    ["temporal_scope", "historical"],
    ["execution_outcome", "expected_rejection"],
    ["execution_outcome", "not_applicable"],
  ];
  for (const [field, value] of mutations) {
    const item = structuredClone(baseline);
    item[field] = value;
    const result = verifyProofRegistry(
      { schema_version: 1, generated_at: OBSERVED_AT, proposal_id: exactFacts.proposalId, items: [item] },
      { artifacts: { "exact-v3.json": exactBytes }, now: OBSERVED_AT },
    );
    assert.equal(result.status, "invalid", `${field}=${value}`);
    assert.match(result.items[0].reasons.join(" "), new RegExp(field), `${field}=${value}`);
  }

  const datedSnapshot = structuredClone(baseline);
  datedSnapshot.observation_mode = "snapshot";
  const acceptedSnapshot = verifyProofRegistry(
    { schema_version: 1, generated_at: OBSERVED_AT, proposal_id: exactFacts.proposalId, items: [datedSnapshot] },
    { artifacts: { "exact-v3.json": exactBytes }, now: OBSERVED_AT },
  );
  assert.equal(acceptedSnapshot.status, "verified");
});

test("native treasury execution cannot turn green without one independently matched exact-v3 item", async () => {
  const artifact = await buildNativeTreasuryArtifact();
  const artifactText = canonicalTranscriptJson(artifact, "native treasury registry fixture");
  const artifactBytes = Buffer.from(artifactText, "ascii");
  const facts = verifyNativeTreasuryExecutionArtifact(parseJsonStrict(artifactText));
  const item = commonItem({
    proofId: "native_treasury_execution_v1",
    proofType: "native_treasury_execution_v1",
    proposalId: facts.proposalId,
    actionId: facts.actionId,
    envelopeHash: facts.envelopeHash,
    artifactPath: "native-treasury.json",
    artifactBytes,
    facts,
    schemaVersion: facts.schemaVersion,
    checkNames: TREASURY_CHECKS,
  });
  item.captured_at = facts.capturedAt;
  const result = verifyProofRegistry(
    { schema_version: 1, generated_at: facts.capturedAt, proposal_id: facts.proposalId, items: [item] },
    { artifacts: { "native-treasury.json": artifactBytes }, now: facts.capturedAt },
  );
  assert.equal(result.status, "invalid");
  assert.match(result.items[0].reasons.join(" "), /exact-envelope v3 proof/i);
});

test("registry turns a treasury execution green only with one identity-matched, correctly ordered exact-v3 proof", async () => {
  const artifact = await buildNativeTreasuryArtifact();
  artifact.release_identity.package_hash = matchedExactProof.deployment.package_hash;
  artifact.release_identity.contract_hash = matchedExactProof.deployment.contract_hash;
  const treasuryText = canonicalTranscriptJson(artifact, "matched native treasury registry fixture");
  const treasuryBytes = Buffer.from(treasuryText, "ascii");
  const treasuryFacts = verifyNativeTreasuryExecutionArtifact(parseJsonStrict(treasuryText));

  const exactProof = structuredClone(matchedExactProof);
  resealExactTemporalEvidence(
    exactProof,
    treasuryFacts.authorizationBlockHeight,
    treasuryFacts.authorizationBlockHash,
  );
  const exactText = canonicalTranscriptJson(exactProof, "matched exact-v3 registry fixture");
  const matchedExactBytes = Buffer.from(exactText, "ascii");
  const matchedExactFacts = verifyExactEnvelopeV3Artifact(parseJsonStrict(exactText));

  const exactItem = commonItem({
    proofId: "exact_envelope_v3",
    proofType: "exact_envelope_v3",
    proposalId: matchedExactFacts.proposalId,
    actionId: matchedExactFacts.actionId,
    envelopeHash: matchedExactFacts.envelopeHash,
    artifactPath: "matched-exact-v3.json",
    artifactBytes: matchedExactBytes,
    facts: matchedExactFacts,
    schemaVersion: "concordia.v3-proof.v1",
    checkNames: EXACT_CHECKS,
  });
  const treasuryItem = commonItem({
    proofId: "native_treasury_execution_v1",
    proofType: "native_treasury_execution_v1",
    proposalId: treasuryFacts.proposalId,
    actionId: treasuryFacts.actionId,
    envelopeHash: treasuryFacts.envelopeHash,
    artifactPath: "matched-native-treasury.json",
    artifactBytes: treasuryBytes,
    facts: treasuryFacts,
    schemaVersion: treasuryFacts.schemaVersion,
    checkNames: TREASURY_CHECKS,
  });
  treasuryItem.captured_at = treasuryFacts.capturedAt;
  const registry = {
    schema_version: 1,
    generated_at: treasuryFacts.capturedAt,
    proposal_id: treasuryFacts.proposalId,
    items: [exactItem, treasuryItem],
  };
  const artifacts = {
    "matched-exact-v3.json": matchedExactBytes,
    "matched-native-treasury.json": treasuryBytes,
  };
  const result = verifyProofRegistry(registry, { artifacts, now: treasuryFacts.capturedAt });
  assert.equal(result.status, "verified");
  assert.equal(result.summary.verified, 2);
  assert.equal(result.items[1].green, true);

  const competingBlockExact = structuredClone(exactProof);
  resealExactTemporalEvidence(
    competingBlockExact,
    treasuryFacts.authorizationBlockHeight,
    "ef".repeat(32),
  );
  const competingBlockText = canonicalTranscriptJson(
    competingBlockExact,
    "competing-block exact-v3 registry fixture",
  );
  const competingBlockBytes = Buffer.from(competingBlockText, "ascii");
  exactItem.artifact_sha256 = sha256(competingBlockBytes);
  const competingBlock = verifyProofRegistry(registry, {
    artifacts: { ...artifacts, "matched-exact-v3.json": competingBlockBytes },
    now: treasuryFacts.capturedAt,
  });
  assert.equal(competingBlock.status, "invalid");
  assert.match(
    competingBlock.items[1].reasons.join(" "),
    /exact scan-start block/i,
  );

  const misorderedExact = structuredClone(exactProof);
  resealExactTemporalEvidence(misorderedExact, treasuryFacts.snapshotBlockHeight);
  const misorderedText = canonicalTranscriptJson(misorderedExact, "misordered exact-v3 registry fixture");
  const misorderedBytes = Buffer.from(misorderedText, "ascii");
  exactItem.artifact_sha256 = sha256(misorderedBytes);
  const invalid = verifyProofRegistry(registry, {
    artifacts: { ...artifacts, "matched-exact-v3.json": misorderedBytes },
    now: treasuryFacts.capturedAt,
  });
  assert.equal(invalid.status, "invalid");
  assert.match(invalid.items[1].reasons.join(" "), /ordering.*snapshot.*finalization/i);
});

test("registry permits treasury execution at the exact authorization block height", async () => {
  const artifact = await buildNativeTreasuryArtifact({ authorizationAtExecution: true });
  artifact.release_identity.package_hash = matchedExactProof.deployment.package_hash;
  artifact.release_identity.contract_hash = matchedExactProof.deployment.contract_hash;
  const treasuryText = canonicalTranscriptJson(artifact, "same-block native treasury registry fixture");
  const treasuryBytes = Buffer.from(treasuryText, "ascii");
  const treasuryFacts = verifyNativeTreasuryExecutionArtifact(parseJsonStrict(treasuryText));
  assert.equal(treasuryFacts.authorizationBlockHeight, treasuryFacts.nativeBlockHeight);

  const exactProof = structuredClone(matchedExactProof);
  resealExactTemporalEvidence(
    exactProof,
    treasuryFacts.authorizationBlockHeight,
    treasuryFacts.authorizationBlockHash,
  );
  const exactText = canonicalTranscriptJson(exactProof, "same-block exact-v3 registry fixture");
  const exactBytesForCase = Buffer.from(exactText, "ascii");
  const exactFactsForCase = verifyExactEnvelopeV3Artifact(parseJsonStrict(exactText));
  const exactItem = commonItem({
    proofId: "exact_envelope_v3",
    proofType: "exact_envelope_v3",
    proposalId: exactFactsForCase.proposalId,
    actionId: exactFactsForCase.actionId,
    envelopeHash: exactFactsForCase.envelopeHash,
    artifactPath: "same-block-exact-v3.json",
    artifactBytes: exactBytesForCase,
    facts: exactFactsForCase,
    schemaVersion: "concordia.v3-proof.v1",
    checkNames: EXACT_CHECKS,
  });
  const treasuryItem = commonItem({
    proofId: "native_treasury_execution_v1",
    proofType: "native_treasury_execution_v1",
    proposalId: treasuryFacts.proposalId,
    actionId: treasuryFacts.actionId,
    envelopeHash: treasuryFacts.envelopeHash,
    artifactPath: "same-block-native-treasury.json",
    artifactBytes: treasuryBytes,
    facts: treasuryFacts,
    schemaVersion: treasuryFacts.schemaVersion,
    checkNames: TREASURY_CHECKS,
  });
  treasuryItem.captured_at = treasuryFacts.capturedAt;
  const result = verifyProofRegistry({
    schema_version: 1,
    generated_at: treasuryFacts.capturedAt,
    proposal_id: treasuryFacts.proposalId,
    items: [exactItem, treasuryItem],
  }, {
    artifacts: {
      "same-block-exact-v3.json": exactBytesForCase,
      "same-block-native-treasury.json": treasuryBytes,
    },
    now: treasuryFacts.capturedAt,
  });
  assert.equal(result.status, "verified");
  assert.equal(result.items[1].green, true);
});
