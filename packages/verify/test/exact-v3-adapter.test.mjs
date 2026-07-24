import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { before, test } from "node:test";

import { canonicalTranscriptJson, parseJsonStrict, verifyExactEnvelopeV3Artifact } from "../dist/index.js";

const REPOSITORY = fileURLToPath(new URL("../../../", import.meta.url));
let baseline;

function sha256Canonical(value) {
  return createHash("sha256")
    .update(canonicalTranscriptJson(value, "test transcript"), "ascii")
    .digest("hex");
}

function addInstallTwoNodeFinality(proof) {
  const deployment = proof.deployment;
  const installHash = deployment.install_deploy_hash.toLowerCase();
  const installResult = deployment.raw_rpc.install_deploy.response.result;
  const blockHash = deployment.install_block_hash;
  const blockHeight = deployment.install_block_height;
  const stateRootHash = deployment.install_state_root_hash;
  const blockTimestamp = "2026-01-23T12:34:58.000Z";
  const observations = proof.run.steps[0].finality_block_evidence.node_observations.map(
    (source, index) => {
      const item = structuredClone(source);
      item.deploy_request.id = `install-finality-${index}`;
      item.deploy_request.params = { deploy_hash: installHash };
      item.deploy_response = {
        jsonrpc: "2.0",
        id: item.deploy_request.id,
        result: structuredClone(installResult),
      };
      item.block_request.id = `install-block-${index}`;
      item.block_request.params = { block_identifier: { Hash: blockHash } };
      item.block_response.id = item.block_request.id;
      const block = item.block_response.result.block_with_signatures.block.Version2;
      block.hash = blockHash;
      block.header.height = blockHeight;
      block.header.state_root_hash = stateRootHash;
      block.header.timestamp = blockTimestamp;
      block.body.transactions = { "0": [{ Deploy: installHash }] };
      return item;
    },
  );
  deployment.two_node_finality = {
    status: "finalized",
    block_hash: blockHash,
    block_height: blockHeight,
    state_root_hash: stateRootHash,
    block_timestamp: blockTimestamp,
    finalized_at: blockTimestamp,
    observed_at: "2026-01-23T12:34:59.000Z",
    deploy_hash: installHash,
    corroboration_count: 2,
    success: true,
    user_error: null,
    node_observations: observations,
    endpoint_identities: observations.map((item) => item.node_url),
  };
}

before(() => {
  const script = [
    "import json",
    "from tests.test_clvalue_roundtrip import _bound_v3_proof",
    "proof, _, _ = _bound_v3_proof()",
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ].join("\n");
  const raw = execFileSync("uv", ["run", "--frozen", "--python", "python3.12", "python", "-c", script], {
    cwd: REPOSITORY,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  baseline = parseJsonStrict(raw);
});

test("exact-envelope v3 adapter independently verifies the frozen seven-step proof", () => {
  const facts = verifyExactEnvelopeV3Artifact(baseline);
  assert.equal(facts.schemaId, "concordia.v3-proof-verification.v1");
  assert.equal(facts.network, "casper-test");
  assert.equal(facts.proposalId, "DAO-PROP-V3-001");
  assert.equal(facts.actionId, baseline.prepared.action_id);
  assert.equal(facts.envelopeHash, baseline.prepared.envelope_hash);
  assert.equal(facts.packageHash, baseline.deployment.package_hash);
  assert.equal(facts.contractHash, baseline.deployment.contract_hash);
  assert.equal(facts.deploymentDomain, baseline.deployment.deployment_domain);
  assert.equal(facts.installDeployHash, baseline.deployment.install_deploy_hash.toLowerCase());
  assert.equal(facts.contractStepOutcomes.finalize_pre_quorum.userError, 8);
  assert.equal(facts.contractStepOutcomes.finalize_mutated_3000_bps.userError, 10);
  assert.equal(facts.contractStepOutcomes.finalize_exact.success, true);
  assert.equal(facts.contractStepOutcomes.finalize_again.userError, 12);
  assert.ok(facts.finalizationBlockHeight <= facts.observedBlockHeight);
});

test("exact-envelope v3 adapter accepts and verifies producer two-node install finality", () => {
  const proof = structuredClone(baseline);
  addInstallTwoNodeFinality(proof);
  assert.equal(verifyExactEnvelopeV3Artifact(proof).installBlockHash, proof.deployment.install_block_hash);

  proof.deployment.two_node_finality.node_observations[1]
    .block_response.result.block_with_signatures.block.Version2.header.state_root_hash = "ff".repeat(32);
  assert.throws(() => verifyExactEnvelopeV3Artifact(proof), /two-node|node facts|state root|finality/i);
});

test("exact-envelope v3 adapter requires producer two-node install finality", () => {
  const proof = structuredClone(baseline);
  delete proof.deployment.two_node_finality;

  assert.throws(() => verifyExactEnvelopeV3Artifact(proof), /two-node.*finality/i);
});

test("exact-envelope v3 adapter rejects altered install two-node summary fields", () => {
  for (const [field, value] of [
    ["status", "operator_asserted"],
    ["state_root_hash", "ff".repeat(32)],
    ["observed_at", "2099-01-01T00:00:00Z"],
    ["success", false],
  ]) {
    const proof = structuredClone(baseline);
    proof.deployment.two_node_finality[field] = value;
    assert.throws(
      () => verifyExactEnvelopeV3Artifact(proof),
      /two-node|node evidence|node facts|state root|finality/i,
      `accepted altered install two-node ${field}`,
    );
  }
});

test("exact-envelope v3 adapter accepts only hash-reconciled lost broadcast evidence", () => {
  const proof = structuredClone(baseline);
  addInstallTwoNodeFinality(proof);
  proof.deployment.raw_rpc.broadcast_response = {
    status: "response_lost_reconciled_by_hash",
    deploy_hash: proof.deployment.install_deploy_hash,
  };
  const step = proof.run.steps[0];
  delete step.broadcast_transcript;
  step.broadcast_evidence = {
    status: "response_lost_reconciled_by_hash",
    deploy_hash: step.deploy_hash.toLowerCase(),
  };
  assert.equal(verifyExactEnvelopeV3Artifact(proof).contractStepOutcomes.propose_exact.success, true);

  proof.run.steps[0].broadcast_evidence.deploy_hash = "ff".repeat(32);
  assert.throws(() => verifyExactEnvelopeV3Artifact(proof), /broadcast.*evidence|deploy hash/i);
});

test("exact-envelope v3 adapter matches the producer's 3000-bps negative mutation branch", () => {
  const script = [
    "import json",
    "import tests.test_clvalue_roundtrip as fixtures",
    "from shared.actions_v3 import build_native_material",
    "document = fixtures._native_document()",
    "document['header']['requested_allocation_bps'] = '4000'",
    "document['header']['approved_allocation_bps'] = '3000'",
    "document['body']['amount_motes'] = '187500000000'",
    "document['header'], document['body'], _ = build_native_material(document['header'], document['body'])",
    "fixtures._native_document = lambda: document",
    "proof, _, _ = fixtures._bound_v3_proof()",
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ].join("\n");
  const raw = execFileSync("uv", ["run", "--frozen", "--python", "python3.12", "python", "-c", script], {
    cwd: REPOSITORY,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  const proof = parseJsonStrict(raw);
  assert.equal(proof.run.steps[4].deploy.session.StoredContractByHash.args
    .find(([name]) => name === "approved_allocation_bps")[1].parsed, 2999);
  assert.equal(verifyExactEnvelopeV3Artifact(proof).contractStepOutcomes.finalize_mutated_3000_bps.userError, 10);
});

test("exact-envelope v3 adapter rejects every unbound summary or raw-evidence mutation", () => {
  const mutations = [
    ["unknown top-level assertion", (proof) => { proof.valid = true; }, /frozen own fields/i],
    ["typed amount", (proof) => { proof.input.body.amount_motes = "1"; }, /amount|recomputation|prepared/i],
    ["prepared CLValue bytes", (proof) => { proof.prepared.runtime_args[0].bytes = "00"; }, /CLValue|String|bytes/i],
    ["release source hash", (proof) => { proof.deployment.source.lib_rs_sha256 = "ff".repeat(32); }, /deployment source|packaged/i],
    ["install wasm", (proof) => {
      const session = proof.deployment.raw_rpc.install_deploy.response.result.deploy.session.ModuleBytes;
      session.module_bytes = `${session.module_bytes.startsWith("00") ? "ff" : "00"}${session.module_bytes.slice(2)}`;
    }, /body hash|Wasm|release/i],
    ["impossible install timestamp", (proof) => {
      proof.deployment.raw_rpc.install_deploy.response.result.deploy.header.timestamp = "2026-02-31T00:00Z";
    }, /timestamp/i],
    ["run signature", (proof) => {
      proof.run.steps[0].deploy.approvals[0].signature = `01${"00".repeat(64)}`;
    }, /signature/i],
    ["node-returned deploy", (proof) => {
      proof.run.steps[0].finality_transcript.response.result.deploy.header.gas_price = 2;
    }, /checksum|hash|node-returned/i],
    ["wrong rejection code", (proof) => {
      proof.run.steps[1].finality_transcript.response.result.execution_info.execution_result.Version2.error_message = "User error: 9";
    }, /checksum|outcome|User error/i],
    ["nonfinal durable state", (proof) => {
      proof.run.steps[0].submission_state = "broadcast_ambiguous";
    }, /submission state|finalized/i],
    ["asserted finality state root", (proof) => {
      proof.run.steps[0].finality_block_evidence.state_root_hash = "ff".repeat(32);
    }, /state_root_hash|raw node evidence/i],
    ["single-node finality", (proof) => {
      proof.run.steps[0].finality_block_evidence.node_observations.pop();
      proof.run.steps[0].finality_block_evidence.endpoint_identities.pop();
      proof.run.steps[0].finality_block_evidence.corroboration_count = 1;
    }, /two-node|two node|exactly two|finalized/i],
    ["observation before canonical finalization", (proof) => {
      proof.run.steps[0].finality_block_evidence.observed_at = "2026-01-23T12:34:55.000Z";
    }, /predates canonical finalization/i],
    ["reversed observation chronology", (proof) => {
      proof.run.steps[0].finality_block_evidence.observed_at = "2099-01-01T00:00:00.000Z";
    }, /observation chronology/i],
    ["second-node competing block", (proof) => {
      const node = proof.run.steps[0].finality_block_evidence.node_observations[1];
      node.block_response.result.block_with_signatures.block.Version2.hash = "ef".repeat(32);
    }, /block|node|evidence/i],
    ["readback fact", (proof) => { proof.readback.facts.action_authorized = false; }, /checksum|facts|authorization|readback/i],
    ["raw state", (proof) => {
      const state = proof.readback.transcripts.find((item) => item.method === "state_get_dictionary_item");
      state.response.result.stored_value.CLValue.parsed[0] ^= 1;
    }, /checksum|parsed|CLValue|readback/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const proof = structuredClone(baseline);
    mutate(proof);
    assert.throws(() => verifyExactEnvelopeV3Artifact(proof), pattern, label);
  }
});

test("exact-envelope v3 adapter requires own frozen fields", () => {
  assert.throws(
    () => verifyExactEnvelopeV3Artifact(Object.create(baseline)),
    /own fields/i,
  );
});

test("exact-envelope v3 adapter reads the installer package key only from a strict Account.named_keys", () => {
  const conflicting = structuredClone(baseline);
  const storedValue = conflicting.deployment.raw_rpc.installer_account.response.result.stored_value;
  const expected = storedValue.Account.named_keys[0].key;
  storedValue.Account.named_keys[0].key = `hash-${"bb".repeat(32)}`;
  storedValue.decoy = {
    name: "concordia_governance_receipt_v3",
    key: expected,
  };
  assert.throws(
    () => verifyExactEnvelopeV3Artifact(conflicting),
    /stored value|named key|Account/i,
  );

  const duplicate = structuredClone(baseline);
  duplicate.deployment.raw_rpc.installer_account.response.result.stored_value.Account.named_keys.push({
    name: "concordia_governance_receipt_v3",
    key: `hash-${"cc".repeat(32)}`,
  });
  assert.throws(
    () => verifyExactEnvelopeV3Artifact(duplicate),
    /duplicate.*named key/i,
  );
});

test("exact-envelope v3 adapter rejects nonmonotonic step finality after checksums are resealed", () => {
  const proof = structuredClone(baseline);
  const step = proof.run.steps[1];
  const transcript = step.finality_transcript;
  const height =
    proof.run.steps[0].finality_transcript.response.result.execution_info.block_height - 1;
  transcript.response.result.execution_info.block_height = height;
  transcript.canonical_sha256 = sha256Canonical({
    request: transcript.request,
    response: transcript.response,
  });
  step.finality_block_evidence.block_height = height;
  for (const node of step.finality_block_evidence.node_observations) {
    node.deploy_response.result.execution_info.block_height = height;
    node.block_response.result.block_with_signatures.block.Version2.header.height = height;
  }
  assert.throws(() => verifyExactEnvelopeV3Artifact(proof), /nonmonotonic/i);
});

test("exact-envelope v3 adapter rejects two different canonical blocks at one step height", () => {
  const proof = structuredClone(baseline);
  const step = proof.run.steps[1];
  const transcript = step.finality_transcript;
  const blockHash = "ef".repeat(32);
  const blockHeight = proof.run.steps[0].finality_transcript.response.result.execution_info.block_height;
  transcript.response.result.execution_info.block_hash = blockHash;
  transcript.response.result.execution_info.block_height = blockHeight;
  transcript.canonical_sha256 = sha256Canonical({
    request: transcript.request,
    response: transcript.response,
  });
  step.finality_block_evidence.block_hash = blockHash;
  step.finality_block_evidence.block_height = blockHeight;
  for (const node of step.finality_block_evidence.node_observations) {
    node.deploy_response.result.execution_info.block_hash = blockHash;
    node.deploy_response.result.execution_info.block_height = blockHeight;
    node.block_request.params.block_identifier.Hash = blockHash;
    node.block_response.result.block_with_signatures.block.Version2.hash = blockHash;
    node.block_response.result.block_with_signatures.block.Version2.header.height = blockHeight;
  }
  assert.throws(
    () => verifyExactEnvelopeV3Artifact(proof),
    /another block at the same height/i,
  );
});

test("exact-envelope v3 adapter requires contract choreography after the install block", () => {
  const proof = structuredClone(baseline);
  const deployment = proof.deployment;
  deployment.raw_rpc.install_deploy.response.result.execution_info.block_height = 9_002;
  deployment.verified_install_deploy.block_height = 9_002;
  deployment.install_block_height = 9_002;
  deployment.finality.block_height = 9_002;
  deployment.two_node_finality.block_height = 9_002;
  for (const node of deployment.two_node_finality.node_observations) {
    node.deploy_response.result.execution_info.block_height = 9_002;
    node.block_response.result.block_with_signatures.block.Version2.header.height = 9_002;
  }
  assert.throws(
    () => verifyExactEnvelopeV3Artifact(proof),
    /after the verified contract installation/i,
  );
});

test("exact-envelope v3 adapter rejects a validly resealed readback from before finalization", () => {
  const proof = structuredClone(baseline);
  const finalizeHeight = proof.run.steps[5].finality_transcript.response.result.execution_info.block_height;
  const blockTranscript = proof.readback.transcripts.find((item) => item.method === "chain_get_block");
  blockTranscript.response.result.block_with_signatures.block.Version2.header.height = finalizeHeight - 1;
  blockTranscript.canonical_sha256 = sha256Canonical({
    request: blockTranscript.request,
    response: blockTranscript.response,
  });
  proof.readback.facts.observed_block_height = finalizeHeight - 1;
  const withoutHash = structuredClone(proof.readback);
  delete withoutHash.artifact_sha256;
  proof.readback.artifact_sha256 = sha256Canonical(withoutHash);
  proof.run.readback = structuredClone(proof.readback);
  assert.throws(() => verifyExactEnvelopeV3Artifact(proof), /predates.*finalization/i);
});

test("exact-envelope v3 adapter rejects a readback from a competing block at the finalization height", () => {
  const proof = structuredClone(baseline);
  const finalizeHeight = proof.run.steps[5].finality_transcript.response.result.execution_info.block_height;
  const blockTranscript = proof.readback.transcripts.find((item) => item.method === "chain_get_block");
  blockTranscript.response.result.block_with_signatures.block.Version2.header.height = finalizeHeight;
  blockTranscript.canonical_sha256 = sha256Canonical({
    request: blockTranscript.request,
    response: blockTranscript.response,
  });
  proof.readback.facts.observed_block_height = finalizeHeight;
  const withoutHash = structuredClone(proof.readback);
  delete withoutHash.artifact_sha256;
  proof.readback.artifact_sha256 = sha256Canonical(withoutHash);
  proof.run.readback = structuredClone(proof.readback);
  assert.throws(
    () => verifyExactEnvelopeV3Artifact(proof),
    /conflicts.*finalization block.*same height/i,
  );
});
