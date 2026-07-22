import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { before, test } from "node:test";

import {
  canonicalRuntimeArgumentsBytes,
  verifyHistoricalOdraReceiptArtifact,
  verifyProofRegistry,
  verifySignedDeployJson,
} from "../dist/index.js";
import {
  __testOnlyVerifyHistoricalOdraReceiptArtifactWithInventory,
} from "../dist/adapters/historical-odra.js";
import {
  buildHistoricalOdraArtifact,
  buildSignedHistoricalReceiptDeploy,
} from "./helpers/historical-odra-artifact.mjs";

let baseline;

before(async () => {
  baseline = await buildHistoricalOdraArtifact();
});

function verify(artifact) {
  return __testOnlyVerifyHistoricalOdraReceiptArtifactWithInventory(
    artifact,
    baseline.inventoryBytes,
    baseline.inventorySha256,
  );
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function packagedV2UnavailableArtifact() {
  const inventory = await readFile(
    new URL("../../../handoff/HISTORICAL_ODRA_RECEIPTS_V1.json", import.meta.url),
    "utf8",
  );
  const parsed = JSON.parse(inventory);
  const v2 = parsed.chain_identity.v2;
  const artifact = structuredClone(baseline.artifact);
  artifact.generation = "v2";
  artifact.lineage_inventory = {
    schema_version: "concordia.historical_odra_inventory.v1",
    sha256: sha256Hex(Buffer.from(inventory, "utf8")),
    canonical_json: inventory,
  };
  artifact.contract_identity = {
    package_hash: v2.package_hash,
    contract_hash: v2.contract_hash,
    contract_wasm_state_hash: v2.contract_wasm_state_hash,
    contract_version: v2.contract_version,
    protocol_version_major: v2.protocol_version_major,
    entry_point: v2.entry_point,
    session_variant: v2.accepted_session.variant,
    session_target_kind: v2.accepted_session.target_kind,
    session_target_hash: v2.accepted_session.target_hash,
    session_version: v2.accepted_session.version,
  };
  return artifact;
}

test("historical Odra adapter independently verifies signed v1 receipt, chain, state, and frozen lineage", () => {
  const facts = verify(baseline.artifact);
  assert.equal(facts.schemaVersion, "concordia.historical_odra_receipt.v1");
  assert.equal(facts.proposalId, "DAO-PROP-6CB25C");
  assert.equal(facts.generation, "v1");
  assert.equal(facts.deployHash, baseline.artifact.raw_rpc.deploy.request.params.deploy_hash);
  assert.equal(facts.blockHash, baseline.artifact.raw_rpc.deploy.response.result.value.execution_info.block_hash);
  assert.equal(facts.blockHeight, 8_340_490);
  assert.equal(facts.stateRootHash, "cd".repeat(32));
  assert.equal(facts.packageHash, baseline.artifact.contract_identity.package_hash);
  assert.equal(facts.contractHash, baseline.artifact.contract_identity.contract_hash);
  assert.equal(facts.contractWasmStateHash, baseline.artifact.contract_identity.contract_wasm_state_hash);
  assert.equal(facts.sessionVariant, "StoredContractByHash");
  assert.equal(facts.sessionTargetKind, "contract");
  assert.equal(facts.sessionTargetHash, baseline.artifact.contract_identity.contract_hash);
  assert.equal(facts.sessionVersion, null);
  assert.equal(facts.finalCardHash, baseline.artifact.card_chain.cards.at(-1).card_hash);
  assert.equal(facts.receiptArgumentDigest, baseline.pythonArgumentDigest);
  assert.equal(facts.sourceDeploymentEquivalence, "unproven");
  assert.equal(facts.verificationScope, "artifact_transcript_consistency");
  assert.deepEqual(facts.observationSources, []);
});

test("public historical adapter cannot be redirected to a caller-selected inventory", () => {
  assert.throws(
    () => verifyHistoricalOdraReceiptArtifact(baseline.artifact),
    /inventory bytes differ|frozen release/i,
  );
});

test("packaged v2 combined proof is unavailable until its distinct card chain is exported", async () => {
  const artifact = await packagedV2UnavailableArtifact();
  assert.throws(
    () => verifyHistoricalOdraReceiptArtifact(artifact),
    /v2 combined.*unavailable|card chain.*exported/i,
  );
});

test("missing historical raw transcripts are unavailable, not a synthetic pass or contradiction", () => {
  const artifact = structuredClone(baseline.artifact);
  delete artifact.raw_rpc.contract;
  assert.throws(
    () => verify(artifact),
    (error) => error?.name === "HistoricalOdraArtifactUnavailableError" && /contract/i.test(error.message),
  );
});

test("historical source metadata rejects local, private, link-local, and reserved destinations", () => {
  const unsafeHosts = [
    "localhost",
    "proof.local",
    "home.arpa",
    "0.0.0.0",
    "169.254.1.2",
    "192.168.1.2",
    "[::1]",
    "[fc00::1]",
    "[fe80::1]",
    "[::ffff:127.0.0.1]",
  ];
  for (const host of unsafeHosts) {
    const artifact = structuredClone(baseline.artifact);
    artifact.source_url = `https://${host}/proof-artifacts/v1/DAO-PROP-6CB25C/historical-odra-receipt`;
    assert.throws(() => verify(artifact), /public HTTPS|source_url/i, host);
  }
});

test("registry preserves packaged v2 combined-proof unavailability", async () => {
  const artifact = await packagedV2UnavailableArtifact();
  const text = JSON.stringify(artifact);
  const path = "artifacts/live/historical-v2-unavailable.json";
  const requiredChecks = [
    "artifact_hash_recomputed",
    "historical_card_chain_recomputed",
    "deploy_processed_without_execution_error",
    "receipt_arguments_match_historical_artifact",
    "package_and_contract_match_historical_manifest",
    "historical_lineage_matches_frozen_inventory",
  ];
  const item = {
    proof_id: "historical_odra_receipt_v2",
    proof_type: "historical_odra_receipt_v2",
    generation: "v2",
    lineage: "supplemental",
    observation_mode: "live",
    temporal_scope: "historical",
    verification_status: "verified",
    execution_outcome: "accepted",
    claim_scope: "Historical supplemental quorum receipt.",
    enforcement_scope: "Casper Testnet historical receipt only.",
    proposal_id: artifact.proposal_id,
    action_id: null,
    envelope_hash: null,
    artifact_path: path,
    artifact_sha256: sha256Hex(Buffer.from(text, "utf8")),
    source_commit: artifact.source_commit,
    deployment_commit: artifact.deployment_commit,
    network: "casper-test",
    package_hash: artifact.contract_identity.package_hash,
    contract_hash: artifact.contract_identity.contract_hash,
    deployment_domain: null,
    schema_version: artifact.schema_version,
    captured_at: artifact.captured_at,
    payment_requirements_hash: null,
    signed_payment_payload_hash: null,
    report_hash: null,
    settlement_transaction: null,
    checks: requiredChecks.map((name) => ({
      name,
      required: true,
      passed: true,
      source: path,
      observed_at: artifact.captured_at,
    })),
    links: [{
      rel: "artifact",
      label: "Historical v2 raw evidence",
      href: "https://concordia.example/proof-artifacts/v1/DAO-PROP-6CB25C/historical-odra-receipt",
      kind: "artifact",
    }],
  };
  const result = verifyProofRegistry({
    schema_version: 1,
    generated_at: artifact.captured_at,
    proposal_id: artifact.proposal_id,
    items: [item],
  }, {
    artifacts: { [path]: text },
    now: artifact.captured_at,
  });
  assert.equal(result.status, "unavailable");
  assert.equal(result.items[0].green, false);
  assert.match(result.items[0].reasons.join(" "), /combined.*unavailable|card chain.*exported/i);
});

test("historical Odra adapter rejects self-asserted fields and every important binding mutation", () => {
  const mutations = [
    ["asserted boolean", (value) => { value.verified = true; }, /own fields|unknown/i],
    ["inventory bytes", (value) => { value.lineage_inventory.canonical_json += " "; }, /inventory/i],
    ["inventory digest", (value) => { value.lineage_inventory.sha256 = "ff".repeat(32); }, /inventory/i],
    ["generation identity", (value) => { value.contract_identity.contract_hash = "ff".repeat(32); }, /inventory|contract/i],
    ["session variant", (value) => { value.contract_identity.session_variant = "StoredVersionedContractByHash"; }, /contract identity|inventory/i],
    ["session target", (value) => { value.contract_identity.session_target_hash = "ff".repeat(32); }, /contract identity|inventory/i],
    ["signed deploy", (value) => { value.raw_rpc.deploy.response.result.value.deploy.approvals[0].signature = `01${"00".repeat(64)}`; }, /signature/i],
    ["execution error", (value) => { value.raw_rpc.deploy.response.result.value.execution_info.execution_result.Version2.error_message = "User error: 8"; }, /execution|failed/i],
    ["block hash", (value) => { value.raw_rpc.canonical_block.response.result.value.block_with_signatures.block.Version2.hash = "ee".repeat(32); }, /block/i],
    ["state root", (value) => { value.raw_rpc.state_root.response.result.value.state_root_hash = "ee".repeat(32); }, /state root/i],
    ["package version", (value) => { value.raw_rpc.package.response.result.value.stored_value.ContractPackage.versions[0].contract_version = 2; }, /package|version/i],
    ["contract package", (value) => { value.raw_rpc.contract.response.result.value.stored_value.Contract.contract_package_hash = `contract-package-${"ee".repeat(32)}`; }, /package/i],
    ["Wasm state", (value) => { value.raw_rpc.contract.response.result.value.stored_value.Contract.contract_wasm_hash = `contract-wasm-${"ee".repeat(32)}`; }, /Wasm/i],
    ["final card", (value) => { value.raw_rpc.deploy.response.result.value.deploy.session.StoredContractByHash.args[3][1].parsed = "ee".repeat(32); }, /parsed|body hash|card/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const artifact = structuredClone(baseline.artifact);
    mutate(artifact);
    assert.throws(() => verify(artifact), pattern, label);
  }
});

test("historical Odra adapter rejects wrong RPC methods, ids, paths, and ambiguous state", () => {
  const mutations = [
    ["request method", (value) => { value.raw_rpc.package.request.method = "query_balance"; }, /query_global_state|request/i],
    ["response id", (value) => { value.raw_rpc.contract.response.id = 99; }, /response id/i],
    ["state path", (value) => { value.raw_rpc.package.request.params.path = ["named_key"]; }, /params|request/i],
    ["duplicate package version", (value) => { value.raw_rpc.package.response.result.value.stored_value.ContractPackage.versions.push(structuredClone(value.raw_rpc.package.response.result.value.stored_value.ContractPackage.versions[0])); }, /ambiguous|exact|package/i],
    ["duplicate block inclusion", (value) => { value.raw_rpc.canonical_block.response.result.value.block_with_signatures.block.Version2.body.transactions["1"] = [{ Deploy: value.raw_rpc.deploy.request.params.deploy_hash }]; }, /multiple|exactly once/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const artifact = structuredClone(baseline.artifact);
    mutate(artifact);
    assert.throws(() => verify(artifact), pattern, label);
  }
});

test("historical Odra adapter rejects reordered, missing, additional, or mistyped signed arguments", () => {
  const mutations = [
    ["reordered", (args) => { [args[0], args[1]] = [args[1], args[0]]; }, /argument order|body hash/i],
    ["missing", (args) => { args.pop(); }, /argument order|body hash/i],
    ["additional", (args) => { args.push(["passed", { cl_type: "Bool", bytes: "01", parsed: "True" }]); }, /argument order|body hash/i],
    ["mistyped", (args) => { args[0][1].cl_type = "U32"; }, /CLType|String|bytes|body hash|invalid byte length/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const artifact = structuredClone(baseline.artifact);
    mutate(artifact.raw_rpc.deploy.response.result.value.deploy.session.StoredContractByHash.args);
    assert.throws(() => verify(artifact), pattern, label);
  }
});

test("Python and TypeScript share exact v1/v2 NamedArg digest vectors and preserve signed order", () => {
  const finalCardHash = baseline.artifact.card_chain.cards.at(-1).card_hash;
  const vectors = [
    {
      generation: "v1",
      signed: {
        deploy: baseline.artifact.raw_rpc.deploy.response.result.value.deploy,
        argument_digest: baseline.pythonArgumentDigest,
      },
    },
    { generation: "v2", signed: buildSignedHistoricalReceiptDeploy(finalCardHash, "v2") },
  ];
  const digests = [];
  for (const vector of vectors) {
    const deploy = vector.signed.deploy;
    const facts = verifySignedDeployJson(deploy, {
      deployHash: deploy.hash,
      initiatorPublicKey: deploy.header.account,
      chainName: "casper-test",
      exactlyOneApproval: true,
    });
    const order = facts.session.args.map((argument) => argument.name);
    const digest = sha256Hex(
      canonicalRuntimeArgumentsBytes(facts.session.args, order, `${vector.generation} digest`),
    );
    assert.equal(digest, vector.signed.argument_digest, `${vector.generation} cross-language digest`);
    digests.push(digest);
  }
  assert.notEqual(digests[0], digests[1], "generation-specific signed order must change the digest");

  const reordered = structuredClone(vectors[0].signed.deploy);
  const args = reordered.session.StoredContractByHash.args;
  [args[0], args[1]] = [args[1], args[0]];
  assert.throws(
    () => verifySignedDeployJson(reordered, {
      deployHash: reordered.hash,
      initiatorPublicKey: reordered.header.account,
      chainName: "casper-test",
      exactlyOneApproval: true,
    }),
    /body hash|signature|deploy/i,
  );
});
