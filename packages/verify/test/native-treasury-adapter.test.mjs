import assert from "node:assert/strict";
import { test } from "node:test";

import { verifyNativeTreasuryExecutionArtifact } from "../dist/index.js";
import { buildNativeTreasuryArtifact } from "./helpers/native-treasury-artifact.mjs";

test("native treasury adapter independently derives the full bounded execution proof", async () => {
  const artifact = await buildNativeTreasuryArtifact();
  const facts = verifyNativeTreasuryExecutionArtifact(artifact);

  assert.equal(facts.proposalId, "DAO-PROP-V3-TREASURY");
  assert.equal(facts.actionId, artifact.authorization.action_id);
  assert.equal(facts.envelopeHash, artifact.authorization.envelope_hash);
  assert.equal(facts.amountMotes, "50000000000");
  assert.equal(facts.treasurySnapshotBalanceMotes, "625000000000");
  assert.equal(facts.approvedAllocationBps, "800");
  assert.equal(facts.nativeDeployHash, artifact.executor_journal.deploy_hash);
  assert.equal(facts.nodeObservationCount, 2);
  assert.equal(facts.authorizationBlockHash, "51".repeat(32));
  assert.equal(facts.observedThroughBlockHeight, facts.nativeBlockHeight + 1);
  assert.equal(
    facts.verificationScope,
    "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified",
  );
});

test("native treasury adapter rejects every caller summary that conflicts with raw proof", async () => {
  const mutations = [
    ["typed material", (value) => { value.authorization.action_id = "ff".repeat(32); }, /action_id/i],
    ["signed bytes", (value) => { value.executor_journal.signed_deploy_sha256 = "ff".repeat(32); }, /signed deploy SHA/i],
    ["broadcast count", (value) => { value.executor_journal.broadcast_attempts = 2; }, /one broadcast|exactly one/i],
    ["finality summary", (value) => { value.finality.facts.gas_motes = "100000001"; }, /finality facts gas_motes/i],
    ["post delta", (value) => {
      value.balance_evidence.post_recipient.balance_response.result.value.total_balance = "57000000001";
      value.balance_evidence.post_recipient.balance_response.result.value.available_balance = "57000000001";
    }, /recipient delta/i],
    ["bounded scan", (value) => { value.bounded_transfer_scan.matched_transfer_count = 2; }, /summary/i],
    ["impossible timestamp", (value) => { value.captured_at = "2026-02-31T00:00:00Z"; }, /RFC3339/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const artifact = structuredClone(await buildNativeTreasuryArtifact());
    mutate(artifact);
    assert.throws(() => verifyNativeTreasuryExecutionArtifact(artifact), pattern, label);
  }
});

test("native treasury adapter rejects a second source and transfer-id match", async () => {
  const artifact = await buildNativeTreasuryArtifact();
  const inclusion = artifact.bounded_transfer_scan.transcript.block_observations[1];
  const duplicate = structuredClone(inclusion.transfers_response.result.transfers[0]);
  duplicate.Version1.deploy_hash = "ef".repeat(32);
  artifact.bounded_transfer_scan.transcript.block_observations[2]
    .transfers_response.result.transfers.push(duplicate);

  assert.throws(
    () => verifyNativeTreasuryExecutionArtifact(artifact),
    /exactly one transfer/i,
  );
});

test("native treasury adapter requires own frozen fields", async () => {
  const artifact = await buildNativeTreasuryArtifact();
  assert.throws(
    () => verifyNativeTreasuryExecutionArtifact(Object.create(artifact)),
    /own fields/i,
  );
});
