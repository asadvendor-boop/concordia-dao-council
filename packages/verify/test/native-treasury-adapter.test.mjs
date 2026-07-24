import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonicalTranscriptJson,
  verifyNativeTreasuryExecutionArtifact,
} from "../dist/index.js";
import { buildNativeTreasuryArtifact } from "./helpers/native-treasury-artifact.mjs";

function resealSnapshot(artifact) {
  artifact.authorization.snapshot_sha256 = createHash("sha256")
    .update(canonicalTranscriptJson(artifact.authorization.snapshot, "test treasury snapshot"), "ascii")
    .digest("hex");
}

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
  assert.equal(facts.snapshotObservationCount, 2);
  assert.equal(facts.authorizationBlockHash, "51".repeat(32));
  assert.equal(facts.observedThroughBlockHeight, facts.nativeBlockHeight + 1);
  assert.equal(
    facts.verificationScope,
    "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified",
  );
});

test("native treasury adapter independently verifies and hash-binds both snapshot observers", async () => {
  const mutations = [
    [
      "legacy single-node shape",
      (value) => {
        value.authorization.snapshot = structuredClone(value.balance_evidence.pre_source);
      },
      /snapshot.*fields|snapshot.*schema/i,
    ],
    [
      "dropped observer",
      (value) => {
        value.authorization.snapshot.observations.pop();
      },
      /exactly two.*observations/i,
    ],
    [
      "swapped observers without a new seal",
      (value) => {
        value.authorization.snapshot.observations.reverse();
      },
      /snapshot SHA-256/i,
    ],
    [
      "mutated second observer",
      (value) => {
        const response = value.authorization.snapshot.observations[1].balance_response;
        response.result.value.total_balance = "625000000001";
        response.result.value.available_balance = "625000000001";
      },
      /observed balance|snapshot.*agree/i,
    ],
    [
      "duplicate node origin",
      (value) => {
        value.authorization.snapshot.observations[1].node_url =
          value.authorization.snapshot.observations[0].node_url;
      },
      /snapshot nodes.*distinct/i,
    ],
    [
      "forged snapshot seal",
      (value) => {
        value.authorization.snapshot_sha256 = "ff".repeat(32);
      },
      /snapshot SHA-256/i,
    ],
  ];

  for (const [label, mutate, pattern] of mutations) {
    const artifact = structuredClone(await buildNativeTreasuryArtifact());
    mutate(artifact);
    assert.throws(() => verifyNativeTreasuryExecutionArtifact(artifact), pattern, label);
  }
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
    ["authorization block hash", (value) => {
      value.bounded_transfer_scan.authorization_block_hash = "ff".repeat(32);
    }, /authorization[_ ]block[_ ]hash/i],
    ["impossible timestamp", (value) => { value.captured_at = "2026-02-31T00:00:00Z"; }, /RFC3339/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const artifact = structuredClone(await buildNativeTreasuryArtifact());
    mutate(artifact);
    assert.throws(() => verifyNativeTreasuryExecutionArtifact(artifact), pattern, label);
  }
});

test("Python and TypeScript freeze identical treasury snapshot scalar validators", async () => {
  const vectorUrl = new URL(
    "../../../tests/golden/treasury_snapshot/validator_parity.json",
    import.meta.url,
  );
  const vectors = JSON.parse(await readFile(vectorUrl, "utf8"));
  assert.equal(vectors.schema_id, "concordia.treasury-snapshot-validator-parity.v1");
  for (const vector of vectors.cases) {
    const artifact = structuredClone(await buildNativeTreasuryArtifact());
    if (vector.field === "node_url") {
      artifact.authorization.snapshot.observations[0].node_url = vector.value;
    } else if (vector.field === "captured_at") {
      artifact.authorization.snapshot.observations[0].captured_at = vector.value;
    } else if (vector.field === "expected_balance_motes") {
      artifact.authorization.snapshot.expected_balance_motes = vector.value;
    }
    resealSnapshot(artifact);
    if (vector.accept === true) {
      assert.doesNotThrow(
        () => verifyNativeTreasuryExecutionArtifact(artifact),
        vector.id,
      );
    } else {
      assert.throws(
        () => verifyNativeTreasuryExecutionArtifact(artifact),
        /treasury snapshot/i,
        vector.id,
      );
    }
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
