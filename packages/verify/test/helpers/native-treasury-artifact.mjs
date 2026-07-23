import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { canonicalTranscriptJson } from "../../dist/index.js";

const SNAPSHOT_ROOT = "45".repeat(32);
const FINALITY_BLOCK = "ab".repeat(32);
const FINALITY_ROOT = "cd".repeat(32);
const GAS = "100000000";
const PRE_RECIPIENT = "7000000000";
const POST_RECIPIENT = "57000000000";

function sha256Ascii(value) {
  return createHash("sha256").update(value, "ascii").digest("hex");
}

function status(id, lastAddedBlockInfo) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      name: "info_get_status_result",
      value: {
        api_version: "2.0.0",
        chainspec_name: "casper-test",
        ...(lastAddedBlockInfo === undefined
          ? {}
          : { last_added_block_info: lastAddedBlockInfo }),
      },
    },
  };
}

function block(id, blockHash, blockHeight, stateRootHash, body, parentHash = "00".repeat(32)) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      name: "chain_get_block_result",
      value: {
        block_with_signatures: {
          block: {
            Version2: {
              hash: blockHash,
              header: {
                height: blockHeight,
                parent_hash: parentHash,
                state_root_hash: stateRootHash,
              },
              body,
            },
          },
          proofs: [],
        },
      },
    },
  };
}

function balanceBundle({ account, blockHash, blockHeight, stateRootHash, balance, idBase }) {
  return {
    status_request: {
      jsonrpc: "2.0",
      id: idBase,
      method: "info_get_status",
      params: {},
    },
    status: status(idBase),
    block_request: {
      jsonrpc: "2.0",
      id: idBase + 1,
      method: "chain_get_block",
      params: { block_identifier: { Hash: blockHash } },
    },
    block: block(idBase + 1, blockHash, blockHeight, stateRootHash, { transactions: {} }),
    balance_request: {
      jsonrpc: "2.0",
      id: idBase + 2,
      method: "query_balance_details",
      params: {
        state_identifier: { StateRootHash: stateRootHash },
        purse_identifier: {
          main_purse_under_account_hash: `account-hash-${account}`,
        },
      },
    },
    balance_response: {
      jsonrpc: "2.0",
      id: idBase + 2,
      result: {
        name: "query_balance_details_result",
        value: {
          api_version: "2.0.0",
          total_balance: balance,
          available_balance: balance,
          total_balance_proof: "aa",
          holds: [],
        },
      },
    },
  };
}

function snapshotObservation({ nodeUrl, capturedAt, bundle }) {
  return {
    node_url: nodeUrl,
    captured_at: capturedAt,
    status_request: bundle.status_request,
    status_response: bundle.status,
    block_request: bundle.block_request,
    block_response: bundle.block,
    balance_request: bundle.balance_request,
    balance_response: bundle.balance_response,
  };
}

function finalityNode(nodeUrl, offset, deployHash, finalityHeight) {
  const statusId = 100 + offset;
  const transactionId = 110 + offset;
  const blockId = 120 + offset;
  return {
    node_url: nodeUrl,
    captured_at: `2026-07-22T23:59:4${offset}Z`,
    status_request: {
      jsonrpc: "2.0",
      id: statusId,
      method: "info_get_status",
      params: {},
    },
    status_response: status(statusId),
    transaction_request: {
      jsonrpc: "2.0",
      id: transactionId,
      method: "info_get_deploy",
      params: { deploy_hash: deployHash, finalized_approvals: true },
    },
    transaction_response: {
      jsonrpc: "2.0",
      id: transactionId,
      result: {
        name: "info_get_deploy_result",
        value: {
          deploy: { hash: deployHash },
          execution_info: {
            block_hash: FINALITY_BLOCK,
            block_height: finalityHeight,
            execution_result: {
              Version2: { error_message: null, cost: GAS },
            },
          },
        },
      },
    },
    canonical_block_request: {
      jsonrpc: "2.0",
      id: blockId,
      method: "chain_get_block",
      params: { block_identifier: { Hash: FINALITY_BLOCK } },
    },
    canonical_block_response: block(
      blockId,
      FINALITY_BLOCK,
      finalityHeight,
      FINALITY_ROOT,
      { transactions: { "0": [{ Deploy: deployHash }] } },
    ),
  };
}

function scanTranscript({ source, recipient, amount, transferId, deployHash, authorizationHeight, finalityHeight }) {
  const observedHeight = finalityHeight + 1;
  const hashes = new Map([
    [authorizationHeight, "51".repeat(32)],
    [finalityHeight, FINALITY_BLOCK],
    [observedHeight, "53".repeat(32)],
  ]);
  const observations = [];
  let parentHash = "50".repeat(32);
  for (let current = authorizationHeight; current <= observedHeight; current += 1) {
    const blockHash = hashes.get(current);
    const transfers = current === finalityHeight
      ? [{
          Version1: {
            deploy_hash: deployHash,
            from: `account-hash-${source}`,
            to: `account-hash-${recipient}`,
            amount,
            id: BigInt(transferId),
          },
        }]
      : [];
    observations.push({
      block_request: {
        jsonrpc: "2.0",
        id: `scan-block-${current}`,
        method: "chain_get_block",
        params: { block_identifier: { Height: current } },
      },
      block_response: block(
        `scan-block-${current}`,
        blockHash,
        current,
        "dd".repeat(32),
        { transactions: {} },
        parentHash,
      ),
      transfers_request: {
        jsonrpc: "2.0",
        id: `scan-transfers-${current}`,
        method: "chain_get_block_transfers",
        params: { block_identifier: { Hash: blockHash } },
      },
      transfers_response: {
        jsonrpc: "2.0",
        id: `scan-transfers-${current}`,
        result: { block_hash: blockHash, transfers },
      },
    });
    parentHash = blockHash;
  }
  return {
    authorization_block_height: authorizationHeight,
    chain_status_request: {
      jsonrpc: "2.0",
      id: "scan-status",
      method: "info_get_status",
      params: {},
    },
    chain_status_response: status("scan-status", {
      hash: hashes.get(observedHeight),
      height: observedHeight,
    }),
    block_observations: observations,
  };
}

export async function buildNativeTreasuryArtifact(options = {}) {
  const coreUrl = new URL("../fixtures/native-treasury-core.json", import.meta.url);
  const core = JSON.parse(await readFile(coreUrl, "utf8"));
  const header = core.authorization.typed_header;
  const body = core.authorization.typed_body;
  const snapshotHeight = Number(body.snapshot_block_height);
  const authorizationHeight = options.authorizationAtExecution === true
    ? snapshotHeight + 2
    : snapshotHeight + 1;
  const finalityHeight = snapshotHeight + 2;
  const source = body.source_account;
  const recipient = body.recipient_account;
  const deployHash = core.executor_journal.deploy_hash;
  const primarySnapshotBundle = balanceBundle({
    account: source,
    blockHash: body.snapshot_block_hash,
    blockHeight: snapshotHeight,
    stateRootHash: SNAPSHOT_ROOT,
    balance: body.treasury_snapshot_balance_motes,
    idBase: 10,
  });
  const secondarySnapshotBundle = balanceBundle({
    account: source,
    blockHash: body.snapshot_block_hash,
    blockHeight: snapshotHeight,
    stateRootHash: SNAPSHOT_ROOT,
    balance: body.treasury_snapshot_balance_motes,
    idBase: 60,
  });
  const snapshot = {
    schema_id: "concordia.native-treasury-snapshot.v1",
    network: "casper-test",
    source_account_hash: source,
    expected_balance_motes: body.treasury_snapshot_balance_motes,
    observations: [
      snapshotObservation({
        nodeUrl: "https://snapshot-a.example.com/rpc",
        capturedAt: "2026-07-22T23:58:00Z",
        bundle: primarySnapshotBundle,
      }),
      snapshotObservation({
        nodeUrl: "https://snapshot-b.example.com/rpc",
        capturedAt: "2026-07-22T23:58:01Z",
        bundle: secondarySnapshotBundle,
      }),
    ],
  };
  const preRecipient = balanceBundle({
    account: recipient,
    blockHash: body.snapshot_block_hash,
    blockHeight: snapshotHeight,
    stateRootHash: SNAPSHOT_ROOT,
    balance: PRE_RECIPIENT,
    idBase: 20,
  });
  const postSource = balanceBundle({
    account: source,
    blockHash: FINALITY_BLOCK,
    blockHeight: finalityHeight,
    stateRootHash: FINALITY_ROOT,
    balance: "574900000000",
    idBase: 30,
  });
  const postRecipient = balanceBundle({
    account: recipient,
    blockHash: FINALITY_BLOCK,
    blockHeight: finalityHeight,
    stateRootHash: FINALITY_ROOT,
    balance: POST_RECIPIENT,
    idBase: 40,
  });
  const nodeObservations = [
    finalityNode("https://rpc-a.example.com/rpc", 0, deployHash, finalityHeight),
    finalityNode("https://rpc-b.example.com/rpc", 1, deployHash, finalityHeight),
  ];
  const balanceEvidence = {
    pre_source: primarySnapshotBundle,
    pre_recipient: preRecipient,
    post_source: postSource,
    post_recipient: postRecipient,
  };
  const transcript = scanTranscript({
    source,
    recipient,
    amount: body.amount_motes,
    transferId: body.transfer_id,
    deployHash,
    authorizationHeight,
    finalityHeight,
  });
  const observedHeight = finalityHeight + 1;
  const observedHash = "53".repeat(32);
  const authorizationBlockHash = authorizationHeight === finalityHeight
    ? FINALITY_BLOCK
    : "51".repeat(32);
  const digestMaterial = canonicalTranscriptJson(
    {
      post_balance_evidence_sha256: sha256Ascii(
        canonicalTranscriptJson(balanceEvidence, "fixture balance evidence"),
      ),
      no_duplicate_scan_sha256: sha256Ascii(
        canonicalTranscriptJson(transcript, "fixture scan transcript"),
      ),
      deploy_hash: deployHash,
    },
    "fixture execution digest",
  );
  return {
    schema_version: "concordia.native_treasury_execution.v1",
    captured_at: "2026-07-23T00:00:00Z",
    source_commit: "1".repeat(40),
    deployment_commit: "2".repeat(40),
    release_identity: core.release_identity,
    authorization: {
      ...core.authorization,
      exact_v3_proof: {},
      v3_readback: {},
      snapshot,
      snapshot_sha256: sha256Ascii(
        canonicalTranscriptJson(snapshot, "fixture treasury snapshot"),
      ),
    },
    executor_journal: {
      state: "PROVEN",
      signed_deploy_bytes_hex: core.executor_journal.signed_deploy_bytes_hex,
      signed_deploy_sha256: core.executor_journal.signed_deploy_sha256,
      deploy_hash: deployHash,
      broadcast_attempts: 1,
      last_detail_code: "execution_proven",
      payment_amount_motes: core.executor_journal.payment_amount_motes,
      created_at: "2026-07-22T23:59:00Z",
      updated_at: "2026-07-22T23:59:59Z",
      execution_proof_sha256: sha256Ascii(digestMaterial),
    },
    finality: {
      facts: {
        deploy_hash: deployHash,
        block_hash: FINALITY_BLOCK,
        block_height: finalityHeight,
        state_root_hash: FINALITY_ROOT,
        execution_result_kind: "Version2",
        gas_motes: GAS,
        corroboration_count: 1,
      },
      node_observations: nodeObservations,
      verification_scope:
        "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified",
    },
    balance_evidence: balanceEvidence,
    bounded_transfer_scan: {
      authorization_block_height: authorizationHeight,
      authorization_block_hash: authorizationBlockHash,
      observed_through_block_height: observedHeight,
      observed_through_block_hash: observedHash,
      scanned_block_count: transcript.block_observations.length,
      matched_transfer_count: 1,
      transcript,
    },
    artifact_sha256_scope: "canonical_json_without_release_manifest",
  };
}
