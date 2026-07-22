import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  verifyCorroboratedNativeTransfer,
  verifyFinalizedNativeTransfer,
  verifyNativeEnvelopeMaterialV3,
  verifySignedNativeTransferDeploy,
} from "../dist/index.js";

const SIGNED_DEPLOY_HEX =
  "0179b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664" +
  "007094349801000040771b00000000000100000000000000" +
  "279f8b9d3a1d1a2094fa37ad97478179e0afa86bc8279ea7c95642b12808a313" +
  "000000000b0000006361737065722d74657374" +
  "f5e101a5c5606300e6faa36591f38d2f7d5152ad0ba7fe1fa2b0cf712bd50ce8" +
  "00000000000100000006000000616d6f756e74050000000400e1f5050805" +
  "0300000006000000746172676574210000000022222222222222222222222222222222222222222222222222222222222222220b" +
  "06000000616d6f756e74060000000500743ba40b08" +
  "020000006964090000000108070605040302010d05" +
  "010000000179b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664" +
  "0120221dffca16d4188b181b15f938fcb5f198c94b42c3a89043c2def6f624e767429a653767ab0f88930ba6703a380eebcd0130012df0a573cca03026932d7308";

const EXPECTED = Object.freeze({
  sourceAccountHash: "2cafe3242874778ed07291e1205a2773e4913b920695cbd8bb5887373eff99f7",
  recipientAccountHash: "22".repeat(32),
  amountMotes: "50000000000",
  transferId: "72623859790382856",
  paymentAmountMotes: "100000000",
  maxPaymentAmountMotes: "100000000",
});

const DEPLOY_HASH = "f5e101a5c5606300e6faa36591f38d2f7d5152ad0ba7fe1fa2b0cf712bd50ce8";
const SECP_SIGNED_DEPLOY_HEX =
  "020284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b" +
  "0007094349801000040771b00000000000100000000000000" +
  "279f8b9d3a1d1a2094fa37ad97478179e0afa86bc8279ea7c95642b12808a313" +
  "000000000b0000006361737065722d74657374" +
  "b090a90c253c2c6ea0bfe256f03a78a673c37296e7f04ac680e3ddf2b78b168f" +
  "00000000000100000006000000616d6f756e74050000000400e1f5050805" +
  "0300000006000000746172676574210000000022222222222222222222222222222222222222222222222222222222222222220b" +
  "06000000616d6f756e74060000000500743ba40b08" +
  "020000006964090000000108070605040302010d05" +
  "01000000020284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b" +
  "0020679c9a75c303bae630dce1b78fe01ea5efa8ba1a44ccbf570e11b3c1624351ee42f70d2797bbfdf8d5da5d7d3fe564d9b81501b1ee6d2e0c2c17f619cfab2b7";
const BLOCK_HASH = "ab".repeat(32);
const STATE_ROOT_HASH = "cd".repeat(32);
const BLOCK_HEIGHT = 8_400_123;

function rpcPayload() {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      name: "info_get_deploy_result",
      value: {
        api_version: "2.0.0",
        deploy: { hash: DEPLOY_HASH },
        execution_info: {
          block_hash: BLOCK_HASH,
          block_height: BLOCK_HEIGHT,
          execution_result: {
            Version2: {
              error_message: null,
              cost: "100000000",
            },
          },
        },
      },
    },
  };
}

function blockPayload() {
  return {
    jsonrpc: "2.0",
    id: 2,
    result: {
      name: "chain_get_block_result",
      value: {
        block_with_signatures: {
          block: {
            Version2: {
              hash: BLOCK_HASH,
              header: { height: BLOCK_HEIGHT, state_root_hash: STATE_ROOT_HASH },
              body: { transactions: { "0": [{ Deploy: DEPLOY_HASH }], "1": [] } },
            },
          },
          proofs: [],
        },
      },
    },
  };
}

function statusPayload(id = 10) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      name: "info_get_status_result",
      value: {
        api_version: "2.0.0",
        chainspec_name: "casper-test",
      },
    },
  };
}

function nodeObservation(nodeUrl, offset = 0) {
  const statusId = 10 + offset;
  const transactionId = 20 + offset;
  const blockId = 30 + offset;
  const transactionResponse = rpcPayload();
  transactionResponse.id = transactionId;
  const canonicalBlockResponse = blockPayload();
  canonicalBlockResponse.id = blockId;
  return {
    node_url: nodeUrl,
    captured_at: `2026-07-23T00:00:0${offset}Z`,
    status_request: {
      jsonrpc: "2.0",
      id: statusId,
      method: "info_get_status",
      params: {},
    },
    status_response: statusPayload(statusId),
    transaction_request: {
      jsonrpc: "2.0",
      id: transactionId,
      method: "info_get_deploy",
      params: { deploy_hash: DEPLOY_HASH, finalized_approvals: true },
    },
    transaction_response: transactionResponse,
    canonical_block_request: {
      jsonrpc: "2.0",
      id: blockId,
      method: "chain_get_block",
      params: { block_identifier: { Hash: BLOCK_HASH } },
    },
    canonical_block_response: canonicalBlockResponse,
  };
}

function legacyRpcPayload() {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: {
      api_version: "1.5.8",
      deploy: { hash: DEPLOY_HASH },
      execution_results: [
        {
          block_hash: BLOCK_HASH,
          result: { Success: { cost: "100000000", transfers: [] } },
        },
      ],
    },
  };
}

function legacyBlockPayload() {
  return {
    jsonrpc: "2.0",
    id: 2,
    result: {
      api_version: "1.5.8",
      block: {
        hash: BLOCK_HASH,
        header: { height: BLOCK_HEIGHT, state_root_hash: STATE_ROOT_HASH },
        body: { deploy_hashes: [], transfer_hashes: [DEPLOY_HASH] },
      },
    },
  };
}

test("signed-deploy adapter independently decodes, hashes, and verifies the exact native transfer", () => {
  const facts = verifySignedNativeTransferDeploy({ signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED });

  assert.equal(facts.deployHash, DEPLOY_HASH);
  assert.equal(facts.bodyHash, "279f8b9d3a1d1a2094fa37ad97478179e0afa86bc8279ea7c95642b12808a313");
  assert.equal(facts.chainName, "casper-test");
  assert.equal(facts.sourceAccountHash, EXPECTED.sourceAccountHash);
  assert.equal(facts.recipientAccountHash, EXPECTED.recipientAccountHash);
  assert.equal(facts.amountMotes, EXPECTED.amountMotes);
  assert.equal(facts.transferId, EXPECTED.transferId);
  assert.equal(facts.paymentAmountMotes, EXPECTED.paymentAmountMotes);
  assert.deepEqual(facts.approvalSigners, ["0179b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664"]);
});

test("signed-deploy adapter verifies secp256k1 approvals without an SDK trust shortcut", () => {
  const facts = verifySignedNativeTransferDeploy({
    signedDeployHex: SECP_SIGNED_DEPLOY_HEX,
    ...EXPECTED,
    sourceAccountHash: "b97a60c67c515548134b9d7b371b9eb88a7cecd369a1f977b0bf51ab84f12c9f",
  });

  assert.equal(facts.deployHash, "b090a90c253c2c6ea0bfe256f03a78a673c37296e7f04ac680e3ddf2b78b168f");
  assert.deepEqual(facts.approvalSigners, [
    "020284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0",
  ]);
});

test("signed-deploy adapter rejects trailing bytes, signature tampering, and semantic mismatches", () => {
  assert.throws(
    () => verifySignedNativeTransferDeploy({ signedDeployHex: `${SIGNED_DEPLOY_HEX}00`, ...EXPECTED }),
    /trailing bytes/i,
  );
  const tamperedSignature = `${SIGNED_DEPLOY_HEX.slice(0, -2)}00`;
  assert.throws(
    () => verifySignedNativeTransferDeploy({ signedDeployHex: tamperedSignature, ...EXPECTED }),
    /signature/i,
  );
  assert.throws(
    () => verifySignedNativeTransferDeploy({
      signedDeployHex: SIGNED_DEPLOY_HEX,
      ...EXPECTED,
      amountMotes: "50000000001",
    }),
    /amount/i,
  );
});

test("finality adapter derives success from raw RPC and canonical block transcripts", () => {
  const proof = verifyFinalizedNativeTransfer({
    requestedDeployHash: DEPLOY_HASH,
    rpcPayload: rpcPayload(),
    canonicalBlockPayload: blockPayload(),
    signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
    corroboratingRpcPayloads: [],
  });

  assert.equal(proof.deployHash, DEPLOY_HASH);
  assert.equal(proof.blockHash, BLOCK_HASH);
  assert.equal(proof.blockHeight, BLOCK_HEIGHT);
  assert.equal(proof.stateRootHash, STATE_ROOT_HASH);
  assert.equal(proof.executionResultKind, "Version2");
  assert.equal(proof.gasMotes, "100000000");
  assert.equal(proof.blockInclusionPath, "transactions.0");
});

test("finality adapter supports strict legacy and transaction RPC evidence without weakening inclusion", () => {
  const legacy = verifyFinalizedNativeTransfer({
    requestedDeployHash: DEPLOY_HASH,
    rpcPayload: legacyRpcPayload(),
    canonicalBlockPayload: legacyBlockPayload(),
    signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
  });
  assert.equal(legacy.rpcMethod, "info_get_deploy");
  assert.equal(legacy.executionResultKind, "Success");
  assert.equal(legacy.blockInclusionPath, "transfer_hashes");

  const transaction = rpcPayload();
  delete transaction.result.value.deploy;
  transaction.result.value.transaction = { Version1: { hash: DEPLOY_HASH } };
  const modern = verifyFinalizedNativeTransfer({
    requestedDeployHash: DEPLOY_HASH,
    rpcPayload: transaction,
    canonicalBlockPayload: blockPayload(),
    signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
  });
  assert.equal(modern.rpcMethod, "info_get_transaction");
});

test("finality corroboration must agree on deploy, block, height, gas, and success", () => {
  const proof = verifyFinalizedNativeTransfer({
    requestedDeployHash: DEPLOY_HASH,
    rpcPayload: rpcPayload(),
    canonicalBlockPayload: blockPayload(),
    signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
    corroboratingRpcPayloads: [rpcPayload()],
  });
  assert.equal(proof.corroborationCount, 1);

  const conflicting = rpcPayload();
  conflicting.result.value.execution_info.execution_result.Version2.cost = "100000001";
  assert.throws(
    () => verifyFinalizedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      rpcPayload: rpcPayload(),
      canonicalBlockPayload: blockPayload(),
      signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
      corroboratingRpcPayloads: [conflicting],
    }),
    /corroborating RPC evidence conflicts/i,
  );
});

test("corroborated finality adapter validates two complete public-node transcripts", () => {
  const proof = verifyCorroboratedNativeTransfer({
    requestedDeployHash: DEPLOY_HASH,
    nodeObservations: [
      nodeObservation("https://rpc-a.example.com/rpc", 0),
      nodeObservation("https://rpc-b.example.com/rpc", 1),
    ],
    signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
  });

  assert.equal(proof.network, "casper-test");
  assert.equal(proof.deployHash, DEPLOY_HASH);
  assert.equal(proof.blockHash, BLOCK_HASH);
  assert.equal(proof.blockHeight, BLOCK_HEIGHT);
  assert.equal(proof.stateRootHash, STATE_ROOT_HASH);
  assert.equal(proof.nodeObservationCount, 2);
  assert.equal(proof.corroborationCount, 1);
  assert.deepEqual(proof.nodeUrls, [
    "https://rpc-a.example.com/rpc",
    "https://rpc-b.example.com/rpc",
  ]);
  assert.deepEqual(proof.rpcMethods, ["info_get_deploy", "info_get_deploy"]);
  assert.equal(proof.nodeObservationJson.length, 2);
  assert.match(proof.nodeObservationSha256[0], /^[0-9a-f]{64}$/);
  assert.equal(
    proof.verificationScope,
    "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified",
  );
});

test("corroborated finality adapter requires distinct canonical public HTTPS origins", () => {
  const signedDeploy = { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED };
  assert.throws(
    () => verifyCorroboratedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      nodeObservations: [nodeObservation("https://rpc-a.example.com/rpc", 0)],
      signedDeploy,
    }),
    /at least two/i,
  );
  assert.throws(
    () => verifyCorroboratedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      nodeObservations: [
        nodeObservation("https://rpc-a.example.com/", 0),
        nodeObservation("https://rpc-a.example.com/rpc", 1),
      ],
      signedDeploy,
    }),
    /distinct.*origin|distinct.*URL/i,
  );
  for (const invalid of [
    "http://rpc-a.example.com/rpc",
    "https://user:secret@rpc-a.example.com/rpc",
    "https://localhost/rpc",
    "https://127.0.0.1/rpc",
    "https://RPC-A.example.com/rpc",
    "https://rpc-a.example.com/rpc?token=secret",
  ]) {
    assert.throws(
      () => verifyCorroboratedNativeTransfer({
        requestedDeployHash: DEPLOY_HASH,
        nodeObservations: [
          nodeObservation(invalid, 0),
          nodeObservation("https://rpc-b.example.com/rpc", 1),
        ],
        signedDeploy,
      }),
      /public.*HTTPS|node URL/i,
      invalid,
    );
  }
});

test("corroborated finality adapter fails closed on transcript mismatch or node conflict", () => {
  const signedDeploy = { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED };
  const first = nodeObservation("https://rpc-a.example.com/rpc", 0);
  const second = nodeObservation("https://rpc-b.example.com/rpc", 1);

  const wrongRequest = structuredClone(second);
  wrongRequest.transaction_request.params.finalized_approvals = false;
  assert.throws(
    () => verifyCorroboratedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      nodeObservations: [first, wrongRequest],
      signedDeploy,
    }),
    /params.*exact|request.*match/i,
  );

  const wrongId = structuredClone(second);
  wrongId.transaction_response.id = 999;
  assert.throws(
    () => verifyCorroboratedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      nodeObservations: [first, wrongId],
      signedDeploy,
    }),
    /response id/i,
  );

  const wrongNetwork = structuredClone(second);
  wrongNetwork.status_response.result.value.chainspec_name = "casper-mainnet";
  assert.throws(
    () => verifyCorroboratedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      nodeObservations: [first, wrongNetwork],
      signedDeploy,
    }),
    /casper-test/i,
  );

  const conflictingGas = structuredClone(second);
  conflictingGas.transaction_response.result.value.execution_info.execution_result.Version2.cost =
    "100000001";
  assert.throws(
    () => verifyCorroboratedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      nodeObservations: [first, conflictingGas],
      signedDeploy,
    }),
    /observations conflict/i,
  );
});

test("finality adapter rejects execution failure, block conflict, and duplicate inclusion", () => {
  const failed = rpcPayload();
  failed.result.value.execution_info.execution_result.Version2.error_message = "revert";
  assert.throws(
    () => verifyFinalizedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      rpcPayload: failed,
      canonicalBlockPayload: blockPayload(),
      signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
    }),
    /execution failed/i,
  );

  const conflict = blockPayload();
  conflict.result.value.block_with_signatures.block.Version2.hash = "ef".repeat(32);
  assert.throws(
    () => verifyFinalizedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      rpcPayload: rpcPayload(),
      canonicalBlockPayload: conflict,
      signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
    }),
    /block hash/i,
  );

  const duplicate = blockPayload();
  duplicate.result.value.block_with_signatures.block.Version2.body.transactions["1"].push({
    Deploy: DEPLOY_HASH,
  });
  assert.throws(
    () => verifyFinalizedNativeTransfer({
      requestedDeployHash: DEPLOY_HASH,
      rpcPayload: rpcPayload(),
      canonicalBlockPayload: duplicate,
      signedDeploy: { signedDeployHex: SIGNED_DEPLOY_HEX, ...EXPECTED },
    }),
    /multiple times/i,
  );
});

test("v3 material adapter recomputes action, transfer, and envelope identities", async () => {
  const vectorUrl = new URL(
    "../../../tests/golden/envelope_v3/native_transfer/GV-NT-01.json",
    import.meta.url,
  );
  const vector = JSON.parse(await readFile(vectorUrl, "utf8"));

  const material = verifyNativeEnvelopeMaterialV3({
    header: vector.typed_input.header,
    body: vector.typed_input.body,
  });

  assert.equal(material.actionId, vector.hashes.action_id);
  assert.equal(material.envelopeHash, vector.hashes.envelope_hash);
  assert.equal(material.transferId, "2386608944735597299");
  assert.equal(material.actionCoreHex, vector.action_core_hex);
  assert.equal(material.headerHex, vector.header_canonical_hex);
});

test("v3 material adapter accepts the exact named maps emitted by the public artifact", async () => {
  const vectorUrl = new URL(
    "../../../tests/golden/envelope_v3/native_transfer/GV-NT-01.json",
    import.meta.url,
  );
  const vector = JSON.parse(await readFile(vectorUrl, "utf8"));
  const header = Object.fromEntries(
    vector.typed_input.header.map(({ name, value }) => [name, value]),
  );
  const body = Object.fromEntries(
    vector.typed_input.body.map(({ name, value }) => [name, value]),
  );

  const material = verifyNativeEnvelopeMaterialV3({ header, body });

  assert.equal(material.actionId, vector.hashes.action_id);
  assert.equal(material.envelopeHash, vector.hashes.envelope_hash);
  assert.equal(material.headerHex, vector.header_canonical_hex);

  const extra = { ...header, unbound_marketing_flag: true };
  assert.throws(
    () => verifyNativeEnvelopeMaterialV3({ header: extra, body }),
    /exact|field|unknown/i,
  );
  const missing = { ...body };
  delete missing.transfer_id;
  assert.throws(
    () => verifyNativeEnvelopeMaterialV3({ header, body: missing }),
    /exact|field|missing/i,
  );
});

test("v3 material adapter rejects a supplied action identity that was not recomputed", async () => {
  const vectorUrl = new URL(
    "../../../tests/golden/envelope_v3/native_transfer/GV-NT-01.json",
    import.meta.url,
  );
  const vector = JSON.parse(await readFile(vectorUrl, "utf8"));
  const header = structuredClone(vector.typed_input.header);
  header.find((field) => field.name === "action_id").value = "ff".repeat(32);

  assert.throws(
    () => verifyNativeEnvelopeMaterialV3({ header, body: vector.typed_input.body }),
    /action_id/i,
  );
});

test("direct library callers cannot satisfy adapter inputs through inherited properties", async () => {
  const vectorUrl = new URL(
    "../../../tests/golden/envelope_v3/native_transfer/GV-NT-01.json",
    import.meta.url,
  );
  const vector = JSON.parse(await readFile(vectorUrl, "utf8"));
  const poisonedHeader = structuredClone(vector.typed_input.header);
  poisonedHeader[0] = Object.assign(
    Object.create({ name: poisonedHeader[0].name }),
    { type: poisonedHeader[0].type, value: poisonedHeader[0].value },
  );
  assert.throws(
    () => verifyNativeEnvelopeMaterialV3({ header: poisonedHeader, body: vector.typed_input.body }),
    /own|field/i,
  );

  const inheritedExpectation = Object.assign(
    Object.create({ sourceAccountHash: EXPECTED.sourceAccountHash }),
    {
      signedDeployHex: SIGNED_DEPLOY_HEX,
      recipientAccountHash: EXPECTED.recipientAccountHash,
      amountMotes: EXPECTED.amountMotes,
      transferId: EXPECTED.transferId,
      paymentAmountMotes: EXPECTED.paymentAmountMotes,
      maxPaymentAmountMotes: EXPECTED.maxPaymentAmountMotes,
    },
  );
  assert.throws(() => verifySignedNativeTransferDeploy(inheritedExpectation), /own|required|source/i);
});
