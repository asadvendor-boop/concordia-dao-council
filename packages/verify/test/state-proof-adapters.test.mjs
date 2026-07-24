import assert from "node:assert/strict";
import { test } from "node:test";

import {
  parseJsonStrict,
  verifyAccountBalanceAtBlock,
  verifyNoDuplicateNativeTransfer,
  verifyPostTransferBalance,
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

const SOURCE = "2cafe3242874778ed07291e1205a2773e4913b920695cbd8bb5887373eff99f7";
const RECIPIENT = "22".repeat(32);
const DEPLOY_HASH = "f5e101a5c5606300e6faa36591f38d2f7d5152ad0ba7fe1fa2b0cf712bd50ce8";
const PRE_BLOCK = "31".repeat(32);
const PRE_ROOT = "32".repeat(32);
const POST_BLOCK = "ab".repeat(32);
const POST_ROOT = "cd".repeat(32);
const PRE_HEIGHT = 8_400_000;
const POST_HEIGHT = 8_400_123;
const AMOUNT = "50000000000";
const GAS = "100000000";
const PRE_SOURCE = "625000000000";
const POST_SOURCE = "574900000000";
const PRE_RECIPIENT = "7000000000";
const POST_RECIPIENT = "57000000000";
const AUTHORIZATION_HEIGHT = POST_HEIGHT - 2;
const OBSERVED_HEIGHT = POST_HEIGHT + 1;

function balanceInput({ account, blockHash, stateRootHash, blockHeight, balanceMotes, idBase }) {
  return {
    chainStatusRequest: {
      jsonrpc: "2.0",
      id: idBase,
      method: "info_get_status",
      params: {},
    },
    chainStatusPayload: {
      jsonrpc: "2.0",
      id: idBase,
      result: {
        name: "info_get_status_result",
        value: { api_version: "2.0.0", chainspec_name: "casper-test" },
      },
    },
    canonicalBlockRequest: {
      jsonrpc: "2.0",
      id: idBase + 1,
      method: "chain_get_block",
      params: { block_identifier: { Hash: blockHash } },
    },
    canonicalBlockPayload: {
      jsonrpc: "2.0",
      id: idBase + 1,
      result: {
        name: "chain_get_block_result",
        value: {
          block_with_signatures: {
            block: {
              Version2: {
                hash: blockHash,
                header: { height: blockHeight, state_root_hash: stateRootHash },
                body: { transactions: {} },
              },
            },
            proofs: [],
          },
        },
      },
    },
    balanceRequest: {
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
    balanceResponse: {
      jsonrpc: "2.0",
      id: idBase + 2,
      result: {
        name: "query_balance_details_result",
        value: {
          api_version: "2.0.0",
          total_balance: balanceMotes,
          available_balance: balanceMotes,
          total_balance_proof: "aa",
          holds: [],
        },
      },
    },
    expectedAccountHash: account,
    expectedBlockHash: blockHash,
    expectedBlockHeight: blockHeight,
    expectedStateRootHash: stateRootHash,
    expectedBalanceMotes: balanceMotes,
  };
}

function finalityInput() {
  return {
    requestedDeployHash: DEPLOY_HASH,
    rpcPayload: {
      jsonrpc: "2.0",
      id: 1,
      result: {
        name: "info_get_deploy_result",
        value: {
          deploy: { hash: DEPLOY_HASH },
          execution_info: {
            block_hash: POST_BLOCK,
            block_height: POST_HEIGHT,
            execution_result: { Version2: { error_message: null, cost: GAS } },
          },
        },
      },
    },
    canonicalBlockPayload: {
      jsonrpc: "2.0",
      id: 2,
      result: {
        name: "chain_get_block_result",
        value: {
          block_with_signatures: {
            block: {
              Version2: {
                hash: POST_BLOCK,
                header: { height: POST_HEIGHT, state_root_hash: POST_ROOT },
                body: { transactions: { "0": [{ Deploy: DEPLOY_HASH }] } },
              },
            },
            proofs: [],
          },
        },
      },
    },
    signedDeploy: {
      signedDeployHex: SIGNED_DEPLOY_HEX,
      sourceAccountHash: SOURCE,
      recipientAccountHash: RECIPIENT,
      amountMotes: AMOUNT,
      transferId: "72623859790382856",
      paymentAmountMotes: GAS,
      maxPaymentAmountMotes: GAS,
    },
  };
}

function postTransferInput() {
  return {
    preSourceBalance: balanceInput({
      account: SOURCE,
      blockHash: PRE_BLOCK,
      stateRootHash: PRE_ROOT,
      blockHeight: PRE_HEIGHT,
      balanceMotes: PRE_SOURCE,
      idBase: 10,
    }),
    preRecipientBalance: balanceInput({
      account: RECIPIENT,
      blockHash: PRE_BLOCK,
      stateRootHash: PRE_ROOT,
      blockHeight: PRE_HEIGHT,
      balanceMotes: PRE_RECIPIENT,
      idBase: 20,
    }),
    postSourceBalance: balanceInput({
      account: SOURCE,
      blockHash: POST_BLOCK,
      stateRootHash: POST_ROOT,
      blockHeight: POST_HEIGHT,
      balanceMotes: POST_SOURCE,
      idBase: 30,
    }),
    postRecipientBalance: balanceInput({
      account: RECIPIENT,
      blockHash: POST_BLOCK,
      stateRootHash: POST_ROOT,
      blockHeight: POST_HEIGHT,
      balanceMotes: POST_RECIPIENT,
      idBase: 40,
    }),
    finality: finalityInput(),
    expectedSourceAccountHash: SOURCE,
    expectedRecipientAccountHash: RECIPIENT,
    expectedAmountMotes: AMOUNT,
  };
}

function scanInput() {
  const blockHashes = new Map();
  for (let height = AUTHORIZATION_HEIGHT; height <= OBSERVED_HEIGHT; height += 1) {
    blockHashes.set(height, (height - AUTHORIZATION_HEIGHT + 1).toString(16).padStart(2, "0").repeat(32));
  }
  blockHashes.set(POST_HEIGHT, POST_BLOCK);
  const blockObservations = [];
  let parentHash = "00".repeat(32);
  for (let height = AUTHORIZATION_HEIGHT; height <= OBSERVED_HEIGHT; height += 1) {
    const blockHash = blockHashes.get(height);
    const transfers = height === POST_HEIGHT
      ? [{
          Version1: {
            deploy_hash: DEPLOY_HASH,
            from: `account-hash-${SOURCE}`,
            to: `account-hash-${RECIPIENT}`,
            source: `uref-${"11".repeat(32)}-007`,
            target: `uref-${"12".repeat(32)}-000`,
            amount: AMOUNT,
            gas: GAS,
            id: 72623859790382856n,
          },
        }]
      : [];
    blockObservations.push({
      block_request: {
        jsonrpc: "2.0",
        id: `block-${height}`,
        method: "chain_get_block",
        params: { block_identifier: { Height: height } },
      },
      block_response: {
        jsonrpc: "2.0",
        id: `block-${height}`,
        result: {
          block: {
            hash: blockHash,
                header: { height, parent_hash: parentHash, state_root_hash: "dd".repeat(32) },
            body: { deploy_hashes: [], transfer_hashes: [] },
          },
        },
      },
      transfers_request: {
        jsonrpc: "2.0",
        id: `transfers-${height}`,
        method: "chain_get_block_transfers",
        params: { block_identifier: { Hash: blockHash } },
      },
      transfers_response: {
        jsonrpc: "2.0",
        id: `transfers-${height}`,
        result: { block_hash: blockHash, transfers },
      },
    });
    parentHash = blockHash;
  }
  return {
    chainStatusRequest: {
      jsonrpc: "2.0",
      id: "status",
      method: "info_get_status",
      params: {},
    },
    chainStatusResponse: {
      jsonrpc: "2.0",
      id: "status",
      result: {
        chainspec_name: "casper-test",
        last_added_block_info: {
          hash: blockHashes.get(OBSERVED_HEIGHT),
          height: OBSERVED_HEIGHT,
        },
      },
    },
    blockObservations,
    authorizationBlockHeight: AUTHORIZATION_HEIGHT,
    finality: finalityInput(),
  };
}

test("balance adapter derives one exact historical balance from six raw RPC transcripts", () => {
  const facts = verifyAccountBalanceAtBlock(
    balanceInput({
      account: SOURCE,
      blockHash: PRE_BLOCK,
      stateRootHash: PRE_ROOT,
      blockHeight: PRE_HEIGHT,
      balanceMotes: PRE_SOURCE,
      idBase: 10,
    }),
  );

  assert.equal(facts.network, "casper-test");
  assert.equal(facts.accountHash, SOURCE);
  assert.equal(facts.blockHash, PRE_BLOCK);
  assert.equal(facts.blockHeight, PRE_HEIGHT);
  assert.equal(facts.stateRootHash, PRE_ROOT);
  assert.equal(facts.balanceMotes, PRE_SOURCE);
  assert.equal(facts.availableBalanceMotes, PRE_SOURCE);
  assert.equal(facts.balanceHoldsTotalMotes, "0");
  assert.deepEqual(facts.balanceHolds, []);
  assert.equal(facts.nodeProvidedMerkleProofHex, "aa");
  assert.equal(facts.merkleProofVerificationScope, "node-provided-not-locally-verified");
  assert.equal(facts.balanceRequestMethod, "query_balance_details");
  assert.equal(facts.balanceRequestId, 12);
  assert.deepEqual(Object.keys(facts.transcriptSha256), [
    "statusRequest",
    "status",
    "blockRequest",
    "block",
    "balanceRequest",
    "balanceResponse",
  ]);
  for (const digest of Object.values(facts.transcriptSha256)) {
    assert.match(digest, /^[0-9a-f]{64}$/);
  }
});

test("balance adapter binds request methods, IDs, network, block, root, account, and exact U512 balance", () => {
  const base = balanceInput({
    account: SOURCE,
    blockHash: PRE_BLOCK,
    stateRootHash: PRE_ROOT,
    blockHeight: PRE_HEIGHT,
    balanceMotes: PRE_SOURCE,
    idBase: 10,
  });
  const mutations = [
    ["status method", (value) => { value.chainStatusRequest.method = "info_get_peers"; }, /info_get_status/i],
    ["status ID", (value) => { value.chainStatusPayload.id = 999; }, /response id/i],
    ["network", (value) => { value.chainStatusPayload.result.value.chainspec_name = "casper-mainnet"; }, /casper-test/i],
    ["block request", (value) => { value.canonicalBlockRequest.params.block_identifier.Hash = "aa".repeat(32); }, /block hash|params/i],
    ["block height", (value) => { value.canonicalBlockPayload.result.value.block_with_signatures.block.Version2.header.height += 1; }, /block height/i],
    ["state root", (value) => { value.balanceRequest.params.state_identifier.StateRootHash = "aa".repeat(32); }, /state root/i],
    ["account", (value) => { value.balanceRequest.params.purse_identifier.main_purse_under_account_hash = `account-hash-${"aa".repeat(32)}`; }, /account hash/i],
    ["response ID", (value) => { value.balanceResponse.id += 1; }, /response id/i],
    ["leading-zero balance", (value) => { value.balanceResponse.result.value.total_balance = "0625000000000"; }, /canonical/i],
    ["wrong balance", (value) => { value.balanceResponse.result.value.total_balance = "1"; value.balanceResponse.result.value.available_balance = "1"; }, /expected balance/i],
    ["missing node proof", (value) => { value.balanceResponse.result.value.total_balance_proof = ""; }, /proof/i],
    ["hold arithmetic", (value) => {
      value.balanceResponse.result.value.holds = [{ time: 1, amount: "1", proof: "bb" }];
    }, /available balance.*hold arithmetic/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const value = structuredClone(base);
    mutate(value);
    assert.throws(() => verifyAccountBalanceAtBlock(value), pattern, label);
  }
});

test("balance adapter rejects inherited required fields and malformed wrapper ambiguity", () => {
  const base = balanceInput({
    account: SOURCE,
    blockHash: PRE_BLOCK,
    stateRootHash: PRE_ROOT,
    blockHeight: PRE_HEIGHT,
    balanceMotes: PRE_SOURCE,
    idBase: 10,
  });
  const inherited = Object.create(base);
  assert.throws(() => verifyAccountBalanceAtBlock(inherited), /required own balance field/i);

  const ambiguous = structuredClone(base);
  ambiguous.chainStatusPayload.result.extra = true;
  assert.throws(() => verifyAccountBalanceAtBlock(ambiguous), /status result.*frozen fields/i);
});

test("post-transfer adapter independently proves exact source and recipient deltas", () => {
  const proof = verifyPostTransferBalance(postTransferInput());

  assert.equal(proof.network, "casper-test");
  assert.equal(proof.sourceAccountHash, SOURCE);
  assert.equal(proof.recipientAccountHash, RECIPIENT);
  assert.equal(proof.preBlockHash, PRE_BLOCK);
  assert.equal(proof.postBlockHash, POST_BLOCK);
  assert.equal(proof.deployHash, DEPLOY_HASH);
  assert.equal(proof.sourceBalanceBeforeMotes, PRE_SOURCE);
  assert.equal(proof.sourceBalanceAfterMotes, POST_SOURCE);
  assert.equal(proof.recipientBalanceBeforeMotes, PRE_RECIPIENT);
  assert.equal(proof.recipientBalanceAfterMotes, POST_RECIPIENT);
  assert.equal(proof.amountMotes, AMOUNT);
  assert.equal(proof.gasMotes, GAS);
  assert.equal(proof.sourceDeltaMotes, "50100000000");
  assert.equal(proof.recipientDeltaMotes, AMOUNT);
  assert.match(proof.signedDeploySha256, /^[0-9a-f]{64}$/);
  assert.equal(proof.transcriptSha256Inventory.length, 24);
  assert.equal(proof.transcriptSha256Inventory[0][0], "pre_source.status_request");
  assert.equal(proof.transcriptSha256Inventory[23][0], "post_recipient.balance_response");
});

test("post-transfer adapter fails closed on snapshot, role, finality, and delta mismatches", () => {
  const mutations = [
    ["pre snapshot", (value) => {
      value.preRecipientBalance.expectedBlockHeight -= 1;
      value.preRecipientBalance.canonicalBlockPayload.result.value.block_with_signatures.block.Version2.header.height -= 1;
    }, /pre-state height/i],
    ["post finality", (value) => {
      const alternate = "41".repeat(32);
      value.postSourceBalance.expectedBlockHash = alternate;
      value.postSourceBalance.canonicalBlockRequest.params.block_identifier.Hash = alternate;
      value.postSourceBalance.canonicalBlockPayload.result.value.block_with_signatures.block.Version2.hash = alternate;
    }, /post-state.*finality block/i],
    ["recipient delta", (value) => {
      value.postRecipientBalance.balanceResponse.result.value.total_balance = "57000000001";
      value.postRecipientBalance.balanceResponse.result.value.available_balance = "57000000001";
      value.postRecipientBalance.expectedBalanceMotes = "57000000001";
    }, /recipient delta/i],
    ["source delta", (value) => {
      value.postSourceBalance.balanceResponse.result.value.total_balance = "574900000001";
      value.postSourceBalance.balanceResponse.result.value.available_balance = "574900000001";
      value.postSourceBalance.expectedBalanceMotes = "574900000001";
    }, /source delta/i],
    ["finality gas", (value) => { value.finality.rpcPayload.result.value.execution_info.execution_result.Version2.cost = "100000001"; }, /source delta/i],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const value = postTransferInput();
    mutate(value);
    assert.throws(() => verifyPostTransferBalance(value), pattern, label);
  }
});

test("post-transfer adapter rejects inherited top-level proof inputs", () => {
  const inherited = Object.create(postTransferInput());
  assert.throws(() => verifyPostTransferBalance(inherited), /required own post-transfer field/i);
});

test("strict JSON preserves unsafe u64 integers for exact transfer-id verification", () => {
  const parsed = parseJsonStrict('{"id":72623859790382856}');
  assert.equal(parsed.id, 72623859790382856n);
});

test("native transfer scan proves exactly one governed transfer through an observed canonical tip", () => {
  const proof = verifyNoDuplicateNativeTransfer(scanInput());
  assert.equal(proof.network, "casper-test");
  assert.equal(proof.authorizationBlockHeight, AUTHORIZATION_HEIGHT);
  assert.equal(proof.authorizationBlockHash, "01".repeat(32));
  assert.equal(proof.inclusionBlockHeight, POST_HEIGHT);
  assert.equal(proof.observedThroughBlockHeight, OBSERVED_HEIGHT);
  assert.equal(proof.scannedBlockCount, 4);
  assert.equal(proof.matchedTransferCount, 1);
  assert.equal(proof.deployHash, DEPLOY_HASH);
  assert.equal(proof.sourceAccountHash, SOURCE);
  assert.equal(proof.recipientAccountHash, RECIPIENT);
  assert.equal(proof.amountMotes, AMOUNT);
  assert.equal(proof.transferId, "72623859790382856");
  assert.match(proof.transcriptSha256, /^[0-9a-f]{64}$/);
});

test("native transfer scan rejects gaps, response mismatch, stale tip, and a second matching action", () => {
  const missing = scanInput();
  missing.blockObservations.splice(1, 1);
  assert.throws(() => verifyNoDuplicateNativeTransfer(missing), /contiguous/i);

  const wrongId = scanInput();
  wrongId.blockObservations[0].transfers_response.id = "wrong";
  assert.throws(() => verifyNoDuplicateNativeTransfer(wrongId), /response id/i);

  const brokenParent = scanInput();
  brokenParent.blockObservations[2].block_response.result.block.header.parent_hash = "ff".repeat(32);
  assert.throws(() => verifyNoDuplicateNativeTransfer(brokenParent), /parent chain/i);

  const stale = scanInput();
  stale.chainStatusResponse.result.last_added_block_info.height = POST_HEIGHT - 1;
  assert.throws(() => verifyNoDuplicateNativeTransfer(stale), /precedes transfer inclusion/i);

  const duplicate = scanInput();
  duplicate.blockObservations.at(-1).transfers_response.result.transfers = [{
    Version1: {
      deploy_hash: "ef".repeat(32),
      from: `account-hash-${SOURCE}`,
      to: `account-hash-${RECIPIENT}`,
      source: `uref-${"11".repeat(32)}-007`,
      target: `uref-${"12".repeat(32)}-000`,
      amount: AMOUNT,
      gas: GAS,
      id: 72623859790382856n,
    },
  }];
  assert.throws(() => verifyNoDuplicateNativeTransfer(duplicate), /exactly one/i);

  const wrongInclusionHash = scanInput();
  const replacement = "ee".repeat(32);
  const inclusion = wrongInclusionHash.blockObservations[2];
  const successor = wrongInclusionHash.blockObservations[3];
  inclusion.block_response.result.block.hash = replacement;
  inclusion.transfers_request.params.block_identifier.Hash = replacement;
  inclusion.transfers_response.result.block_hash = replacement;
  successor.block_response.result.block.header.parent_hash = replacement;
  assert.throws(() => verifyNoDuplicateNativeTransfer(wrongInclusionHash), /finalized action/i);
});

test("native transfer scan rejects inherited top-level inputs and over-broad source matches", () => {
  assert.throws(
    () => verifyNoDuplicateNativeTransfer(Object.create(scanInput())),
    /required own transfer-scan field/i,
  );
  const wrongSource = scanInput();
  wrongSource.blockObservations[2].transfers_response.result.transfers[0].Version1.from =
    `account-hash-${"aa".repeat(32)}`;
  assert.throws(() => verifyNoDuplicateNativeTransfer(wrongSource), /exactly one/i);
});
