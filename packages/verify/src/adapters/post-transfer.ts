import { createHash } from "node:crypto";

import { parseUnsigned } from "../encoders.js";
import {
  verifyAccountBalanceAtBlock,
  type AccountBalanceFacts,
  type CasperAccountBalanceInput,
} from "./casper-state.js";
import {
  verifyFinalizedNativeTransfer,
  type FinalizedNativeTransferFacts,
  type NativeFinalityInput,
} from "./native-finality.js";

export type PostTransferInput = Readonly<{
  preSourceBalance: CasperAccountBalanceInput;
  preRecipientBalance: CasperAccountBalanceInput;
  postSourceBalance: CasperAccountBalanceInput;
  postRecipientBalance: CasperAccountBalanceInput;
  finality: NativeFinalityInput;
  expectedSourceAccountHash: string;
  expectedRecipientAccountHash: string;
  expectedAmountMotes: string | number | bigint;
}>;

export type PostTransferFacts = Readonly<{
  network: "casper-test";
  sourceAccountHash: string;
  recipientAccountHash: string;
  preBlockHash: string;
  preBlockHeight: number;
  preStateRootHash: string;
  postBlockHash: string;
  postBlockHeight: number;
  postStateRootHash: string;
  deployHash: string;
  sourceBalanceBeforeMotes: string;
  sourceBalanceAfterMotes: string;
  recipientBalanceBeforeMotes: string;
  recipientBalanceAfterMotes: string;
  amountMotes: string;
  gasMotes: string;
  sourceDeltaMotes: string;
  recipientDeltaMotes: string;
  signedDeploySha256: string;
  transcriptSha256Inventory: readonly (readonly [string, string])[];
}>;

const TRANSCRIPT_FIELDS = Object.freeze([
  ["status_request", "statusRequest"],
  ["status", "status"],
  ["block_request", "blockRequest"],
  ["block", "block"],
  ["balance_request", "balanceRequest"],
  ["balance_response", "balanceResponse"],
] as const);

function requireAccount(value: string, label: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} must be lowercase 32-byte hex`);
  return value;
}
function inventory(role: string, proof: AccountBalanceFacts): readonly (readonly [string, string])[] {
  return TRANSCRIPT_FIELDS.map(([artifactName, property]) =>
    Object.freeze([`${role}.${artifactName}`, proof.transcriptSha256[property]] as const),
  );
}

function assertAccount(proof: AccountBalanceFacts, expected: string, label: string): void {
  if (proof.accountHash !== expected) throw new Error(`${label} does not match expected account`);
}

function assertSamePreSnapshot(left: AccountBalanceFacts, right: AccountBalanceFacts): void {
  if (left.blockHash !== right.blockHash) throw new Error("pre-state block does not match");
  if (left.blockHeight !== right.blockHeight) throw new Error("pre-state height does not match");
  if (left.stateRootHash !== right.stateRootHash) throw new Error("pre-state root does not match");
}

function assertPostSnapshot(proof: AccountBalanceFacts, finality: FinalizedNativeTransferFacts): void {
  if (proof.blockHash !== finality.blockHash) throw new Error("post-state does not match finality block");
  if (proof.blockHeight !== finality.blockHeight) throw new Error("post-state does not match finality height");
  if (proof.stateRootHash !== finality.stateRootHash) throw new Error("post-state does not match finality state root");
}

export function verifyPostTransferBalance(input: PostTransferInput): PostTransferFacts {
  for (const field of [
    "preSourceBalance",
    "preRecipientBalance",
    "postSourceBalance",
    "postRecipientBalance",
    "finality",
    "expectedSourceAccountHash",
    "expectedRecipientAccountHash",
    "expectedAmountMotes",
  ] as const) {
    if (!Object.hasOwn(input, field)) throw new Error(`required own post-transfer field ${field} is missing`);
  }
  const source = requireAccount(input.expectedSourceAccountHash, "expected source account");
  const recipient = requireAccount(input.expectedRecipientAccountHash, "expected recipient account");
  if (source === recipient) throw new Error("source and recipient accounts must be distinct");
  const amount = parseUnsigned(input.expectedAmountMotes, 512);
  if (amount === 0n) throw new Error("expected amount must be positive U512");

  const preSource = verifyAccountBalanceAtBlock(input.preSourceBalance);
  const preRecipient = verifyAccountBalanceAtBlock(input.preRecipientBalance);
  const postSource = verifyAccountBalanceAtBlock(input.postSourceBalance);
  const postRecipient = verifyAccountBalanceAtBlock(input.postRecipientBalance);
  const finality = verifyFinalizedNativeTransfer(input.finality);

  if (finality.signedDeploy.sourceAccountHash !== source) {
    throw new Error("expected source does not match signed transfer source");
  }
  if (finality.signedDeploy.recipientAccountHash !== recipient) {
    throw new Error("expected recipient does not match signed transfer recipient");
  }
  if (finality.signedDeploy.amountMotes !== amount.toString()) {
    throw new Error("expected amount does not match signed transfer amount");
  }

  assertAccount(preSource, source, "pre-source account");
  assertAccount(postSource, source, "post-source account");
  assertAccount(preRecipient, recipient, "pre-recipient account");
  assertAccount(postRecipient, recipient, "post-recipient account");
  assertSamePreSnapshot(preSource, preRecipient);
  assertPostSnapshot(postSource, finality);
  assertPostSnapshot(postRecipient, finality);
  if (preSource.blockHeight >= finality.blockHeight) {
    throw new Error("pre-state snapshot must strictly precede post-state snapshot");
  }

  const gas = parseUnsigned(finality.gasMotes, 512);
  const sourceBefore = parseUnsigned(preSource.balanceMotes, 512);
  const sourceAfter = parseUnsigned(postSource.balanceMotes, 512);
  const recipientBefore = parseUnsigned(preRecipient.balanceMotes, 512);
  const recipientAfter = parseUnsigned(postRecipient.balanceMotes, 512);
  const expectedSourceDelta = amount + gas;
  if (expectedSourceDelta >= 1n << 512n) throw new Error("amount plus gas causes U512 overflow");
  if (sourceAfter > sourceBefore) throw new Error("source balance increased");
  if (recipientAfter < recipientBefore) throw new Error("recipient balance decreased");
  const sourceDelta = sourceBefore - sourceAfter;
  const recipientDelta = recipientAfter - recipientBefore;
  if (sourceDelta !== expectedSourceDelta) {
    throw new Error("source delta does not match transfer amount plus gas");
  }
  if (recipientDelta !== amount) throw new Error("recipient delta does not match transfer amount");

  const transcriptSha256Inventory = Object.freeze([
    ...inventory("pre_source", preSource),
    ...inventory("pre_recipient", preRecipient),
    ...inventory("post_source", postSource),
    ...inventory("post_recipient", postRecipient),
  ]);
  const signedDeploySha256 = createHash("sha256")
    .update(Buffer.from(finality.signedDeploy.canonicalSignedDeployHex, "hex"))
    .digest("hex");

  return Object.freeze({
    network: "casper-test",
    sourceAccountHash: source,
    recipientAccountHash: recipient,
    preBlockHash: preSource.blockHash,
    preBlockHeight: preSource.blockHeight,
    preStateRootHash: preSource.stateRootHash,
    postBlockHash: finality.blockHash,
    postBlockHeight: finality.blockHeight,
    postStateRootHash: finality.stateRootHash,
    deployHash: finality.deployHash,
    sourceBalanceBeforeMotes: sourceBefore.toString(),
    sourceBalanceAfterMotes: sourceAfter.toString(),
    recipientBalanceBeforeMotes: recipientBefore.toString(),
    recipientBalanceAfterMotes: recipientAfter.toString(),
    amountMotes: amount.toString(),
    gasMotes: gas.toString(),
    sourceDeltaMotes: sourceDelta.toString(),
    recipientDeltaMotes: recipientDelta.toString(),
    signedDeploySha256,
    transcriptSha256Inventory,
  });
}
