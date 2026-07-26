import { isRecord, parseUnsigned } from "../encoders.js";
import {
  canonicalTranscriptJson,
  sha256CanonicalTranscript,
} from "./casper-state.js";
import {
  verifyFinalizedNativeTransfer,
  type NativeFinalityInput,
} from "./native-finality.js";

const HEX32 = /^[0-9a-f]{64}$/;
const ACCOUNT_HASH = /^account-hash-([0-9a-f]{64})$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const MAX_SCAN_BLOCKS = 2_048;

type JsonRpcId = number | string | bigint;

export type NativeTransferScanInput = Readonly<{
  chainStatusRequest: unknown;
  chainStatusResponse: unknown;
  blockObservations: readonly unknown[];
  authorizationBlockHeight: number;
  finality: NativeFinalityInput;
}>;

export type NoDuplicateNativeTransferFacts = Readonly<{
  network: "casper-test";
  authorizationBlockHeight: number;
  authorizationBlockHash: string;
  inclusionBlockHeight: number;
  observedThroughBlockHeight: number;
  observedThroughBlockHash: string;
  scannedBlockCount: number;
  matchedTransferCount: 1;
  deployHash: string;
  sourceAccountHash: string;
  recipientAccountHash: string;
  amountMotes: string;
  transferId: string;
  transcriptSha256: string;
}>;

type ParsedTransfer = {
  deployHash: string;
  sourceAccountHash: string;
  recipientAccountHash: string;
  amountMotes: bigint;
  transferId: bigint | null;
};

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

function exactOwnKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((name, index) => name !== wanted[index]) ||
    wanted.some((name) => !Object.hasOwn(value, name))
  ) {
    throw new Error(`${label} fields are not exact`);
  }
}

function lowerHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function height(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe u64`);
  }
  return value;
}

function rpcId(value: unknown, label: string): JsonRpcId {
  if (
    (typeof value !== "number" || !Number.isSafeInteger(value)) &&
    typeof value !== "bigint" &&
    (typeof value !== "string" || value.length === 0)
  ) {
    throw new Error(`${label} request id is invalid`);
  }
  return value;
}

function unwrapResult(payload: unknown, label: string): { result: Record<string, unknown>; id: JsonRpcId } {
  const body = record(payload, `${label} response`);
  if (own(body, "jsonrpc") !== "2.0") throw new Error(`${label} response is invalid`);
  const error = own(body, "error");
  if (error !== undefined && error !== null) throw new Error(`${label} response is invalid`);
  const id = rpcId(own(body, "id"), label);
  let result = record(own(body, "result"), `${label} result`);
  if (Object.hasOwn(result, "name") || Object.hasOwn(result, "value")) {
    exactOwnKeys(result, ["name", "value"], `${label} result`);
    if (typeof own(result, "name") !== "string") throw new Error(`${label} result is malformed`);
    result = record(own(result, "value"), `${label} result`);
  }
  return { result, id };
}

function exactRequest(
  raw: unknown,
  method: string,
  params: Record<string, unknown>,
  label: string,
): JsonRpcId {
  const request = record(raw, `${label} request`);
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], `${label} request`);
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== method) {
    throw new Error(`${label} request must call ${method}`);
  }
  if (
    canonicalTranscriptJson(own(request, "params"), `${label} request params`) !==
    canonicalTranscriptJson(params, `${label} expected params`)
  ) {
    throw new Error(`${label} request params do not match`);
  }
  return rpcId(own(request, "id"), label);
}

function requireResponseId(actual: JsonRpcId, expected: JsonRpcId, label: string): void {
  if (actual !== expected) throw new Error(`${label} response id does not match request id`);
}

function parseStatus(request: unknown, response: unknown): { height: number; hash: string } {
  const expectedId = exactRequest(request, "info_get_status", {}, "status");
  const observed = unwrapResult(response, "status");
  requireResponseId(observed.id, expectedId, "status");
  const names = ["chainspec_name", "chainspecName", "chain_name"]
    .filter((name) => Object.hasOwn(observed.result, name))
    .map((name) => own(observed.result, name));
  if (names.length !== 1 || names[0] !== "casper-test") {
    throw new Error("status must prove chain casper-test");
  }
  const tipNames = ["last_added_block_info", "lastAddedBlockInfo"].filter((name) =>
    Object.hasOwn(observed.result, name),
  );
  if (tipNames.length !== 1) throw new Error("status observed tip is ambiguous or missing");
  const tip = record(own(observed.result, tipNames[0] as string), "status observed tip");
  const hashNames = ["hash", "block_hash"].filter((name) => Object.hasOwn(tip, name));
  if (hashNames.length !== 1) throw new Error("status observed tip block hash is ambiguous or missing");
  return {
    height: height(own(tip, "height"), "status observed tip height"),
    hash: lowerHash(own(tip, hashNames[0] as string), "status observed tip block hash"),
  };
}

function parseBlock(
  request: unknown,
  response: unknown,
  expectedHeight: number,
): { blockHash: string; parentHash: string } {
  const label = `block ${expectedHeight}`;
  const expectedId = exactRequest(
    request,
    "chain_get_block",
    { block_identifier: { Height: expectedHeight } },
    label,
  );
  const observed = unwrapResult(response, label);
  requireResponseId(observed.id, expectedId, label);
  const hasWrapped = Object.hasOwn(observed.result, "block_with_signatures");
  const hasLegacy = Object.hasOwn(observed.result, "block");
  if (hasWrapped === hasLegacy) throw new Error("canonical block is ambiguous");
  let raw: Record<string, unknown>;
  if (hasWrapped) {
    const wrapper = record(own(observed.result, "block_with_signatures"), "canonical block wrapper");
    raw = record(own(wrapper, "block"), "canonical block");
  } else {
    raw = record(own(observed.result, "block"), "canonical block");
  }
  const variants = ["Version1", "Version2"].filter((variant) => Object.hasOwn(raw, variant));
  if (variants.length > 0) {
    if (variants.length !== 1 || Object.keys(raw).length !== 1) throw new Error("canonical block is ambiguous");
    raw = record(own(raw, variants[0] as string), "canonical block");
  }
  const blockHash = lowerHash(own(raw, "hash"), "canonical block hash");
  const header = record(own(raw, "header"), "canonical block header");
  if (height(own(header, "height"), "canonical block height") !== expectedHeight) {
    throw new Error("canonical block height does not match request");
  }
  const parentNames = ["parent_hash", "parentHash"].filter((name) => Object.hasOwn(header, name));
  if (parentNames.length !== 1) throw new Error("canonical parent hash is ambiguous or missing");
  const parentHash = lowerHash(own(header, parentNames[0] as string), "canonical parent hash");
  record(own(raw, "body"), "canonical block body");
  return { blockHash, parentHash };
}

function parseAccountHash(value: unknown, label: string): string {
  if (isRecord(value)) {
    exactOwnKeys(value, ["AccountHash"], label);
    value = own(value, "AccountHash");
  }
  if (typeof value !== "string") throw new Error(`${label} must be an account hash`);
  const prefixed = ACCOUNT_HASH.exec(value);
  if (prefixed) return prefixed[1] as string;
  return lowerHash(value, label);
}

function parseTransactionHash(value: unknown, label: string): string {
  if (typeof value === "string") return lowerHash(value, label);
  const wrapped = record(value, label);
  const variants = ["Deploy", "Version1"].filter((name) => Object.hasOwn(wrapped, name));
  if (variants.length !== 1 || Object.keys(wrapped).length !== 1) throw new Error(`${label} is malformed`);
  return lowerHash(own(wrapped, variants[0] as string), label);
}

function parseTransferId(value: unknown): bigint | null {
  if (typeof value === "bigint") {
    return value >= 0n && value < 1n << 64n ? value : null;
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

function parseTransfers(
  request: unknown,
  response: unknown,
  expectedBlockHash: string,
  expectedHeight: number,
): ParsedTransfer[] {
  const label = `block transfers ${expectedHeight}`;
  const expectedId = exactRequest(
    request,
    "chain_get_block_transfers",
    { block_identifier: { Hash: expectedBlockHash } },
    label,
  );
  const observed = unwrapResult(response, label);
  requireResponseId(observed.id, expectedId, label);
  if (lowerHash(own(observed.result, "block_hash"), "transfer response block hash") !== expectedBlockHash) {
    throw new Error("transfer response block hash does not match block");
  }
  const rawTransfers = own(observed.result, "transfers");
  if (!Array.isArray(rawTransfers)) throw new Error("block transfers must be a list");
  return rawTransfers.map((raw, index) => {
    const wrapper = record(raw, `transfer ${index}`);
    const variants = ["Version1", "Version2"].filter((name) => Object.hasOwn(wrapper, name));
    if (variants.length !== 1 || Object.keys(wrapper).length !== 1) throw new Error(`transfer ${index} is ambiguous`);
    const version = variants[0] as "Version1" | "Version2";
    const transfer = record(own(wrapper, version), `transfer ${index}`);
    const rawAmount = own(transfer, "amount");
    if (typeof rawAmount !== "string" || !DECIMAL.test(rawAmount)) {
      throw new Error(`transfer ${index} amount must be canonical decimal`);
    }
    const amountMotes = parseUnsigned(rawAmount, 512);
    return {
      deployHash: parseTransactionHash(
        own(transfer, version === "Version1" ? "deploy_hash" : "transaction_hash"),
        `transfer ${index} hash`,
      ),
      sourceAccountHash: parseAccountHash(own(transfer, "from"), `transfer ${index} source`),
      recipientAccountHash: parseAccountHash(own(transfer, "to"), `transfer ${index} recipient`),
      amountMotes,
      transferId: parseTransferId(own(transfer, "id")),
    };
  });
}

export function verifyNoDuplicateNativeTransfer(
  input: NativeTransferScanInput,
): NoDuplicateNativeTransferFacts {
  for (const field of [
    "chainStatusRequest",
    "chainStatusResponse",
    "blockObservations",
    "authorizationBlockHeight",
    "finality",
  ] as const) {
    if (!Object.hasOwn(input, field)) throw new Error(`required own transfer-scan field ${field} is missing`);
  }
  if (!Array.isArray(input.blockObservations)) throw new Error("block observations must be a list");
  const finality = verifyFinalizedNativeTransfer(input.finality);
  const start = height(input.authorizationBlockHeight, "authorization block height");
  if (start > finality.blockHeight) throw new Error("authorization block height cannot follow transfer inclusion");
  const tip = parseStatus(input.chainStatusRequest, input.chainStatusResponse);
  if (tip.height < finality.blockHeight) throw new Error("observed tip precedes transfer inclusion");
  const expectedCount = tip.height - start + 1;
  if (expectedCount > MAX_SCAN_BLOCKS) throw new Error("block scan exceeds bounded range");
  if (input.blockObservations.length !== expectedCount) throw new Error("block scan is not contiguous");

  const expectedTransferId = BigInt(finality.signedDeploy.transferId);
  const expectedAmount = BigInt(finality.signedDeploy.amountMotes);
  const relevant: { height: number; blockHash: string; transfer: ParsedTransfer }[] = [];
  const seenHashes = new Set<string>();
  let lastBlockHash = "";
  let authorizationBlockHash = "";
  let previousBlockHash: string | null = null;
  for (let offset = 0; offset < input.blockObservations.length; offset += 1) {
    const currentHeight = start + offset;
    const observation = record(input.blockObservations[offset], `block observation ${currentHeight}`);
    exactOwnKeys(
      observation,
      ["block_request", "block_response", "transfers_request", "transfers_response"],
      `block observation ${currentHeight}`,
    );
    const block = parseBlock(
      own(observation, "block_request"),
      own(observation, "block_response"),
      currentHeight,
    );
    const { blockHash } = block;
    if (offset === 0) authorizationBlockHash = blockHash;
    if (seenHashes.has(blockHash)) throw new Error("canonical block hash repeats within scan");
    if (previousBlockHash !== null && block.parentHash !== previousBlockHash) {
      throw new Error("block scan parent chain is not contiguous");
    }
    seenHashes.add(blockHash);
    lastBlockHash = blockHash;
    previousBlockHash = blockHash;
    const transfers = parseTransfers(
      own(observation, "transfers_request"),
      own(observation, "transfers_response"),
      blockHash,
      currentHeight,
    );
    for (const transfer of transfers) {
      if (
        transfer.sourceAccountHash === finality.signedDeploy.sourceAccountHash &&
        transfer.transferId === expectedTransferId
      ) {
        relevant.push({ height: currentHeight, blockHash, transfer });
      }
    }
  }
  if (lastBlockHash !== tip.hash) throw new Error("block scan does not end at observed tip");
  if (relevant.length !== 1) throw new Error("scan must contain exactly one transfer for source and transfer id");
  const match = relevant[0] as { height: number; blockHash: string; transfer: ParsedTransfer };
  if (
    match.height !== finality.blockHeight ||
    match.blockHash !== finality.blockHash ||
    match.transfer.deployHash !== finality.deployHash ||
    match.transfer.recipientAccountHash !== finality.signedDeploy.recipientAccountHash ||
    match.transfer.amountMotes !== expectedAmount
  ) {
    throw new Error("only matching transfer does not equal the finalized action");
  }

  const transcript = canonicalTranscriptJson(
    {
      authorization_block_height: start,
      chain_status_request: input.chainStatusRequest,
      chain_status_response: input.chainStatusResponse,
      block_observations: input.blockObservations,
    },
    "scan transcript",
  );
  return Object.freeze({
    network: "casper-test",
    authorizationBlockHeight: start,
    authorizationBlockHash,
    inclusionBlockHeight: finality.blockHeight,
    observedThroughBlockHeight: tip.height,
    observedThroughBlockHash: tip.hash,
    scannedBlockCount: expectedCount,
    matchedTransferCount: 1,
    deployHash: finality.deployHash,
    sourceAccountHash: finality.signedDeploy.sourceAccountHash,
    recipientAccountHash: finality.signedDeploy.recipientAccountHash,
    amountMotes: finality.signedDeploy.amountMotes,
    transferId: finality.signedDeploy.transferId,
    transcriptSha256: sha256CanonicalTranscript(transcript),
  });
}
