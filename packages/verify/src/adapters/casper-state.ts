import { createHash } from "node:crypto";

import { isRecord, parseUnsigned } from "../encoders.js";

const HEX32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const PROOF_HEX = /^(?:[0-9a-f]{2})+$/;
// A bounded no-duplicate scan can legitimately carry up to 32 MiB of raw
// block transcripts. Individual balance observations remain much smaller,
// but the shared canonicalizer must not invalidate the frozen scan schema.
const MAX_TRANSCRIPT_BYTES = 32 * 1024 * 1024;

export type CasperAccountBalanceInput = Readonly<{
  chainStatusRequest: unknown;
  chainStatusPayload: unknown;
  canonicalBlockRequest: unknown;
  canonicalBlockPayload: unknown;
  balanceRequest: unknown;
  balanceResponse: unknown;
  expectedAccountHash: string;
  expectedBlockHash: string;
  expectedBlockHeight: number;
  expectedStateRootHash: string;
  expectedBalanceMotes?: string | number | bigint;
}>;

export type AccountBalanceFacts = Readonly<{
  network: "casper-test";
  accountHash: string;
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
  balanceMotes: string;
  availableBalanceMotes: string;
  balanceHoldsTotalMotes: string;
  balanceHolds: readonly Readonly<{ time: string; amount: string; proof: string }>[];
  nodeProvidedMerkleProofHex: string;
  merkleProofVerificationScope: "node-provided-not-locally-verified";
  balanceRequestMethod: "query_balance_details";
  balanceRequestId: number | string;
  transcriptSha256: Readonly<{
    statusRequest: string;
    status: string;
    blockRequest: string;
    block: string;
    balanceRequest: string;
    balanceResponse: string;
  }>;
}>;

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

function exactOwnKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((name, index) => name !== wanted[index]) ||
    wanted.some((name) => !Object.hasOwn(value, name))
  ) {
    throw new Error(`${label} must contain exactly frozen fields`);
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

function requestId(value: unknown, label: string): number | string {
  if (
    (typeof value !== "number" || !Number.isSafeInteger(value)) &&
    (typeof value !== "string" || value.length === 0)
  ) {
    throw new Error(`${label} request id is invalid`);
  }
  return value;
}

function unwrapResult(payload: unknown, label: string): Record<string, unknown> {
  const body = record(payload, `${label} payload`);
  const error = own(body, "error");
  if (error !== undefined && error !== null) throw new Error(`${label} payload contains error`);
  if (own(body, "jsonrpc") !== "2.0") throw new Error(`${label} payload must use JSON-RPC 2.0`);
  const result = record(own(body, "result"), `${label} result`);
  if (Object.keys(result).length === 0) throw new Error(`${label} result is malformed`);
  const wrapped = Object.hasOwn(result, "name") || Object.hasOwn(result, "value");
  if (!wrapped) return result;
  exactOwnKeys(result, ["name", "value"], `${label} result`);
  if (typeof own(result, "name") !== "string") throw new Error(`${label} result is malformed`);
  const value = record(own(result, "value"), `${label} result`);
  if (Object.keys(value).length === 0) throw new Error(`${label} result is malformed`);
  return value;
}

function exactRequest(
  raw: unknown,
  method: string,
  params: Record<string, unknown>,
  label: string,
): number | string {
  const request = record(raw, `${label} request`);
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], `${label} request`);
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== method) {
    throw new Error(`${label} request must call ${method}`);
  }
  if (
    canonicalTranscriptJson(own(request, "params"), `${label} request params`) !==
    canonicalTranscriptJson(params, `${label} expected params`)
  ) {
    throw new Error(`${label} request params do not match exactly`);
  }
  return requestId(own(request, "id"), label);
}

function requireResponseId(payload: unknown, expected: number | string, label: string): void {
  const body = record(payload, `${label} payload`);
  if (own(body, "id") !== expected) throw new Error(`${label} response id does not match request id`);
}

function quoteAscii(value: string): string {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function canonicalJsonValue(value: unknown, label: string, depth: number): string {
  if (depth > 128) throw new Error(`${label} exceeds JSON nesting limit`);
  if (value === null) return "null";
  if (typeof value === "string") return quoteAscii(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${label} contains a non-canonical JSON number`);
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJsonValue(entry, label, depth + 1)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${quoteAscii(key)}:${canonicalJsonValue(own(value, key), label, depth + 1)}`)
      .join(",")}}`;
  }
  throw new Error(`${label} is not canonical JSON`);
}

export function canonicalTranscriptJson(value: unknown, label: string): string {
  const encoded = canonicalJsonValue(value, label, 0);
  if (Buffer.byteLength(encoded, "ascii") > MAX_TRANSCRIPT_BYTES) {
    throw new Error(`${label} exceeds transcript size limit`);
  }
  return encoded;
}

export function sha256CanonicalTranscript(value: string): string {
  return createHash("sha256").update(value, "ascii").digest("hex");
}

function parseNetwork(payload: unknown): "casper-test" {
  const value = unwrapResult(payload, "status");
  const names = ["chainspec_name", "chainspecName", "chain_name"]
    .filter((name) => Object.hasOwn(value, name))
    .map((name) => own(value, name));
  if (names.length !== 1 || names[0] !== "casper-test") {
    throw new Error("status must prove chain casper-test");
  }
  return "casper-test";
}

function parseBlock(payload: unknown): { blockHash: string; blockHeight: number; stateRootHash: string } {
  const value = unwrapResult(payload, "canonical block");
  const hasWrapped = Object.hasOwn(value, "block_with_signatures");
  const hasLegacy = Object.hasOwn(value, "block");
  if (hasWrapped === hasLegacy) throw new Error("canonical block result is malformed");
  let rawBlock: Record<string, unknown>;
  if (hasWrapped) {
    const wrapper = record(own(value, "block_with_signatures"), "canonical block wrapper");
    rawBlock = record(own(wrapper, "block"), "canonical block result");
  } else {
    rawBlock = record(own(value, "block"), "canonical block result");
  }
  const versions = ["Version1", "Version2"].filter((name) => Object.hasOwn(rawBlock, name));
  let block = rawBlock;
  if (versions.length > 0) {
    if (versions.length !== 1 || Object.keys(rawBlock).length !== 1) {
      throw new Error("canonical block result is malformed");
    }
    block = record(own(rawBlock, versions[0] as string), "canonical block result");
  }
  const blockHash = lowerHash(own(block, "hash"), "canonical block hash");
  const header = record(own(block, "header"), "canonical block header");
  const roots = ["state_root_hash", "stateRootHash"].filter((name) => Object.hasOwn(header, name));
  if (roots.length !== 1) throw new Error("canonical state root is ambiguous or missing");
  const stateRootHash = lowerHash(own(header, roots[0] as string), "canonical state root");
  record(own(block, "body"), "canonical block body");
  return {
    blockHash,
    blockHeight: height(own(header, "height"), "canonical block height"),
    stateRootHash,
  };
}

function parseBalanceRequest(
  raw: unknown,
  accountHash: string,
  stateRootHash: string,
): { requestId: number | string; method: "query_balance_details" } {
  const request = record(raw, "balance request");
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], "balance request");
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== "query_balance_details") {
    throw new Error("balance request must call query_balance_details");
  }
  const params = record(own(request, "params"), "balance request params");
  exactOwnKeys(params, ["state_identifier", "purse_identifier"], "balance request params");
  const state = record(own(params, "state_identifier"), "balance state identifier");
  if (
    canonicalTranscriptJson(state, "balance state identifier") !==
    canonicalTranscriptJson({ StateRootHash: stateRootHash }, "expected state identifier")
  ) {
    throw new Error("balance request state root does not match block");
  }
  const purse = record(own(params, "purse_identifier"), "balance purse identifier");
  if (
    canonicalTranscriptJson(purse, "balance purse identifier") !==
    canonicalTranscriptJson(
      { main_purse_under_account_hash: `account-hash-${accountHash}` },
      "expected purse identifier",
    )
  ) {
    throw new Error("balance request account hash does not match");
  }
  return {
    requestId: requestId(own(request, "id"), "balance"),
    method: "query_balance_details",
  };
}

function canonicalDecimal(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    throw new Error(`${label} must be canonical non-negative U512 decimal`);
  }
  return parseUnsigned(value, 512);
}

function canonicalProof(value: unknown, label: string): string {
  if (typeof value !== "string" || !PROOF_HEX.test(value)) {
    throw new Error(`${label} must be nonempty canonical lowercase hex`);
  }
  return value;
}

function parseBalanceResponse(
  payload: unknown,
  expectedId: number | string,
): Readonly<{
  balanceMotes: string;
  availableBalanceMotes: string;
  balanceHoldsTotalMotes: string;
  balanceHolds: readonly Readonly<{ time: string; amount: string; proof: string }>[];
  nodeProvidedMerkleProofHex: string;
}> {
  requireResponseId(payload, expectedId, "balance");
  const body = record(payload, "balance response payload");
  const result = record(own(body, "result"), "balance response result");
  exactOwnKeys(result, ["name", "value"], "balance response result");
  if (own(result, "name") !== "query_balance_details_result") {
    throw new Error("balance response result name must be query_balance_details_result");
  }
  const value = record(own(result, "value"), "balance response value");
  exactOwnKeys(
    value,
    ["api_version", "total_balance", "available_balance", "total_balance_proof", "holds"],
    "balance details result",
  );
  if (typeof own(value, "api_version") !== "string" || own(value, "api_version") === "") {
    throw new Error("balance details api_version is malformed");
  }
  const balance = canonicalDecimal(own(value, "total_balance"), "total balance");
  const available = canonicalDecimal(own(value, "available_balance"), "available balance");
  const rawHolds = own(value, "holds");
  if (!Array.isArray(rawHolds)) throw new Error("balance holds must be an array");
  let holdsTotal = 0n;
  const balanceHolds = rawHolds.map((raw, index) => {
    const hold = record(raw, `balance hold ${index}`);
    exactOwnKeys(hold, ["time", "amount", "proof"], `balance hold ${index}`);
    const time = parseUnsigned(own(hold, "time"), 64);
    const amount = canonicalDecimal(own(hold, "amount"), "balance hold amount");
    const proof = canonicalProof(own(hold, "proof"), "balance hold proof");
    holdsTotal += amount;
    if (holdsTotal >= 1n << 512n) throw new Error("balance hold total exceeds U512");
    return Object.freeze({ time: time.toString(), amount: amount.toString(), proof });
  });
  if (holdsTotal > balance || balance - holdsTotal !== available) {
    throw new Error("available balance does not match total balance and hold arithmetic");
  }
  return Object.freeze({
    balanceMotes: balance.toString(),
    availableBalanceMotes: available.toString(),
    balanceHoldsTotalMotes: holdsTotal.toString(),
    balanceHolds: Object.freeze(balanceHolds),
    nodeProvidedMerkleProofHex: canonicalProof(
      own(value, "total_balance_proof"),
      "total balance Merkle proof",
    ),
  });
}

export function verifyAccountBalanceAtBlock(input: CasperAccountBalanceInput): AccountBalanceFacts {
  for (const field of [
    "chainStatusRequest",
    "chainStatusPayload",
    "canonicalBlockRequest",
    "canonicalBlockPayload",
    "balanceRequest",
    "balanceResponse",
    "expectedAccountHash",
    "expectedBlockHash",
    "expectedBlockHeight",
    "expectedStateRootHash",
  ] as const) {
    if (!Object.hasOwn(input, field)) throw new Error(`required own balance field ${field} is missing`);
  }
  const accountHash = lowerHash(input.expectedAccountHash, "expected account hash");
  const expectedBlockHash = lowerHash(input.expectedBlockHash, "expected block hash");
  const expectedStateRootHash = lowerHash(input.expectedStateRootHash, "expected state root hash");
  const expectedBlockHeight = height(input.expectedBlockHeight, "expected block height");

  const statusId = exactRequest(input.chainStatusRequest, "info_get_status", {}, "status");
  requireResponseId(input.chainStatusPayload, statusId, "status");
  const network = parseNetwork(input.chainStatusPayload);
  const blockId = exactRequest(
    input.canonicalBlockRequest,
    "chain_get_block",
    { block_identifier: { Hash: expectedBlockHash } },
    "canonical block",
  );
  requireResponseId(input.canonicalBlockPayload, blockId, "canonical block");
  const block = parseBlock(input.canonicalBlockPayload);
  if (block.blockHash !== expectedBlockHash) throw new Error("canonical block hash does not match expected block hash");
  if (block.blockHeight !== expectedBlockHeight) throw new Error("canonical block height does not match expected block height");
  if (block.stateRootHash !== expectedStateRootHash) throw new Error("canonical state root does not match expected state root");

  const balanceRequest = parseBalanceRequest(input.balanceRequest, accountHash, block.stateRootHash);
  const balance = parseBalanceResponse(input.balanceResponse, balanceRequest.requestId);
  if (Object.hasOwn(input, "expectedBalanceMotes")) {
    const expected = parseUnsigned(input.expectedBalanceMotes, 512).toString();
    if (balance.balanceMotes !== expected) throw new Error("observed balance does not match expected balance");
  }

  const transcripts = {
    statusRequest: canonicalTranscriptJson(input.chainStatusRequest, "status request"),
    status: canonicalTranscriptJson(input.chainStatusPayload, "status payload"),
    blockRequest: canonicalTranscriptJson(input.canonicalBlockRequest, "canonical block request"),
    block: canonicalTranscriptJson(input.canonicalBlockPayload, "block payload"),
    balanceRequest: canonicalTranscriptJson(input.balanceRequest, "balance request"),
    balanceResponse: canonicalTranscriptJson(input.balanceResponse, "balance response"),
  };
  const transcriptSha256 = Object.freeze({
    statusRequest: sha256CanonicalTranscript(transcripts.statusRequest),
    status: sha256CanonicalTranscript(transcripts.status),
    blockRequest: sha256CanonicalTranscript(transcripts.blockRequest),
    block: sha256CanonicalTranscript(transcripts.block),
    balanceRequest: sha256CanonicalTranscript(transcripts.balanceRequest),
    balanceResponse: sha256CanonicalTranscript(transcripts.balanceResponse),
  });

  return Object.freeze({
    network,
    accountHash,
    blockHash: block.blockHash,
    blockHeight: block.blockHeight,
    stateRootHash: block.stateRootHash,
    balanceMotes: balance.balanceMotes,
    availableBalanceMotes: balance.availableBalanceMotes,
    balanceHoldsTotalMotes: balance.balanceHoldsTotalMotes,
    balanceHolds: balance.balanceHolds,
    nodeProvidedMerkleProofHex: balance.nodeProvidedMerkleProofHex,
    merkleProofVerificationScope: "node-provided-not-locally-verified",
    balanceRequestMethod: balanceRequest.method,
    balanceRequestId: balanceRequest.requestId,
    transcriptSha256,
  });
}
