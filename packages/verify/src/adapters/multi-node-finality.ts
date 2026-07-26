import {
  canonicalTranscriptJson,
  sha256CanonicalTranscript,
} from "./casper-state.js";
import {
  verifyFinalizedNativeTransfer,
  type FinalizedNativeTransferFacts,
} from "./native-finality.js";
import type { SignedNativeTransferExpectation } from "./native-deploy.js";
import { isRecord } from "../encoders.js";

const CAPTURED_AT =
  /^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})(?:\.(?<fraction>[0-9]{1,6}))?Z$/;
const VERIFICATION_SCOPE =
  "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified" as const;

const NODE_FIELDS = Object.freeze([
  "node_url",
  "captured_at",
  "status_request",
  "status_response",
  "transaction_request",
  "transaction_response",
  "canonical_block_request",
  "canonical_block_response",
] as const);

export type CorroboratedNativeTransferInput = Readonly<{
  requestedDeployHash: string;
  nodeObservations: readonly unknown[];
  signedDeploy: SignedNativeTransferExpectation;
}>;

export type CorroboratedNativeTransferFacts = Readonly<{
  requestedDeployHash: string;
  deployHash: string;
  network: "casper-test";
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
  rpcMethod: "info_get_deploy" | "info_get_transaction";
  executionResultKind: string;
  gasMotes: string;
  blockInclusionPath: string;
  nodeObservationCount: number;
  corroborationCount: number;
  nodeUrls: readonly string[];
  capturedAt: readonly string[];
  rpcMethods: readonly ("info_get_deploy" | "info_get_transaction")[];
  nodeObservationJson: readonly string[];
  nodeObservationSha256: readonly string[];
  verificationScope: typeof VERIFICATION_SCOPE;
  signedDeploy: FinalizedNativeTransferFacts["signedDeploy"];
}>;

type ParsedNode = Readonly<{
  nodeUrl: string;
  origin: string;
  capturedAt: string;
  transcriptJson: string;
  transcriptSha256: string;
  facts: FinalizedNativeTransferFacts;
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
    throw new Error(`${label} must contain exactly frozen own fields`);
  }
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

function exactResponse(
  raw: unknown,
  expectedId: number | string,
  label: string,
): Record<string, unknown> {
  const response = record(raw, `${label} response`);
  exactOwnKeys(response, ["jsonrpc", "id", "result"], `${label} response`);
  if (own(response, "jsonrpc") !== "2.0") {
    throw new Error(`${label} response must use JSON-RPC 2.0`);
  }
  if (own(response, "id") !== expectedId) {
    throw new Error(`${label} response id does not match request id`);
  }
  record(own(response, "result"), `${label} result`);
  return response;
}

function resultValue(
  response: Record<string, unknown>,
  expectedName: string,
  label: string,
): Record<string, unknown> {
  const result = record(own(response, "result"), `${label} result`);
  const wrapped = Object.hasOwn(result, "name") || Object.hasOwn(result, "value");
  if (!wrapped) {
    if (Object.keys(result).length === 0) throw new Error(`${label} result is malformed`);
    return result;
  }
  exactOwnKeys(result, ["name", "value"], `${label} result`);
  if (own(result, "name") !== expectedName) {
    throw new Error(`${label} result name does not match request method`);
  }
  const value = record(own(result, "value"), `${label} result value`);
  if (Object.keys(value).length === 0) throw new Error(`${label} result is malformed`);
  return value;
}

function statusNetwork(response: Record<string, unknown>): "casper-test" {
  const value = resultValue(response, "info_get_status_result", "status");
  const names = ["chainspec_name", "chainspecName", "chain_name"]
    .filter((name) => Object.hasOwn(value, name))
    .map((name) => own(value, name));
  if (names.length !== 1 || names[0] !== "casper-test") {
    throw new Error("status response must prove chain casper-test");
  }
  return "casper-test";
}

function canonicalCapturedAt(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("capture timestamp must be canonical UTC RFC3339");
  }
  const match = CAPTURED_AT.exec(value);
  if (match?.groups === undefined) {
    throw new Error("capture timestamp must be canonical UTC RFC3339");
  }
  const year = Number(match.groups.year);
  const month = Number(match.groups.month);
  const day = Number(match.groups.day);
  const hour = Number(match.groups.hour);
  const minute = Number(match.groups.minute);
  const second = Number(match.groups.second);
  if (year === 0 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
    throw new Error("capture timestamp must be canonical UTC RFC3339");
  }
  const parsed = new Date(0);
  parsed.setUTCFullYear(year, month - 1, day);
  parsed.setUTCHours(hour, minute, second, 0);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day ||
    parsed.getUTCHours() !== hour ||
    parsed.getUTCMinutes() !== minute ||
    parsed.getUTCSeconds() !== second
  ) {
    throw new Error("capture timestamp must be canonical UTC RFC3339");
  }
  return value;
}

function publicNodeUrl(value: unknown): { url: string; origin: string } {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("node URL must identify a public credential-free HTTPS RPC endpoint");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("node URL must identify a public credential-free HTTPS RPC endpoint");
  }
  const hostname = parsed.hostname.toLowerCase();
  const localName =
    hostname === "localhost" ||
    hostname === "localhost.localdomain" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local");
  const literalAddress =
    /^\[[0-9a-f:.]+\]$/.test(hostname) ||
    /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    (parsed.pathname !== "/" && parsed.pathname !== "/rpc") ||
    hostname.length === 0 ||
    !hostname.includes(".") ||
    localName ||
    literalAddress ||
    parsed.href !== value
  ) {
    throw new Error("node URL must identify a public credential-free HTTPS RPC endpoint");
  }
  return { url: value, origin: parsed.origin };
}

function parseNode(
  rawValue: unknown,
  requestedDeployHash: string,
  signedDeploy: SignedNativeTransferExpectation,
): ParsedNode {
  const raw = record(rawValue, "node observation");
  exactOwnKeys(raw, NODE_FIELDS, "node observation");
  const node = publicNodeUrl(own(raw, "node_url"));
  const capturedAt = canonicalCapturedAt(own(raw, "captured_at"));

  const statusId = exactRequest(own(raw, "status_request"), "info_get_status", {}, "status");
  const statusResponse = exactResponse(own(raw, "status_response"), statusId, "status");
  statusNetwork(statusResponse);

  const transactionResponseRaw = own(raw, "transaction_response");
  const canonicalBlockResponseRaw = own(raw, "canonical_block_response");
  const provisional = verifyFinalizedNativeTransfer({
    requestedDeployHash,
    rpcPayload: transactionResponseRaw,
    canonicalBlockPayload: canonicalBlockResponseRaw,
    signedDeploy,
  });
  const transactionParams = provisional.rpcMethod === "info_get_deploy"
    ? { deploy_hash: requestedDeployHash, finalized_approvals: true }
    : { transaction_hash: { Deploy: requestedDeployHash }, finalized_approvals: true };
  const transactionId = exactRequest(
    own(raw, "transaction_request"),
    provisional.rpcMethod,
    transactionParams,
    "transaction",
  );
  const transactionResponse = exactResponse(
    transactionResponseRaw,
    transactionId,
    "transaction",
  );
  resultValue(transactionResponse, `${provisional.rpcMethod}_result`, "transaction");

  const blockId = exactRequest(
    own(raw, "canonical_block_request"),
    "chain_get_block",
    { block_identifier: { Hash: provisional.blockHash } },
    "canonical block",
  );
  const blockResponse = exactResponse(canonicalBlockResponseRaw, blockId, "canonical block");
  resultValue(blockResponse, "chain_get_block_result", "canonical block");

  const transcriptJson = canonicalTranscriptJson(raw, "node observation transcript");
  return Object.freeze({
    nodeUrl: node.url,
    origin: node.origin,
    capturedAt,
    transcriptJson,
    transcriptSha256: sha256CanonicalTranscript(transcriptJson),
    facts: provisional,
  });
}

export function verifyCorroboratedNativeTransfer(
  input: CorroboratedNativeTransferInput,
): CorroboratedNativeTransferFacts {
  for (const field of ["requestedDeployHash", "nodeObservations", "signedDeploy"] as const) {
    if (!Object.hasOwn(input, field)) {
      throw new Error(`required own corroborated-finality field ${field} is missing`);
    }
  }
  if (!Array.isArray(input.nodeObservations) || input.nodeObservations.length < 2) {
    throw new Error("at least two distinct public RPC node observations are required");
  }
  const nodes = input.nodeObservations.map((raw) =>
    parseNode(raw, input.requestedDeployHash, input.signedDeploy),
  );
  if (new Set(nodes.map((node) => node.origin)).size !== nodes.length) {
    throw new Error("node observations must use distinct public RPC URL origins");
  }

  const first = nodes[0];
  if (first === undefined) throw new Error("at least two node observations are required");
  for (const node of nodes.slice(1)) {
    if (
      node.facts.deployHash !== first.facts.deployHash ||
      node.facts.blockHash !== first.facts.blockHash ||
      node.facts.blockHeight !== first.facts.blockHeight ||
      node.facts.stateRootHash !== first.facts.stateRootHash ||
      node.facts.gasMotes !== first.facts.gasMotes
    ) {
      throw new Error("node observations conflict");
    }
  }

  const nodeUrls = Object.freeze(nodes.map((node) => node.nodeUrl));
  const capturedAt = Object.freeze(nodes.map((node) => node.capturedAt));
  const rpcMethods = Object.freeze(nodes.map((node) => node.facts.rpcMethod));
  const nodeObservationJson = Object.freeze(nodes.map((node) => node.transcriptJson));
  const nodeObservationSha256 = Object.freeze(nodes.map((node) => node.transcriptSha256));
  return Object.freeze({
    requestedDeployHash: first.facts.requestedDeployHash,
    deployHash: first.facts.deployHash,
    network: "casper-test",
    blockHash: first.facts.blockHash,
    blockHeight: first.facts.blockHeight,
    stateRootHash: first.facts.stateRootHash,
    rpcMethod: first.facts.rpcMethod,
    executionResultKind: first.facts.executionResultKind,
    gasMotes: first.facts.gasMotes,
    blockInclusionPath: first.facts.blockInclusionPath,
    nodeObservationCount: nodes.length,
    corroborationCount: nodes.length - 1,
    nodeUrls,
    capturedAt,
    rpcMethods,
    nodeObservationJson,
    nodeObservationSha256,
    verificationScope: VERIFICATION_SCOPE,
    signedDeploy: first.facts.signedDeploy,
  });
}
