import { createHash, timingSafeEqual } from "node:crypto";

import { blake2b256, concatBytes, hexBytes, isRecord, toHex } from "../encoders.js";
import { canonicalTranscriptJson } from "./casper-state.js";

const HEX32 = /^[0-9a-f]{64}$/;
const PROPOSAL_ID = /^[A-Z0-9-]{1,64}$/;
const TRANSCRIPT_FIELDS = Object.freeze([
  "rpc_url_identity_or_node_id",
  "method",
  "params",
  "request",
  "response",
  "canonical_sha256",
]);
const READBACK_FACT_FIELDS = Object.freeze([
  "schema_id",
  "network",
  "package_hash",
  "contract_hash",
  "schema_version",
  "deployment_domain",
  "casper_chain_name",
  "proposer",
  "finalizer",
  "signers",
  "threshold",
  "proposal_id",
  "proposed_envelope",
  "approval_count",
  "finalized",
  "finalized_envelope",
  "action_id",
  "action_authorized",
  "observed_block_hash",
  "observed_block_height",
  "observed_state_root_hash",
]);

export type V3ReadbackFacts = Readonly<{
  schemaId: "concordia.v3-chain-readback.v1";
  network: "casper-test";
  packageHash: string;
  contractHash: string;
  schemaVersion: 3;
  deploymentDomain: string;
  casperChainName: "casper-test";
  proposer: string;
  finalizer: string;
  signers: readonly [string, string, string];
  threshold: 2 | 3;
  proposalId: string;
  proposedEnvelope: string;
  approvalCount: number;
  finalized: true;
  finalizedEnvelope: string;
  actionId: string;
  actionAuthorized: true;
  observedBlockHash: string;
  observedBlockHeight: number;
  observedStateRootHash: string;
  artifactSha256: string;
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
    throw new Error(`${label} must contain exactly the frozen own fields`);
  }
}

function canonical(value: unknown, label: string): string {
  return canonicalTranscriptJson(value, label);
}

function equalCanonical(actual: unknown, expected: unknown, label: string): void {
  if (canonical(actual, `${label} actual`) !== canonical(expected, `${label} expected`)) {
    throw new Error(`${label} differs from raw evidence`);
  }
}

function hash32(value: unknown, label: string, nonzero = true): string {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be canonical lowercase 32-byte hex`);
  }
  if (nonzero && value === "00".repeat(32)) throw new Error(`${label} cannot be zero`);
  return value;
}

function height(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe u64`);
  }
  return value;
}

function asciiProposal(value: unknown): string {
  if (typeof value !== "string" || !PROPOSAL_ID.test(value)) {
    throw new Error("readback proposal_id is invalid");
  }
  return value;
}

function sha256Canonical(value: unknown, label: string): string {
  return createHash("sha256").update(canonical(value, label), "ascii").digest("hex");
}

function secureEqualHex(actual: string, expected: string): boolean {
  return actual.length === expected.length && timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function transcript(value: unknown): Record<string, unknown> {
  const item = record(value, "v3 readback transcript");
  exactOwnKeys(item, TRANSCRIPT_FIELDS, "v3 readback transcript");
  const node = own(item, "rpc_url_identity_or_node_id");
  if (typeof node !== "string" || node.length === 0 || node.includes("@")) {
    throw new Error("v3 readback node identity is invalid or contains credentials");
  }
  const method = own(item, "method");
  if (typeof method !== "string" || method.length === 0) throw new Error("v3 readback method is invalid");
  const params = record(own(item, "params"), "v3 readback params");
  const request = record(own(item, "request"), "v3 readback request");
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], "v3 readback request");
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== method) {
    throw new Error("v3 readback request method is invalid");
  }
  equalCanonical(own(request, "params"), params, "v3 readback request params");
  const response = record(own(item, "response"), "v3 readback response");
  exactOwnKeys(response, ["jsonrpc", "id", "result"], "v3 readback response");
  if (own(response, "jsonrpc") !== "2.0" || own(response, "id") !== own(request, "id")) {
    throw new Error("v3 readback response identity mismatch");
  }
  const expectedDigest = sha256Canonical({ request, response }, "v3 readback transcript");
  const suppliedDigest = hash32(own(item, "canonical_sha256"), "v3 readback transcript digest", false);
  if (!secureEqualHex(expectedDigest, suppliedDigest)) throw new Error("v3 readback transcript digest mismatch");
  return item;
}

function storedValue(value: Record<string, unknown>): Record<string, unknown> {
  const response = record(own(value, "response"), "v3 readback response");
  const result = record(own(response, "result"), "v3 readback result");
  return record(own(result, "stored_value"), "v3 readback stored value");
}

function innerStateBytes(value: Record<string, unknown>, label: string): Uint8Array {
  const clValue = record(own(storedValue(value), "CLValue"), `${label} CLValue`);
  exactOwnKeys(clValue, ["cl_type", "bytes", "parsed"], `${label} CLValue`);
  equalCanonical(own(clValue, "cl_type"), { List: "U8" }, `${label} CLType`);
  const parsed = own(clValue, "parsed");
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "number" || !Number.isInteger(item) || item < 0 || item > 255)) {
    throw new Error(`${label} parsed bytes are invalid`);
  }
  if (typeof own(clValue, "bytes") !== "string") throw new Error(`${label} raw bytes are missing`);
  const raw = hexBytes(own(clValue, "bytes") as string);
  const inner = Uint8Array.from(parsed as number[]);
  const expected = concatBytes(
    Uint8Array.of(inner.length & 0xff, (inner.length >>> 8) & 0xff, (inner.length >>> 16) & 0xff, (inner.length >>> 24) & 0xff),
    inner,
  );
  if (!Buffer.from(raw).equals(Buffer.from(expected))) {
    throw new Error(`${label} parsed value differs from raw CLValue bytes`);
  }
  return inner;
}

function stateDictionaryKey(index: number, mappingKey = new Uint8Array()): string {
  if (!Number.isInteger(index) || index < 0 || index > 255) throw new Error("Odra state index is invalid");
  const path = index <= 15
    ? Uint8Array.of(0, 0, 0, index)
    : Uint8Array.of(0xff, 1, index);
  return toHex(blake2b256(concatBytes(path, mappingKey)));
}

function littleU32(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function u32(value: Uint8Array, label: string): number {
  if (value.length !== 4) throw new Error(`${label} must be canonical u32 bytes`);
  return ((value[0] as number) | ((value[1] as number) << 8) | ((value[2] as number) << 16) | ((value[3] as number) << 24)) >>> 0;
}

function u8Value(value: Uint8Array, label: string): number {
  if (value.length !== 1) throw new Error(`${label} must be canonical u8 bytes`);
  return value[0] as number;
}

function boolValue(value: Uint8Array, label: string): boolean {
  if (value.length !== 1 || (value[0] !== 0 && value[0] !== 1)) {
    throw new Error(`${label} must be canonical Bool bytes`);
  }
  return value[0] === 1;
}

function bytes32Value(value: Uint8Array, label: string): string {
  if (value.length !== 32) throw new Error(`${label} must be canonical Bytes32`);
  return toHex(value);
}

function stringValue(value: Uint8Array, label: string): string {
  if (value.length < 4) throw new Error(`${label} String is malformed`);
  const length = u32(value.slice(0, 4), `${label} length`);
  if (length !== value.length - 4) throw new Error(`${label} String length is non-canonical`);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value.slice(4));
  } catch {
    throw new Error(`${label} String is invalid UTF-8`);
  }
}

function unwrapBlock(response: Record<string, unknown>): {
  blockHash: string;
  stateRootHash: string;
  blockHeight: number;
} {
  const result = record(own(response, "result"), "v3 readback block result");
  exactOwnKeys(result, ["api_version", "block_with_signatures"], "v3 readback block result");
  if (typeof own(result, "api_version") !== "string" || (own(result, "api_version") as string).length === 0) {
    throw new Error("v3 readback block api_version is invalid");
  }
  const wrapper = record(own(result, "block_with_signatures"), "v3 readback block wrapper");
  exactOwnKeys(wrapper, ["block", "proofs"], "v3 readback block wrapper");
  if (!Array.isArray(own(wrapper, "proofs"))) throw new Error("v3 readback block proofs must be a list");
  const versioned = record(own(wrapper, "block"), "v3 readback versioned block");
  const versions = ["Version1", "Version2"].filter((name) => Object.hasOwn(versioned, name));
  if (versions.length !== 1 || Object.keys(versioned).length !== 1) {
    throw new Error("v3 readback block must contain exactly one supported version");
  }
  const block = record(own(versioned, versions[0] as string), "v3 readback block");
  if (!Object.hasOwn(block, "hash") || !Object.hasOwn(block, "header") || !Object.hasOwn(block, "body")) {
    throw new Error("v3 readback block lacks hash/header/body");
  }
  record(own(block, "body"), "v3 readback block body");
  const header = record(own(block, "header"), "v3 readback block header");
  return {
    blockHash: hash32(own(block, "hash"), "v3 readback block hash"),
    stateRootHash: hash32(own(header, "state_root_hash"), "v3 readback state root"),
    blockHeight: height(own(header, "height"), "v3 readback block height"),
  };
}

function packageHashFromContract(value: Record<string, unknown>): string {
  const contract = record(own(storedValue(value), "Contract"), "v3 readback contract record");
  const raw = own(contract, "contract_package_hash");
  if (typeof raw !== "string") throw new Error("v3 readback contract package hash is missing");
  const stripped = raw.startsWith("contract-package-") ? raw.slice(17) : raw.startsWith("hash-") ? raw.slice(5) : raw;
  return hash32(stripped, "v3 readback package hash");
}

export function verifyV3ReadbackArtifact(input: unknown): V3ReadbackFacts {
  const artifact = record(input, "v3 readback artifact");
  exactOwnKeys(
    artifact,
    ["schema_id", "network", "expected", "transcripts", "facts", "artifact_sha256"],
    "v3 readback artifact",
  );
  if (own(artifact, "schema_id") !== "concordia.v3-chain-readback.v1" || own(artifact, "network") !== "casper-test") {
    throw new Error("v3 readback schema/network is unsupported");
  }
  const expected = record(own(artifact, "expected"), "v3 readback expected identity");
  exactOwnKeys(expected, ["package_hash", "contract_hash", "proposal_id", "action_id"], "v3 readback expected identity");
  const packageHash = hash32(own(expected, "package_hash"), "v3 readback expected package hash");
  const contractHash = hash32(own(expected, "contract_hash"), "v3 readback expected contract hash");
  const proposalId = asciiProposal(own(expected, "proposal_id"));
  const actionId = hash32(own(expected, "action_id"), "v3 readback expected action id");
  const suppliedArtifactHash = hash32(own(artifact, "artifact_sha256"), "v3 readback artifact SHA-256", false);
  const artifactWithoutHash: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(artifact)) if (key !== "artifact_sha256") artifactWithoutHash[key] = value;
  const recomputedArtifactHash = sha256Canonical(artifactWithoutHash, "v3 readback artifact");
  if (!secureEqualHex(suppliedArtifactHash, recomputedArtifactHash)) {
    throw new Error("v3 readback artifact checksum mismatch");
  }

  const rawTranscripts = own(artifact, "transcripts");
  if (!Array.isArray(rawTranscripts) || rawTranscripts.length !== 16) {
    throw new Error("v3 readback requires exactly sixteen transcripts");
  }
  const transcripts = rawTranscripts.map((value) => transcript(value));
  const blockCalls = transcripts.filter((item) => own(item, "method") === "chain_get_block");
  const contractCalls = transcripts.filter((item) => own(item, "method") === "query_global_state");
  const dictionaryCalls = transcripts.filter((item) => own(item, "method") === "state_get_dictionary_item");
  if (blockCalls.length !== 1 || contractCalls.length !== 1 || dictionaryCalls.length !== 14) {
    throw new Error("v3 readback transcript method inventory is invalid");
  }
  const blockResponse = record(own(blockCalls[0] as Record<string, unknown>, "response"), "v3 readback block response");
  const block = unwrapBlock(blockResponse);
  const blockParams = record(own(blockCalls[0] as Record<string, unknown>, "params"), "v3 readback block params");
  if (Object.keys(blockParams).length !== 1) throw new Error("v3 readback block params are not exact");
  equalCanonical(own(blockParams, "block_identifier"), { Hash: block.blockHash }, "v3 readback block identifier");

  const contractParams = own(contractCalls[0] as Record<string, unknown>, "params");
  equalCanonical(
    contractParams,
    { state_identifier: { StateRootHash: block.stateRootHash }, key: `hash-${contractHash}`, path: [] },
    "v3 readback contract query",
  );
  if (packageHashFromContract(contractCalls[0] as Record<string, unknown>) !== packageHash) {
    throw new Error("v3 readback exact contract does not belong to expected package");
  }

  const dictionaryIdentifier = {
    ContractNamedKey: { key: `hash-${contractHash}`, dictionary_name: "state" },
  };
  const byKey = new Map<string, Record<string, unknown>>();
  for (const item of dictionaryCalls) {
    const params = record(own(item, "params"), "v3 readback dictionary params");
    exactOwnKeys(params, ["state_root_hash", "dictionary_identifier", "dictionary_item_key"], "v3 readback dictionary params");
    if (own(params, "state_root_hash") !== block.stateRootHash) throw new Error("v3 readback dictionary query uses another state root");
    equalCanonical(own(params, "dictionary_identifier"), dictionaryIdentifier, "v3 readback dictionary identity");
    const itemKey = own(params, "dictionary_item_key");
    if (typeof itemKey !== "string" || !HEX32.test(itemKey) || byKey.has(itemKey)) {
      throw new Error("v3 readback dictionary key is invalid or duplicated");
    }
    byKey.set(itemKey, item);
  }

  const proposalBytes = Buffer.from(proposalId, "ascii");
  const proposalKey = concatBytes(littleU32(proposalBytes.length), proposalBytes);
  const stateItems: Readonly<Record<string, readonly [number, Uint8Array]>> = Object.freeze({
    schema_version: [1, new Uint8Array()],
    deployment_domain: [2, new Uint8Array()],
    casper_chain_name: [3, new Uint8Array()],
    proposer: [4, new Uint8Array()],
    finalizer: [5, new Uint8Array()],
    signer_a: [6, new Uint8Array()],
    signer_b: [7, new Uint8Array()],
    signer_c: [8, new Uint8Array()],
    threshold: [9, new Uint8Array()],
    proposed_envelope: [11, proposalKey],
    approval_count: [12, proposalKey],
    finalized: [14, proposalKey],
    finalized_envelope: [15, proposalKey],
    action_authorized: [16, hexBytes(actionId, 32)],
  });
  const observed: Record<string, Uint8Array> = Object.create(null);
  for (const [name, [index, mappingKey]] of Object.entries(stateItems)) {
    const key = stateDictionaryKey(index, Uint8Array.from(mappingKey));
    const item = byKey.get(key);
    if (!item) throw new Error(`v3 readback is missing exact state query ${name}`);
    observed[name] = innerStateBytes(item, `v3 readback ${name}`);
  }
  if (byKey.size !== Object.keys(observed).length) throw new Error("v3 readback contains an unexpected state query");

  const schemaVersion = u32(observed.schema_version as Uint8Array, "v3 readback schema_version");
  const deploymentDomain = bytes32Value(observed.deployment_domain as Uint8Array, "v3 readback deployment_domain");
  const casperChainName = stringValue(observed.casper_chain_name as Uint8Array, "v3 readback casper_chain_name");
  const proposer = bytes32Value(observed.proposer as Uint8Array, "v3 readback proposer");
  const finalizer = bytes32Value(observed.finalizer as Uint8Array, "v3 readback finalizer");
  const signers = [
    bytes32Value(observed.signer_a as Uint8Array, "v3 readback signer_a"),
    bytes32Value(observed.signer_b as Uint8Array, "v3 readback signer_b"),
    bytes32Value(observed.signer_c as Uint8Array, "v3 readback signer_c"),
  ] as const;
  const threshold = u8Value(observed.threshold as Uint8Array, "v3 readback threshold");
  const proposedEnvelope = bytes32Value(observed.proposed_envelope as Uint8Array, "v3 readback proposed envelope");
  const approvalCount = u8Value(observed.approval_count as Uint8Array, "v3 readback approval count");
  const finalized = boolValue(observed.finalized as Uint8Array, "v3 readback finalized");
  const finalizedEnvelope = bytes32Value(observed.finalized_envelope as Uint8Array, "v3 readback finalized envelope");
  const actionAuthorized = boolValue(observed.action_authorized as Uint8Array, "v3 readback action authorized");
  const roles = [proposer, finalizer, ...signers];
  if (
    schemaVersion !== 3 ||
    casperChainName !== "casper-test" ||
    roles.some((role) => role === "00".repeat(32)) ||
    new Set(roles).size !== 5 ||
    (threshold !== 2 && threshold !== 3)
  ) {
    throw new Error("v3 readback governance schema, roles, network or threshold is invalid");
  }
  if (!finalized || !actionAuthorized || approvalCount < threshold || proposedEnvelope !== finalizedEnvelope) {
    throw new Error("v3 readback does not prove exact finalized authorization");
  }
  const rawFacts = {
    schema_id: "concordia.v3-chain-readback.v1",
    network: "casper-test",
    package_hash: packageHash,
    contract_hash: contractHash,
    schema_version: schemaVersion,
    deployment_domain: deploymentDomain,
    casper_chain_name: casperChainName,
    proposer,
    finalizer,
    signers: [...signers],
    threshold,
    proposal_id: proposalId,
    proposed_envelope: proposedEnvelope,
    approval_count: approvalCount,
    finalized,
    finalized_envelope: finalizedEnvelope,
    action_id: actionId,
    action_authorized: actionAuthorized,
    observed_block_hash: block.blockHash,
    observed_block_height: block.blockHeight,
    observed_state_root_hash: block.stateRootHash,
  };
  const persistedFacts = record(own(artifact, "facts"), "v3 readback persisted facts");
  exactOwnKeys(persistedFacts, READBACK_FACT_FIELDS, "v3 readback persisted facts");
  equalCanonical(persistedFacts, rawFacts, "v3 readback persisted facts");
  return Object.freeze({
    schemaId: "concordia.v3-chain-readback.v1",
    network: "casper-test",
    packageHash,
    contractHash,
    schemaVersion: 3,
    deploymentDomain,
    casperChainName: "casper-test",
    proposer,
    finalizer,
    signers,
    threshold: threshold as 2 | 3,
    proposalId,
    proposedEnvelope,
    approvalCount,
    finalized: true,
    finalizedEnvelope,
    actionId,
    actionAuthorized: true,
    observedBlockHash: block.blockHash,
    observedBlockHeight: block.blockHeight,
    observedStateRootHash: block.stateRootHash,
    artifactSha256: suppliedArtifactHash,
  });
}
