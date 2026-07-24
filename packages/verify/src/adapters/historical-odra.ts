import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { BlockList, isIP } from "node:net";

import { isRecord } from "../encoders.js";
import { parseJsonStrict } from "../json.js";
import { verifyCardChainArtifact } from "./card-chain.js";
import {
  canonicalRuntimeArgumentsBytes,
  runtimeArgumentMap,
  verifySignedDeployJson,
  type DeployRuntimeArgument,
} from "./casper-deploy-json.js";
import { canonicalTranscriptJson } from "./casper-state.js";

const SCHEMA_VERSION = "concordia.historical_odra_receipt.v1";
const INVENTORY_SCHEMA = "concordia.historical_odra_inventory.v1";
const INVENTORY_SHA256 = "3c73db58180d19e3d91e360d650c6765023487e3c5b11b3a266d40e85dc26e4d";
const ENTRY_POINT = "store_governance_receipt";
const HEX32 = /^[0-9a-f]{64}$/;
const GIT40 = /^[0-9a-f]{40}$/;
const PROPOSAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UTC_Z = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const TOP_FIELDS = [
  "schema_version",
  "proposal_id",
  "generation",
  "captured_at",
  "source_commit",
  "deployment_commit",
  "source_url",
  "network",
  "lineage_inventory",
  "contract_identity",
  "card_chain",
  "raw_rpc",
] as const;
const INVENTORY_FIELDS = ["schema_version", "sha256", "canonical_json"] as const;
const IDENTITY_FIELDS = [
  "package_hash",
  "contract_hash",
  "contract_wasm_state_hash",
  "contract_version",
  "protocol_version_major",
  "entry_point",
  "session_variant",
  "session_target_kind",
  "session_target_hash",
  "session_version",
] as const;
const RAW_RPC_FIELDS = ["deploy", "canonical_block", "state_root", "package", "contract"] as const;
const V1_RECEIPT_ARGUMENTS = [
  "proposal_id",
  "proposal_type",
  "proposal_hash",
  "final_card_hash",
  "plan_hash",
  "decision",
  "risk_level",
  "risk_score",
  "treasury_action",
  "policy_hash",
  "policy_version",
  "dissent_hash",
  "approved_allocation_bps",
  "casper_network",
  "agent_council_version",
  "evidence_uri",
  "agent_action_hash",
] as const;
const V2_RECEIPT_ARGUMENTS = [
  "proposal_id",
  "proposal_type",
  "proposal_hash",
  "policy_hash",
  "dissent_hash",
  "final_card_hash",
  "plan_hash",
  "agent_action_hash",
  "approved_allocation_bps",
  "risk_score",
  "risk_level",
  "decision",
  "treasury_action",
  "policy_version",
  "casper_network",
  "agent_council_version",
  "evidence_uri",
] as const;
const RESTRICTED_IPV4 = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const;
const RESTRICTED_IPV6 = [
  ["::", 96], ["::1", 128], ["64:ff9b::", 96], ["64:ff9b:1::", 48],
  ["100::", 64], ["2001::", 23], ["2001:db8::", 32], ["2002::", 16],
  ["3fff::", 20], ["5f00::", 16], ["fc00::", 7], ["fe80::", 10],
  ["fec0::", 10], ["ff00::", 8],
] as const;
const restrictedIpv4 = new BlockList();
const restrictedIpv6 = new BlockList();
for (const [network, prefix] of RESTRICTED_IPV4) {
  restrictedIpv4.addSubnet(network, prefix, "ipv4");
  restrictedIpv6.addSubnet(`::ffff:${network}`, 96 + prefix, "ipv6");
}
for (const [network, prefix] of RESTRICTED_IPV6) {
  restrictedIpv6.addSubnet(network, prefix, "ipv6");
}

export class HistoricalOdraArtifactUnavailableError extends Error {
  override readonly name = "HistoricalOdraArtifactUnavailableError";
}

export type HistoricalOdraReceiptFacts = Readonly<{
  schemaVersion: typeof SCHEMA_VERSION;
  proposalId: string;
  generation: "v1" | "v2";
  deployHash: string;
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
  packageHash: string;
  contractHash: string;
  contractWasmStateHash: string;
  sessionVariant: "StoredContractByHash" | "StoredVersionedContractByHash";
  sessionTargetKind: "contract" | "package";
  sessionTargetHash: string;
  sessionVersion: number | null;
  finalCardHash: string;
  receiptArgumentDigest: string;
  sourceCommit: string;
  deploymentCommit: string;
  capturedAt: string;
  sourceDeploymentEquivalence: "unproven";
  verificationScope: "artifact_transcript_consistency";
  observationSources: readonly [];
}>;

type FrozenIdentity = Readonly<{
  packageHash: string;
  contractHash: string;
  contractWasmStateHash: string;
  contractVersion: number;
  protocolVersionMajor: number;
  deployHash: string;
  sessionVariant: "StoredContractByHash" | "StoredVersionedContractByHash";
  sessionTargetKind: "contract" | "package";
  sessionTargetHash: string;
  sessionVersion: number | null;
  finalCardHash: string;
  argumentOrder: readonly string[];
  argumentTypes: Readonly<Record<string, string>>;
  combinedArtifactAvailable: boolean;
}>;

type Transcript = Readonly<{
  request: Record<string, unknown>;
  response: Record<string, unknown>;
}>;

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
    throw new Error(`${label} must contain exactly the frozen own fields`);
  }
}

function hash32(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be canonical lowercase 32-byte hex`);
  }
  return value;
}

function prefixedHash(value: unknown, prefix: string, label: string): string {
  if (typeof value !== "string" || !value.startsWith(prefix)) {
    throw new Error(`${label} prefix is invalid`);
  }
  return hash32(value.slice(prefix.length), label);
}

function safeHeight(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe block height`);
  }
  return value;
}

function strictUtc(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be RFC3339 UTC-Z`);
  const match = UTC_Z.exec(value);
  if (match === null || match[1] === "0000") throw new Error(`${label} must be RFC3339 UTC-Z`);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) throw new Error(`${label} must be RFC3339 UTC-Z`);
  const date = new Date(millis);
  if (
    date.getUTCFullYear() !== Number(match[1]) ||
    date.getUTCMonth() + 1 !== Number(match[2]) ||
    date.getUTCDate() !== Number(match[3]) ||
    date.getUTCHours() !== Number(match[4]) ||
    date.getUTCMinutes() !== Number(match[5]) ||
    date.getUTCSeconds() !== Number(match[6])
  ) {
    throw new Error(`${label} must be RFC3339 UTC-Z`);
  }
  return value;
}

function sourceUrl(value: unknown, proposalId: string): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 2_048) {
    throw new Error("historical source_url must be a bounded HTTPS URL");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("historical source_url must be a bounded HTTPS URL");
  }
  const host = parsed.hostname
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "")
    .toLowerCase();
  const family = isIP(host);
  const forbiddenHost =
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host === "home.arpa" ||
    host.endsWith(".home.arpa") ||
    (family === 4 && restrictedIpv4.check(host, "ipv4")) ||
    (family === 6 && restrictedIpv6.check(host, "ipv6"));
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    forbiddenHost ||
    parsed.pathname !== `/proof-artifacts/v1/${proposalId}/historical-odra-receipt`
  ) {
    throw new Error("historical source_url must be credential-free public HTTPS with the frozen path");
  }
  return parsed.href;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function releaseInventoryBytes(): Buffer {
  return readFileSync(new URL("../release/historical/HISTORICAL_ODRA_RECEIPTS_V1.json", import.meta.url));
}

function parseTrustedInventory(
  artifactInventory: unknown,
  generation: "v1" | "v2",
  releaseBytes: Uint8Array,
  expectedInventorySha256: string,
): FrozenIdentity {
  if (sha256(releaseBytes) !== expectedInventorySha256) {
    throw new Error("packaged historical inventory differs from its frozen release digest");
  }
  const asserted = record(artifactInventory, "historical lineage inventory");
  exactOwnKeys(asserted, INVENTORY_FIELDS, "historical lineage inventory");
  if (own(asserted, "schema_version") !== INVENTORY_SCHEMA) {
    throw new Error("historical inventory schema differs from frozen release");
  }
  const canonical = own(asserted, "canonical_json");
  if (typeof canonical !== "string") throw new Error("historical inventory canonical_json must be text");
  const suppliedBytes = Buffer.from(canonical, "utf8");
  if (
    suppliedBytes.length !== releaseBytes.length ||
    !timingSafeEqual(suppliedBytes, releaseBytes)
  ) {
    throw new Error("historical inventory bytes differ from the packaged frozen release");
  }
  if (hash32(own(asserted, "sha256"), "historical inventory SHA-256") !== sha256(releaseBytes)) {
    throw new Error("historical inventory SHA-256 differs from the packaged frozen release");
  }

  const inventory = record(
    parseJsonStrict(Buffer.from(releaseBytes).toString("utf8")),
    "packaged historical inventory",
  );
  if (own(inventory, "schema_version") !== INVENTORY_SCHEMA || own(inventory, "network") !== "casper-test") {
    throw new Error("packaged historical inventory identity is invalid");
  }
  const preserved = record(own(inventory, "preserved_repo_source"), "packaged preserved source identity");
  if (own(preserved, "source_deployment_equivalence") !== "unproven") {
    throw new Error("packaged historical source/deployment equivalence must remain unproven");
  }
  const rawArgumentTypes = record(own(inventory, "receipt_argument_types"), "packaged historical argument types");
  const chain = record(own(inventory, "chain_identity"), "packaged historical chain identity");
  const identity = record(own(chain, generation), `packaged historical ${generation} identity`);
  const receipts = record(own(identity, "receipt_deploys"), `packaged historical ${generation} receipt deploys`);
  const session = record(own(identity, "accepted_session"), `packaged historical ${generation} accepted session`);
  const selectedReceipt = generation === "v1" ? own(receipts, "canonical_accepted") : own(receipts, "post_quorum_accepted");
  const expectedOrder = generation === "v1" ? V1_RECEIPT_ARGUMENTS : V2_RECEIPT_ARGUMENTS;
  const rawOrder = own(session, "argument_order");
  if (
    !Array.isArray(rawOrder) ||
    rawOrder.length !== expectedOrder.length ||
    rawOrder.some((name, index) => name !== expectedOrder[index])
  ) {
    throw new Error(`packaged historical ${generation} argument order is invalid`);
  }
  const sessionVariant = own(session, "variant");
  const sessionTargetKind = own(session, "target_kind");
  const expectedVariant = generation === "v1" ? "StoredContractByHash" : "StoredVersionedContractByHash";
  const expectedTargetKind = generation === "v1" ? "contract" : "package";
  const sessionVersion = own(session, "version");
  if (
    sessionVariant !== expectedVariant ||
    sessionTargetKind !== expectedTargetKind ||
    (generation === "v1" ? sessionVersion !== null : sessionVersion !== 1)
  ) {
    throw new Error(`packaged historical ${generation} session identity is invalid`);
  }
  const argumentTypes: Record<string, string> = Object.create(null);
  for (const name of expectedOrder) {
    const value = own(rawArgumentTypes, name);
    if (value !== "String" && value !== "U32" && value !== "ByteArray(32)") {
      throw new Error(`packaged historical argument type for ${name} is invalid`);
    }
    argumentTypes[name] = value;
  }
  if (Object.keys(rawArgumentTypes).length !== expectedOrder.length) {
    throw new Error("packaged historical argument type inventory contains unknown fields");
  }
  return Object.freeze({
    packageHash: hash32(own(identity, "package_hash"), "frozen package hash"),
    contractHash: hash32(own(identity, "contract_hash"), "frozen contract hash"),
    contractWasmStateHash: hash32(own(identity, "contract_wasm_state_hash"), "frozen Wasm state hash"),
    contractVersion: safeHeight(own(identity, "contract_version"), "frozen contract version"),
    protocolVersionMajor: safeHeight(own(identity, "protocol_version_major"), "frozen protocol version"),
    deployHash: hash32(selectedReceipt, "frozen accepted receipt deploy hash"),
    sessionVariant: expectedVariant,
    sessionTargetKind: expectedTargetKind,
    sessionTargetHash: hash32(own(session, "target_hash"), "frozen session target hash"),
    sessionVersion: generation === "v1" ? null : 1,
    finalCardHash: hash32(own(session, "final_card_hash"), "frozen final card hash"),
    argumentOrder: Object.freeze([...expectedOrder]),
    argumentTypes: Object.freeze(argumentTypes),
    combinedArtifactAvailable: own(session, "card_chain_binding") === "canonical_export_required",
  });
}

function transcript(value: unknown, label: string): Transcript {
  const item = record(value, `${label} transcript`);
  exactOwnKeys(item, ["request", "response"], `${label} transcript`);
  return {
    request: record(own(item, "request"), `${label} request`),
    response: record(own(item, "response"), `${label} response`),
  };
}

function requestId(value: unknown, label: string): number | string {
  if (
    (typeof value !== "number" || !Number.isSafeInteger(value)) &&
    (typeof value !== "string" || value.length === 0 || value.length > 256)
  ) {
    throw new Error(`${label} request id is invalid`);
  }
  return value;
}

function exactRequest(
  item: Transcript,
  method: string,
  params: Record<string, unknown>,
  label: string,
): Record<string, unknown> {
  exactOwnKeys(item.request, ["jsonrpc", "id", "method", "params"], `${label} request`);
  if (own(item.request, "jsonrpc") !== "2.0" || own(item.request, "method") !== method) {
    throw new Error(`${label} request must call ${method}`);
  }
  if (
    canonicalTranscriptJson(own(item.request, "params"), `${label} request params`) !==
    canonicalTranscriptJson(params, `${label} expected params`)
  ) {
    throw new Error(`${label} request params differ from the frozen binding`);
  }
  const id = requestId(own(item.request, "id"), label);
  exactOwnKeys(item.response, ["jsonrpc", "id", "result"], `${label} response`);
  if (own(item.response, "jsonrpc") !== "2.0" || own(item.response, "id") !== id) {
    throw new Error(`${label} response id does not match request id`);
  }
  const rawResult = record(own(item.response, "result"), `${label} response result`);
  const wrapped = Object.hasOwn(rawResult, "name") || Object.hasOwn(rawResult, "value");
  if (!wrapped) return rawResult;
  exactOwnKeys(rawResult, ["name", "value"], `${label} response result`);
  if (typeof own(rawResult, "name") !== "string" || own(rawResult, "name") === "") {
    throw new Error(`${label} response result name is invalid`);
  }
  return record(own(rawResult, "value"), `${label} response value`);
}

function executionSucceeded(value: unknown): void {
  const result = record(value, "historical execution result");
  exactOwnKeys(result, ["Version2"], "historical execution result");
  const body = record(own(result, "Version2"), "historical Version2 execution result");
  if (!Object.hasOwn(body, "error_message") || own(body, "error_message") !== null) {
    throw new Error("historical receipt execution failed or has no explicit success marker");
  }
}

function runtimeType(argument: DeployRuntimeArgument, name: string, expectedType: string): void {
  if (expectedType === "String") {
    if (argument.clType !== "String" || typeof argument.parsed !== "string") {
      throw new Error(`historical receipt ${name} must use String CLType`);
    }
    return;
  }
  if (expectedType === "U32") {
    if (argument.clType !== "U32") throw new Error(`historical receipt ${name} must use U32 CLType`);
    return;
  }
  if (expectedType !== "ByteArray(32)") {
    throw new Error(`historical receipt ${name} has an unsupported frozen CLType`);
  }
  const clType = record(argument.clType, `historical receipt ${name} CLType`);
  exactOwnKeys(clType, ["ByteArray"], `historical receipt ${name} CLType`);
  if (own(clType, "ByteArray") !== 32 || typeof argument.parsed !== "string" || !/^[0-9a-fA-F]{64}$/.test(argument.parsed)) {
    throw new Error(`historical receipt ${name} must use ByteArray(32) CLType`);
  }
}

function receiptArgumentDigest(
  runtimeArguments: readonly DeployRuntimeArgument[],
  argumentOrder: readonly string[],
): string {
  return sha256(
    canonicalRuntimeArgumentsBytes(runtimeArguments, argumentOrder, "historical receipt digest"),
  );
}

function parseCanonicalBlock(value: Record<string, unknown>, deployHash: string): {
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
} {
  const wrapper = record(own(value, "block_with_signatures"), "historical canonical block wrapper");
  const rawBlock = record(own(wrapper, "block"), "historical canonical block");
  exactOwnKeys(rawBlock, ["Version2"], "historical canonical block");
  const block = record(own(rawBlock, "Version2"), "historical Version2 block");
  const header = record(own(block, "header"), "historical canonical block header");
  const body = record(own(block, "body"), "historical canonical block body");
  const transactions = record(own(body, "transactions"), "historical canonical block transactions");
  let inclusions = 0;
  for (const rawItems of Object.values(transactions)) {
    if (!Array.isArray(rawItems)) throw new Error("historical canonical block transaction lane is malformed");
    for (const rawItem of rawItems) {
      const item = record(rawItem, "historical canonical block transaction");
      const variants = ["Deploy", "Version1"].filter((name) => Object.hasOwn(item, name));
      if (variants.length !== 1 || Object.keys(item).length !== 1) {
        throw new Error("historical canonical block transaction is ambiguous");
      }
      if (hash32(own(item, variants[0] as string), "historical canonical transaction hash") === deployHash) {
        inclusions += 1;
      }
    }
  }
  if (inclusions !== 1) throw new Error("historical deploy must appear exactly once in its canonical block");
  return {
    blockHash: hash32(own(block, "hash"), "historical canonical block hash"),
    blockHeight: safeHeight(own(header, "height"), "historical canonical block height"),
    stateRootHash: hash32(own(header, "state_root_hash"), "historical canonical state root"),
  };
}

function storedValue(value: Record<string, unknown>, label: string): Record<string, unknown> {
  return record(own(value, "stored_value"), `${label} stored value`);
}

function verifyPackageAndContract(
  packageValue: Record<string, unknown>,
  contractValue: Record<string, unknown>,
  frozen: FrozenIdentity,
): void {
  const packageStored = storedValue(packageValue, "historical package");
  exactOwnKeys(packageStored, ["ContractPackage"], "historical package stored value");
  const packageRecord = record(own(packageStored, "ContractPackage"), "historical ContractPackage");
  const versions = own(packageRecord, "versions");
  if (!Array.isArray(versions) || versions.length === 0 || versions.length > 128) {
    throw new Error("historical package versions are malformed");
  }
  let selected = 0;
  for (const raw of versions) {
    const version = record(raw, "historical package version");
    if (
      own(version, "protocol_version_major") === frozen.protocolVersionMajor &&
      own(version, "contract_version") === frozen.contractVersion &&
      prefixedHash(own(version, "contract_hash"), "contract-", "historical package contract hash") === frozen.contractHash
    ) {
      selected += 1;
    }
  }
  if (selected !== 1) throw new Error("historical package must contain one unambiguous frozen contract version");
  const disabled = own(packageRecord, "disabled_versions");
  if (!Array.isArray(disabled)) throw new Error("historical package disabled_versions is malformed");
  for (const raw of disabled) {
    const item = record(raw, "historical disabled package version");
    if (
      own(item, "protocol_version_major") === frozen.protocolVersionMajor &&
      own(item, "contract_version") === frozen.contractVersion
    ) {
      throw new Error("historical frozen contract version is disabled");
    }
  }

  const contractStored = storedValue(contractValue, "historical contract");
  exactOwnKeys(contractStored, ["Contract"], "historical contract stored value");
  const contract = record(own(contractStored, "Contract"), "historical Contract");
  if (prefixedHash(own(contract, "contract_package_hash"), "contract-package-", "historical contract package hash") !== frozen.packageHash) {
    throw new Error("historical contract points to another package");
  }
  if (prefixedHash(own(contract, "contract_wasm_hash"), "contract-wasm-", "historical contract Wasm hash") !== frozen.contractWasmStateHash) {
    throw new Error("historical contract Wasm state differs from frozen inventory");
  }
  const protocol = own(contract, "protocol_version");
  if (typeof protocol !== "string" || !protocol.startsWith(`${frozen.protocolVersionMajor}.`)) {
    throw new Error("historical contract protocol version differs from frozen inventory");
  }
  const entryPoints = own(contract, "entry_points");
  if (!Array.isArray(entryPoints) || entryPoints.filter((raw) => isRecord(raw) && own(raw, "name") === ENTRY_POINT).length !== 1) {
    throw new Error("historical contract does not expose one exact receipt entry point");
  }
}

function verifyHistoricalOdraReceiptArtifactWithInventory(
  input: unknown,
  inventoryBytes: Uint8Array,
  inventorySha256: string,
): HistoricalOdraReceiptFacts {
  const artifact = record(input, "historical Odra receipt artifact");
  if (!Object.hasOwn(artifact, "raw_rpc")) {
    throw new HistoricalOdraArtifactUnavailableError(
      "historical Odra raw evidence is unavailable: raw_rpc",
    );
  }
  if (isRecord(own(artifact, "raw_rpc"))) {
    const missing = RAW_RPC_FIELDS.filter(
      (field) => !Object.hasOwn(own(artifact, "raw_rpc") as Record<string, unknown>, field),
    );
    if (missing.length > 0) {
      throw new HistoricalOdraArtifactUnavailableError(
        `historical Odra raw evidence is unavailable: ${missing.join(",")}`,
      );
    }
  }
  exactOwnKeys(artifact, TOP_FIELDS, "historical Odra receipt artifact");
  if (own(artifact, "schema_version") !== SCHEMA_VERSION) throw new Error("historical receipt schema is unsupported");
  const proposalId = own(artifact, "proposal_id");
  if (typeof proposalId !== "string" || !PROPOSAL_ID.test(proposalId)) throw new Error("historical proposal_id is invalid");
  const generation = own(artifact, "generation");
  if (generation !== "v1" && generation !== "v2") throw new Error("historical generation must be v1 or v2");
  const capturedAt = strictUtc(own(artifact, "captured_at"), "historical captured_at");
  const sourceCommit = own(artifact, "source_commit");
  const deploymentCommit = own(artifact, "deployment_commit");
  if (typeof sourceCommit !== "string" || !GIT40.test(sourceCommit)) throw new Error("historical source_commit must be lowercase git40");
  if (typeof deploymentCommit !== "string" || !GIT40.test(deploymentCommit)) throw new Error("historical deployment_commit must be lowercase git40");
  sourceUrl(own(artifact, "source_url"), proposalId);
  if (own(artifact, "network") !== "casper-test") throw new Error("historical network must be casper-test");

  const frozen = parseTrustedInventory(
    own(artifact, "lineage_inventory"),
    generation,
    inventoryBytes,
    inventorySha256,
  );
  if (!frozen.combinedArtifactAvailable) {
    throw new HistoricalOdraArtifactUnavailableError(
      `historical ${generation} combined receipt-and-card-chain artifact is unavailable until its exact card chain is independently exported`,
    );
  }
  const identity = record(own(artifact, "contract_identity"), "historical contract identity");
  exactOwnKeys(identity, IDENTITY_FIELDS, "historical contract identity");
  if (
    hash32(own(identity, "package_hash"), "historical package hash") !== frozen.packageHash ||
    hash32(own(identity, "contract_hash"), "historical contract hash") !== frozen.contractHash ||
    hash32(own(identity, "contract_wasm_state_hash"), "historical Wasm state hash") !== frozen.contractWasmStateHash ||
    own(identity, "contract_version") !== frozen.contractVersion ||
    own(identity, "protocol_version_major") !== frozen.protocolVersionMajor ||
    own(identity, "entry_point") !== ENTRY_POINT ||
    own(identity, "session_variant") !== frozen.sessionVariant ||
    own(identity, "session_target_kind") !== frozen.sessionTargetKind ||
    hash32(own(identity, "session_target_hash"), "historical session target hash") !== frozen.sessionTargetHash ||
    own(identity, "session_version") !== frozen.sessionVersion
  ) {
    throw new Error("historical contract identity differs from frozen inventory");
  }

  const rawRpc = record(own(artifact, "raw_rpc"), "historical raw_rpc");
  exactOwnKeys(rawRpc, RAW_RPC_FIELDS, "historical raw_rpc");
  const deployTranscript = transcript(own(rawRpc, "deploy"), "historical deploy");
  const deployValue = exactRequest(
    deployTranscript,
    "info_get_deploy",
    { deploy_hash: frozen.deployHash },
    "historical deploy",
  );
  const returnedDeploy = record(own(deployValue, "deploy"), "historical returned deploy");
  const header = record(own(returnedDeploy, "header"), "historical returned deploy header");
  const initiator = own(header, "account");
  if (typeof initiator !== "string") throw new Error("historical deploy initiator is missing");
  const deploy = verifySignedDeployJson(returnedDeploy, {
    deployHash: frozen.deployHash,
    initiatorPublicKey: initiator,
    chainName: "casper-test",
    exactlyOneApproval: false,
  });
  const executionInfo = record(own(deployValue, "execution_info"), "historical execution_info");
  executionSucceeded(own(executionInfo, "execution_result"));
  const executionBlockHash = hash32(own(executionInfo, "block_hash"), "historical execution block hash");
  const executionBlockHeight = safeHeight(own(executionInfo, "block_height"), "historical execution block height");
  if (frozen.sessionVariant === "StoredContractByHash") {
    if (
      deploy.session.kind !== "StoredContractByHash" ||
      deploy.session.contractHash !== frozen.sessionTargetHash ||
      frozen.sessionTargetKind !== "contract" ||
      frozen.sessionTargetHash !== frozen.contractHash ||
      deploy.session.entryPoint !== ENTRY_POINT
    ) {
      throw new Error("historical v1 deploy must call the exact frozen receipt contract and entry point");
    }
  } else if (
    deploy.session.kind !== "StoredVersionedContractByHash" ||
    deploy.session.packageHash !== frozen.sessionTargetHash ||
    deploy.session.version !== frozen.sessionVersion ||
    frozen.sessionTargetKind !== "package" ||
    frozen.sessionTargetHash !== frozen.packageHash ||
    deploy.session.entryPoint !== ENTRY_POINT
  ) {
    throw new Error("historical v2 deploy must call the exact frozen receipt package version and entry point");
  }
  const argumentsByName = runtimeArgumentMap(deploy.session.args, frozen.argumentOrder, "historical receipt");
  for (const name of frozen.argumentOrder) {
    runtimeType(
      argumentsByName[name] as DeployRuntimeArgument,
      name,
      frozen.argumentTypes[name] as string,
    );
  }
  if (argumentsByName.proposal_id?.parsed !== proposalId) throw new Error("historical receipt proposal_id differs from artifact");
  if (argumentsByName.casper_network?.parsed !== "casper-test") throw new Error("historical receipt casper_network differs from artifact");
  const finalCardHash = hash32(
    String(argumentsByName.final_card_hash?.parsed).toLowerCase(),
    "historical receipt final_card_hash",
  );
  if (finalCardHash !== frozen.finalCardHash) {
    throw new Error("historical receipt final_card_hash differs from the selected frozen generation");
  }
  const cards = verifyCardChainArtifact(own(artifact, "card_chain"), { expectedFinalCardHash: finalCardHash });
  if (cards.proposalId !== proposalId) throw new Error("historical card chain proposal differs from receipt artifact");

  const blockTranscript = transcript(own(rawRpc, "canonical_block"), "historical canonical block");
  const blockValue = exactRequest(
    blockTranscript,
    "chain_get_block",
    { block_identifier: { Hash: executionBlockHash } },
    "historical canonical block",
  );
  const block = parseCanonicalBlock(blockValue, frozen.deployHash);
  if (block.blockHash !== executionBlockHash || block.blockHeight !== executionBlockHeight) {
    throw new Error("historical canonical block differs from deploy execution observation");
  }

  const stateTranscript = transcript(own(rawRpc, "state_root"), "historical state root");
  const stateValue = exactRequest(
    stateTranscript,
    "chain_get_state_root_hash",
    { block_identifier: { Hash: executionBlockHash } },
    "historical state root",
  );
  const observedStateRoot = hash32(own(stateValue, "state_root_hash"), "historical returned state root");
  if (observedStateRoot !== block.stateRootHash) throw new Error("historical state root differs from canonical block");

  const packageTranscript = transcript(own(rawRpc, "package"), "historical package");
  const packageValue = exactRequest(
    packageTranscript,
    "query_global_state",
    { state_identifier: { StateRootHash: observedStateRoot }, key: `hash-${frozen.packageHash}`, path: [] },
    "historical package",
  );
  const contractTranscript = transcript(own(rawRpc, "contract"), "historical contract");
  const contractValue = exactRequest(
    contractTranscript,
    "query_global_state",
    { state_identifier: { StateRootHash: observedStateRoot }, key: `hash-${frozen.contractHash}`, path: [] },
    "historical contract",
  );
  verifyPackageAndContract(packageValue, contractValue, frozen);

  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    proposalId,
    generation,
    deployHash: deploy.deployHash,
    blockHash: block.blockHash,
    blockHeight: block.blockHeight,
    stateRootHash: observedStateRoot,
    packageHash: frozen.packageHash,
    contractHash: frozen.contractHash,
    contractWasmStateHash: frozen.contractWasmStateHash,
    sessionVariant: frozen.sessionVariant,
    sessionTargetKind: frozen.sessionTargetKind,
    sessionTargetHash: frozen.sessionTargetHash,
    sessionVersion: frozen.sessionVersion,
    finalCardHash,
    receiptArgumentDigest: receiptArgumentDigest(deploy.session.args, frozen.argumentOrder),
    sourceCommit,
    deploymentCommit,
    capturedAt,
    sourceDeploymentEquivalence: "unproven",
    verificationScope: "artifact_transcript_consistency",
    observationSources: Object.freeze([]) as readonly [],
  });
}

/**
 * Verify a published historical receipt against the immutable inventory asset
 * packaged with this release. The caller cannot select another inventory.
 */
export function verifyHistoricalOdraReceiptArtifact(input: unknown): HistoricalOdraReceiptFacts {
  const releaseBytes = releaseInventoryBytes();
  return verifyHistoricalOdraReceiptArtifactWithInventory(input, releaseBytes, INVENTORY_SHA256);
}

/** @internal Test seam for deterministic offline vectors; not re-exported by the package root. */
export function __testOnlyVerifyHistoricalOdraReceiptArtifactWithInventory(
  input: unknown,
  inventoryBytes: Uint8Array,
  inventorySha256: string,
): HistoricalOdraReceiptFacts {
  return verifyHistoricalOdraReceiptArtifactWithInventory(input, inventoryBytes, inventorySha256);
}
