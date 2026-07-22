import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  DOMAINS,
  HEADER_SCHEMA,
  NATIVE_SCHEMA,
  blake2b256,
  concatBytes,
  hexBytes,
  isRecord,
  lengthPrefixed,
  parseUnsigned,
  toHex,
} from "../encoders.js";
import { canonicalTranscriptJson } from "./casper-state.js";
import {
  accountHashFromPublicKey,
  runtimeArgumentMap,
  verifyRuntimeArgumentPairs,
  verifySignedDeployJson,
  type DeployRuntimeArgument,
  type SignedDeployJsonFacts,
} from "./casper-deploy-json.js";
import { verifyNativeEnvelopeMaterialV3 } from "./v3.js";
import { verifyV3ReadbackArtifact } from "./v3-readback.js";

const HEX32 = /^[0-9a-f]{64}$/;
const GIT40 = /^[0-9a-f]{40}$/;
const USER_ERROR = /(?:User error|ApiError::User)[:( ]+([0-9]+)/;
const PACKAGE_KEY_NAME = "concordia_governance_receipt_v3";
const CALL_HEADER_SCHEMA = HEADER_SCHEMA.slice(3);
const INSTALL_ARGUMENT_NAMES = Object.freeze([
  "odra_cfg_package_hash_key_name",
  "odra_cfg_allow_key_override",
  "odra_cfg_is_upgradable",
  "odra_cfg_is_upgrade",
  "proposer",
  "finalizer",
  "signer_a",
  "signer_b",
  "signer_c",
  "threshold",
  "casper_chain_name",
  "installation_nonce",
]);
const STEP_BASE_FIELDS = Object.freeze([
  "name",
  "role",
  "custody",
  "entry_point",
  "expected",
  "expected_error",
  "deploy_hash",
  "deploy",
  "finality_transcript",
  "observed_outcome",
  "submission_state",
  "finality_block_evidence",
]);
const FINALITY_BLOCK_FIELDS = Object.freeze([
  "status",
  "block_hash",
  "block_height",
  "state_root_hash",
  "block_timestamp",
  "finalized_at",
  "observed_at",
  "deploy_hash",
  "corroboration_count",
  "success",
  "user_error",
  "node_observations",
  "endpoint_identities",
]);
const FINALITY_NODE_FIELDS = Object.freeze([
  "node_id",
  "node_url",
  "deploy_request",
  "deploy_response",
  "block_request",
  "block_response",
]);
const TRANSCRIPT_FIELDS = Object.freeze([
  "rpc_url_identity_or_node_id",
  "method",
  "params",
  "request",
  "response",
  "canonical_sha256",
]);

export type ExactEnvelopeV3Facts = Readonly<{
  schemaId: "concordia.v3-proof-verification.v1";
  network: "casper-test";
  packageHash: string;
  contractHash: string;
  deploymentDomain: string;
  proposalId: string;
  actionId: string;
  envelopeHash: string;
  observedBlockHash: string;
  observedBlockHeight: number;
  observedStateRootHash: string;
  finalizationBlockHash: string;
  finalizationBlockHeight: number;
  finalizationDeployHash: string;
  installDeployHash: string;
  installBlockHash: string;
  installBlockHeight: number;
  sourceCommit: string;
  deploymentCommit: string;
  contractStepOutcomes: Readonly<Record<string, Readonly<{
    success: boolean;
    userError: number | null;
    finalizedAt: string;
    observedAt: string;
  }>>>;
}>;

type DeploymentFacts = Readonly<{
  packageHash: string;
  contractHash: string;
  deploymentDomain: string;
  threshold: 2 | 3;
  roles: Readonly<Record<string, string>>;
  installDeployHash: string;
  installBlockHash: string;
  installBlockHeight: number;
  sourceCommit: string;
  deploymentCommit: string;
}>;

type RawStepOutcome = Readonly<{
  deployHash: string;
  success: boolean;
  userError: number | null;
  blockHash: string;
  blockHeight: number;
}>;

type StepOutcome = Readonly<{
  deployHash: string;
  success: boolean;
  userError: number | null;
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
  blockTimestamp: string;
  finalizedAt: string;
  observedAt: string;
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

function canonical(value: unknown, label: string): string {
  return canonicalTranscriptJson(value, label);
}

function equalCanonical(actual: unknown, expected: unknown, label: string): void {
  if (canonical(actual, `${label} actual`) !== canonical(expected, `${label} expected`)) {
    throw new Error(`${label} does not match independent recomputation`);
  }
}

function hash32(value: unknown, label: string, nonzero = true): string {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be canonical lowercase 32-byte hex`);
  }
  if (nonzero && value === "00".repeat(32)) throw new Error(`${label} cannot be zero`);
  return value;
}

function hash32Insensitive(value: unknown, label: string, nonzero = true): string {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be 32-byte hexadecimal`);
  }
  return hash32(value.toLowerCase(), label, nonzero);
}

function gitCommit(value: unknown, label: string): string {
  if (typeof value !== "string" || !GIT40.test(value)) throw new Error(`${label} must be a lowercase Git commit`);
  return value;
}

function height(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe u64`);
  }
  return value;
}

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function releaseUrl(relative: string): URL {
  return new URL(`../release/v3/${relative}`, import.meta.url);
}

function loadPackagedRelease(): Record<string, unknown> {
  const manifest = record(
    JSON.parse(readFileSync(releaseUrl("deployment.manifest.json"), "utf8")) as unknown,
    "packaged v3 deployment manifest",
  );
  const build = record(own(manifest, "build"), "packaged v3 build identity");
  const source = record(own(manifest, "source"), "packaged v3 source identity");
  const historical = record(own(manifest, "historical_isolation"), "packaged v3 historical identity");
  const assets: ReadonlyArray<readonly [string, unknown, Uint8Array]> = [
    ["packaged v3 Wasm", own(build, "wasm_sha256"), readFileSync(releaseUrl("wasm/GovernanceReceiptV3.wasm"))],
    ["packaged v3 schema", own(build, "schema_sha256"), readFileSync(releaseUrl("schema/governance_receiptv3_schema.json"))],
    ["packaged v3 lib.rs", own(source, "lib_rs_sha256"), readFileSync(releaseUrl("source/lib.rs"))],
    ["packaged v3 encoding.rs", own(source, "encoding_rs_sha256"), readFileSync(releaseUrl("source/encoding.rs"))],
    ["packaged v3 Cargo.lock", own(source, "cargo_lock_sha256"), readFileSync(releaseUrl("source/Cargo.lock"))],
    ["packaged historical inventory", own(historical, "manifest_sha256"), readFileSync(releaseUrl("source/HISTORICAL_ODRA_SHA256.txt"))],
  ];
  for (const [label, expected, bytes] of assets) {
    if (hash32(expected, `${label} SHA-256`, false) !== sha256(bytes)) {
      throw new Error(`${label} differs from the packaged release identity`);
    }
  }
  if (own(build, "wasm_size_bytes") !== assets[0]?.[2].length) {
    throw new Error("packaged v3 Wasm size differs from its release manifest");
  }
  return manifest;
}

function deploymentDomain(installationNonce: string): string {
  const nonce = hexBytes(hash32(installationNonce, "installation nonce"), 32);
  return toHex(
    blake2b256(
      concatBytes(
        DOMAINS.deployment,
        lengthPrefixed("casper-test"),
        lengthPrefixed(PACKAGE_KEY_NAME),
        nonce,
      ),
    ),
  );
}

function clValueEquals(argument: DeployRuntimeArgument, expected: unknown, label: string): void {
  if (argument.clType === "Bool") {
    const expectedParsed = expected === true ? "True" : expected === false ? "False" : null;
    if (expectedParsed === null || argument.parsed !== expectedParsed) throw new Error(`${label} differs from expected Bool`);
  } else if (argument.clType === "String") {
    if (typeof expected !== "string" || argument.parsed !== expected) throw new Error(`${label} differs from expected String`);
  } else if (argument.clType === "U8" || argument.clType === "U32" || argument.clType === "U64" || argument.clType === "U512") {
    const bits = argument.clType === "U8" ? 8 : argument.clType === "U32" ? 32 : argument.clType === "U64" ? 64 : 512;
    if (parseUnsigned(argument.parsed, bits) !== parseUnsigned(expected, bits)) throw new Error(`${label} differs from expected integer`);
  } else if (isRecord(argument.clType) && own(argument.clType, "ByteArray") === 32) {
    if (hash32Insensitive(argument.parsed, `${label} parsed ByteArray`) !== hash32(expected, `${label} expected ByteArray`)) {
      throw new Error(`${label} differs from expected ByteArray`);
    }
  } else {
    throw new Error(`${label} uses an unsupported CLType`);
  }
}

function validateStandardPayment(deploy: SignedDeployJsonFacts, expectedMotes: unknown, label: string): void {
  if (deploy.payment.kind !== "ModuleBytes" || deploy.payment.moduleBytes.length !== 0) {
    throw new Error(`${label} payment must be empty ModuleBytes`);
  }
  const args = runtimeArgumentMap(deploy.payment.args, ["amount"], `${label} payment`);
  const amount = args.amount;
  if (!amount || amount.clType !== "U512") throw new Error(`${label} payment amount must be U512`);
  clValueEquals(amount, expectedMotes, `${label} payment amount`);
}

function installerPackageNamedKey(
  storedValue: unknown,
  installerAccountHash: string,
): string {
  const stored = record(storedValue, "v3 installer account stored value");
  exactOwnKeys(stored, ["Account"], "v3 installer account stored value");
  const account = record(own(stored, "Account"), "v3 installer Account");
  const minimalFields = ["named_keys"];
  const fullFields = ["account_hash", "named_keys", "main_purse", "associated_keys", "action_thresholds"];
  const fields = Object.keys(account).sort();
  const isMinimal = equalStringSets(fields, minimalFields);
  const isFull = equalStringSets(fields, fullFields);
  if (!isMinimal && !isFull) {
    throw new Error("v3 installer Account fields do not match a supported Casper Account shape");
  }
  if (isFull) {
    const accountHash = String(own(account, "account_hash")).replace(/^account-hash-/, "");
    if (hash32Insensitive(accountHash, "v3 installer Account account_hash") !== installerAccountHash) {
      throw new Error("v3 installer Account account_hash mismatch");
    }
    if (!/^uref-[0-9a-f]{64}-[0-9]{3}$/.test(String(own(account, "main_purse")))) {
      throw new Error("v3 installer Account main_purse is invalid");
    }
    const associatedKeys = own(account, "associated_keys");
    if (!Array.isArray(associatedKeys)) throw new Error("v3 installer Account associated_keys is invalid");
    const associatedSeen = new Set<string>();
    for (const raw of associatedKeys) {
      const key = record(raw, "v3 installer Account associated key");
      exactOwnKeys(key, ["account_hash", "weight"], "v3 installer Account associated key");
      const keyHash = hash32Insensitive(
        String(own(key, "account_hash")).replace(/^account-hash-/, ""),
        "v3 installer Account associated account_hash",
      );
      if (associatedSeen.has(keyHash)) throw new Error("v3 installer Account has duplicate associated keys");
      associatedSeen.add(keyHash);
      parseUnsigned(own(key, "weight"), 8);
    }
    const thresholds = record(own(account, "action_thresholds"), "v3 installer Account action_thresholds");
    exactOwnKeys(thresholds, ["deployment", "key_management"], "v3 installer Account action_thresholds");
    parseUnsigned(own(thresholds, "deployment"), 8);
    parseUnsigned(own(thresholds, "key_management"), 8);
  }

  const namedKeys = own(account, "named_keys");
  if (!Array.isArray(namedKeys)) throw new Error("v3 installer Account named_keys must be an array");
  const names = new Set<string>();
  let targetKey: string | null = null;
  for (const raw of namedKeys) {
    const namedKey = record(raw, "v3 installer Account named key");
    exactOwnKeys(namedKey, ["name", "key"], "v3 installer Account named key");
    const name = own(namedKey, "name");
    const key = own(namedKey, "key");
    if (typeof name !== "string" || name.length === 0 || typeof key !== "string" || key.length === 0) {
      throw new Error("v3 installer Account named key name/key is invalid");
    }
    if (names.has(name)) throw new Error(`v3 installer Account has duplicate named key ${name}`);
    names.add(name);
    if (name === PACKAGE_KEY_NAME) targetKey = key;
  }
  if (targetKey === null) throw new Error("v3 installer package named key is missing");
  return targetKey;
}

function equalStringSets(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const expected = new Set(right);
  return left.every((value) => expected.has(value));
}

function exactRpc(value: unknown, method: string, label: string): Record<string, unknown> {
  const transcript = record(value, label);
  exactOwnKeys(transcript, ["request", "response"], label);
  const request = record(own(transcript, "request"), `${label} request`);
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], `${label} request`);
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== method) {
    throw new Error(`${label} request method is invalid`);
  }
  record(own(request, "params"), `${label} request params`);
  const response = record(own(transcript, "response"), `${label} response`);
  exactOwnKeys(response, ["jsonrpc", "id", "result"], `${label} response`);
  if (own(response, "jsonrpc") !== "2.0" || own(response, "id") !== own(request, "id")) {
    throw new Error(`${label} response identity mismatch`);
  }
  record(own(response, "result"), `${label} result`);
  return transcript;
}

function rpcStoredValue(value: Record<string, unknown>, label: string): Record<string, unknown> {
  const response = record(own(value, "response"), `${label} response`);
  const result = record(own(response, "result"), `${label} result`);
  return record(own(result, "stored_value"), `${label} stored value`);
}

function executionOutcome(value: unknown, expectedPublicKey: string, label: string): {
  success: boolean;
  userError: number | null;
} {
  const versioned = record(value, `${label} execution result`);
  exactOwnKeys(versioned, ["Version2"], `${label} execution result`);
  const outcome = record(own(versioned, "Version2"), `${label} Version2 outcome`);
  exactOwnKeys(
    outcome,
    ["initiator", "error_message", "current_price", "limit", "consumed", "cost", "refund", "transfers", "size_estimate", "effects"],
    `${label} Version2 outcome`,
  );
  equalCanonical(own(outcome, "initiator"), { PublicKey: expectedPublicKey }, `${label} initiator`);
  for (const name of ["limit", "consumed", "cost", "refund"] as const) {
    const raw = own(outcome, name);
    if (typeof raw !== "string" || !/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`${label} ${name} is invalid`);
  }
  if (typeof own(outcome, "current_price") !== "number" || !Number.isSafeInteger(own(outcome, "current_price"))) {
    throw new Error(`${label} current_price is invalid`);
  }
  if (typeof own(outcome, "size_estimate") !== "number" || !Number.isSafeInteger(own(outcome, "size_estimate"))) {
    throw new Error(`${label} size_estimate is invalid`);
  }
  if (!Array.isArray(own(outcome, "transfers")) || !Array.isArray(own(outcome, "effects"))) {
    throw new Error(`${label} transfers/effects must be lists`);
  }
  const error = own(outcome, "error_message");
  if (error === null) return { success: true, userError: null };
  if (typeof error !== "string") throw new Error(`${label} error_message is invalid`);
  const match = USER_ERROR.exec(error);
  return { success: false, userError: match ? Number(match[1]) : null };
}

function verifyDeployment(value: unknown): DeploymentFacts {
  const manifest = record(value, "v3 deployment manifest");
  const packaged = loadPackagedRelease();
  const dynamicFields = [
    "installer_public_key",
    "installer_account_hash",
    "threshold",
    "install_payment_motes",
    "install_ttl",
    "finality",
    "verified_install_deploy",
    "raw_rpc",
  ];
  if (Object.hasOwn(manifest, "two_node_finality")) dynamicFields.push("two_node_finality");
  exactOwnKeys(manifest, [...Object.keys(packaged), ...dynamicFields], "v3 deployment manifest");
  for (const name of ["schema_id", "network", "package_key_name", "contract_name", "locked_install", "toolchain", "build", "source", "historical_isolation", "abi", "note"] as const) {
    equalCanonical(own(manifest, name), own(packaged, name), `v3 deployment ${name}`);
  }
  if (own(manifest, "status") !== "finalized" || own(manifest, "network") !== "casper-test") {
    throw new Error("v3 deployment is not finalized on casper-test");
  }
  const sourceCommit = gitCommit(own(manifest, "source_commit"), "v3 deployment source_commit");
  const deploymentCommit = gitCommit(own(manifest, "deployment_commit"), "v3 deployment deployment_commit");
  const packageHash = hash32(own(manifest, "package_hash"), "v3 deployment package hash");
  const contractHash = hash32(own(manifest, "contract_hash"), "v3 deployment contract hash");
  if (own(manifest, "contract_version") !== 1) throw new Error("v3 deployment contract version must be 1");
  const installationNonce = hash32(own(manifest, "installation_nonce"), "v3 installation nonce");
  const derivedDomain = deploymentDomain(installationNonce);
  if (own(manifest, "deployment_domain") !== derivedDomain) throw new Error("v3 deployment domain derivation mismatch");
  const roleNames = ["proposer", "finalizer", "signer_a", "signer_b", "signer_c"];
  const rolesValue = record(own(manifest, "roles"), "v3 deployment roles");
  exactOwnKeys(rolesValue, roleNames, "v3 deployment roles");
  const roles: Record<string, string> = Object.create(null);
  for (const name of roleNames) {
    const role = record(own(rolesValue, name), `v3 deployment ${name}`);
    exactOwnKeys(role, ["kind", "account_hash"], `v3 deployment ${name}`);
    if (own(role, "kind") !== "Account") throw new Error(`v3 deployment ${name} must be account-only`);
    roles[name] = hash32(own(role, "account_hash"), `v3 deployment ${name} account hash`);
  }
  if (new Set(Object.values(roles)).size !== 5) throw new Error("v3 deployment governance roles collide");
  const threshold = own(manifest, "threshold");
  if (threshold !== 2 && threshold !== 3) throw new Error("v3 deployment threshold is invalid");
  const installerPublicKey = own(manifest, "installer_public_key");
  if (typeof installerPublicKey !== "string") throw new Error("v3 installer public key is missing");
  const installerHash = hash32(own(manifest, "installer_account_hash"), "v3 installer account hash");
  if (accountHashFromPublicKey(installerPublicKey) !== installerHash || Object.values(roles).includes(installerHash)) {
    throw new Error("v3 installer identity is invalid or collides with governance");
  }

  const raw = record(own(manifest, "raw_rpc"), "v3 deployment raw RPC");
  exactOwnKeys(raw, ["broadcast_response", "install_deploy", "state_root", "installer_account", "package", "contract"], "v3 deployment raw RPC");
  const installDeployHash = hash32Insensitive(own(manifest, "install_deploy_hash"), "v3 install deploy hash");
  const broadcast = record(own(raw, "broadcast_response"), "v3 install broadcast response");
  let installBroadcastWasReconciled = false;
  if (Object.hasOwn(broadcast, "jsonrpc")) {
    exactOwnKeys(broadcast, ["jsonrpc", "id", "result"], "v3 install broadcast response");
    if (own(broadcast, "jsonrpc") !== "2.0" || own(broadcast, "id") !== "concordia-v3-install") {
      throw new Error("v3 install broadcast response identity is invalid");
    }
    const broadcastResult = record(own(broadcast, "result"), "v3 install broadcast result");
    exactOwnKeys(broadcastResult, ["api_version", "deploy_hash"], "v3 install broadcast result");
    if (typeof own(broadcastResult, "api_version") !== "string" || (own(broadcastResult, "api_version") as string).length === 0) {
      throw new Error("v3 install broadcast api_version is invalid");
    }
    if (hash32Insensitive(own(broadcastResult, "deploy_hash"), "v3 install broadcast deploy hash") !== installDeployHash) {
      throw new Error("v3 install broadcast returned another deploy hash");
    }
  } else {
    exactOwnKeys(broadcast, ["status", "deploy_hash"], "v3 reconciled install broadcast evidence");
    if (
      own(broadcast, "status") !== "response_lost_reconciled_by_hash" ||
      hash32Insensitive(own(broadcast, "deploy_hash"), "v3 reconciled install deploy hash") !== installDeployHash
    ) {
      throw new Error("v3 reconciled install broadcast evidence is invalid");
    }
    installBroadcastWasReconciled = true;
  }
  const installRpc = exactRpc(own(raw, "install_deploy"), "info_get_deploy", "v3 install finality RPC");
  const installRequest = record(own(installRpc, "request"), "v3 install finality request");
  equalCanonical(own(installRequest, "params"), { deploy_hash: own(manifest, "install_deploy_hash") }, "v3 install finality params");
  const installResponse = record(own(installRpc, "response"), "v3 install finality response");
  const installResult = record(own(installResponse, "result"), "v3 install finality result");
  exactOwnKeys(installResult, ["api_version", "deploy", "execution_info"], "v3 install finality result");
  const installDeploy = verifySignedDeployJson(own(installResult, "deploy"), {
    deployHash: installDeployHash,
    initiatorPublicKey: installerPublicKey,
  });
  validateStandardPayment(installDeploy, own(manifest, "install_payment_motes"), "v3 install");
  if (installDeploy.session.kind !== "ModuleBytes") throw new Error("v3 install session must be ModuleBytes");
  const packagedWasm = readFileSync(releaseUrl("wasm/GovernanceReceiptV3.wasm"));
  if (!Buffer.from(installDeploy.session.moduleBytes).equals(packagedWasm)) {
    throw new Error("v3 install session Wasm differs from packaged release");
  }
  const installArgs = runtimeArgumentMap(installDeploy.session.args, INSTALL_ARGUMENT_NAMES, "v3 install");
  const installExpected: Record<string, unknown> = {
    odra_cfg_package_hash_key_name: PACKAGE_KEY_NAME,
    odra_cfg_allow_key_override: false,
    odra_cfg_is_upgradable: false,
    odra_cfg_is_upgrade: false,
    proposer: roles.proposer,
    finalizer: roles.finalizer,
    signer_a: roles.signer_a,
    signer_b: roles.signer_b,
    signer_c: roles.signer_c,
    threshold,
    casper_chain_name: "casper-test",
    installation_nonce: installationNonce,
  };
  for (const name of INSTALL_ARGUMENT_NAMES) {
    const argument = installArgs[name];
    if (!argument) throw new Error(`v3 install argument ${name} is missing`);
    clValueEquals(argument, installExpected[name], `v3 install ${name}`);
  }
  const executionInfo = record(own(installResult, "execution_info"), "v3 install execution_info");
  exactOwnKeys(executionInfo, ["block_hash", "block_height", "execution_result"], "v3 install execution_info");
  const installBlockHash = hash32Insensitive(own(executionInfo, "block_hash"), "v3 install execution block hash");
  const installBlockHeight = height(own(executionInfo, "block_height"), "v3 install execution block height");
  const installOutcome = executionOutcome(own(executionInfo, "execution_result"), installDeploy.initiatorPublicKey, "v3 install");
  if (!installOutcome.success) throw new Error("v3 install execution did not succeed");
  const verifiedInstall = record(own(manifest, "verified_install_deploy"), "v3 verified install summary");
  equalCanonical(
    verifiedInstall,
    {
      deploy_hash: installDeploy.deployHash,
      body_hash: installDeploy.bodyHash,
      wasm_sha256: sha256(installDeploy.session.moduleBytes),
      installer_public_key: installDeploy.initiatorPublicKey,
      locked_argument_names: [...INSTALL_ARGUMENT_NAMES],
      block_hash: installBlockHash,
      block_height: installBlockHeight,
    },
    "v3 verified install summary",
  );
  if (hash32Insensitive(own(manifest, "install_block_hash"), "v3 manifest install block hash") !== installBlockHash || own(manifest, "install_block_height") !== installBlockHeight) {
    throw new Error("v3 install block summary differs from raw finality");
  }
  const finality = record(own(manifest, "finality"), "v3 install finality summary");
  if (
    own(finality, "success") !== true ||
    own(finality, "status") !== "finalized" ||
    hash32Insensitive(own(finality, "deploy_hash"), "v3 install finality deploy hash") !== installDeployHash ||
    hash32Insensitive(own(finality, "block_hash"), "v3 install finality block hash") !== installBlockHash ||
    own(finality, "block_height") !== installBlockHeight
  ) {
    throw new Error("v3 install finality summary differs from raw finality evidence");
  }

  let installTwoNode: StepOutcome | null = null;
  if (Object.hasOwn(manifest, "two_node_finality")) {
    installTwoNode = verifyFinalityBlockEvidence(
      own(manifest, "two_node_finality"),
      {
        deployHash: installDeployHash,
        recordedDeploy: own(installResult, "deploy"),
        publicKey: installerPublicKey,
        expectedUserError: null,
        rawOutcome: Object.freeze({
          deployHash: installDeployHash,
          success: true,
          userError: null,
          blockHash: installBlockHash,
          blockHeight: installBlockHeight,
        }),
        label: "v3 install",
      },
    );
  } else if (installBroadcastWasReconciled) {
    throw new Error("v3 reconciled install broadcast requires two-node finality evidence");
  }

  const stateRootRpc = exactRpc(own(raw, "state_root"), "chain_get_state_root_hash", "v3 install state-root RPC");
  const stateRootRequest = record(own(stateRootRpc, "request"), "v3 install state-root request");
  equalCanonical(own(stateRootRequest, "params"), { block_identifier: { Hash: installBlockHash } }, "v3 install state-root params");
  const stateRootResponse = record(own(stateRootRpc, "response"), "v3 install state-root response");
  const stateRootResult = record(own(stateRootResponse, "result"), "v3 install state-root result");
  exactOwnKeys(stateRootResult, ["api_version", "state_root_hash"], "v3 install state-root result");
  if (typeof own(stateRootResult, "api_version") !== "string" || (own(stateRootResult, "api_version") as string).length === 0) {
    throw new Error("v3 install state-root api_version is invalid");
  }
  const stateRoot = hash32(own(stateRootResult, "state_root_hash"), "v3 install state root");
  if (own(manifest, "install_state_root_hash") !== stateRoot) throw new Error("v3 install state root summary mismatch");
  if (installTwoNode !== null && installTwoNode.stateRootHash !== stateRoot) {
    throw new Error("v3 install two-node finality state root disagrees with block-pinned state readback");
  }
  const stateIdentifier = { StateRootHash: stateRoot };
  const accountRpc = exactRpc(own(raw, "installer_account"), "query_global_state", "v3 installer account RPC");
  const accountRequest = record(own(accountRpc, "request"), "v3 installer account request");
  equalCanonical(own(accountRequest, "params"), { state_identifier: stateIdentifier, key: `account-hash-${installerHash}`, path: [] }, "v3 installer account params");
  const namedKey = installerPackageNamedKey(
    rpcStoredValue(accountRpc, "v3 installer account"),
    installerHash,
  );
  if (typeof namedKey !== "string" || hash32Insensitive(namedKey.replace(/^hash-/, ""), "v3 package named key") !== packageHash) {
    throw new Error("v3 installer package named key mismatch");
  }
  const packageRpc = exactRpc(own(raw, "package"), "query_global_state", "v3 package RPC");
  const packageRequest = record(own(packageRpc, "request"), "v3 package request");
  equalCanonical(own(packageRequest, "params"), { state_identifier: stateIdentifier, key: `hash-${packageHash}`, path: [] }, "v3 package query params");
  const packageRecord = record(own(rpcStoredValue(packageRpc, "v3 package"), "ContractPackage"), "v3 ContractPackage");
  exactOwnKeys(packageRecord, ["access_key", "versions", "disabled_versions", "groups", "lock_status"], "v3 ContractPackage");
  if (own(packageRecord, "lock_status") !== "Locked" || !Array.isArray(own(packageRecord, "disabled_versions")) || (own(packageRecord, "disabled_versions") as unknown[]).length !== 0) {
    throw new Error("v3 package is not permanently locked and single-version");
  }
  const versions = own(packageRecord, "versions");
  if (!Array.isArray(versions) || versions.length !== 1) throw new Error("v3 package must contain one contract version");
  const version = record(versions[0], "v3 package contract version");
  exactOwnKeys(version, ["protocol_version_major", "contract_version", "contract_hash"], "v3 package contract version");
  if (own(version, "protocol_version_major") !== 2 || own(version, "contract_version") !== 1 || hash32Insensitive(String(own(version, "contract_hash")).replace(/^contract-/, ""), "v3 package contract hash") !== contractHash) {
    throw new Error("v3 package contract version identity is invalid");
  }
  const groups = own(packageRecord, "groups");
  if (!Array.isArray(groups)) throw new Error("v3 package groups are invalid");
  for (const rawGroup of groups) {
    const group = record(rawGroup, "v3 package group");
    exactOwnKeys(group, ["group_name", "group_users"], "v3 package group");
    if (typeof own(group, "group_name") !== "string" || !Array.isArray(own(group, "group_users")) || (own(group, "group_users") as unknown[]).length !== 0) {
      throw new Error("v3 package exposes an upgrade-capable group");
    }
  }
  if (typeof own(packageRecord, "access_key") !== "string" || !(own(packageRecord, "access_key") as string).startsWith("uref-")) {
    throw new Error("v3 package access key is invalid");
  }
  const contractRpc = exactRpc(own(raw, "contract"), "query_global_state", "v3 contract RPC");
  const contractRequest = record(own(contractRpc, "request"), "v3 contract request");
  equalCanonical(own(contractRequest, "params"), { state_identifier: stateIdentifier, key: `hash-${contractHash}`, path: [] }, "v3 contract query params");
  const contractState = record(own(rpcStoredValue(contractRpc, "v3 contract"), "Contract"), "v3 contract state");
  const owner = own(contractState, "contract_package_hash");
  if (typeof owner !== "string" || hash32Insensitive(owner.replace(/^contract-package-/, ""), "v3 contract owner") !== packageHash) {
    throw new Error("v3 exact contract does not belong to its package");
  }
  return Object.freeze({
    packageHash,
    contractHash,
    deploymentDomain: derivedDomain,
    threshold,
    roles: Object.freeze(roles),
    installDeployHash,
    installBlockHash,
    installBlockHeight,
    sourceCommit,
    deploymentCommit,
  });
}

function transcript(value: unknown, method: string, label: string): Record<string, unknown> {
  const item = record(value, label);
  exactOwnKeys(item, TRANSCRIPT_FIELDS, label);
  if (own(item, "method") !== method) throw new Error(`${label} method mismatch`);
  const node = own(item, "rpc_url_identity_or_node_id");
  if (typeof node !== "string" || node.length === 0 || node.includes("@")) throw new Error(`${label} node identity is invalid`);
  const params = record(own(item, "params"), `${label} params`);
  const request = record(own(item, "request"), `${label} request`);
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], `${label} request`);
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== method) throw new Error(`${label} request is invalid`);
  equalCanonical(own(request, "params"), params, `${label} params`);
  const response = record(own(item, "response"), `${label} response`);
  if (own(response, "jsonrpc") !== "2.0" || own(response, "id") !== own(request, "id") || Object.hasOwn(response, "error") || !Object.hasOwn(response, "result")) {
    throw new Error(`${label} response is not successful JSON-RPC evidence`);
  }
  const digest = sha256(canonical({ request, response }, `${label} transcript`));
  if (hash32(own(item, "canonical_sha256"), `${label} checksum`, false) !== digest) throw new Error(`${label} checksum mismatch`);
  return item;
}

function simpleArgs(args: readonly DeployRuntimeArgument[], proposalId: string, envelopeHash: string, label: string): void {
  const mapped = runtimeArgumentMap(args, ["proposal_id", "envelope_hash"], label);
  clValueEquals(mapped.proposal_id as DeployRuntimeArgument, proposalId, `${label} proposal_id`);
  clValueEquals(mapped.envelope_hash as DeployRuntimeArgument, envelopeHash, `${label} envelope_hash`);
}

function exactFinalizeArgs(
  args: readonly DeployRuntimeArgument[],
  expected: Readonly<Record<string, unknown>>,
  mutated: boolean,
  label: string,
): void {
  const names = [...CALL_HEADER_SCHEMA.map(([name]) => name), ...NATIVE_SCHEMA.map(([name]) => name)];
  const mapped = runtimeArgumentMap(args, names, label);
  for (const name of names) {
    const argument = mapped[name];
    if (!argument) throw new Error(`${label} argument ${name} is missing`);
    const approvedAllocation = String(expected.approved_allocation_bps);
    const expectedValue = mutated && name === "approved_allocation_bps"
      ? (approvedAllocation === "3000" ? "2999" : "3000")
      : expected[name];
    clValueEquals(argument, expectedValue, `${label} ${name}`);
  }
}

function finalityOutcome(
  value: unknown,
  deployHash: string,
  recordedDeploy: unknown,
  publicKey: string,
  label: string,
): RawStepOutcome {
  const item = transcript(value, "info_get_deploy", `${label} finality`);
  const finalityParams = record(own(item, "params"), `${label} finality params`);
  exactOwnKeys(finalityParams, ["deploy_hash"], `${label} finality params`);
  if (hash32Insensitive(own(finalityParams, "deploy_hash"), `${label} finality deploy hash`) !== deployHash) {
    throw new Error(`${label} finality query targets another deploy`);
  }
  const response = record(own(item, "response"), `${label} finality response`);
  const result = record(own(response, "result"), `${label} finality result`);
  exactOwnKeys(result, ["api_version", "deploy", "execution_info"], `${label} finality result`);
  if (typeof own(result, "api_version") !== "string" || (own(result, "api_version") as string).length === 0) {
    throw new Error(`${label} finality api_version is invalid`);
  }
  const recorded = verifySignedDeployJson(recordedDeploy, { deployHash, initiatorPublicKey: publicKey });
  const returned = verifySignedDeployJson(own(result, "deploy"), { deployHash, initiatorPublicKey: publicKey });
  if (!Buffer.from(recorded.canonicalBytes).equals(Buffer.from(returned.canonicalBytes))) {
    throw new Error(`${label} node-returned deploy differs from broadcast deploy`);
  }
  const executionInfo = record(own(result, "execution_info"), `${label} execution_info`);
  exactOwnKeys(executionInfo, ["block_hash", "block_height", "execution_result"], `${label} execution_info`);
  const blockHash = hash32(own(executionInfo, "block_hash"), `${label} block hash`);
  const blockHeight = height(own(executionInfo, "block_height"), `${label} block height`);
  const outcome = executionOutcome(own(executionInfo, "execution_result"), publicKey.toLowerCase(), label);
  return Object.freeze({ deployHash, ...outcome, blockHash, blockHeight });
}

function utcTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be canonical UTC RFC3339`);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (match === null) throw new Error(`${label} must be canonical UTC RFC3339`);
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (
    year === undefined || month === undefined || day === undefined || hour === undefined ||
    minute === undefined || second === undefined || year < 1 || month < 1 || month > 12 ||
    hour > 23 || minute > 59 || second > 59
  ) {
    throw new Error(`${label} must be canonical UTC RFC3339`);
  }
  const parsed = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day || parsed.getUTCHours() !== hour ||
    parsed.getUTCMinutes() !== minute || parsed.getUTCSeconds() !== second
  ) {
    throw new Error(`${label} must be canonical UTC RFC3339`);
  }
  return value;
}

function rpcRequestResponse(
  requestValue: unknown,
  responseValue: unknown,
  method: string,
  params: Record<string, unknown>,
  label: string,
): Readonly<{ request: Record<string, unknown>; response: Record<string, unknown>; result: Record<string, unknown> }> {
  const request = record(requestValue, `${label} request`);
  exactOwnKeys(request, ["jsonrpc", "id", "method", "params"], `${label} request`);
  if (own(request, "jsonrpc") !== "2.0" || own(request, "method") !== method) {
    throw new Error(`${label} request method is invalid`);
  }
  equalCanonical(own(request, "params"), params, `${label} request params`);
  const response = record(responseValue, `${label} response`);
  exactOwnKeys(response, ["jsonrpc", "id", "result"], `${label} response`);
  if (own(response, "jsonrpc") !== "2.0" || own(response, "id") !== own(request, "id")) {
    throw new Error(`${label} response identity mismatch`);
  }
  const result = record(own(response, "result"), `${label} result`);
  return Object.freeze({ request, response, result });
}

function finalityNodeUrl(nodeIdValue: unknown, nodeUrlValue: unknown, label: string): string {
  if (typeof nodeIdValue !== "string" || nodeIdValue.length === 0 || typeof nodeUrlValue !== "string") {
    throw new Error(`${label} node identity is invalid`);
  }
  let parsed: URL;
  try {
    parsed = new URL(nodeUrlValue);
  } catch {
    throw new Error(`${label} node identity is invalid`);
  }
  if (
    parsed.protocol !== "https:" || parsed.hostname !== nodeIdValue || parsed.username !== "" ||
    parsed.password !== "" || parsed.pathname !== "/rpc" || parsed.search !== "" ||
    parsed.hash !== "" || (parsed.port !== "" && parsed.port !== "443") || parsed.href !== nodeUrlValue
  ) {
    throw new Error(`${label} node identity is invalid`);
  }
  return nodeUrlValue;
}

function canonicalBlockFacts(
  result: Record<string, unknown>,
  deployHash: string,
  label: string,
): Readonly<{ blockHash: string; blockHeight: number; stateRootHash: string; blockTimestamp: string }> {
  const wrapper = record(own(result, "block_with_signatures"), `${label} block wrapper`);
  exactOwnKeys(wrapper, ["block", "proofs"], `${label} block wrapper`);
  if (!Array.isArray(own(wrapper, "proofs"))) throw new Error(`${label} block proofs are invalid`);
  const versioned = record(own(wrapper, "block"), `${label} versioned block`);
  const versions = ["Version1", "Version2"].filter((name) => Object.hasOwn(versioned, name));
  if (versions.length !== 1 || Object.keys(versioned).length !== 1) {
    throw new Error(`${label} canonical block version is invalid`);
  }
  const version = versions[0] as "Version1" | "Version2";
  const block = record(own(versioned, version), `${label} canonical block`);
  const blockHash = hash32Insensitive(own(block, "hash"), `${label} block hash`);
  const header = record(own(block, "header"), `${label} block header`);
  const blockHeight = height(own(header, "height"), `${label} block height`);
  const stateRootHash = hash32Insensitive(own(header, "state_root_hash"), `${label} state root`);
  const blockTimestamp = utcTimestamp(own(header, "timestamp"), `${label} block timestamp`);
  const body = record(own(block, "body"), `${label} block body`);
  let matches = 0;
  if (version === "Version1") {
    for (const field of ["deploy_hashes", "transfer_hashes"] as const) {
      const values = own(body, field);
      if (!Array.isArray(values)) throw new Error(`${label} block ${field} is invalid`);
      matches += values.filter((value) =>
        hash32Insensitive(value, `${label} block transaction hash`) === deployHash
      ).length;
    }
  } else {
    const transactions = record(own(body, "transactions"), `${label} block transactions`);
    for (const rawItems of Object.values(transactions)) {
      if (!Array.isArray(rawItems)) throw new Error(`${label} block transaction lane is invalid`);
      for (const rawItem of rawItems) {
        const item = record(rawItem, `${label} block transaction`);
        if (Object.keys(item).length !== 1) throw new Error(`${label} block transaction is invalid`);
        const transactionHash = own(item, Object.keys(item)[0] as string);
        if (hash32Insensitive(transactionHash, `${label} block transaction hash`) === deployHash) matches += 1;
      }
    }
  }
  if (matches !== 1) throw new Error(`${label} deploy must appear exactly once in its canonical block`);
  return Object.freeze({ blockHash, blockHeight, stateRootHash, blockTimestamp });
}

function verifyFinalityBlockEvidence(
  value: unknown,
  options: Readonly<{
    deployHash: string;
    recordedDeploy: unknown;
    publicKey: string;
    expectedUserError: number | null;
    rawOutcome: RawStepOutcome;
    label: string;
  }>,
): StepOutcome {
  const { deployHash, recordedDeploy, publicKey, expectedUserError, rawOutcome, label } = options;
  const evidence = record(value, `${label} two-node block evidence`);
  exactOwnKeys(evidence, FINALITY_BLOCK_FIELDS, `${label} two-node block evidence`);
  if (own(evidence, "status") !== "finalized" || own(evidence, "corroboration_count") !== 2) {
    throw new Error(`${label} two-node block evidence is not finalized`);
  }
  const observations = own(evidence, "node_observations");
  if (!Array.isArray(observations) || observations.length !== 2) {
    throw new Error(`${label} requires exactly two node observations`);
  }
  const endpointIdentities = own(evidence, "endpoint_identities");
  if (!Array.isArray(endpointIdentities) || endpointIdentities.length !== 2) {
    throw new Error(`${label} endpoint identities are invalid`);
  }
  const recorded = verifySignedDeployJson(recordedDeploy, {
    deployHash,
    initiatorPublicKey: publicKey,
  });
  const nodeIds = new Set<string>();
  const nodeUrls: string[] = [];
  const facts: Array<Readonly<{
    blockHash: string;
    blockHeight: number;
    stateRootHash: string;
    blockTimestamp: string;
    success: boolean;
    userError: number | null;
  }>> = [];
  for (let index = 0; index < observations.length; index += 1) {
    const observation = record(observations[index], `${label} node observation ${index + 1}`);
    exactOwnKeys(observation, FINALITY_NODE_FIELDS, `${label} node observation ${index + 1}`);
    const nodeId = own(observation, "node_id");
    const nodeUrl = finalityNodeUrl(nodeId, own(observation, "node_url"), `${label} node observation ${index + 1}`);
    if (typeof nodeId !== "string" || nodeIds.has(nodeId)) throw new Error(`${label} node observations must be distinct`);
    nodeIds.add(nodeId);
    nodeUrls.push(nodeUrl);
    const deployPair = rpcRequestResponse(
      own(observation, "deploy_request"),
      own(observation, "deploy_response"),
      "info_get_deploy",
      { deploy_hash: deployHash },
      `${label} node observation ${index + 1} deploy`,
    );
    exactOwnKeys(deployPair.result, ["api_version", "deploy", "execution_info"], `${label} node deploy result`);
    const returned = verifySignedDeployJson(own(deployPair.result, "deploy"), {
      deployHash,
      initiatorPublicKey: publicKey,
    });
    if (!Buffer.from(recorded.canonicalBytes).equals(Buffer.from(returned.canonicalBytes))) {
      throw new Error(`${label} node-returned deploy differs from recorded deploy`);
    }
    const executionInfo = record(own(deployPair.result, "execution_info"), `${label} node execution_info`);
    exactOwnKeys(executionInfo, ["block_hash", "block_height", "execution_result"], `${label} node execution_info`);
    const executionBlockHash = hash32Insensitive(own(executionInfo, "block_hash"), `${label} node execution block hash`);
    const executionBlockHeight = height(own(executionInfo, "block_height"), `${label} node execution block height`);
    const outcome = executionOutcome(own(executionInfo, "execution_result"), publicKey.toLowerCase(), `${label} node outcome`);
    if (
      (expectedUserError === null && (!outcome.success || outcome.userError !== null)) ||
      (expectedUserError !== null && (outcome.success || outcome.userError !== expectedUserError))
    ) {
      throw new Error(`${label} node execution outcome differs from frozen expectation`);
    }
    const blockPair = rpcRequestResponse(
      own(observation, "block_request"),
      own(observation, "block_response"),
      "chain_get_block",
      { block_identifier: { Hash: executionBlockHash } },
      `${label} node observation ${index + 1} block`,
    );
    const block = canonicalBlockFacts(blockPair.result, deployHash, `${label} node observation ${index + 1}`);
    if (block.blockHash !== executionBlockHash || block.blockHeight !== executionBlockHeight) {
      throw new Error(`${label} node deploy finality and canonical block disagree`);
    }
    facts.push(Object.freeze({ ...block, ...outcome }));
  }
  equalCanonical(endpointIdentities, nodeUrls, `${label} endpoint identities`);
  equalCanonical(facts[1], facts[0], `${label} public RPC node facts`);
  const fact = facts[0] as (typeof facts)[number];
  const finalizedAt = utcTimestamp(own(evidence, "finalized_at"), `${label} finalized_at`);
  const observedAt = utcTimestamp(own(evidence, "observed_at"), `${label} observed_at`);
  if (Date.parse(observedAt) < Date.parse(finalizedAt)) {
    throw new Error(`${label} finality observation predates canonical finalization`);
  }
  const asserted = {
    block_hash: fact.blockHash,
    block_height: fact.blockHeight,
    state_root_hash: fact.stateRootHash,
    block_timestamp: fact.blockTimestamp,
    finalized_at: fact.blockTimestamp,
    deploy_hash: deployHash,
    success: fact.success,
    user_error: fact.userError,
  };
  for (const [field, expected] of Object.entries(asserted)) {
    if (own(evidence, field) !== expected) throw new Error(`${label} ${field} disagrees with raw node evidence`);
  }
  if (
    rawOutcome.blockHash !== fact.blockHash || rawOutcome.blockHeight !== fact.blockHeight ||
    rawOutcome.success !== fact.success || rawOutcome.userError !== fact.userError
  ) {
    throw new Error(`${label} two-node block evidence disagrees with raw finality`);
  }
  return Object.freeze({
    ...rawOutcome,
    stateRootHash: fact.stateRootHash,
    blockTimestamp: fact.blockTimestamp,
    finalizedAt,
    observedAt,
  });
}

function verifyLiveRun(
  value: unknown,
  prepared: Record<string, unknown>,
  input: Record<string, unknown>,
  readbackArtifact: unknown,
): Readonly<{
  packageHash: string;
  contractHash: string;
  roles: Readonly<Record<string, string>>;
  outcomes: Readonly<Record<string, StepOutcome>>;
}> {
  const run = record(value, "v3 live run");
  exactOwnKeys(run, ["schema_id", "status", "network", "package_hash", "contract_hash", "prepared", "role_accounts", "steps", "readback"], "v3 live run");
  if (own(run, "schema_id") !== "concordia.v3-live-proof-run.v1" || own(run, "status") !== "contract_sequence_verified" || own(run, "network") !== "casper-test") {
    throw new Error("v3 live run is not a complete casper-test sequence");
  }
  equalCanonical(own(run, "prepared"), prepared, "v3 live run prepared envelope");
  equalCanonical(own(run, "readback"), readbackArtifact, "v3 live run readback");
  const packageHash = hash32(own(run, "package_hash"), "v3 live run package hash");
  const contractHash = hash32(own(run, "contract_hash"), "v3 live run contract hash");
  const roleNames = ["proposer", "finalizer", "signer_a", "signer_b", "signer_c"];
  const roleAccounts = record(own(run, "role_accounts"), "v3 live run role accounts");
  exactOwnKeys(roleAccounts, roleNames, "v3 live run role accounts");
  const roles: Record<string, string> = Object.create(null);
  const publicKeys: Record<string, string> = Object.create(null);
  for (const name of roleNames) {
    const role = record(own(roleAccounts, name), `v3 live run ${name}`);
    exactOwnKeys(role, ["custody", "public_key", "account_hash"], `v3 live run ${name}`);
    if (own(role, "custody") !== "browser" && own(role, "custody") !== "server") throw new Error(`v3 live run ${name} custody is invalid`);
    if (typeof own(role, "public_key") !== "string") throw new Error(`v3 live run ${name} public key is invalid`);
    const publicKey = (own(role, "public_key") as string).toLowerCase();
    const accountHash = hash32(own(role, "account_hash"), `v3 live run ${name} account hash`);
    if (accountHashFromPublicKey(publicKey) !== accountHash) throw new Error(`v3 live run ${name} account hash derivation mismatch`);
    publicKeys[name] = publicKey;
    roles[name] = accountHash;
  }
  if (new Set(Object.values(roles)).size !== 5) throw new Error("v3 live run governance roles collide");
  const inputHeader = record(own(input, "header"), "v3 input header");
  const inputBody = record(own(input, "body"), "v3 input body");
  const finalizeValues: Record<string, unknown> = { ...inputHeader, ...inputBody };
  const proposalId = own(prepared, "proposal_id");
  const envelopeHash = own(prepared, "envelope_hash");
  if (typeof proposalId !== "string" || typeof envelopeHash !== "string") throw new Error("v3 prepared identifiers are missing");
  const specs = [
    ["propose_exact", "proposer", "propose_envelope", "success", null, "simple"],
    ["finalize_pre_quorum", "finalizer", "finalize_native_transfer", null, 8, "finalize"],
    ["approve_a", "signer_a", "approve_envelope", "success", null, "simple"],
    ["approve_b", "signer_b", "approve_envelope", "success", null, "simple"],
    ["finalize_mutated_3000_bps", "finalizer", "finalize_native_transfer", null, 10, "mutated"],
    ["finalize_exact", "finalizer", "finalize_native_transfer", "success", null, "finalize"],
    ["finalize_again", "finalizer", "finalize_native_transfer", null, 12, "finalize"],
  ] as const;
  const steps = own(run, "steps");
  if (!Array.isArray(steps) || steps.length !== specs.length) throw new Error("v3 live run must contain seven ordered steps");
  const outcomes: Record<string, StepOutcome> = Object.create(null);
  let previousBlockHeight = -1;
  let previousBlockHash: string | null = null;
  let previousObservedAt: string | null = null;
  for (let index = 0; index < specs.length; index += 1) {
    const spec = specs[index] as (typeof specs)[number];
    const [name, role, entryPoint, expectedLabel, expectedError, argKind] = spec;
    const step = record(steps[index], `v3 live step ${name}`);
    const hasBroadcastTranscript = Object.hasOwn(step, "broadcast_transcript");
    const hasBroadcastEvidence = Object.hasOwn(step, "broadcast_evidence");
    if (hasBroadcastTranscript === hasBroadcastEvidence) {
      throw new Error(`v3 live step ${name} must contain exactly one broadcast evidence form`);
    }
    exactOwnKeys(
      step,
      [...STEP_BASE_FIELDS, hasBroadcastTranscript ? "broadcast_transcript" : "broadcast_evidence"],
      `v3 live step ${name}`,
    );
    if (
      own(step, "name") !== name || own(step, "role") !== role || own(step, "entry_point") !== entryPoint ||
      own(step, "expected") !== expectedLabel || own(step, "expected_error") !== expectedError
    ) {
      throw new Error(`v3 live step ${name} differs from frozen choreography`);
    }
    const roleRecord = record(own(roleAccounts, role), `v3 live run ${role}`);
    if (own(step, "custody") !== own(roleRecord, "custody")) throw new Error(`v3 live step ${name} custody mismatch`);
    const deployHash = hash32Insensitive(own(step, "deploy_hash"), `v3 live step ${name} deploy hash`);
    const deploy = verifySignedDeployJson(own(step, "deploy"), { deployHash, initiatorPublicKey: publicKeys[role] as string });
    validateStandardPayment(deploy, "5000000000", `v3 live step ${name}`);
    if (deploy.session.kind !== "StoredContractByHash" || deploy.session.contractHash !== contractHash || deploy.session.entryPoint !== entryPoint) {
      throw new Error(`v3 live step ${name} does not call the exact contract/entry point`);
    }
    if (argKind === "simple") simpleArgs(deploy.session.args, proposalId, envelopeHash, `v3 live step ${name}`);
    else exactFinalizeArgs(deploy.session.args, finalizeValues, argKind === "mutated", `v3 live step ${name}`);
    if (own(step, "submission_state") !== "finalized") {
      throw new Error(`v3 live step ${name} durable submission state is not finalized`);
    }
    if (hasBroadcastTranscript) {
      const broadcast = transcript(own(step, "broadcast_transcript"), "account_put_deploy", `v3 live step ${name} broadcast`);
      equalCanonical(own(broadcast, "params"), { deploy: own(step, "deploy") }, `v3 live step ${name} broadcast params`);
      const broadcastResponse = record(own(broadcast, "response"), `v3 live step ${name} broadcast response`);
      const broadcastResult = record(own(broadcastResponse, "result"), `v3 live step ${name} broadcast result`);
      exactOwnKeys(broadcastResult, ["api_version", "deploy_hash"], `v3 live step ${name} broadcast result`);
      if (hash32Insensitive(own(broadcastResult, "deploy_hash"), `v3 live step ${name} broadcast hash`) !== deployHash) {
        throw new Error(`v3 live step ${name} broadcast hash mismatch`);
      }
    } else {
      const reconciled = record(own(step, "broadcast_evidence"), `v3 live step ${name} reconciled broadcast evidence`);
      exactOwnKeys(reconciled, ["status", "deploy_hash"], `v3 live step ${name} reconciled broadcast evidence`);
      if (
        own(reconciled, "status") !== "response_lost_reconciled_by_hash" ||
        hash32Insensitive(own(reconciled, "deploy_hash"), `v3 live step ${name} reconciled deploy hash`) !== deployHash
      ) {
        throw new Error(`v3 live step ${name} reconciled broadcast evidence is invalid`);
      }
    }
    const rawOutcome = finalityOutcome(own(step, "finality_transcript"), deployHash, own(step, "deploy"), publicKeys[role] as string, `v3 live step ${name}`);
    const outcome = verifyFinalityBlockEvidence(
      own(step, "finality_block_evidence"),
      {
        deployHash,
        recordedDeploy: own(step, "deploy"),
        publicKey: publicKeys[role] as string,
        expectedUserError: expectedError,
        rawOutcome,
        label: `v3 live step ${name}`,
      },
    );
    if (outcome.blockHeight < previousBlockHeight) {
      throw new Error(`v3 live step ${name} block height is nonmonotonic`);
    }
    if (
      outcome.blockHeight === previousBlockHeight &&
      previousBlockHash !== null &&
      outcome.blockHash !== previousBlockHash
    ) {
      throw new Error(`v3 live step ${name} conflicts with another block at the same height`);
    }
    if (previousObservedAt !== null && Date.parse(outcome.observedAt) < Date.parse(previousObservedAt)) {
      throw new Error(`v3 live step ${name} finality observation chronology predates the preceding step`);
    }
    previousBlockHeight = outcome.blockHeight;
    previousBlockHash = outcome.blockHash;
    previousObservedAt = outcome.observedAt;
    if ((expectedError === null && !outcome.success) || (expectedError !== null && (outcome.success || outcome.userError !== expectedError))) {
      throw new Error(`v3 live step ${name} raw finality differs from expected outcome`);
    }
    equalCanonical(own(step, "observed_outcome"), { success: outcome.success, user_error: outcome.userError }, `v3 live step ${name} observed outcome`);
    outcomes[name] = outcome;
  }
  return Object.freeze({ packageHash, contractHash, roles: Object.freeze(roles), outcomes: Object.freeze(outcomes) });
}

function verifyPrepared(
  input: Record<string, unknown>,
  preparedValue: unknown,
): Readonly<{ proposalId: string; actionId: string; envelopeHash: string; deploymentDomain: string }> {
  exactOwnKeys(input, ["schema_id", "action", "header", "body"], "v3 typed input");
  if (own(input, "schema_id") !== "concordia.exact-envelope-v3.input.v1" || own(input, "action") !== "NativeTransferV1") {
    throw new Error("v3 typed input schema/action is unsupported");
  }
  const header = record(own(input, "header"), "v3 typed input header");
  const body = record(own(input, "body"), "v3 typed input body");
  const material = verifyNativeEnvelopeMaterialV3({ header, body });
  const prepared = record(preparedValue, "v3 prepared envelope");
  exactOwnKeys(
    prepared,
    ["schema_id", "action", "entry_point", "proposal_id", "action_id", "transfer_id", "envelope_hash", "canonical", "runtime_args"],
    "v3 prepared envelope",
  );
  if (
    own(prepared, "schema_id") !== "concordia.exact-envelope-v3.prepared.v1" ||
    own(prepared, "action") !== "NativeTransferV1" ||
    own(prepared, "entry_point") !== "finalize_native_transfer" ||
    own(prepared, "proposal_id") !== own(header, "proposal_id") ||
    own(prepared, "action_id") !== material.actionId ||
    String(own(prepared, "transfer_id")) !== material.transferId ||
    own(prepared, "envelope_hash") !== material.envelopeHash
  ) {
    throw new Error("v3 prepared identifiers differ from typed recomputation");
  }
  const canonicalMaterial = record(own(prepared, "canonical"), "v3 prepared canonical material");
  exactOwnKeys(canonicalMaterial, ["header_hex", "body_hex", "action_core_hex"], "v3 prepared canonical material");
  equalCanonical(canonicalMaterial, { header_hex: material.headerHex, body_hex: material.bodyHex, action_core_hex: material.actionCoreHex }, "v3 prepared canonical material");
  const runtimeArgs = own(prepared, "runtime_args");
  if (!Array.isArray(runtimeArgs)) throw new Error("v3 prepared runtime_args must be a list");
  const names = [...CALL_HEADER_SCHEMA.map(([name]) => name), ...NATIVE_SCHEMA.map(([name]) => name)];
  if (runtimeArgs.length !== names.length) throw new Error("v3 prepared runtime_args length is invalid");
  const pairs = runtimeArgs.map((value, index) => {
    const name = names[index] as string;
    const item = record(value, `v3 prepared runtime arg ${name}`);
    exactOwnKeys(item, ["name", "cl_type", "bytes", "parsed"], `v3 prepared runtime arg ${name}`);
    if (own(item, "name") !== name) throw new Error(`v3 prepared runtime arg ${name} order mismatch`);
    return [name, { cl_type: own(item, "cl_type"), bytes: own(item, "bytes"), parsed: own(item, "parsed") }];
  });
  const verifiedArgs = verifyRuntimeArgumentPairs(pairs, names, "v3 prepared runtime args");
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index] as string;
    const expectedValue = Object.hasOwn(header, name) ? own(header, name) : own(body, name);
    clValueEquals(verifiedArgs[name] as DeployRuntimeArgument, expectedValue, `v3 prepared runtime arg ${name}`);
  }
  return Object.freeze({
    proposalId: own(header, "proposal_id") as string,
    actionId: material.actionId,
    envelopeHash: material.envelopeHash,
    deploymentDomain: hash32(own(header, "deployment_domain"), "v3 typed deployment domain"),
  });
}

export function verifyExactEnvelopeV3Artifact(input: unknown): ExactEnvelopeV3Facts {
  const proof = record(input, "exact-envelope v3 proof");
  exactOwnKeys(proof, ["schema_id", "deployment", "input", "prepared", "run", "readback"], "exact-envelope v3 proof");
  if (own(proof, "schema_id") !== "concordia.v3-proof.v1") throw new Error("exact-envelope v3 proof schema is unsupported");
  const deployment = verifyDeployment(own(proof, "deployment"));
  const typedInput = record(own(proof, "input"), "v3 typed input");
  const prepared = record(own(proof, "prepared"), "v3 prepared envelope");
  const preparedFacts = verifyPrepared(typedInput, prepared);
  const run = verifyLiveRun(own(proof, "run"), prepared, typedInput, own(proof, "readback"));
  const readback = verifyV3ReadbackArtifact(own(proof, "readback"));
  if (
    readback.proposalId !== preparedFacts.proposalId ||
    readback.actionId !== preparedFacts.actionId ||
    readback.proposedEnvelope !== preparedFacts.envelopeHash ||
    readback.finalizedEnvelope !== preparedFacts.envelopeHash ||
    readback.deploymentDomain !== preparedFacts.deploymentDomain ||
    run.packageHash !== readback.packageHash ||
    run.contractHash !== readback.contractHash ||
    deployment.packageHash !== readback.packageHash ||
    deployment.contractHash !== readback.contractHash ||
    deployment.deploymentDomain !== readback.deploymentDomain ||
    deployment.threshold !== readback.threshold
  ) {
    throw new Error("exact-envelope v3 proof identities disagree across typed input, deployment, run and readback");
  }
  const readbackRoles: Record<string, string> = {
    proposer: readback.proposer,
    finalizer: readback.finalizer,
    signer_a: readback.signers[0],
    signer_b: readback.signers[1],
    signer_c: readback.signers[2],
  };
  equalCanonical(deployment.roles, readbackRoles, "v3 deployment/readback roles");
  equalCanonical(run.roles, readbackRoles, "v3 run/readback roles");
  const finalization = run.outcomes.finalize_exact;
  if (!finalization?.success) throw new Error("v3 exact finalization outcome is missing");
  if (Object.values(run.outcomes).some((outcome) => outcome.blockHeight <= deployment.installBlockHeight)) {
    throw new Error("v3 contract choreography does not occur after the verified contract installation");
  }
  if (readback.observedBlockHeight < finalization.blockHeight) {
    throw new Error("v3 chain readback predates the exact finalization block");
  }
  if (
    readback.observedBlockHeight === finalization.blockHeight &&
    readback.observedBlockHash !== finalization.blockHash
  ) {
    throw new Error("v3 chain readback conflicts with the exact finalization block at the same height");
  }
  const publicOutcomes: Record<string, Readonly<{
    success: boolean;
    userError: number | null;
    finalizedAt: string;
    observedAt: string;
  }>> = Object.create(null);
  for (const [name, outcome] of Object.entries(run.outcomes)) {
    publicOutcomes[name] = Object.freeze({
      success: outcome.success,
      userError: outcome.userError,
      finalizedAt: outcome.finalizedAt,
      observedAt: outcome.observedAt,
    });
  }
  return Object.freeze({
    schemaId: "concordia.v3-proof-verification.v1",
    network: "casper-test",
    packageHash: readback.packageHash,
    contractHash: readback.contractHash,
    deploymentDomain: readback.deploymentDomain,
    proposalId: readback.proposalId,
    actionId: preparedFacts.actionId,
    envelopeHash: preparedFacts.envelopeHash,
    observedBlockHash: readback.observedBlockHash,
    observedBlockHeight: readback.observedBlockHeight,
    observedStateRootHash: readback.observedStateRootHash,
    finalizationBlockHash: finalization.blockHash,
    finalizationBlockHeight: finalization.blockHeight,
    finalizationDeployHash: finalization.deployHash,
    installDeployHash: deployment.installDeployHash,
    installBlockHash: deployment.installBlockHash,
    installBlockHeight: deployment.installBlockHeight,
    sourceCommit: deployment.sourceCommit,
    deploymentCommit: deployment.deploymentCommit,
    contractStepOutcomes: Object.freeze(publicOutcomes),
  });
}
