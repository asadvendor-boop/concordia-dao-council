import { createHash } from "node:crypto";

import { isRecord, parseUnsigned } from "../encoders.js";
import {
  canonicalTranscriptJson,
  verifyAccountBalanceAtBlock,
  type CasperAccountBalanceInput,
} from "./casper-state.js";
import {
  verifyCorroboratedNativeTransfer,
  type CorroboratedNativeTransferFacts,
} from "./multi-node-finality.js";
import type { NativeFinalityInput } from "./native-finality.js";
import { verifyNoDuplicateNativeTransfer } from "./native-transfer-scan.js";
import { verifyPostTransferBalance } from "./post-transfer.js";
import { verifyNativeEnvelopeMaterialV3 } from "./v3.js";

const HEX32 = /^[0-9a-f]{64}$/;
const GIT40 = /^[0-9a-f]{40}$/;
const RFC3339_UTC =
  /^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})(?:\.(?<fraction>[0-9]{1,9}))?Z$/;
const VERIFICATION_SCOPE =
  "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified";

const OUTER_FIELDS = Object.freeze([
  "schema_version",
  "captured_at",
  "source_commit",
  "deployment_commit",
  "release_identity",
  "authorization",
  "executor_journal",
  "finality",
  "balance_evidence",
  "bounded_transfer_scan",
  "artifact_sha256_scope",
]);

const BALANCE_FIELDS = Object.freeze([
  "status_request",
  "status",
  "block_request",
  "block",
  "balance_request",
  "balance_response",
]);

const SNAPSHOT_FIELDS = Object.freeze([
  "schema_id",
  "network",
  "source_account_hash",
  "expected_balance_motes",
  "observations",
]);

const SNAPSHOT_OBSERVATION_FIELDS = Object.freeze([
  "node_url",
  "captured_at",
  "status_request",
  "status_response",
  "block_request",
  "block_response",
  "balance_request",
  "balance_response",
]);

export type NativeTreasuryExecutionFacts = Readonly<{
  schemaVersion: "concordia.native_treasury_execution.v1";
  capturedAt: string;
  sourceCommit: string;
  deploymentCommit: string;
  network: "casper-test";
  packageHash: string;
  contractHash: string;
  deploymentDomain: string;
  sourceSha256: string;
  wasmSha256: string;
  generatedSchemaSha256: string;
  proposalId: string;
  actionId: string;
  envelopeHash: string;
  sourceAccountHash: string;
  recipientAccountHash: string;
  amountMotes: string;
  transferId: string;
  treasurySnapshotBalanceMotes: string;
  approvedAllocationBps: string;
  snapshotBlockHash: string;
  snapshotBlockHeight: number;
  snapshotStateRootHash: string;
  nativeDeployHash: string;
  nativeBlockHash: string;
  nativeBlockHeight: number;
  nativeStateRootHash: string;
  gasMotes: string;
  authorizationBlockHeight: number;
  authorizationBlockHash: string;
  observedThroughBlockHeight: number;
  observedThroughBlockHash: string;
  snapshotObservationCount: 2;
  nodeObservationCount: number;
  verificationScope: typeof VERIFICATION_SCOPE;
  executionProofSha256: string;
  v3Readback: unknown;
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

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be text`);
  return value;
}

function hash32(value: unknown, label: string, nonzero = false): string {
  if (typeof value !== "string" || !HEX32.test(value) || (nonzero && value === "00".repeat(32))) {
    throw new Error(`${label} must be canonical nonzero lowercase 32-byte hex`);
  }
  return value;
}

function gitCommit(value: unknown, label: string): string {
  if (typeof value !== "string" || !GIT40.test(value)) {
    throw new Error(`${label} must be a lowercase 40-character Git commit`);
  }
  return value;
}

function height(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe u64`);
  }
  return value;
}

function canonicalUtc(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be canonical UTC RFC3339`);
  const match = RFC3339_UTC.exec(value);
  if (match?.groups === undefined) throw new Error(`${label} must be canonical UTC RFC3339`);
  const year = Number(match.groups.year);
  const month = Number(match.groups.month);
  const day = Number(match.groups.day);
  const hour = Number(match.groups.hour);
  const minute = Number(match.groups.minute);
  const second = Number(match.groups.second);
  if (year === 0 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
    throw new Error(`${label} must be canonical UTC RFC3339`);
  }
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  ) {
    throw new Error(`${label} must be canonical UTC RFC3339`);
  }
  return value;
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "ascii").digest("hex");
}

function sha256HexBytes(value: string, label: string): string {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error(`${label} must be canonical hex bytes`);
  return createHash("sha256").update(Buffer.from(value, "hex")).digest("hex");
}

function exactBalanceBundle(value: unknown, label: string): Record<string, unknown> {
  const bundle = record(value, label);
  exactOwnKeys(bundle, BALANCE_FIELDS, label);
  return bundle;
}

function publicSnapshotNodeUrl(value: unknown): Readonly<{ url: string; origin: string }> {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("treasury snapshot node URL must be canonical public DNS HTTPS /rpc");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("treasury snapshot node URL must be canonical public DNS HTTPS /rpc");
  }
  const hostname = parsed.hostname.toLowerCase();
  const labels = hostname.split(".");
  const canonicalDnsName =
    hostname.length <= 253 &&
    labels.length >= 2 &&
    labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
    /[a-z]/.test(labels.at(-1) ?? "");
  const literalAddress =
    /^\[[0-9a-f:.]+\]$/.test(hostname) || /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  const localName =
    hostname === "localhost" ||
    hostname === "localhost.localdomain" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local");
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/rpc" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.port !== "" ||
    hostname.length === 0 ||
    !hostname.includes(".") ||
    hostname.endsWith(".") ||
    !canonicalDnsName ||
    literalAddress ||
    localName ||
    parsed.href !== value
  ) {
    throw new Error("treasury snapshot node URL must be canonical public DNS HTTPS /rpc");
  }
  return Object.freeze({ url: value, origin: parsed.origin });
}

function snapshotObservationBundle(
  value: unknown,
  index: number,
): Readonly<{ bundle: Record<string, unknown>; origin: string }> {
  const label = `treasury snapshot observation ${index + 1}`;
  const observation = record(value, label);
  exactOwnKeys(observation, SNAPSHOT_OBSERVATION_FIELDS, label);
  const node = publicSnapshotNodeUrl(own(observation, "node_url"));
  canonicalUtc(own(observation, "captured_at"), `${label} captured_at`);
  return Object.freeze({
    origin: node.origin,
    bundle: {
      status_request: own(observation, "status_request"),
      status: own(observation, "status_response"),
      block_request: own(observation, "block_request"),
      block: own(observation, "block_response"),
      balance_request: own(observation, "balance_request"),
      balance_response: own(observation, "balance_response"),
    },
  });
}

function verifyTreasurySnapshot(
  value: unknown,
  expectedSha256: unknown,
  expectation: Readonly<{
    accountHash: string;
    blockHash: string;
    blockHeight: number;
    balanceMotes: string;
  }>,
): Readonly<{
  primaryBundle: Record<string, unknown>;
  stateRootHash: string;
  observationCount: 2;
}> {
  const snapshot = record(value, "treasury snapshot");
  exactOwnKeys(snapshot, SNAPSHOT_FIELDS, "treasury snapshot");
  if (own(snapshot, "schema_id") !== "concordia.native-treasury-snapshot.v1") {
    throw new Error("treasury snapshot schema is unsupported");
  }
  if (
    own(snapshot, "network") !== "casper-test" ||
    own(snapshot, "source_account_hash") !== expectation.accountHash ||
    typeof own(snapshot, "expected_balance_motes") !== "string" ||
    own(snapshot, "expected_balance_motes") !== expectation.balanceMotes
  ) {
    throw new Error("treasury snapshot identity differs from the typed action");
  }
  const observations = own(snapshot, "observations");
  if (!Array.isArray(observations) || observations.length !== 2) {
    throw new Error("treasury snapshot requires exactly two node observations");
  }
  const parsed = observations.map((observation, index) =>
    snapshotObservationBundle(observation, index),
  );
  const first = parsed[0];
  const second = parsed[1];
  if (first === undefined || second === undefined) {
    throw new Error("treasury snapshot requires exactly two node observations");
  }
  if (first.origin === second.origin) {
    throw new Error("treasury snapshot nodes must be distinct");
  }
  const firstRoot = stateRootFromBalanceRequest(first.bundle, "treasury snapshot observation 1");
  const secondRoot = stateRootFromBalanceRequest(second.bundle, "treasury snapshot observation 2");
  const firstFacts = verifyAccountBalanceAtBlock(
    balanceInput(first.bundle, {
      ...expectation,
      stateRootHash: firstRoot,
    }),
  );
  const secondFacts = verifyAccountBalanceAtBlock(
    balanceInput(second.bundle, {
      ...expectation,
      stateRootHash: secondRoot,
    }),
  );
  const agreed =
    firstFacts.network === secondFacts.network &&
    firstFacts.accountHash === secondFacts.accountHash &&
    firstFacts.blockHash === secondFacts.blockHash &&
    firstFacts.blockHeight === secondFacts.blockHeight &&
    firstFacts.stateRootHash === secondFacts.stateRootHash &&
    firstFacts.balanceMotes === secondFacts.balanceMotes;
  if (!agreed) throw new Error("treasury snapshot node observations do not agree");
  const snapshotSha256 = hash32(expectedSha256, "treasury snapshot SHA-256", true);
  if (sha256Text(canonicalTranscriptJson(snapshot, "treasury snapshot")) !== snapshotSha256) {
    throw new Error("treasury snapshot SHA-256 does not match both observations");
  }
  return Object.freeze({
    primaryBundle: first.bundle,
    stateRootHash: firstFacts.stateRootHash,
    observationCount: 2,
  });
}

function stateRootFromBalanceRequest(bundle: Record<string, unknown>, label: string): string {
  const request = record(own(bundle, "balance_request"), `${label} balance request`);
  const params = record(own(request, "params"), `${label} balance request params`);
  const state = record(own(params, "state_identifier"), `${label} state identifier`);
  exactOwnKeys(state, ["StateRootHash"], `${label} state identifier`);
  return hash32(own(state, "StateRootHash"), `${label} state root`, true);
}

function balanceInput(
  bundle: Record<string, unknown>,
  expectation: Readonly<{
    accountHash: string;
    blockHash: string;
    blockHeight: number;
    stateRootHash: string;
    balanceMotes?: string;
  }>,
): CasperAccountBalanceInput {
  return {
    chainStatusRequest: own(bundle, "status_request"),
    chainStatusPayload: own(bundle, "status"),
    canonicalBlockRequest: own(bundle, "block_request"),
    canonicalBlockPayload: own(bundle, "block"),
    balanceRequest: own(bundle, "balance_request"),
    balanceResponse: own(bundle, "balance_response"),
    expectedAccountHash: expectation.accountHash,
    expectedBlockHash: expectation.blockHash,
    expectedBlockHeight: expectation.blockHeight,
    expectedStateRootHash: expectation.stateRootHash,
    ...(expectation.balanceMotes === undefined
      ? {}
      : { expectedBalanceMotes: expectation.balanceMotes }),
  };
}

function firstNodeFinality(
  nodeObservations: readonly unknown[],
  requestedDeployHash: string,
  signedDeploy: NativeFinalityInput["signedDeploy"],
): NativeFinalityInput {
  const first = record(nodeObservations[0], "first node observation");
  return {
    requestedDeployHash,
    rpcPayload: own(first, "transaction_response"),
    canonicalBlockPayload: own(first, "canonical_block_response"),
    signedDeploy,
  };
}

function compareFinalitySummary(
  summary: Record<string, unknown>,
  finality: CorroboratedNativeTransferFacts,
): void {
  exactOwnKeys(
    summary,
    [
      "deploy_hash",
      "block_hash",
      "block_height",
      "state_root_hash",
      "execution_result_kind",
      "gas_motes",
      "corroboration_count",
    ],
    "finality facts",
  );
  const expected: Record<string, unknown> = {
    deploy_hash: finality.deployHash,
    block_hash: finality.blockHash,
    block_height: finality.blockHeight,
    state_root_hash: finality.stateRootHash,
    execution_result_kind: finality.executionResultKind,
    gas_motes: finality.gasMotes,
    corroboration_count: finality.corroborationCount,
  };
  for (const [name, value] of Object.entries(expected)) {
    if (own(summary, name) !== value) throw new Error(`finality facts ${name} does not match raw evidence`);
  }
}

export function verifyNativeTreasuryExecutionArtifact(
  input: unknown,
): NativeTreasuryExecutionFacts {
  const artifact = record(input, "native treasury artifact");
  exactOwnKeys(artifact, OUTER_FIELDS, "native treasury artifact");
  if (own(artifact, "schema_version") !== "concordia.native_treasury_execution.v1") {
    throw new Error("native treasury artifact schema_version is unsupported");
  }
  if (own(artifact, "artifact_sha256_scope") !== "canonical_json_without_release_manifest") {
    throw new Error("native treasury artifact SHA-256 scope is unsupported");
  }
  const capturedAt = canonicalUtc(own(artifact, "captured_at"), "captured_at");
  const sourceCommit = gitCommit(own(artifact, "source_commit"), "source_commit");
  const deploymentCommit = gitCommit(own(artifact, "deployment_commit"), "deployment_commit");

  const release = record(own(artifact, "release_identity"), "release identity");
  exactOwnKeys(
    release,
    [
      "network",
      "package_hash",
      "contract_hash",
      "deployment_domain",
      "source_sha256",
      "wasm_sha256",
      "generated_schema_sha256",
    ],
    "release identity",
  );
  if (own(release, "network") !== "casper-test") throw new Error("release network must be casper-test");
  const packageHash = hash32(own(release, "package_hash"), "package hash", true);
  const contractHash = hash32(own(release, "contract_hash"), "contract hash", true);
  const deploymentDomain = hash32(own(release, "deployment_domain"), "deployment domain", true);
  const sourceSha256 = hash32(own(release, "source_sha256"), "source SHA-256", true);
  const wasmSha256 = hash32(own(release, "wasm_sha256"), "Wasm SHA-256", true);
  const generatedSchemaSha256 = hash32(
    own(release, "generated_schema_sha256"),
    "generated schema SHA-256",
    true,
  );

  const authorization = record(own(artifact, "authorization"), "authorization");
  exactOwnKeys(
    authorization,
    [
      "proposal_id",
      "action_id",
      "envelope_hash",
      "typed_header",
      "typed_body",
      "header_bytes_hex",
      "body_bytes_hex",
      "action_core_bytes_hex",
      "exact_v3_proof",
      "v3_readback",
      "snapshot",
      "snapshot_sha256",
    ],
    "authorization",
  );
  const header = record(own(authorization, "typed_header"), "typed header");
  const body = record(own(authorization, "typed_body"), "typed body");
  const material = verifyNativeEnvelopeMaterialV3({ header, body });
  const proposalId = text(own(authorization, "proposal_id"), "proposal_id");
  if (own(header, "proposal_id") !== proposalId) throw new Error("proposal_id does not match typed header");
  if (own(authorization, "action_id") !== material.actionId) throw new Error("action_id does not match typed material");
  if (own(authorization, "envelope_hash") !== material.envelopeHash) {
    throw new Error("envelope_hash does not match typed material");
  }
  if (
    own(authorization, "header_bytes_hex") !== material.headerHex ||
    own(authorization, "body_bytes_hex") !== material.bodyHex ||
    own(authorization, "action_core_bytes_hex") !== material.actionCoreHex
  ) {
    throw new Error("serialized v3 material does not match recomputation");
  }
  if (own(header, "deployment_domain") !== deploymentDomain) {
    throw new Error("typed deployment domain does not match release identity");
  }
  const sourceAccountHash = hash32(own(body, "source_account"), "source account", true);
  const recipientAccountHash = hash32(own(body, "recipient_account"), "recipient account", true);
  const amountMotes = parseUnsigned(own(body, "amount_motes"), 512).toString();
  const treasurySnapshotBalanceMotes = parseUnsigned(
    own(body, "treasury_snapshot_balance_motes"),
    512,
  ).toString();
  const approvedAllocationBps = parseUnsigned(own(header, "approved_allocation_bps"), 32).toString();
  const snapshotBlockHash = hash32(own(body, "snapshot_block_hash"), "snapshot block hash", true);
  const snapshotBlockHeightBig = parseUnsigned(own(body, "snapshot_block_height"), 64);
  if (snapshotBlockHeightBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("snapshot block height exceeds safe JSON range");
  }
  const snapshotBlockHeight = Number(snapshotBlockHeightBig);

  record(own(authorization, "exact_v3_proof"), "exact v3 proof");
  const snapshot = verifyTreasurySnapshot(
    own(authorization, "snapshot"),
    own(authorization, "snapshot_sha256"),
    {
      accountHash: sourceAccountHash,
      blockHash: snapshotBlockHash,
      blockHeight: snapshotBlockHeight,
      balanceMotes: treasurySnapshotBalanceMotes,
    },
  );
  const snapshotStateRootHash = snapshot.stateRootHash;

  const journal = record(own(artifact, "executor_journal"), "executor journal");
  exactOwnKeys(
    journal,
    [
      "state",
      "signed_deploy_bytes_hex",
      "signed_deploy_sha256",
      "deploy_hash",
      "broadcast_attempts",
      "last_detail_code",
      "payment_amount_motes",
      "created_at",
      "updated_at",
      "execution_proof_sha256",
    ],
    "executor journal",
  );
  if (own(journal, "state") !== "PROVEN" || own(journal, "last_detail_code") !== "execution_proven") {
    throw new Error("executor journal must be PROVEN with execution_proven detail");
  }
  if (own(journal, "broadcast_attempts") !== 1) {
    throw new Error("executor journal must prove exactly one broadcast attempt");
  }
  const createdAt = canonicalUtc(own(journal, "created_at"), "journal created_at");
  const updatedAt = canonicalUtc(own(journal, "updated_at"), "journal updated_at");
  if (Date.parse(updatedAt) < Date.parse(createdAt) || Date.parse(capturedAt) < Date.parse(updatedAt)) {
    throw new Error("native treasury artifact timestamps are out of order");
  }
  const signedDeployHex = text(own(journal, "signed_deploy_bytes_hex"), "signed deploy bytes");
  const signedDeploySha256 = hash32(own(journal, "signed_deploy_sha256"), "signed deploy SHA-256");
  if (sha256HexBytes(signedDeployHex, "signed deploy bytes") !== signedDeploySha256) {
    throw new Error("signed deploy SHA-256 does not match persisted bytes");
  }
  const nativeDeployHash = hash32(own(journal, "deploy_hash"), "native deploy hash");
  const paymentAmountMotes = parseUnsigned(own(journal, "payment_amount_motes"), 512).toString();
  const signedDeploy = {
    signedDeployHex,
    sourceAccountHash,
    recipientAccountHash,
    amountMotes,
    transferId: material.transferId,
    paymentAmountMotes,
    maxPaymentAmountMotes: paymentAmountMotes,
  };

  const finalitySection = record(own(artifact, "finality"), "finality");
  exactOwnKeys(finalitySection, ["facts", "node_observations", "verification_scope"], "finality");
  const nodeObservations = own(finalitySection, "node_observations");
  if (!Array.isArray(nodeObservations)) throw new Error("finality node_observations must be an array");
  if (own(finalitySection, "verification_scope") !== VERIFICATION_SCOPE) {
    throw new Error("finality verification_scope is overstated or unsupported");
  }
  const finality = verifyCorroboratedNativeTransfer({
    requestedDeployHash: nativeDeployHash,
    nodeObservations,
    signedDeploy,
  });
  compareFinalitySummary(record(own(finalitySection, "facts"), "finality facts"), finality);

  const balanceEvidence = record(own(artifact, "balance_evidence"), "balance evidence");
  exactOwnKeys(
    balanceEvidence,
    ["pre_source", "pre_recipient", "post_source", "post_recipient"],
    "balance evidence",
  );
  const preSource = exactBalanceBundle(own(balanceEvidence, "pre_source"), "pre-source evidence");
  if (
    canonicalTranscriptJson(preSource, "pre-source evidence") !==
    canonicalTranscriptJson(snapshot.primaryBundle, "authorization snapshot primary observation")
  ) {
    throw new Error("pre-source evidence does not equal the authorization snapshot");
  }
  const preRecipient = exactBalanceBundle(own(balanceEvidence, "pre_recipient"), "pre-recipient evidence");
  const postSource = exactBalanceBundle(own(balanceEvidence, "post_source"), "post-source evidence");
  const postRecipient = exactBalanceBundle(own(balanceEvidence, "post_recipient"), "post-recipient evidence");
  const finalityInput = firstNodeFinality(nodeObservations, nativeDeployHash, signedDeploy);
  const postProof = verifyPostTransferBalance({
    preSourceBalance: balanceInput(preSource, {
      accountHash: sourceAccountHash,
      blockHash: snapshotBlockHash,
      blockHeight: snapshotBlockHeight,
      stateRootHash: snapshotStateRootHash,
      balanceMotes: treasurySnapshotBalanceMotes,
    }),
    preRecipientBalance: balanceInput(preRecipient, {
      accountHash: recipientAccountHash,
      blockHash: snapshotBlockHash,
      blockHeight: snapshotBlockHeight,
      stateRootHash: snapshotStateRootHash,
    }),
    postSourceBalance: balanceInput(postSource, {
      accountHash: sourceAccountHash,
      blockHash: finality.blockHash,
      blockHeight: finality.blockHeight,
      stateRootHash: finality.stateRootHash,
    }),
    postRecipientBalance: balanceInput(postRecipient, {
      accountHash: recipientAccountHash,
      blockHash: finality.blockHash,
      blockHeight: finality.blockHeight,
      stateRootHash: finality.stateRootHash,
    }),
    finality: finalityInput,
    expectedSourceAccountHash: sourceAccountHash,
    expectedRecipientAccountHash: recipientAccountHash,
    expectedAmountMotes: amountMotes,
  });
  if (
    postProof.deployHash !== finality.deployHash ||
    postProof.postBlockHash !== finality.blockHash ||
    postProof.postStateRootHash !== finality.stateRootHash ||
    postProof.gasMotes !== finality.gasMotes
  ) {
    throw new Error("post-transfer balance evidence conflicts with corroborated finality");
  }

  const bounded = record(own(artifact, "bounded_transfer_scan"), "bounded transfer scan");
  exactOwnKeys(
    bounded,
    [
      "authorization_block_height",
      "authorization_block_hash",
      "observed_through_block_height",
      "observed_through_block_hash",
      "scanned_block_count",
      "matched_transfer_count",
      "transcript",
    ],
    "bounded transfer scan",
  );
  const transcript = record(own(bounded, "transcript"), "bounded transfer scan transcript");
  exactOwnKeys(
    transcript,
    ["authorization_block_height", "chain_status_request", "chain_status_response", "block_observations"],
    "bounded transfer scan transcript",
  );
  const authorizationBlockHeight = height(
    own(transcript, "authorization_block_height"),
    "authorization block height",
  );
  if (own(bounded, "authorization_block_height") !== authorizationBlockHeight) {
    throw new Error("bounded scan authorization height summary does not match transcript");
  }
  const blockObservations = own(transcript, "block_observations");
  if (!Array.isArray(blockObservations)) throw new Error("bounded scan block observations must be an array");
  const scan = verifyNoDuplicateNativeTransfer({
    chainStatusRequest: own(transcript, "chain_status_request"),
    chainStatusResponse: own(transcript, "chain_status_response"),
    blockObservations,
    authorizationBlockHeight,
    finality: finalityInput,
  });
  const scanExpected: Record<string, unknown> = {
    authorization_block_hash: scan.authorizationBlockHash,
    observed_through_block_height: scan.observedThroughBlockHeight,
    observed_through_block_hash: scan.observedThroughBlockHash,
    scanned_block_count: scan.scannedBlockCount,
    matched_transfer_count: scan.matchedTransferCount,
  };
  for (const [name, value] of Object.entries(scanExpected)) {
    if (own(bounded, name) !== value) throw new Error(`bounded scan ${name} summary does not match transcript`);
  }

  const balanceEvidenceJson = canonicalTranscriptJson(balanceEvidence, "balance evidence");
  const scanTranscriptJson = canonicalTranscriptJson(transcript, "bounded transfer scan transcript");
  const digestMaterial = canonicalTranscriptJson(
    {
      post_balance_evidence_sha256: sha256Text(balanceEvidenceJson),
      no_duplicate_scan_sha256: sha256Text(scanTranscriptJson),
      deploy_hash: nativeDeployHash,
    },
    "execution proof digest",
  );
  const executionProofSha256 = hash32(
    own(journal, "execution_proof_sha256"),
    "execution proof SHA-256",
  );
  if (sha256Text(digestMaterial) !== executionProofSha256) {
    throw new Error("execution proof SHA-256 does not match raw evidence");
  }

  // Keep the raw v3 readback available for the separate exact-envelope adapter.
  // Treasury verification never treats it as a truth shortcut.
  const v3Readback = own(authorization, "v3_readback");
  record(v3Readback, "v3 readback");
  if (snapshotBlockHeight >= finality.blockHeight) {
    throw new Error("treasury snapshot must precede native execution");
  }
  return Object.freeze({
    schemaVersion: "concordia.native_treasury_execution.v1",
    capturedAt,
    sourceCommit,
    deploymentCommit,
    network: "casper-test",
    packageHash,
    contractHash,
    deploymentDomain,
    sourceSha256,
    wasmSha256,
    generatedSchemaSha256,
    proposalId,
    actionId: material.actionId,
    envelopeHash: material.envelopeHash,
    sourceAccountHash,
    recipientAccountHash,
    amountMotes,
    transferId: material.transferId,
    treasurySnapshotBalanceMotes,
    approvedAllocationBps,
    snapshotBlockHash,
    snapshotBlockHeight,
    snapshotStateRootHash,
    nativeDeployHash: finality.deployHash,
    nativeBlockHash: finality.blockHash,
    nativeBlockHeight: finality.blockHeight,
    nativeStateRootHash: finality.stateRootHash,
    gasMotes: finality.gasMotes,
    authorizationBlockHeight,
    authorizationBlockHash: scan.authorizationBlockHash,
    observedThroughBlockHeight: scan.observedThroughBlockHeight,
    observedThroughBlockHash: scan.observedThroughBlockHash,
    snapshotObservationCount: snapshot.observationCount,
    nodeObservationCount: finality.nodeObservationCount,
    verificationScope: VERIFICATION_SCOPE,
    executionProofSha256,
    v3Readback,
  });
}
