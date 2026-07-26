import { createHash } from "node:crypto";

import { isRecord } from "../encoders.js";

const HEX64 = /^[0-9a-f]{64}$/;
const GIT40 = /^[0-9a-f]{40}$/;
const PROPOSAL_ID = /^[A-Z0-9-]{1,64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const SAFEPAY_TOP_LEVEL_FIELDS = [
  "schema_version",
  "captured_at",
  "source_commit",
  "deployment_commit",
  "capture_identity",
  "quote",
  "issued_quote_rows",
  "chain_evidence",
  "consumption_rows",
  "ledger_evidence",
  "redemption_observations",
  "protected_report",
] as const;

const OFFICIAL_TOP_LEVEL_FIELDS = [
  "schema_version",
  "captured_at",
  "source_commit",
  "deployment_commit",
  "capture_identity",
  "governance_binding",
  "resource_and_payment",
  "authorization",
  "facilitator",
  "wcspr_readbacks",
  "settlement_chain_evidence",
  "fulfillment",
  "protected_report",
  "release_order",
] as const;

const SAFEPAY_QUOTE_FIELDS = [
  "schema_version",
  "quote_id",
  "proposal_id",
  "resource_id",
  "network",
  "payee_account_hash",
  "amount_motes",
  "correlation_id",
  "report_version",
  "report_hash",
  "expires_at",
  "quote_nonce",
  "quote_hash",
] as const;

const SAFEPAY_CHAIN_FIELDS = [
  "network",
  "payment_hash",
  "providers",
  "parsed_transfer",
] as const;

const SAFEPAY_PARSED_TRANSFER_FIELDS = [
  "network",
  "payment_hash",
  "block_hash",
  "block_height",
  "state_root_hash",
  "block_timestamp",
  "execution_status",
  "finality_status",
  "execution_error",
  "native_transfer_count",
  "source_account_hash",
  "payee_account_hash",
  "amount_motes",
  "transfer_id",
] as const;

const SAFEPAY_REPORT_FIELDS = [
  "report_version",
  "proposal_id",
  "resource_id",
  "correlation_id",
  "media_type",
  "content_base64",
  "decoded_length",
  "report_hash",
  "response_hash",
  "persisted_at",
  "released_at",
] as const;

const OFFICIAL_BINDING_FIELDS = [
  "proposal_id",
  "proposal_hash",
  "proposal_nonce",
  "action_id",
  "action_kind",
  "action_version",
  "envelope_hash",
  "deployment_domain",
  "network",
  "package_hash",
  "contract_hash",
  "finalization_transaction",
  "finalized_at",
  "observed_at",
  "resource_url_hash",
  "payment_requirements_hash",
  "signed_payment_payload_hash",
  "report_hash",
  "v3_proof_sha256",
  "v3_proof_bytes_base64",
] as const;

const OFFICIAL_SETTLEMENT_FIELDS = [
  "network",
  "settlement_transaction",
  "providers",
  "parsed_settlement",
] as const;

export type SafePayV2ArtifactEnvelopeFacts = {
  proposalId: string;
  network: string;
  reportHash: string;
  settlementTransaction: string;
  sourceCommit: string;
  deploymentCommit: string;
  schemaVersion: "safepay-v2";
  capturedAt: string;
};

export type OfficialX402ArtifactEnvelopeFacts = {
  proposalId: string;
  actionId: string;
  envelopeHash: string;
  network: string;
  packageHash: string;
  contractHash: string;
  deploymentDomain: string;
  paymentRequirementsHash: string;
  signedPaymentPayloadHash: string;
  reportHash: string;
  settlementTransaction: string;
  sourceCommit: string;
  deploymentCommit: string;
  schemaVersion: "concordia.official_x402_settlement.v2";
  capturedAt: string;
};

/**
 * Validate only the immutable, registry-facing identity envelope of a SafePay
 * artifact. This deliberately does not validate quote recomputation, SQLite
 * restart persistence, native-transfer semantics, or replay behavior.
 */
export function verifySafePayV2ArtifactEnvelope(
  input: unknown,
): SafePayV2ArtifactEnvelopeFacts {
  const artifact = record(input, "SafePay artifact");
  exactFields(artifact, SAFEPAY_TOP_LEVEL_FIELDS, "SafePay artifact");
  if (artifact.schema_version !== "safepay-v2") {
    throw new Error("SafePay artifact schema_version is unsupported");
  }
  const sourceCommit = matchingString(artifact.source_commit, GIT40, "SafePay source_commit");
  const deploymentCommit = matchingString(
    artifact.deployment_commit,
    GIT40,
    "SafePay deployment_commit",
  );
  const capturedAt = nonemptyString(artifact.captured_at, "SafePay captured_at");
  for (const field of [
    "capture_identity",
    "issued_quote_rows",
    "consumption_rows",
    "ledger_evidence",
    "redemption_observations",
  ] as const) {
    record(artifact[field], `SafePay ${field}`);
  }

  const quote = record(artifact.quote, "SafePay quote");
  exactFields(quote, SAFEPAY_QUOTE_FIELDS, "SafePay quote");
  if (quote.schema_version !== "safepay-v2") {
    throw new Error("SafePay quote schema_version differs from the artifact");
  }
  const proposalId = matchingString(quote.proposal_id, PROPOSAL_ID, "SafePay quote proposal_id");
  const network = nonemptyString(quote.network, "SafePay quote network");
  if (network !== "casper:casper-test") {
    throw new Error("SafePay quote network is unsupported");
  }
  const reportHash = matchingString(quote.report_hash, HEX64, "SafePay quote report_hash");

  const chain = record(artifact.chain_evidence, "SafePay chain_evidence");
  exactFields(chain, SAFEPAY_CHAIN_FIELDS, "SafePay chain_evidence");
  const settlementTransaction = matchingString(
    chain.payment_hash,
    HEX64,
    "SafePay chain payment_hash",
  );
  if (chain.network !== network || !Array.isArray(chain.providers)) {
    throw new Error("SafePay chain identity differs from the quote envelope");
  }
  const parsedTransfer = record(chain.parsed_transfer, "SafePay parsed_transfer");
  exactFields(
    parsedTransfer,
    SAFEPAY_PARSED_TRANSFER_FIELDS,
    "SafePay parsed_transfer",
  );
  if (
    parsedTransfer.network !== network ||
    parsedTransfer.payment_hash !== settlementTransaction
  ) {
    throw new Error("SafePay parsed transfer differs from the chain envelope");
  }

  const report = record(artifact.protected_report, "SafePay protected_report");
  exactFields(report, SAFEPAY_REPORT_FIELDS, "SafePay protected_report");
  if (
    report.report_version !== quote.report_version ||
    report.proposal_id !== proposalId ||
    report.resource_id !== quote.resource_id ||
    report.correlation_id !== quote.correlation_id ||
    report.report_hash !== reportHash
  ) {
    throw new Error("SafePay protected report differs from the quote envelope");
  }

  return {
    proposalId,
    network,
    reportHash,
    settlementTransaction,
    sourceCommit,
    deploymentCommit,
    schemaVersion: "safepay-v2",
    capturedAt,
  };
}

/**
 * Validate only the immutable, registry-facing identity envelope of an
 * official-x402 artifact. This deliberately does not validate EIP-712
 * authorization, facilitator behavior, WCSPR semantics, finality, fulfillment,
 * or replay behavior.
 */
export function verifyOfficialX402ArtifactEnvelope(
  input: unknown,
): OfficialX402ArtifactEnvelopeFacts {
  const artifact = record(input, "official x402 artifact");
  exactFields(artifact, OFFICIAL_TOP_LEVEL_FIELDS, "official x402 artifact");
  if (artifact.schema_version !== "concordia.official_x402_settlement.v2") {
    throw new Error("official x402 artifact schema_version is unsupported");
  }
  const sourceCommit = matchingString(
    artifact.source_commit,
    GIT40,
    "official x402 source_commit",
  );
  const deploymentCommit = matchingString(
    artifact.deployment_commit,
    GIT40,
    "official x402 deployment_commit",
  );
  const capturedAt = nonemptyString(artifact.captured_at, "official x402 captured_at");
  for (const field of [
    "capture_identity",
    "resource_and_payment",
    "authorization",
    "facilitator",
    "wcspr_readbacks",
    "fulfillment",
    "protected_report",
    "release_order",
  ] as const) {
    record(artifact[field], `official x402 ${field}`);
  }

  const binding = record(artifact.governance_binding, "official x402 governance_binding");
  exactFields(binding, OFFICIAL_BINDING_FIELDS, "official x402 governance_binding");
  const proposalId = matchingString(
    binding.proposal_id,
    PROPOSAL_ID,
    "official x402 proposal_id",
  );
  const actionId = matchingString(binding.action_id, HEX64, "official x402 action_id");
  const envelopeHash = matchingString(
    binding.envelope_hash,
    HEX64,
    "official x402 envelope_hash",
  );
  const network = nonemptyString(binding.network, "official x402 network");
  if (network !== "casper:casper-test") {
    throw new Error("official x402 network is unsupported");
  }
  const packageHash = matchingString(
    binding.package_hash,
    HEX64,
    "official x402 package_hash",
  );
  const contractHash = matchingString(
    binding.contract_hash,
    HEX64,
    "official x402 contract_hash",
  );
  const deploymentDomain = matchingString(
    binding.deployment_domain,
    HEX64,
    "official x402 deployment_domain",
  );
  const paymentRequirementsHash = matchingString(
    binding.payment_requirements_hash,
    HEX64,
    "official x402 payment_requirements_hash",
  );
  const signedPaymentPayloadHash = matchingString(
    binding.signed_payment_payload_hash,
    HEX64,
    "official x402 signed_payment_payload_hash",
  );
  const reportHash = matchingString(
    binding.report_hash,
    HEX64,
    "official x402 report_hash",
  );
  if (
    binding.action_kind !== "OfficialX402SettlementV1" ||
    binding.action_version !== 1
  ) {
    throw new Error("official x402 action identity is unsupported");
  }

  const embeddedV3 = canonicalBase64Bytes(
    binding.v3_proof_bytes_base64,
    "official x402 embedded v3 proof",
  );
  const embeddedV3Sha256 = matchingString(
    binding.v3_proof_sha256,
    HEX64,
    "official x402 v3_proof_sha256",
  );
  if (createHash("sha256").update(embeddedV3).digest("hex") !== embeddedV3Sha256) {
    throw new Error("official x402 embedded v3 proof SHA-256 mismatch");
  }

  const settlement = record(
    artifact.settlement_chain_evidence,
    "official x402 settlement_chain_evidence",
  );
  exactFields(
    settlement,
    OFFICIAL_SETTLEMENT_FIELDS,
    "official x402 settlement_chain_evidence",
  );
  const settlementTransaction = matchingString(
    settlement.settlement_transaction,
    HEX64,
    "official x402 settlement_transaction",
  );
  if (settlement.network !== network || !Array.isArray(settlement.providers)) {
    throw new Error("official x402 settlement identity differs from the governance envelope");
  }
  record(settlement.parsed_settlement, "official x402 parsed_settlement");

  return {
    proposalId,
    actionId,
    envelopeHash,
    network,
    packageHash,
    contractHash,
    deploymentDomain,
    paymentRequirementsHash,
    signedPaymentPayloadHash,
    reportHash,
    settlementTransaction,
    sourceCommit,
    deploymentCommit,
    schemaVersion: "concordia.official_x402_settlement.v2",
    capturedAt,
  };
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function exactFields(
  value: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  const expected = new Set(fields);
  const missing = fields.filter((field) => !Object.hasOwn(value, field));
  const unknown = Object.keys(value).filter((field) => !expected.has(field));
  if (missing.length > 0 || unknown.length > 0) {
    throw new Error(
      `${label} fields differ (missing=${missing.sort().join(",") || "none"}; unknown=${unknown.sort().join(",") || "none"})`,
    );
  }
}

function nonemptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be nonempty text`);
  }
  return value;
}

function matchingString(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function canonicalBase64Bytes(value: unknown, label: string): Uint8Array {
  if (typeof value !== "string" || !BASE64.test(value)) {
    throw new Error(`${label} is not canonical base64`);
  }
  const bytes = Buffer.from(value, "base64");
  if (Buffer.from(bytes).toString("base64") !== value) {
    throw new Error(`${label} is not canonical base64`);
  }
  return bytes;
}
