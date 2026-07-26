import { createHash } from "node:crypto";

import { blake2b } from "@noble/hashes/blake2";

export type KeyValue = {
  variant: "Account" | "Hash";
  value: string;
};

export type PublicKeyValue = {
  algorithm: "Ed25519" | "Secp256k1";
  value: string;
};

export type OptionU64Value = {
  variant: "None" | "Some";
  value: string | number | bigint | null;
};

export type TypedField = {
  name: string;
  type: string;
  value: unknown;
};

export type FieldSchema = readonly (readonly [name: string, type: string])[];

export class EncodingError extends Error {
  readonly code: number | null;

  constructor(name: string, message: string, code: number | null = null) {
    super(message);
    this.name = name;
    this.code = code;
  }
}

export const DOMAINS = Object.freeze({
  actionId: asciiLiteral("CONCORDIA_ACTION_ID_V3\0"),
  transferId: asciiLiteral("CONCORDIA_TRANSFER_ID_V3\0"),
  envelope: asciiLiteral("CONCORDIA_GOVERNANCE_ENVELOPE_V3\0"),
  deployment: asciiLiteral("CONCORDIA_DOMAIN_V3\0"),
  resourceUrl: asciiLiteral("CONCORDIA_RESOURCE_URL_V1\0"),
  evidence: asciiLiteral("CONCORDIA_PREAUTH_EVIDENCE_V1\0"),
  metadata: asciiLiteral("CONCORDIA_AUTHORIZED_METADATA_V1\0"),
  execArgs: asciiLiteral("CONCORDIA_EXEC_ARGS_V1\0"),
  paymentRequirements: asciiLiteral("CONCORDIA_PAYMENT_REQUIREMENTS_V1\0"),
  signedPaymentPayload: asciiLiteral("CONCORDIA_SIGNED_PAYMENT_PAYLOAD_V1\0"),
  x402Report: asciiLiteral("CONCORDIA_X402_REPORT_V1\0"),
});

export const TYPE_TAGS = Object.freeze<Record<string, number>>({
  bool: 1,
  u8: 2,
  u32: 3,
  u64: 4,
  U256: 5,
  U512: 6,
  Bytes32: 7,
  AccountHash: 8,
  Key: 9,
  String: 10,
  Bytes: 11,
  "List<Key>": 12,
  PublicKey: 13,
  "Option<u64>": 14,
});

export const HEADER_SCHEMA = Object.freeze([
  ["schema_version", "u32"],
  ["deployment_domain", "Bytes32"],
  ["casper_chain_name", "String"],
  ["proposal_id", "String"],
  ["proposal_nonce", "Bytes32"],
  ["decision_code", "u8"],
  ["requested_allocation_bps", "u32"],
  ["approved_allocation_bps", "u32"],
  ["action_kind", "u8"],
  ["action_version", "u32"],
  ["action_id", "Bytes32"],
  ["proposal_hash", "Bytes32"],
  ["policy_hash", "Bytes32"],
  ["plan_hash", "Bytes32"],
  ["final_card_hash", "Bytes32"],
  ["dissent_hash", "Bytes32"],
  ["agent_action_hash", "Bytes32"],
  ["preauth_evidence_root", "Bytes32"],
  ["authorized_metadata_root", "Bytes32"],
] as const);

export const NATIVE_SCHEMA = Object.freeze([
  ["asset_kind", "u8"],
  ["source_account", "AccountHash"],
  ["recipient_account", "AccountHash"],
  ["amount_motes", "U512"],
  ["treasury_snapshot_balance_motes", "U512"],
  ["snapshot_block_hash", "Bytes32"],
  ["snapshot_block_height", "u64"],
  ["transfer_id", "u64"],
  ["action_nonce", "Bytes32"],
  ["execution_target", "String"],
  ["execution_version", "u32"],
] as const);

export const NATIVE_CORE_NAMES = Object.freeze([
  "asset_kind",
  "source_account",
  "recipient_account",
  "amount_motes",
  "treasury_snapshot_balance_motes",
  "snapshot_block_hash",
  "snapshot_block_height",
  "execution_target",
  "execution_version",
]);

export const X402_SCHEMA = Object.freeze([
  ["x402_version", "u32"],
  ["scheme", "String"],
  ["caip2_network", "String"],
  ["wcspr_package", "Bytes32"],
  ["wcspr_contract", "Bytes32"],
  ["token_name", "String"],
  ["token_symbol", "String"],
  ["eip712_domain_version", "String"],
  ["token_decimals", "u8"],
  ["payer", "AccountHash"],
  ["payee", "AccountHash"],
  ["value", "U256"],
  ["resource_url_hash", "Bytes32"],
  ["report_hash", "Bytes32"],
  ["payment_requirements_hash", "Bytes32"],
  ["signed_payment_payload_hash", "Bytes32"],
  ["eip712_auth_nonce", "Bytes32"],
  ["valid_after", "u64"],
  ["valid_before", "u64"],
  ["action_nonce", "Bytes32"],
  ["settlement_target", "String"],
  ["settlement_version", "u32"],
] as const);

export const X402_CORE_NAMES = Object.freeze(
  X402_SCHEMA.map(([name]) => name).filter((name) => name !== "action_nonce"),
);

export const EVIDENCE_SCHEMA = Object.freeze([
  ["artifact_id", "String"],
  ["artifact_kind", "u8"],
  ["content_sha256", "Bytes32"],
  ["byte_length", "u64"],
  ["media_type", "String"],
  ["provenance_class", "u8"],
  ["captured_at_unix_seconds", "u64"],
] as const);

const PROPOSAL_ID_RE = /^[A-Z0-9-]{1,64}$/;
const MACHINE_NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const ZERO32 = "00".repeat(32);
const MAX_U512 = (1n << 512n) - 1n;

export const FROZEN_WCSPR = Object.freeze({
  packageHash: "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e",
  contractHash: "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
  tokenName: "Wrapped CSPR",
  tokenSymbol: "WCSPR",
  domainVersion: "1",
  decimals: 9n,
});

function asciiLiteral(value: string): Uint8Array {
  return Uint8Array.from([...value].map((character) => character.charCodeAt(0)));
}

export function concatBytes(...values: readonly Uint8Array[]): Uint8Array {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export function toHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

export function blake2b256(value: Uint8Array): Uint8Array {
  return blake2b(value, { dkLen: 32 });
}

export function sha256(value: Uint8Array): Uint8Array {
  return createHash("sha256").update(value).digest();
}

export function parseUnsigned(value: unknown, bits: number): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value)) {
    parsed = BigInt(value);
  } else if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    parsed = BigInt(value);
  } else {
    throw new EncodingError("InvalidInteger", `integer outside u${bits} range`);
  }
  if (parsed < 0n || parsed >= 1n << BigInt(bits)) {
    throw new EncodingError("InvalidInteger", `integer outside u${bits} range`);
  }
  return parsed;
}

export function fixedUnsigned(value: unknown, bits: number): Uint8Array {
  let parsed = parseUnsigned(value, bits);
  const output = new Uint8Array(bits / 8);
  for (let index = output.length - 1; index >= 0; index -= 1) {
    output[index] = Number(parsed & 0xffn);
    parsed >>= 8n;
  }
  return output;
}

export function hexBytes(value: unknown, expectedBytes?: number): Uint8Array {
  if (typeof value !== "string" || !/^(?:[0-9a-f]{2})*$/.test(value)) {
    throw new EncodingError("InvalidHex", "hex value must be canonical lowercase hexadecimal");
  }
  const output = Uint8Array.from(Buffer.from(value, "hex"));
  if (expectedBytes !== undefined && output.length !== expectedBytes) {
    throw new EncodingError("InvalidHex", `expected exactly ${expectedBytes} bytes`);
  }
  return output;
}

export function asciiBytes(value: unknown): Uint8Array {
  if (typeof value !== "string") {
    throw new EncodingError("InvalidString", "value must be an ASCII string");
  }
  const output = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) {
      throw new EncodingError("InvalidString", "value must contain only printable ASCII bytes");
    }
    output[index] = code;
  }
  return output;
}

export function lengthPrefixed(value: string | Uint8Array): Uint8Array {
  const bytes = typeof value === "string" ? asciiBytes(value) : value;
  return concatBytes(fixedUnsigned(bytes.length, 32), bytes);
}

function encodeKey(value: unknown): Uint8Array {
  if (!isRecord(value)) throw new EncodingError("InvalidKey", "Key must be an object");
  requireExactOwnKeys(value, ["variant", "value"], "Key");
  const variant = value.variant === "Account" ? 0 : value.variant === "Hash" ? 1 : null;
  if (variant === null) throw new EncodingError("InvalidKey", "unsupported Key variant");
  return concatBytes(Uint8Array.of(variant), hexBytes(value.value, 32));
}

function encodePublicKey(value: unknown): Uint8Array {
  if (!isRecord(value)) throw new EncodingError("InvalidPublicKey", "PublicKey must be an object");
  requireExactOwnKeys(value, ["algorithm", "value"], "PublicKey");
  const raw = hexBytes(value.value);
  if (value.algorithm === "Ed25519") {
    if (raw.length !== 32) {
      throw new EncodingError("InvalidPublicKey", "Ed25519 public key must contain exactly 32 bytes");
    }
    return concatBytes(Uint8Array.of(1), raw);
  }
  if (value.algorithm === "Secp256k1") {
    if (raw.length !== 33 || (raw[0] !== 2 && raw[0] !== 3)) {
      throw new EncodingError(
        "InvalidPublicKey",
        "Secp256k1 public key must be a 33-byte compressed point",
      );
    }
    return concatBytes(Uint8Array.of(2), raw);
  }
  throw new EncodingError("InvalidPublicKey", "unsupported PublicKey algorithm");
}

export function encodeCanonicalValue(type: string, value: unknown): Uint8Array {
  switch (type) {
    case "bool":
      if (value === true) return Uint8Array.of(1);
      if (value === false) return Uint8Array.of(0);
      throw new EncodingError("InvalidBoolean", "bool must be a JSON boolean");
    case "u8":
      return fixedUnsigned(value, 8);
    case "u32":
      return fixedUnsigned(value, 32);
    case "u64":
      return fixedUnsigned(value, 64);
    case "U256":
      return fixedUnsigned(value, 256);
    case "U512":
      return fixedUnsigned(value, 512);
    case "Bytes32":
    case "AccountHash":
      return hexBytes(value, 32);
    case "String":
      return lengthPrefixed(asString(value));
    case "Bytes":
      return lengthPrefixed(hexBytes(value));
    case "Key":
      return encodeKey(value);
    case "List<Key>": {
      if (!Array.isArray(value)) throw new EncodingError("InvalidKey", "List<Key> must be an array");
      return concatBytes(
        fixedUnsigned(value.length, 32),
        ...value.map((entry) => encodeKey(entry)),
      );
    }
    case "PublicKey":
      return encodePublicKey(value);
    case "Option<u64>": {
      if (!isRecord(value)) throw new EncodingError("InvalidOption", "Option<u64> must be an object");
      requireExactOwnKeys(value, ["variant", "value"], "Option<u64>");
      if (value.variant === "None") {
        if (value.value !== null && value.value !== undefined) {
          throw new EncodingError("InvalidOption", "None Option<u64> cannot carry a value");
        }
        return Uint8Array.of(0);
      }
      if (value.variant === "Some") {
        return concatBytes(Uint8Array.of(1), fixedUnsigned(value.value, 64));
      }
      throw new EncodingError("InvalidOption", "unsupported Option<u64> variant");
    }
    default:
      throw new EncodingError("UnknownType", `unknown type: ${type}`);
  }
}

export function fieldsToRecord(fields: unknown, schema: FieldSchema): Record<string, unknown> {
  if (!Array.isArray(fields)) throw new EncodingError("InvalidFields", "typed fields must be an array");
  if (fields.length !== schema.length) {
    throw new EncodingError("InvalidFields", `expected ${schema.length} fields, received ${fields.length}`);
  }
  const result: Record<string, unknown> = {};
  for (let index = 0; index < schema.length; index += 1) {
    const expected = schema[index];
    const field = fields[index];
    if (expected === undefined || !isRecord(field)) {
      throw new EncodingError("InvalidFields", "malformed typed field");
    }
    requireExactOwnKeys(field, ["name", "type", "value"], `field ${index}`);
    const [expectedName, expectedType] = expected;
    if (field.name !== expectedName || field.type !== expectedType) {
      throw new EncodingError(
        "InvalidFields",
        `field ${index} must be ${expectedName}:${expectedType}`,
      );
    }
    if (Object.hasOwn(result, expectedName)) {
      throw new EncodingError("DuplicateArgumentName", `duplicate field ${expectedName}`);
    }
    result[expectedName] = field.value;
  }
  return result;
}

export function encodeRecord(values: Record<string, unknown>, schema: FieldSchema): Uint8Array {
  return concatBytes(
    ...schema.map(([name, type]) => {
      if (!Object.hasOwn(values, name)) {
        throw new EncodingError("InvalidFields", `missing field ${name}`);
      }
      return encodeCanonicalValue(type, values[name]);
    }),
  );
}

export function encodeTypedFields(fields: unknown, schema: FieldSchema): Uint8Array {
  return encodeRecord(fieldsToRecord(fields, schema), schema);
}

export function validateHeader(values: Record<string, unknown>): void {
  if (parseUnsigned(values.schema_version, 32) !== 3n) {
    throw new EncodingError("InvalidEnvelopeField", "schema_version must equal 3", 15);
  }
  const proposalId = asString(values.proposal_id);
  if (!PROPOSAL_ID_RE.test(proposalId)) {
    throw new EncodingError("InvalidProposalId", "proposal_id is not canonical", 14);
  }
  if (values.casper_chain_name !== "casper-test") {
    throw new EncodingError("InvalidEnvelopeField", "casper_chain_name must equal casper-test", 15);
  }
  const requested = parseUnsigned(values.requested_allocation_bps, 32);
  const approved = parseUnsigned(values.approved_allocation_bps, 32);
  if (requested > 10_000n || approved > 10_000n) {
    throw new EncodingError("InvalidEnvelopeField", "basis points exceed 10000", 15);
  }
  const actionKind = parseUnsigned(values.action_kind, 8);
  const decision = parseUnsigned(values.decision_code, 8);
  if (decision > 4n) {
    throw new EncodingError("InvalidEnvelopeField", "unsupported decision code", 15);
  }
  if (actionKind !== 1n && actionKind !== 2n) {
    throw new EncodingError("InvalidActionField", "unsupported action kind", 16);
  }
  if (parseUnsigned(values.action_version, 32) !== 1n) {
    throw new EncodingError("InvalidActionField", "action_version must equal 1", 16);
  }
  if (actionKind === 1n) {
    if (decision !== 1n && decision !== 2n) {
      throw new EncodingError("InvalidEnvelopeField", "native action requires an executable decision", 15);
    }
    if (requested === 0n || approved === 0n || approved > requested) {
      throw new EncodingError("InvalidEnvelopeField", "invalid native allocation", 15);
    }
    if (decision === 1n && approved !== requested) {
      throw new EncodingError("InvalidEnvelopeField", "approved decision must authorize full request", 15);
    }
    if (decision === 2n && approved >= requested) {
      throw new EncodingError("InvalidEnvelopeField", "limited decision must reduce the request", 15);
    }
  } else if (actionKind === 2n) {
    if (decision !== 1n || requested !== 0n || approved !== 0n) {
      throw new EncodingError("InvalidEnvelopeField", "official x402 header must use zero allocations", 15);
    }
  }
}

export function validateNativeBody(
  header: Record<string, unknown>,
  body: Record<string, unknown>,
): void {
  if (parseUnsigned(header.action_kind, 8) !== 1n) {
    throw new EncodingError("InvalidActionField", "native body requires action_kind 1", 16);
  }
  if (parseUnsigned(body.asset_kind, 8) !== 0n) {
    throw new EncodingError("InvalidActionField", "asset_kind must identify native CSPR", 16);
  }
  if (body.source_account === body.recipient_account) {
    throw new EncodingError("InvalidActionField", "native source and recipient must differ", 16);
  }
  const amount = parseUnsigned(body.amount_motes, 512);
  const balance = parseUnsigned(body.treasury_snapshot_balance_motes, 512);
  const approved = parseUnsigned(header.approved_allocation_bps, 32);
  if (isZeroBytes32(body.action_nonce)) {
    throw new EncodingError("InvalidActionField", "action_nonce must be non-zero", 16);
  }
  const product = balance * approved;
  if (balance === 0n || product > MAX_U512) {
    throw new EncodingError("InvalidActionField", "native allocation multiplication overflows U512", 16);
  }
  if (amount === 0n || amount !== product / 10_000n) {
    throw new EncodingError("InvalidActionField", "amount does not equal the exact policy cap", 16);
  }
  if (body.execution_target !== "native-transfer" || parseUnsigned(body.execution_version, 32) !== 1n) {
    throw new EncodingError("InvalidActionField", "unsupported native execution target", 16);
  }
}

export function validateX402Body(
  body: Record<string, unknown>,
  header?: Record<string, unknown>,
): void {
  if (header !== undefined && parseUnsigned(header.action_kind, 8) !== 2n) {
    throw new EncodingError("InvalidActionField", "official x402 body requires action_kind 2", 16);
  }
  const validAfter = parseUnsigned(body.valid_after, 64);
  const validBefore = parseUnsigned(body.valid_before, 64);
  if (validBefore <= validAfter) {
    throw new EncodingError("InvalidActionField", "valid_before must be greater than valid_after", 16);
  }
  if (
    parseUnsigned(body.x402_version, 32) !== 2n ||
    body.scheme !== "exact" ||
    body.caip2_network !== "casper:casper-test" ||
    body.wcspr_package !== FROZEN_WCSPR.packageHash ||
    body.wcspr_contract !== FROZEN_WCSPR.contractHash ||
    body.token_name !== FROZEN_WCSPR.tokenName ||
    body.token_symbol !== FROZEN_WCSPR.tokenSymbol ||
    body.eip712_domain_version !== FROZEN_WCSPR.domainVersion ||
    parseUnsigned(body.token_decimals, 8) !== FROZEN_WCSPR.decimals ||
    body.settlement_target !== "cspr-cloud-facilitator" ||
    parseUnsigned(body.settlement_version, 32) !== 1n ||
    parseUnsigned(body.value, 256) === 0n ||
    isZeroBytes32(body.resource_url_hash) ||
    isZeroBytes32(body.report_hash) ||
    isZeroBytes32(body.payment_requirements_hash) ||
    isZeroBytes32(body.signed_payment_payload_hash) ||
    isZeroBytes32(body.eip712_auth_nonce) ||
    isZeroBytes32(body.action_nonce)
  ) {
    throw new EncodingError("InvalidActionField", "unsupported official x402 action", 16);
  }
  if (body.payer === body.payee) {
    throw new EncodingError("InvalidActionField", "x402 payer and payee must differ", 16);
  }
}

export function actionId(actionKind: number, actionNonce: unknown, actionCore: Uint8Array): string {
  if (isZeroBytes32(actionNonce)) {
    throw new EncodingError("InvalidActionField", "action_nonce must be non-zero", 16);
  }
  return toHex(
    blake2b256(
      concatBytes(
        DOMAINS.actionId,
        fixedUnsigned(actionKind, 8),
        hexBytes(actionNonce, 32),
        actionCore,
      ),
    ),
  );
}

export function transferId(
  proposalId: string,
  proposalNonce: unknown,
  computedActionId: unknown,
): { decimal: string; digestHex: string } {
  const digest = blake2b256(
    concatBytes(
      DOMAINS.transferId,
      lengthPrefixed(proposalId),
      hexBytes(proposalNonce, 32),
      hexBytes(computedActionId, 32),
    ),
  );
  let value = 0n;
  for (const byte of digest.slice(0, 8)) value = (value << 8n) | BigInt(byte);
  return { decimal: value.toString(), digestHex: toHex(digest) };
}

export function encodeEnvelopeHeader(fields: unknown): Uint8Array {
  const values = fieldsToRecord(fields, HEADER_SCHEMA);
  validateHeader(values);
  return encodeRecord(values, HEADER_SCHEMA);
}

export function encodeNativeTransfer(fields: unknown): Uint8Array {
  return encodeTypedFields(fields, NATIVE_SCHEMA);
}

export function encodeOfficialX402Settlement(fields: unknown): Uint8Array {
  const values = fieldsToRecord(fields, X402_SCHEMA);
  validateX402Body(values);
  return encodeRecord(values, X402_SCHEMA);
}

export function encodeEvidenceManifest(input: unknown): {
  canonical: Uint8Array;
  order: string[];
} {
  if (!isRecord(input) || !isRecord(input.version) || input.version.value !== "1") {
    throw new EncodingError("InvalidManifestVersion", "evidence manifest version must equal 1");
  }
  if (!Array.isArray(input.entries_in_input_order)) {
    throw new EncodingError("InvalidFields", "evidence entries must be an array");
  }
  const entries = input.entries_in_input_order.map((fields) => fieldsToRecord(fields, EVIDENCE_SCHEMA));
  entries.sort((left, right) => compareAscii(asString(left.artifact_id), asString(right.artifact_id)));
  const names = entries.map((entry) => asString(entry.artifact_id));
  if (new Set(names).size !== names.length) {
    throw new EncodingError("DuplicateArtifactId", "duplicate artifact IDs are forbidden");
  }
  for (const name of names) {
    if (!MACHINE_NAME_RE.test(name)) {
      throw new EncodingError("InvalidArtifactId", `invalid artifact ID ${name}`);
    }
  }
  return {
    canonical: concatBytes(
      fixedUnsigned(1, 32),
      fixedUnsigned(entries.length, 32),
      ...entries.map((entry) => encodeRecord(entry, EVIDENCE_SCHEMA)),
    ),
    order: names,
  };
}

export function encodeMetadataManifest(input: unknown): {
  canonical: Uint8Array;
  order: string[];
} {
  if (!isRecord(input) || !isRecord(input.version) || input.version.value !== "1") {
    throw new EncodingError("InvalidManifestVersion", "metadata manifest version must equal 1");
  }
  if (!Array.isArray(input.entries_in_input_order)) {
    throw new EncodingError("InvalidFields", "metadata entries must be an array");
  }
  const entries = input.entries_in_input_order.map(requireAncillaryEntry);
  entries.sort((left, right) => compareAscii(left.name, right.name));
  const canonicalEntries = encodeAncillary(entries);
  return {
    canonical: concatBytes(fixedUnsigned(1, 32), canonicalEntries),
    order: entries.map((entry) => entry.name),
  };
}

export function encodeExecutionArguments(input: unknown): Uint8Array {
  if (!isRecord(input) || !isRecord(input.version) || input.version.value !== "1") {
    throw new EncodingError("InvalidManifestVersion", "execution manifest version must equal 1");
  }
  if (!isRecord(input.target) || !isRecord(input.entry_point) || !Array.isArray(input.args_in_abi_order)) {
    throw new EncodingError("InvalidFields", "malformed execution manifest");
  }
  const target = asString(input.target.value);
  const entryPoint = asString(input.entry_point.value);
  const entries = input.args_in_abi_order.map(requireAncillaryEntry);
  const expected = expectedExecOrder(target, entryPoint);
  const supplied = entries.map((entry) => entry.name);
  if (expected.length !== supplied.length || expected.some((name, index) => supplied[index] !== name)) {
    throw new EncodingError("ExecutionArgumentOrderMismatch", "execution arguments are not in ABI order");
  }
  return concatBytes(
    fixedUnsigned(1, 32),
    lengthPrefixed(target),
    lengthPrefixed(entryPoint),
    encodeAncillary(entries),
  );
}

function encodeAncillary(entries: readonly TypedField[]): Uint8Array {
  const names = entries.map((entry) => entry.name);
  if (new Set(names).size !== names.length) {
    throw new EncodingError("DuplicateArgumentName", "duplicate argument names are forbidden");
  }
  for (const name of names) {
    if (!MACHINE_NAME_RE.test(name)) {
      throw new EncodingError("InvalidArgumentName", `invalid argument name ${name}`);
    }
  }
  return concatBytes(
    fixedUnsigned(entries.length, 32),
    ...entries.map((entry) => {
      const tag = TYPE_TAGS[entry.type];
      if (tag === undefined) throw new EncodingError("UnknownType", `unknown type: ${entry.type}`);
      return concatBytes(
        lengthPrefixed(entry.name),
        Uint8Array.of(tag),
        encodeCanonicalValue(entry.type, entry.value),
      );
    }),
  );
}

function expectedExecOrder(target: string, entryPoint: string): string[] {
  if (target === "native-transfer" && entryPoint === "transfer") return ["target", "amount", "id"];
  if (target.startsWith("contract-") && entryPoint === "transfer_with_authorization") {
    return ["from", "to", "value", "valid_after", "valid_before", "nonce", "public_key", "signature"];
  }
  throw new EncodingError("ExecutionArgumentOrderMismatch", "unsupported execution target or entry point");
}

function requireAncillaryEntry(value: unknown): TypedField {
  if (!isRecord(value) || typeof value.name !== "string" || typeof value.type !== "string") {
    throw new EncodingError("InvalidFields", "malformed typed argument");
  }
  return { name: value.name, type: value.type, value: value.value };
}

function compareAscii(left: string, right: string): number {
  return Buffer.compare(Buffer.from(asciiBytes(left)), Buffer.from(asciiBytes(right)));
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireExactOwnKeys(
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
    throw new EncodingError(
      "InvalidFields",
      `${label} must contain exactly the required own properties`,
    );
  }
}

function isZeroBytes32(value: unknown): boolean {
  return toHex(hexBytes(value, 32)) === ZERO32;
}

export function asString(value: unknown): string {
  if (typeof value !== "string") throw new EncodingError("InvalidString", "expected string");
  return value;
}
