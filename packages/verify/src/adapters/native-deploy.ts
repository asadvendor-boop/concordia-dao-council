import {
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";

import {
  blake2b256,
  concatBytes,
  hexBytes,
  parseUnsigned,
  toHex,
} from "../encoders.js";

const MAX_DEPLOY_BYTES = 4 * 1024 * 1024;
const MAX_VECTOR_ITEMS = 1024;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SECP256K1_SPKI_PREFIX = Buffer.from(
  "3036301006072a8648ce3d020106052b8104000a032200",
  "hex",
);

export type SignedNativeTransferExpectation = Readonly<{
  signedDeployHex: string;
  sourceAccountHash: string;
  recipientAccountHash: string;
  amountMotes: string | number | bigint;
  transferId: string | number | bigint;
  paymentAmountMotes?: string | number | bigint;
  maxPaymentAmountMotes?: string | number | bigint;
}>;

export type SignedNativeTransferFacts = Readonly<{
  canonicalSignedDeployHex: string;
  deployHash: string;
  bodyHash: string;
  chainName: "casper-test";
  sourcePublicKey: string;
  sourceAccountHash: string;
  recipientAccountHash: string;
  amountMotes: string;
  transferId: string;
  paymentAmountMotes: string;
  approvalSigners: readonly string[];
}>;

type ParsedPublicKey = {
  algorithm: 1 | 2;
  raw: Uint8Array;
  encoded: Uint8Array;
};

class DeployReader {
  readonly bytes: Uint8Array;
  offset = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  read(length: number, label: string): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
      throw new Error(`signed deploy is truncated while reading ${label}`);
    }
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  u8(label: string): number {
    return this.read(1, label)[0] as number;
  }

  u32le(label: string): number {
    const bytes = this.read(4, label);
    return (
      (bytes[0] as number) |
      ((bytes[1] as number) << 8) |
      ((bytes[2] as number) << 16) |
      ((bytes[3] as number) << 24)
    ) >>> 0;
  }

  u64le(label: string): bigint {
    const bytes = this.read(8, label);
    let value = 0n;
    for (let index = bytes.length - 1; index >= 0; index -= 1) {
      value = (value << 8n) | BigInt(bytes[index] as number);
    }
    return value;
  }

  vectorBytes(label: string): Uint8Array {
    const length = this.u32le(`${label} length`);
    if (length > MAX_DEPLOY_BYTES) throw new Error(`${label} exceeds the verifier size limit`);
    return this.read(length, label);
  }

  text(label: string): string {
    const raw = this.vectorBytes(label);
    let value: string;
    try {
      value = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new Error(`${label} is not canonical UTF-8`);
    }
    if (!Buffer.from(value, "utf8").equals(Buffer.from(raw))) {
      throw new Error(`${label} is not canonical UTF-8`);
    }
    return value;
  }
}

function parsePublicKey(reader: DeployReader, label: string): ParsedPublicKey {
  const start = reader.offset;
  const algorithm = reader.u8(`${label} algorithm`);
  if (algorithm !== 1 && algorithm !== 2) throw new Error(`${label} uses an unsupported algorithm`);
  const raw = reader.read(algorithm === 1 ? 32 : 33, `${label} bytes`);
  if (algorithm === 2 && raw[0] !== 2 && raw[0] !== 3) {
    throw new Error(`${label} secp256k1 key is not compressed`);
  }
  return {
    algorithm,
    raw,
    encoded: reader.bytes.slice(start, reader.offset),
  };
}

function accountHash(publicKey: ParsedPublicKey): string {
  const algorithmName = publicKey.algorithm === 1 ? "ed25519" : "secp256k1";
  const preimage = concatBytes(
    Uint8Array.from(Buffer.from(algorithmName, "ascii")),
    Uint8Array.of(0),
    publicKey.raw,
  );
  return toHex(blake2b256(preimage));
}

function publicKeyObject(publicKey: ParsedPublicKey): KeyObject {
  const prefix = publicKey.algorithm === 1 ? ED25519_SPKI_PREFIX : SECP256K1_SPKI_PREFIX;
  return createPublicKey({
    key: Buffer.concat([prefix, Buffer.from(publicKey.raw)]),
    format: "der",
    type: "spki",
  });
}

function approvalSignatureValid(
  publicKey: ParsedPublicKey,
  deployHash: Uint8Array,
  signature: Uint8Array,
): boolean {
  const key = publicKeyObject(publicKey);
  if (publicKey.algorithm === 1) {
    return verifySignature(null, deployHash, key, signature);
  }
  return verifySignature(
    "sha256",
    deployHash,
    { key, dsaEncoding: "ieee-p1363" },
    signature,
  );
}

function requireName(reader: DeployReader, expected: string): void {
  const actual = reader.text("runtime argument name");
  if (actual !== expected) throw new Error(`runtime arguments must be exactly ordered; expected ${expected}`);
}

function parseCanonicalU512(raw: Uint8Array, label: string): bigint {
  if (raw.length < 1) throw new Error(`${label} is malformed`);
  const magnitudeLength = raw[0] as number;
  if (magnitudeLength > 64 || raw.length !== magnitudeLength + 1) {
    throw new Error(`${label} is not canonical U512`);
  }
  if (magnitudeLength > 0 && raw[raw.length - 1] === 0) {
    throw new Error(`${label} is not canonical U512`);
  }
  let value = 0n;
  for (let index = raw.length - 1; index >= 1; index -= 1) {
    value = (value << 8n) | BigInt(raw[index] as number);
  }
  return value;
}

function parseU512ClValue(reader: DeployReader, label: string): bigint {
  const raw = reader.vectorBytes(`${label} CLValue`);
  const type = reader.u8(`${label} CLType`);
  if (type !== 8) throw new Error(`${label} must be U512`);
  return parseCanonicalU512(raw, label);
}

function parseTargetClValue(reader: DeployReader): string {
  const raw = reader.vectorBytes("target CLValue");
  const type = reader.u8("target CLType");
  if (type !== 11 || raw.length !== 33 || raw[0] !== 0) {
    throw new Error("target must be an account-variant Key");
  }
  return toHex(raw.slice(1));
}

function parseTransferIdClValue(reader: DeployReader): bigint {
  const raw = reader.vectorBytes("transfer id CLValue");
  const optionType = reader.u8("transfer id option CLType");
  const nestedType = reader.u8("transfer id nested CLType");
  if (optionType !== 13 || nestedType !== 5 || raw.length !== 9 || raw[0] !== 1) {
    throw new Error("transfer id must be Some U64");
  }
  let value = 0n;
  for (let index = 8; index >= 1; index -= 1) {
    value = (value << 8n) | BigInt(raw[index] as number);
  }
  return value;
}

function exactHex(value: unknown, label: string): string {
  try {
    return toHex(hexBytes(value, 32));
  } catch {
    throw new Error(`${label} must be canonical lowercase 32-byte hex`);
  }
}

export function verifySignedNativeTransferDeploy(
  input: SignedNativeTransferExpectation,
): SignedNativeTransferFacts {
  for (const field of [
    "signedDeployHex",
    "sourceAccountHash",
    "recipientAccountHash",
    "amountMotes",
    "transferId",
  ] as const) {
    if (!Object.hasOwn(input, field)) throw new Error(`required own input field ${field} is missing`);
  }
  const signedBytes = hexBytes(input.signedDeployHex);
  if (signedBytes.length === 0 || signedBytes.length > MAX_DEPLOY_BYTES) {
    throw new Error("signed deploy bytes must be non-empty and within the verifier size limit");
  }
  const expectedSource = exactHex(input.sourceAccountHash, "sourceAccountHash");
  const expectedRecipient = exactHex(input.recipientAccountHash, "recipientAccountHash");
  const expectedAmount = parseUnsigned(input.amountMotes, 512);
  const expectedTransferId = parseUnsigned(input.transferId, 64);
  const expectedPayment = parseUnsigned(input.paymentAmountMotes ?? "100000000", 512);
  const maxPayment = parseUnsigned(input.maxPaymentAmountMotes ?? "100000000", 512);
  if (expectedAmount === 0n || expectedPayment === 0n || maxPayment === 0n) {
    throw new Error("expected transfer and payment amounts must be positive");
  }

  const reader = new DeployReader(signedBytes);
  const headerStart = reader.offset;
  const sourcePublicKey = parsePublicKey(reader, "header account");
  reader.u64le("timestamp");
  reader.u64le("ttl");
  reader.u64le("gas price");
  const suppliedBodyHash = reader.read(32, "body hash");
  const dependencyCount = reader.u32le("dependency count");
  if (dependencyCount > MAX_VECTOR_ITEMS) throw new Error("dependency count exceeds limit");
  for (let index = 0; index < dependencyCount; index += 1) reader.read(32, "dependency hash");
  const chainName = reader.text("chain name");
  const headerEnd = reader.offset;
  const suppliedDeployHash = reader.read(32, "deploy hash");

  const paymentStart = reader.offset;
  if (reader.u8("payment variant") !== 0) throw new Error("payment must be exactly ModuleBytes");
  if (reader.vectorBytes("payment module bytes").length !== 0) {
    throw new Error("standard payment module bytes must be empty");
  }
  if (reader.u32le("payment argument count") !== 1) {
    throw new Error("payment arguments must be exactly amount");
  }
  requireName(reader, "amount");
  const paymentAmount = parseU512ClValue(reader, "payment amount");
  const paymentEnd = reader.offset;

  const sessionStart = reader.offset;
  if (reader.u8("session variant") !== 5) throw new Error("session must be exactly Transfer");
  if (reader.u32le("session argument count") !== 3) {
    throw new Error("session arguments must be exactly ordered target, amount, id");
  }
  requireName(reader, "target");
  const recipient = parseTargetClValue(reader);
  requireName(reader, "amount");
  const amount = parseU512ClValue(reader, "transfer amount");
  requireName(reader, "id");
  const transferId = parseTransferIdClValue(reader);
  const sessionEnd = reader.offset;

  const approvalCount = reader.u32le("approval count");
  if (approvalCount === 0 || approvalCount > MAX_VECTOR_ITEMS) {
    throw new Error("signed deploy requires a bounded, non-empty approval set");
  }
  const approvals: Array<{ signer: ParsedPublicKey; signature: Uint8Array }> = [];
  const signerHexes = new Set<string>();
  for (let index = 0; index < approvalCount; index += 1) {
    const signer = parsePublicKey(reader, "approval signer");
    const signatureAlgorithm = reader.u8("approval signature algorithm");
    const signature = reader.read(64, "approval signature");
    if (signatureAlgorithm !== signer.algorithm) {
      throw new Error("approval signature algorithm does not match signer");
    }
    const signerHex = toHex(signer.encoded);
    if (signerHexes.has(signerHex)) throw new Error("duplicate approval signer");
    signerHexes.add(signerHex);
    approvals.push({ signer, signature });
  }
  if (reader.offset !== signedBytes.length) throw new Error("signed deploy contains trailing bytes");

  const paymentBytes = signedBytes.slice(paymentStart, paymentEnd);
  const sessionBytes = signedBytes.slice(sessionStart, sessionEnd);
  const computedBodyHash = blake2b256(concatBytes(paymentBytes, sessionBytes));
  if (toHex(computedBodyHash) !== toHex(suppliedBodyHash)) throw new Error("body hash mismatch");
  const computedDeployHash = blake2b256(signedBytes.slice(headerStart, headerEnd));
  if (toHex(computedDeployHash) !== toHex(suppliedDeployHash)) throw new Error("deploy hash mismatch");
  for (const approval of approvals) {
    let valid = false;
    try {
      valid = approvalSignatureValid(approval.signer, computedDeployHash, approval.signature);
    } catch {
      valid = false;
    }
    if (!valid) throw new Error("invalid approval signature");
  }

  if (chainName !== "casper-test") throw new Error("chain must be exactly casper-test");
  const source = accountHash(sourcePublicKey);
  if (source !== expectedSource) throw new Error("source account hash mismatch");
  if (recipient !== expectedRecipient) throw new Error("recipient account hash mismatch");
  if (amount !== expectedAmount) throw new Error("transfer amount mismatch");
  if (transferId !== expectedTransferId) throw new Error("transfer id mismatch");
  if (paymentAmount > maxPayment) throw new Error("payment amount exceeds bound");
  if (paymentAmount !== expectedPayment) throw new Error("payment amount mismatch");

  return Object.freeze({
    canonicalSignedDeployHex: toHex(signedBytes),
    deployHash: toHex(computedDeployHash),
    bodyHash: toHex(computedBodyHash),
    chainName,
    sourcePublicKey: toHex(sourcePublicKey.encoded),
    sourceAccountHash: source,
    recipientAccountHash: recipient,
    amountMotes: amount.toString(),
    transferId: transferId.toString(),
    paymentAmountMotes: paymentAmount.toString(),
    approvalSigners: Object.freeze([...signerHexes]),
  });
}
