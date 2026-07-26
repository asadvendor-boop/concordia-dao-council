import {
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";

import {
  blake2b256,
  concatBytes,
  hexBytes,
  isRecord,
  parseUnsigned,
  toHex,
} from "../encoders.js";

const MAX_DEPLOY_BYTES = 8 * 1024 * 1024;
const MAX_COLLECTION_ITEMS = 1_024;
const HEX32_CASE_INSENSITIVE = /^[0-9a-fA-F]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SECP256K1_SPKI_PREFIX = Buffer.from(
  "3036301006072a8648ce3d020106052b8104000a032200",
  "hex",
);

type ParsedPublicKey = Readonly<{
  algorithm: 1 | 2;
  raw: Uint8Array;
  encoded: Uint8Array;
}>;

export type DeployRuntimeArgument = Readonly<{
  name: string;
  clType: unknown;
  bytes: Uint8Array;
  parsed: unknown;
}>;

export type DeployExecutable =
  | Readonly<{
      kind: "ModuleBytes";
      moduleBytes: Uint8Array;
      args: readonly DeployRuntimeArgument[];
      canonicalBytes: Uint8Array;
    }>
  | Readonly<{
      kind: "StoredContractByHash";
      contractHash: string;
      entryPoint: string;
      args: readonly DeployRuntimeArgument[];
      canonicalBytes: Uint8Array;
    }>
  | Readonly<{
      kind: "StoredVersionedContractByHash";
      packageHash: string;
      version: number | null;
      entryPoint: string;
      args: readonly DeployRuntimeArgument[];
      canonicalBytes: Uint8Array;
    }>;

export type SignedDeployJsonFacts = Readonly<{
  deployHash: string;
  bodyHash: string;
  chainName: "casper-test";
  timestampMs: string;
  ttlMs: string;
  gasPrice: string;
  initiatorPublicKey: string;
  initiatorAccountHash: string;
  payment: DeployExecutable;
  session: DeployExecutable;
  approvalSigners: readonly string[];
  canonicalBytes: Uint8Array;
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

function bytes(...parts: readonly Uint8Array[]): Uint8Array {
  return concatBytes(...parts);
}

function u8(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
    throw new Error("value is outside u8 range");
  }
  return Uint8Array.of(value);
}

function littleUnsigned(value: bigint, byteLength: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(byteLength * 8)) {
    throw new Error(`value is outside u${byteLength * 8} range`);
  }
  const output = new Uint8Array(byteLength);
  let remaining = value;
  for (let index = 0; index < byteLength; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function u32le(value: number): Uint8Array {
  return littleUnsigned(BigInt(value), 4);
}

function vector(value: Uint8Array): Uint8Array {
  if (value.length > MAX_DEPLOY_BYTES) throw new Error("deploy vector exceeds size limit");
  return bytes(u32le(value.length), value);
}

function text(value: unknown, label: string): Uint8Array {
  if (typeof value !== "string") throw new Error(`${label} must be text`);
  const encoded = Buffer.from(value, "utf8");
  if (encoded.length > MAX_DEPLOY_BYTES || encoded.toString("utf8") !== value) {
    throw new Error(`${label} must be canonical UTF-8`);
  }
  return vector(encoded);
}

function lowerHash(value: unknown, label: string, nonzero = false): string {
  if (typeof value !== "string" || !HEX32_CASE_INSENSITIVE.test(value)) {
    throw new Error(`${label} must be a 32-byte hexadecimal value`);
  }
  const lowered = value.toLowerCase();
  if (nonzero && lowered === "00".repeat(32)) throw new Error(`${label} cannot be zero`);
  return lowered;
}

function caseInsensitiveHexBytes(value: unknown, label: string): Uint8Array {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value)) {
    throw new Error(`${label} must be even-length hexadecimal`);
  }
  return hexBytes(value.toLowerCase());
}

function parsePublicKey(value: unknown, label: string): ParsedPublicKey {
  if (typeof value !== "string" || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`${label} must be a Casper public key`);
  }
  const encoded = caseInsensitiveHexBytes(value, label);
  const algorithm = encoded[0];
  if (algorithm !== 1 && algorithm !== 2) throw new Error(`${label} algorithm is unsupported`);
  const expectedLength = algorithm === 1 ? 33 : 34;
  if (encoded.length !== expectedLength) throw new Error(`${label} length is invalid`);
  const raw = encoded.slice(1);
  if (algorithm === 2 && raw[0] !== 2 && raw[0] !== 3) {
    throw new Error(`${label} secp256k1 key is not compressed`);
  }
  return { algorithm, raw, encoded };
}

export function accountHashFromPublicKey(value: unknown): string {
  const publicKey = parsePublicKey(value, "public key");
  const algorithmName = publicKey.algorithm === 1 ? "ed25519" : "secp256k1";
  return toHex(
    blake2b256(
      bytes(Buffer.from(algorithmName, "ascii"), Uint8Array.of(0), publicKey.raw),
    ),
  );
}

function publicKeyObject(publicKey: ParsedPublicKey): KeyObject {
  const prefix = publicKey.algorithm === 1 ? ED25519_SPKI_PREFIX : SECP256K1_SPKI_PREFIX;
  return createPublicKey({
    key: Buffer.concat([prefix, Buffer.from(publicKey.raw)]),
    format: "der",
    type: "spki",
  });
}

function validApproval(
  signer: ParsedPublicKey,
  deployHash: Uint8Array,
  signature: Uint8Array,
): boolean {
  const key = publicKeyObject(signer);
  if (signer.algorithm === 1) return verifySignature(null, deployHash, key, signature);
  return verifySignature("sha256", deployHash, { key, dsaEncoding: "ieee-p1363" }, signature);
}

function timestampMillis(value: unknown): bigint {
  if (typeof value !== "string") {
    throw new Error("deploy timestamp must be canonical UTC RFC3339");
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?Z$/.exec(value);
  if (!match) throw new Error("deploy timestamp must be canonical UTC RFC3339");
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = secondText === undefined ? 0 : Number(secondText);
  if (year === 0 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
    throw new Error("deploy timestamp must be canonical UTC RFC3339");
  }
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthLengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > (monthLengths[month - 1] ?? 0)) {
    throw new Error("deploy timestamp must be canonical UTC RFC3339");
  }
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error("deploy timestamp is outside the supported range");
  }
  return BigInt(parsed);
}

function ttlMillis(value: unknown): bigint {
  if (typeof value !== "string") throw new Error("deploy ttl must be text");
  const match = /^(0|[1-9][0-9]*)(ms|s|m|h)$/.exec(value);
  if (!match) throw new Error("deploy ttl must be one canonical duration");
  const magnitude = BigInt(match[1] as string);
  const multiplier = match[2] === "ms" ? 1n : match[2] === "s" ? 1_000n : match[2] === "m" ? 60_000n : 3_600_000n;
  const result = magnitude * multiplier;
  if (result >= 1n << 64n) throw new Error("deploy ttl is outside u64 range");
  return result;
}

function parseCanonicalU512(value: Uint8Array, label: string): bigint {
  if (value.length < 1) throw new Error(`${label} is malformed U512`);
  const magnitudeLength = value[0] as number;
  if (magnitudeLength > 64 || value.length !== magnitudeLength + 1) {
    throw new Error(`${label} is malformed U512`);
  }
  if (magnitudeLength > 0 && value[value.length - 1] === 0) {
    throw new Error(`${label} is non-canonical U512`);
  }
  let result = 0n;
  for (let index = value.length - 1; index >= 1; index -= 1) {
    result = (result << 8n) | BigInt(value[index] as number);
  }
  return result;
}

function parseLittle(value: Uint8Array, length: number, label: string): bigint {
  if (value.length !== length) throw new Error(`${label} has an invalid byte length`);
  let result = 0n;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(value[index] as number);
  }
  return result;
}

function clTypeBytes(value: unknown, label: string): Uint8Array {
  if (value === "Bool") return u8(0);
  if (value === "U8") return u8(3);
  if (value === "U32") return u8(4);
  if (value === "U64") return u8(5);
  if (value === "U512") return u8(8);
  if (value === "String") return u8(10);
  if (isRecord(value)) {
    exactOwnKeys(value, ["ByteArray"], `${label} CLType`);
    if (own(value, "ByteArray") !== 32) throw new Error(`${label} only supports ByteArray(32)`);
    return bytes(u8(15), u32le(32));
  }
  throw new Error(`${label} uses an unsupported CLType`);
}

function validateParsedClValue(
  raw: Uint8Array,
  clType: unknown,
  parsed: unknown,
  label: string,
): void {
  if (clType === "Bool") {
    const expectedParsed = raw[0] === 1 ? "True" : "False";
    if (raw.length !== 1 || (raw[0] !== 0 && raw[0] !== 1) || parsed !== expectedParsed) {
      throw new Error(`${label} parsed Bool differs from bytes`);
    }
    return;
  }
  if (clType === "U8" || clType === "U32" || clType === "U64") {
    const width = clType === "U8" ? 1 : clType === "U32" ? 4 : 8;
    const decoded = parseLittle(raw, width, label);
    if (parseUnsigned(parsed, width * 8) !== decoded) {
      throw new Error(`${label} parsed ${clType} differs from bytes`);
    }
    return;
  }
  if (clType === "U512") {
    if (parseUnsigned(parsed, 512) !== parseCanonicalU512(raw, label)) {
      throw new Error(`${label} parsed U512 differs from bytes`);
    }
    return;
  }
  if (clType === "String") {
    if (raw.length < 4) throw new Error(`${label} String is malformed`);
    const length = Number(parseLittle(raw.slice(0, 4), 4, label));
    const encoded = raw.slice(4);
    if (length !== encoded.length) throw new Error(`${label} String length is non-canonical`);
    let decoded: string;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
    } catch {
      throw new Error(`${label} String is invalid UTF-8`);
    }
    if (typeof parsed !== "string" || decoded !== parsed) {
      throw new Error(`${label} parsed String differs from bytes`);
    }
    return;
  }
  if (isRecord(clType) && own(clType, "ByteArray") === 32) {
    const expected = lowerHash(parsed, `${label} parsed ByteArray`);
    if (raw.length !== 32 || toHex(raw) !== expected) {
      throw new Error(`${label} parsed ByteArray differs from bytes`);
    }
    return;
  }
  throw new Error(`${label} uses an unsupported CLType`);
}

function runtimeArgs(value: unknown, label: string): {
  facts: readonly DeployRuntimeArgument[];
  canonicalBytes: Uint8Array;
} {
  if (!Array.isArray(value) || value.length > MAX_COLLECTION_ITEMS) {
    throw new Error(`${label} must be a bounded runtime-argument list`);
  }
  const facts: DeployRuntimeArgument[] = [];
  const encoded: Uint8Array[] = [u32le(value.length)];
  const names = new Set<string>();
  for (const item of value) {
    if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== "string" || item[0].length === 0) {
      throw new Error(`${label} runtime argument shape is invalid`);
    }
    const name = item[0];
    if (names.has(name)) throw new Error(`${label} contains duplicate runtime argument ${name}`);
    names.add(name);
    const clValue = record(item[1], `${label} ${name}`);
    exactOwnKeys(clValue, ["bytes", "cl_type", "parsed"], `${label} ${name}`);
    if (typeof own(clValue, "bytes") !== "string") throw new Error(`${label} ${name} bytes are missing`);
    const raw = caseInsensitiveHexBytes(own(clValue, "bytes"), `${label} ${name} bytes`);
    const clType = own(clValue, "cl_type");
    const parsed = own(clValue, "parsed");
    validateParsedClValue(raw, clType, parsed, `${label} ${name}`);
    encoded.push(text(name, `${label} argument name`), vector(raw), clTypeBytes(clType, `${label} ${name}`));
    facts.push(Object.freeze({ name, clType, bytes: raw, parsed }));
  }
  return { facts: Object.freeze(facts), canonicalBytes: bytes(...encoded) };
}

function executable(value: unknown, label: string): DeployExecutable {
  const outer = record(value, label);
  const variants = ["ModuleBytes", "StoredContractByHash", "StoredVersionedContractByHash"]
    .filter((name) => Object.hasOwn(outer, name));
  if (variants.length !== 1 || Object.keys(outer).length !== 1) {
    throw new Error(`${label} must contain one supported executable variant`);
  }
  const variant = variants[0] as "ModuleBytes" | "StoredContractByHash" | "StoredVersionedContractByHash";
  const body = record(own(outer, variant), `${label} ${variant}`);
  if (variant === "ModuleBytes") {
    exactOwnKeys(body, ["module_bytes", "args"], `${label} ModuleBytes`);
    if (typeof own(body, "module_bytes") !== "string") throw new Error(`${label} module bytes are missing`);
    const moduleBytes = caseInsensitiveHexBytes(own(body, "module_bytes"), `${label} module bytes`);
    const args = runtimeArgs(own(body, "args"), label);
    return Object.freeze({
      kind: "ModuleBytes",
      moduleBytes,
      args: args.facts,
      canonicalBytes: bytes(u8(0), vector(moduleBytes), args.canonicalBytes),
    });
  }
  const versioned = variant === "StoredVersionedContractByHash";
  exactOwnKeys(
    body,
    versioned ? ["hash", "version", "entry_point", "args"] : ["hash", "entry_point", "args"],
    `${label} ${variant}`,
  );
  const targetHash = lowerHash(own(body, "hash"), `${label} ${versioned ? "package" : "contract"} hash`, true);
  if (typeof own(body, "entry_point") !== "string" || (own(body, "entry_point") as string).length === 0) {
    throw new Error(`${label} entry point is invalid`);
  }
  const entryPoint = own(body, "entry_point") as string;
  const args = runtimeArgs(own(body, "args"), label);
  if (versioned) {
    const rawVersion = own(body, "version");
    if (
      rawVersion !== null &&
      (typeof rawVersion !== "number" || !Number.isSafeInteger(rawVersion) || rawVersion < 0 || rawVersion > 0xffff_ffff)
    ) {
      throw new Error(`${label} version must be null or canonical u32`);
    }
    const version = rawVersion as number | null;
    return Object.freeze({
      kind: "StoredVersionedContractByHash",
      packageHash: targetHash,
      version,
      entryPoint,
      args: args.facts,
      canonicalBytes: bytes(
        u8(3),
        hexBytes(targetHash, 32),
        version === null ? u8(0) : bytes(u8(1), u32le(version)),
        text(entryPoint, `${label} entry point`),
        args.canonicalBytes,
      ),
    });
  }
  return Object.freeze({
    kind: "StoredContractByHash",
    contractHash: targetHash,
    entryPoint,
    args: args.facts,
    canonicalBytes: bytes(u8(1), hexBytes(targetHash, 32), text(entryPoint, `${label} entry point`), args.canonicalBytes),
  });
}

export function runtimeArgumentMap(
  args: readonly DeployRuntimeArgument[],
  expectedNames: readonly string[],
  label: string,
): Readonly<Record<string, DeployRuntimeArgument>> {
  if (
    args.length !== expectedNames.length ||
    args.some((argument, index) => argument.name !== expectedNames[index])
  ) {
    throw new Error(`${label} runtime argument order differs from the frozen interface`);
  }
  const result: Record<string, DeployRuntimeArgument> = Object.create(null);
  for (const argument of args) result[argument.name] = argument;
  return Object.freeze(result);
}

/** Return the exact bytesrepr vector signed inside a deploy executable. */
export function canonicalRuntimeArgumentsBytes(
  args: readonly DeployRuntimeArgument[],
  expectedNames: readonly string[],
  label: string,
): Uint8Array {
  runtimeArgumentMap(args, expectedNames, label);
  const encoded: Uint8Array[] = [u32le(args.length)];
  for (const argument of args) {
    encoded.push(
      text(argument.name, `${label} argument name`),
      vector(argument.bytes),
      clTypeBytes(argument.clType, `${label} ${argument.name}`),
    );
  }
  return bytes(...encoded);
}

export function verifyRuntimeArgumentPairs(
  value: unknown,
  expectedNames: readonly string[],
  label: string,
): Readonly<Record<string, DeployRuntimeArgument>> {
  const verified = runtimeArgs(value, label);
  return runtimeArgumentMap(verified.facts, expectedNames, label);
}

export function verifySignedDeployJson(
  value: unknown,
  expectation: Readonly<{
    deployHash: string;
    initiatorPublicKey: string;
    chainName?: "casper-test";
    exactlyOneApproval?: boolean;
  }>,
): SignedDeployJsonFacts {
  const deploy = record(value, "signed deploy JSON");
  exactOwnKeys(deploy, ["approvals", "hash", "header", "payment", "session"], "signed deploy JSON");
  const header = record(own(deploy, "header"), "deploy header");
  exactOwnKeys(
    header,
    ["account", "body_hash", "chain_name", "dependencies", "gas_price", "timestamp", "ttl"],
    "deploy header",
  );
  const initiator = parsePublicKey(own(header, "account"), "deploy initiator");
  const expectedInitiator = parsePublicKey(expectation.initiatorPublicKey, "expected deploy initiator");
  if (toHex(initiator.encoded) !== toHex(expectedInitiator.encoded)) {
    throw new Error("deploy initiator differs from configured role");
  }
  const timestamp = timestampMillis(own(header, "timestamp"));
  const ttl = ttlMillis(own(header, "ttl"));
  const gasPrice = parseUnsigned(own(header, "gas_price"), 64);
  const bodyHash = lowerHash(own(header, "body_hash"), "deploy body hash");
  const dependencies = own(header, "dependencies");
  if (!Array.isArray(dependencies) || dependencies.length > MAX_COLLECTION_ITEMS) {
    throw new Error("deploy dependencies must be a bounded list");
  }
  const dependencyBytes = dependencies.map((item) => hexBytes(lowerHash(item, "deploy dependency"), 32));
  const chainName = own(header, "chain_name");
  if (chainName !== (expectation.chainName ?? "casper-test")) {
    throw new Error("deploy chain must be exactly casper-test");
  }
  const headerBytes = bytes(
    initiator.encoded,
    littleUnsigned(timestamp, 8),
    littleUnsigned(ttl, 8),
    littleUnsigned(gasPrice, 8),
    hexBytes(bodyHash, 32),
    u32le(dependencyBytes.length),
    ...dependencyBytes,
    text(chainName, "deploy chain name"),
  );
  const computedDeployHash = blake2b256(headerBytes);
  const expectedHash = lowerHash(expectation.deployHash, "expected deploy hash");
  const suppliedHash = lowerHash(own(deploy, "hash"), "supplied deploy hash");
  if (toHex(computedDeployHash) !== expectedHash || suppliedHash !== expectedHash) {
    throw new Error("deploy hash differs from canonical header bytes");
  }

  const payment = executable(own(deploy, "payment"), "deploy payment");
  const session = executable(own(deploy, "session"), "deploy session");
  const computedBodyHash = blake2b256(bytes(payment.canonicalBytes, session.canonicalBytes));
  if (toHex(computedBodyHash) !== bodyHash) throw new Error("deploy body hash differs from executable bytes");

  const rawApprovals = own(deploy, "approvals");
  if (!Array.isArray(rawApprovals) || rawApprovals.length === 0 || rawApprovals.length > MAX_COLLECTION_ITEMS) {
    throw new Error("deploy approvals must be a bounded, non-empty list");
  }
  if ((expectation.exactlyOneApproval ?? true) && rawApprovals.length !== 1) {
    throw new Error("deploy must carry exactly one role approval");
  }
  const approvalBytes: Uint8Array[] = [u32le(rawApprovals.length)];
  const signers = new Set<string>();
  for (const raw of rawApprovals) {
    const approval = record(raw, "deploy approval");
    exactOwnKeys(approval, ["signer", "signature"], "deploy approval");
    const signer = parsePublicKey(own(approval, "signer"), "approval signer");
    const signerHex = toHex(signer.encoded);
    if (signers.has(signerHex)) throw new Error("deploy contains a duplicate approval signer");
    signers.add(signerHex);
    if (typeof own(approval, "signature") !== "string") throw new Error("approval signature is missing");
    const signature = caseInsensitiveHexBytes(own(approval, "signature"), "approval signature");
    if (signature.length !== 65 || signature[0] !== signer.algorithm) {
      throw new Error("approval signature algorithm or length is invalid");
    }
    if (!validApproval(signer, computedDeployHash, signature.slice(1))) {
      throw new Error("approval signature is invalid");
    }
    approvalBytes.push(signer.encoded, signature);
  }
  if (!signers.has(toHex(initiator.encoded))) {
    throw new Error("deploy initiator did not approve the deploy");
  }
  const canonicalBytes = bytes(
    headerBytes,
    computedDeployHash,
    payment.canonicalBytes,
    session.canonicalBytes,
    ...approvalBytes,
  );
  if (canonicalBytes.length > MAX_DEPLOY_BYTES) throw new Error("canonical deploy exceeds size limit");
  return Object.freeze({
    deployHash: expectedHash,
    bodyHash,
    chainName: "casper-test",
    timestampMs: timestamp.toString(),
    ttlMs: ttl.toString(),
    gasPrice: gasPrice.toString(),
    initiatorPublicKey: toHex(initiator.encoded),
    initiatorAccountHash: accountHashFromPublicKey(toHex(initiator.encoded)),
    payment,
    session,
    approvalSigners: Object.freeze([...signers]),
    canonicalBytes,
  });
}
