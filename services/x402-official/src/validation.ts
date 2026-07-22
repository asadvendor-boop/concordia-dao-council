/**
 * Strict local validation for verify/settle requests.
 *
 * Everything here runs BEFORE any ledger claim and BEFORE any credentialed
 * upstream call (§6, §12). All parsing is canonical and exact: no trimming,
 * no normalization, no substring matching, no >= comparisons.
 */

import casperSdk from "casper-js-sdk";

import { invalidRequest } from "./errors.js";
import {
  U64_MAX,
  U256_MAX,
  blake2b256,
  paymentRequirementsHash,
  signedPaymentPayloadHash,
} from "./hashes.js";
import type { ServiceConfig } from "./config.js";
import type {
  AuthorizationWire,
  ConfiguredResource,
  ExactPayloadWire,
  PaymentPayloadWire,
  PaymentRequirementsWire,
  ResourceInfoWire,
  ValidatedPayment,
  VerifySettleRequestWire,
} from "./types.js";

const CANONICAL_DECIMAL_RE = /^(?:0|[1-9][0-9]*)$/;
const ACCOUNT_ADDRESS_RE = /^00[0-9a-f]{64}$/;
const LOWER_HEX_RE = /^[0-9a-f]*$/;
const UNRESERVED = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    .split("")
    .map((c) => c.charCodeAt(0)),
);

/**
 * Canonical unsigned decimal per §6: no sign, whitespace, leading zero
 * (except "0" itself), decimal point, or exponent. Returns the parsed bigint.
 */
export function parseCanonicalDecimal(
  value: unknown,
  max: bigint,
  code: string,
): bigint {
  if (typeof value !== "string" || !CANONICAL_DECIMAL_RE.test(value)) {
    throw invalidRequest(code);
  }
  const parsed = BigInt(value);
  if (parsed > max) throw invalidRequest(code);
  return parsed;
}

export function parseCanonicalU256(value: unknown, code: string): bigint {
  return parseCanonicalDecimal(value, U256_MAX, code);
}

export function parseCanonicalU64(value: unknown, code: string): bigint {
  return parseCanonicalDecimal(value, U64_MAX, code);
}

/** "00" + 64 lowercase hex → 32 raw payee/payer account-hash bytes. */
export function parseAccountAddress(value: unknown, code: string): Buffer {
  if (typeof value !== "string" || !ACCOUNT_ADDRESS_RE.test(value)) {
    throw invalidRequest(code);
  }
  return Buffer.from(value.slice(2), "hex");
}

export function isLowercaseHex(value: string, byteLength?: number): boolean {
  if (!LOWER_HEX_RE.test(value) || value.length % 2 !== 0) return false;
  if (byteLength !== undefined && value.length !== byteLength * 2) return false;
  return true;
}

/**
 * §6 strict canonical HTTPS URL validation. Rejects non-canonical input and
 * NEVER normalizes: lowercase https scheme, lowercase ASCII DNS host, no
 * userinfo/fragment/explicit port/backslash/control/NUL, non-empty path, no
 * dot segments, uppercase percent-escape hex, unreserved characters not
 * percent-encoded. Query byte order and trailing slash are significant and
 * left untouched.
 */
export function validateCanonicalHttpsUrl(url: string): void {
  const fail = () => invalidRequest("invalid_resource_url");
  if (url.length === 0 || url.length > 2048) throw fail();
  for (let i = 0; i < url.length; i++) {
    const c = url.charCodeAt(i);
    // Printable ASCII excluding space; no control, NUL, DEL, non-ASCII.
    if (c <= 0x20 || c >= 0x7f) throw fail();
    if (c === 0x5c) throw fail(); // backslash
  }
  if (url.includes("#")) throw fail(); // fragment
  const prefix = "https://";
  if (!url.startsWith(prefix)) throw fail();
  const rest = url.slice(prefix.length);
  const slash = rest.indexOf("/");
  if (slash === -1 || slash === 0) throw fail(); // empty host or empty path
  const host = rest.slice(0, slash);
  if (host.includes("@") || host.includes(":")) throw fail(); // userinfo / port
  const labels = host.split(".");
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) throw fail();
    if (!/^[a-z0-9-]+$/.test(label)) throw fail();
    if (label.startsWith("-") || label.endsWith("-")) throw fail();
  }
  const pathAndQuery = rest.slice(slash);
  const q = pathAndQuery.indexOf("?");
  const path = q === -1 ? pathAndQuery : pathAndQuery.slice(0, q);
  for (const segment of path.split("/")) {
    if (segment === "." || segment === "..") throw fail(); // dot segments
  }
  // Percent escapes: uppercase hex; unreserved bytes must not be escaped.
  for (let i = 0; i < pathAndQuery.length; i++) {
    if (pathAndQuery[i] !== "%") continue;
    const escape = pathAndQuery.slice(i + 1, i + 3);
    if (!/^[0-9A-F]{2}$/.test(escape)) throw fail();
    if (UNRESERVED.has(parseInt(escape, 16))) throw fail();
    i += 2;
  }
}

function requireExactKeys(
  obj: Record<string, unknown>,
  required: string[],
  optional: string[],
  code: string,
): void {
  for (const key of required) {
    if (!(key in obj)) throw invalidRequest(code);
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) throw invalidRequest(code);
  }
}

function requireObject(value: unknown, code: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidRequest(code);
  }
  return value as Record<string, unknown>;
}

function requireAsciiString(
  value: unknown,
  code: string,
  maxLength = 4096,
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw invalidRequest(code);
  }
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) throw invalidRequest(code);
  }
  return value;
}

/** Strict structural equality with identical key sets (order-insensitive). */
export function structurallyEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((item, i) => structurallyEqual(item, b[i]));
  }
  const ka = Object.keys(a as Record<string, unknown>).sort();
  const kb = Object.keys(b as Record<string, unknown>).sort();
  if (ka.length !== kb.length || ka.some((k, i) => k !== kb[i])) return false;
  return ka.every((k) =>
    structurallyEqual(
      (a as Record<string, unknown>)[k],
      (b as Record<string, unknown>)[k],
    ),
  );
}

/** Extensions must be absent or an exactly-empty object (§6, schemas). */
function validateExtensionsAbsentOrEmpty(
  obj: Record<string, unknown>,
  code: string,
): void {
  if (!("extensions" in obj)) return;
  const ext = requireObject(obj["extensions"], code);
  if (Object.keys(ext).length !== 0) throw invalidRequest(code);
}

export function validateResourceInfo(value: unknown): ResourceInfoWire {
  const obj = requireObject(value, "invalid_resource_object");
  requireExactKeys(obj, ["url", "description", "mimeType"], [], "invalid_resource_object");
  const url = requireAsciiString(obj["url"], "invalid_resource_object", 2048);
  const description = requireAsciiString(obj["description"], "invalid_resource_object", 1024);
  const mimeType = requireAsciiString(obj["mimeType"], "invalid_resource_object", 128);
  validateCanonicalHttpsUrl(url);
  return { url, description, mimeType };
}

export function validatePaymentRequirements(
  value: unknown,
  config: ServiceConfig,
  resource: ConfiguredResource,
): PaymentRequirementsWire {
  const code = "invalid_payment_requirements";
  const obj = requireObject(value, code);
  requireExactKeys(
    obj,
    ["scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"],
    [],
    code,
  );
  if (obj["scheme"] !== "exact") throw invalidRequest(code);
  if (obj["network"] !== config.network) throw invalidRequest(code);
  if (obj["asset"] !== config.wcsprPackageHash) throw invalidRequest(code);
  const amount = parseCanonicalU256(obj["amount"], code);
  if (amount < 1n) throw invalidRequest(code);
  parseAccountAddress(obj["payTo"], code);
  const timeout = obj["maxTimeoutSeconds"];
  if (
    typeof timeout !== "number" ||
    !Number.isInteger(timeout) ||
    timeout < 1 ||
    timeout > 4294967295
  ) {
    throw invalidRequest(code);
  }
  const extra = requireObject(obj["extra"], code);
  requireExactKeys(extra, ["name", "version", "decimals", "symbol"], [], code);
  if (
    extra["name"] !== config.tokenName ||
    extra["version"] !== config.tokenDomainVersion ||
    extra["decimals"] !== String(config.tokenDecimals) ||
    extra["symbol"] !== config.tokenSymbol
  ) {
    throw invalidRequest(code);
  }
  // Binding to the configured resource this service issued requirements for.
  if (obj["amount"] !== resource.amount) throw invalidRequest("requirements_amount_mismatch");
  if (obj["payTo"] !== resource.payTo) throw invalidRequest("requirements_payto_mismatch");
  if (timeout !== resource.maxTimeoutSeconds) {
    throw invalidRequest("requirements_timeout_mismatch");
  }
  return {
    scheme: "exact",
    network: config.network,
    asset: config.wcsprPackageHash,
    amount: obj["amount"] as string,
    payTo: obj["payTo"] as string,
    maxTimeoutSeconds: timeout,
    extra: extra as Record<string, string>,
  };
}

const ALGORITHM_BY_TAG: Record<number, { name: string; rawLength: number }> = {
  0x01: { name: "ed25519", rawLength: 32 },
  0x02: { name: "secp256k1", rawLength: 33 },
};

interface ParsedSignaturePayload {
  signature: Buffer;
  publicKeyBytes: Buffer;
  payerAccountHash: Buffer;
}

/**
 * §6 signature/public-key discipline:
 *  - signature is exactly 65 raw bytes from 130 bare lowercase hex chars;
 *  - the leading signature byte must equal the public-key algorithm tag;
 *  - PublicKey parses via the pinned casper-js-sdk and accountHash() must
 *    equal the typed payer / authorization.from account hash;
 *  - the account-hash derivation is independently cross-checked as
 *    BLAKE2b-256(algorithm_name_ascii || 0x00 || raw_key_bytes), never
 *    tag||key.
 */
function validateSignatureAndKey(
  payload: ExactPayloadWire,
  payerAccountHash: Buffer,
): ParsedSignaturePayload {
  const sigHex = payload.signature;
  if (typeof sigHex !== "string" || !isLowercaseHex(sigHex, 65)) {
    throw invalidRequest("invalid_signature_encoding");
  }
  const signature = Buffer.from(sigHex, "hex");
  const keyHex = payload.publicKey;
  if (typeof keyHex !== "string" || !LOWER_HEX_RE.test(keyHex) || keyHex.length < 2) {
    throw invalidRequest("invalid_public_key_encoding");
  }
  const publicKeyBytes = Buffer.from(keyHex, "hex");
  const tag = publicKeyBytes[0] as number;
  const algorithm = ALGORITHM_BY_TAG[tag];
  if (!algorithm || publicKeyBytes.length !== algorithm.rawLength + 1) {
    throw invalidRequest("invalid_public_key_encoding");
  }
  if (signature[0] !== tag) {
    throw invalidRequest("signature_algorithm_mismatch");
  }
  let sdkAccountHashHex: string;
  try {
    const parsed = casperSdk.PublicKey.fromHex(keyHex);
    sdkAccountHashHex = parsed.accountHash().toHex();
  } catch {
    throw invalidRequest("invalid_public_key_encoding");
  }
  const payerHex = payerAccountHash.toString("hex");
  if (sdkAccountHashHex !== payerHex) {
    throw invalidRequest("public_key_payer_mismatch");
  }
  // Independent cross-check of Casper's AccountHash::from_public_key.
  const derived = blake2b256(
    Buffer.concat([
      Buffer.from(algorithm.name, "ascii"),
      Buffer.from([0x00]),
      publicKeyBytes.subarray(1),
    ]),
  );
  if (!derived.equals(payerAccountHash)) {
    throw invalidRequest("account_hash_derivation_mismatch");
  }
  return { signature, publicKeyBytes, payerAccountHash };
}

function validateAuthorization(
  value: unknown,
  requirements: PaymentRequirementsWire,
): AuthorizationWire {
  const code = "invalid_authorization";
  const obj = requireObject(value, code);
  requireExactKeys(
    obj,
    ["from", "to", "value", "validAfter", "validBefore", "nonce"],
    [],
    code,
  );
  parseAccountAddress(obj["from"], "invalid_authorization_from");
  parseAccountAddress(obj["to"], "invalid_authorization_to");
  if (obj["from"] === obj["to"]) throw invalidRequest("payer_equals_payee");
  if (obj["to"] !== requirements.payTo) throw invalidRequest("payto_mismatch");
  const authValue = parseCanonicalU256(obj["value"], "invalid_authorization_value");
  if (authValue < 1n) throw invalidRequest("invalid_authorization_value");
  const requiredAmount = parseCanonicalU256(requirements.amount, "invalid_payment_requirements");
  if (authValue !== requiredAmount) throw invalidRequest("authorization_amount_mismatch");
  const validAfter = parseCanonicalU64(obj["validAfter"], "invalid_valid_after");
  const validBefore = parseCanonicalU64(obj["validBefore"], "invalid_valid_before");
  if (validBefore <= validAfter) throw invalidRequest("invalid_validity_window");
  const nonce = obj["nonce"];
  if (typeof nonce !== "string" || !isLowercaseHex(nonce, 32)) {
    throw invalidRequest("invalid_authorization_nonce");
  }
  if (/^0+$/.test(nonce)) throw invalidRequest("invalid_authorization_nonce");
  return obj as unknown as AuthorizationWire;
}

/**
 * Full local validation of a POST /verify or POST /settle request body.
 * Returns the validated payment with both bound hashes computed from the
 * validated request (never caller-supplied).
 */
export function validateVerifySettleRequest(
  body: unknown,
  config: ServiceConfig,
): ValidatedPayment {
  const outer = requireObject(body, "invalid_request_body");
  requireExactKeys(
    outer,
    ["x402Version", "paymentPayload", "paymentRequirements"],
    [],
    "invalid_request_body",
  );
  if (outer["x402Version"] !== 2) throw invalidRequest("unsupported_x402_version");

  const payloadObj = requireObject(outer["paymentPayload"], "invalid_payment_payload");
  requireExactKeys(
    payloadObj,
    ["x402Version", "resource", "accepted", "payload"],
    ["extensions"],
    "invalid_payment_payload",
  );
  if (payloadObj["x402Version"] !== 2) throw invalidRequest("unsupported_x402_version");
  validateExtensionsAbsentOrEmpty(payloadObj, "invalid_payment_payload_extensions");

  const resourceInfo = validateResourceInfo(payloadObj["resource"]);
  const resource = config.resources.find(
    (r) =>
      r.url === resourceInfo.url &&
      r.description === resourceInfo.description &&
      r.mimeType === resourceInfo.mimeType,
  );
  if (!resource) throw invalidRequest("unknown_resource");

  const requirements = validatePaymentRequirements(
    outer["paymentRequirements"],
    config,
    resource,
  );
  // paymentPayload.accepted must be field-for-field equal to the outer
  // paymentRequirements, including extras (§6).
  if (!structurallyEqual(payloadObj["accepted"], outer["paymentRequirements"])) {
    throw invalidRequest("accepted_requirements_mismatch");
  }

  const inner = requireObject(payloadObj["payload"], "invalid_exact_payload");
  requireExactKeys(inner, ["signature", "publicKey", "authorization"], [], "invalid_exact_payload");
  const authorization = validateAuthorization(inner["authorization"], requirements);
  const payerAccountHash = parseAccountAddress(authorization.from, "invalid_authorization_from");
  const payeeAccountHash = parseAccountAddress(authorization.to, "invalid_authorization_to");
  const parsedSig = validateSignatureAndKey(inner as unknown as ExactPayloadWire, payerAccountHash);

  const valueAtomic = parseCanonicalU256(authorization.value, "invalid_authorization_value");
  const validAfter = parseCanonicalU64(authorization.validAfter, "invalid_valid_after");
  const validBefore = parseCanonicalU64(authorization.validBefore, "invalid_valid_before");
  const nonce = Buffer.from(authorization.nonce, "hex");

  const requirementsHash = paymentRequirementsHash({
    scheme: requirements.scheme,
    caip2Network: requirements.network,
    wcsprPackage: Buffer.from(config.wcsprPackageHash, "hex"),
    value: valueAtomic,
    payeeAccountHash,
    maxTimeoutSeconds: requirements.maxTimeoutSeconds,
    tokenName: config.tokenName,
    eip712DomainVersion: config.tokenDomainVersion,
    tokenDecimals: config.tokenDecimals,
    tokenSymbol: config.tokenSymbol,
  });
  const payloadHash = signedPaymentPayloadHash({
    x402Version: 2,
    resourceUrl: resourceInfo.url,
    resourceDescription: resourceInfo.description,
    resourceMimeType: resourceInfo.mimeType,
    paymentRequirementsHash: requirementsHash,
    signature: parsedSig.signature,
    canonicalPublicKey: parsedSig.publicKeyBytes,
    payerAccountHash,
    payeeAccountHash,
    value: valueAtomic,
    validAfter,
    validBefore,
    eip712AuthNonce: nonce,
  });

  return {
    resource,
    requirements,
    paymentPayload: payloadObj as unknown as PaymentPayloadWire,
    valueAtomic,
    payerAccountHash,
    payeeAccountHash,
    signature: parsedSig.signature,
    publicKeyBytes: parsedSig.publicKeyBytes,
    nonce,
    validAfter,
    validBefore,
    paymentRequirementsHashHex: requirementsHash.toString("hex"),
    signedPaymentPayloadHashHex: payloadHash.toString("hex"),
  } satisfies ValidatedPayment;
}

export type { VerifySettleRequestWire };
