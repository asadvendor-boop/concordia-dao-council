/**
 * Canonical Concordia hash encodings for the official x402 path.
 *
 * Per handoff/G1_INTERFACE_SPEC.md §2 and §6:
 *  - BLAKE2b-256 means RFC 7693 BLAKE2b configured directly with
 *    digest_size=32, empty key/salt/personalization (NOT a truncated
 *    64-byte digest).
 *  - Every domain separator is exact ASCII followed by one 0x00 byte.
 *  - String/Bytes encode as u32_be(byte_length) || exact bytes ("lp").
 *  - U256 encodes as exactly 32 unsigned big-endian bytes.
 *
 * blakejs implements RFC 7693 BLAKE2b with a configurable output length,
 * which is the digest_size parameter — cross-checked against Python
 * hashlib.blake2b(digest_size=32) golden vectors in test/hashes.test.ts.
 */

import blake from "blakejs";

export const U256_MAX = (1n << 256n) - 1n;
export const U64_MAX = (1n << 64n) - 1n;
export const U32_MAX = (1n << 32n) - 1n;

function separator(ascii: string): Buffer {
  for (let i = 0; i < ascii.length; i++) {
    const c = ascii.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) throw new Error("non_ascii_separator");
  }
  return Buffer.concat([Buffer.from(ascii, "ascii"), Buffer.from([0x00])]);
}

/** §2 authoritative separators (exact ASCII + one 0x00 byte). */
export const SEPARATORS = {
  resourceUrl: separator("CONCORDIA_RESOURCE_URL_V1"),
  paymentRequirements: separator("CONCORDIA_PAYMENT_REQUIREMENTS_V1"),
  signedPaymentPayload: separator("CONCORDIA_SIGNED_PAYMENT_PAYLOAD_V1"),
  x402Report: separator("CONCORDIA_X402_REPORT_V1"),
} as const;

export function blake2b256(data: Buffer): Buffer {
  return Buffer.from(blake.blake2b(data, undefined, 32));
}

export function u8(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new Error("u8_out_of_range");
  }
  return Buffer.from([value]);
}

export function u32be(value: number | bigint): Buffer {
  const v = BigInt(value);
  if (v < 0n || v > U32_MAX) throw new Error("u32_out_of_range");
  const b = Buffer.alloc(4);
  b.writeUInt32BE(Number(v));
  return b;
}

export function u64be(value: bigint): Buffer {
  if (value < 0n || value > U64_MAX) throw new Error("u64_out_of_range");
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(value);
  return b;
}

export function u256be(value: bigint): Buffer {
  if (value < 0n || value > U256_MAX) throw new Error("u256_out_of_range");
  const hex = value.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

/** Length-prefixed bytes: u32_be(byte_length) || exact bytes. */
export function lp(data: Buffer): Buffer {
  return Buffer.concat([u32be(data.length), data]);
}

/** Length-prefixed exact ASCII string. Rejects non-ASCII and embedded NUL. */
export function lpAscii(value: string): Buffer {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x00 || c > 0x7f) throw new Error("non_ascii_string");
  }
  return lp(Buffer.from(value, "ascii"));
}

function require32(name: string, b: Buffer): void {
  if (b.length !== 32) throw new Error(`${name}_not_32_bytes`);
}

/** §6: resource_url_hash = BLAKE2b-256("CONCORDIA_RESOURCE_URL_V1\0" || lp(url)). */
export function resourceUrlHash(exactResourceUrlAscii: string): Buffer {
  return blake2b256(
    Buffer.concat([SEPARATORS.resourceUrl, lpAscii(exactResourceUrlAscii)]),
  );
}

/** §6: report_hash = BLAKE2b-256("CONCORDIA_X402_REPORT_V1\0" || lp(bytes)). */
export function reportHash(exactReportBytes: Buffer): Buffer {
  return blake2b256(Buffer.concat([SEPARATORS.x402Report, lp(exactReportBytes)]));
}

export interface PaymentRequirementsHashInput {
  scheme: string;
  caip2Network: string;
  wcsprPackage: Buffer;
  value: bigint;
  payeeAccountHash: Buffer;
  maxTimeoutSeconds: number;
  tokenName: string;
  eip712DomainVersion: string;
  tokenDecimals: number;
  tokenSymbol: string;
}

/** §6 payment_requirements_hash typed binary preimage. */
export function paymentRequirementsHash(i: PaymentRequirementsHashInput): Buffer {
  require32("wcspr_package", i.wcsprPackage);
  require32("payee_account_hash", i.payeeAccountHash);
  return blake2b256(
    Buffer.concat([
      SEPARATORS.paymentRequirements,
      lpAscii(i.scheme),
      lpAscii(i.caip2Network),
      i.wcsprPackage,
      u256be(i.value),
      i.payeeAccountHash,
      u32be(i.maxTimeoutSeconds),
      lpAscii(i.tokenName),
      lpAscii(i.eip712DomainVersion),
      u8(i.tokenDecimals),
      lpAscii(i.tokenSymbol),
    ]),
  );
}

export interface SignedPaymentPayloadHashInput {
  x402Version: number;
  resourceUrl: string;
  resourceDescription: string;
  resourceMimeType: string;
  paymentRequirementsHash: Buffer;
  signature: Buffer;
  canonicalPublicKey: Buffer;
  payerAccountHash: Buffer;
  payeeAccountHash: Buffer;
  value: bigint;
  validAfter: bigint;
  validBefore: bigint;
  eip712AuthNonce: Buffer;
}

/**
 * §6 signed_payment_payload_hash typed binary preimage. The trailing
 * u32_be(0) commits to an empty extensions map.
 */
export function signedPaymentPayloadHash(i: SignedPaymentPayloadHashInput): Buffer {
  require32("payment_requirements_hash", i.paymentRequirementsHash);
  require32("payer_account_hash", i.payerAccountHash);
  require32("payee_account_hash", i.payeeAccountHash);
  require32("eip712_auth_nonce", i.eip712AuthNonce);
  if (i.signature.length !== 65) throw new Error("signature_not_65_bytes");
  return blake2b256(
    Buffer.concat([
      SEPARATORS.signedPaymentPayload,
      u32be(i.x402Version),
      lpAscii(i.resourceUrl),
      lpAscii(i.resourceDescription),
      lpAscii(i.resourceMimeType),
      i.paymentRequirementsHash,
      lp(i.signature),
      i.canonicalPublicKey,
      i.payerAccountHash,
      i.payeeAccountHash,
      u256be(i.value),
      u64be(i.validAfter),
      u64be(i.validBefore),
      i.eip712AuthNonce,
      u32be(0),
    ]),
  );
}
