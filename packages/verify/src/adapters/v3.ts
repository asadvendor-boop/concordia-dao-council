import {
  DOMAINS,
  EncodingError,
  HEADER_SCHEMA,
  NATIVE_CORE_NAMES,
  NATIVE_SCHEMA,
  actionId,
  blake2b256,
  concatBytes,
  encodeRecord,
  fieldsToRecord,
  hexBytes,
  isRecord,
  parseUnsigned,
  toHex,
  transferId,
  validateHeader,
  validateNativeBody,
  type FieldSchema,
} from "../encoders.js";

export type NativeEnvelopeMaterialV3 = Readonly<{
  actionId: string;
  transferId: string;
  envelopeHash: string;
  headerHex: string;
  bodyHex: string;
  actionCoreHex: string;
}>;

const CORE_NAMES = new Set<string>(NATIVE_CORE_NAMES);
const NATIVE_CORE_SCHEMA: FieldSchema = NATIVE_SCHEMA.filter(([name]) => CORE_NAMES.has(name));

function typedRecord(input: unknown, schema: FieldSchema, label: string): Record<string, unknown> {
  if (Array.isArray(input)) return fieldsToRecord(input, schema);
  if (!isRecord(input)) {
    throw new EncodingError("InvalidFields", `${label} must be typed fields or an exact named map`);
  }
  const expected = schema.map(([name]) => name);
  const actual = Object.keys(input);
  if (
    actual.length !== expected.length ||
    [...actual].sort().some((name, index) => name !== [...expected].sort()[index]) ||
    expected.some((name) => !Object.hasOwn(input, name))
  ) {
    throw new EncodingError("InvalidFields", `${label} must contain exactly the frozen fields`);
  }
  return { ...input };
}

/**
 * Recompute one typed NativeTransferV1 authorization entirely from frozen G1
 * fields.  This proves the binary material only; callers must separately prove
 * package identity, on-chain readback, and finality from raw node transcripts.
 */
export function verifyNativeEnvelopeMaterialV3(input: {
  header: unknown;
  body: unknown;
}): NativeEnvelopeMaterialV3 {
  if (!Object.hasOwn(input, "header") || !Object.hasOwn(input, "body")) {
    throw new Error("v3 material input requires own header and body fields");
  }
  const header = typedRecord(input.header, HEADER_SCHEMA, "v3 header");
  const body = typedRecord(input.body, NATIVE_SCHEMA, "v3 native body");
  validateHeader(header);
  validateNativeBody(header, body);

  const actionKind = Number(parseUnsigned(header.action_kind, 8));
  const actionCore = encodeRecord(body, NATIVE_CORE_SCHEMA);
  const computedActionId = actionId(actionKind, body.action_nonce, actionCore);
  const suppliedActionId = toHex(hexBytes(header.action_id, 32));
  if (computedActionId !== suppliedActionId) {
    throw new Error("action_id does not match the recomputed NativeTransferV1 action");
  }

  const derivedTransfer = transferId(
    String(header.proposal_id),
    header.proposal_nonce,
    computedActionId,
  );
  if (parseUnsigned(body.transfer_id, 64) !== BigInt(derivedTransfer.decimal)) {
    throw new Error("transfer_id does not match the recomputed proposal/action binding");
  }

  const headerBytes = encodeRecord(header, HEADER_SCHEMA);
  const bodyBytes = encodeRecord(body, NATIVE_SCHEMA);
  const envelopeHash = toHex(
    blake2b256(concatBytes(DOMAINS.envelope, headerBytes, bodyBytes)),
  );

  return Object.freeze({
    actionId: computedActionId,
    transferId: derivedTransfer.decimal,
    envelopeHash,
    headerHex: toHex(headerBytes),
    bodyHex: toHex(bodyBytes),
    actionCoreHex: toHex(actionCore),
  });
}
