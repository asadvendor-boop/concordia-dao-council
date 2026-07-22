import {
  DOMAINS,
  EVIDENCE_SCHEMA,
  EncodingError,
  HEADER_SCHEMA,
  NATIVE_CORE_NAMES,
  NATIVE_SCHEMA,
  X402_CORE_NAMES,
  X402_SCHEMA,
  actionId,
  asString,
  blake2b256,
  concatBytes,
  encodeEnvelopeHeader,
  encodeEvidenceManifest,
  encodeExecutionArguments,
  encodeMetadataManifest,
  encodeOfficialX402Settlement,
  encodeRecord,
  fieldsToRecord,
  fixedUnsigned,
  hexBytes,
  isRecord,
  lengthPrefixed,
  toHex,
  transferId,
  validateHeader,
  validateNativeBody,
  validateX402Body,
  type FieldSchema,
} from "./encoders.js";

export type VerificationCheck = {
  name: string;
  passed: boolean;
  expected?: string | number | boolean | null;
  observed?: string | number | boolean | null;
};

export type GoldenVerificationResult = {
  vectorId: string;
  status: "verified" | "invalid";
  valid: boolean;
  canonicalHex: string | null;
  checks: VerificationCheck[];
  error?: { name: string; code: number | null; message: string };
};

export type GoldenVectorContext = {
  vectors?: ReadonlyMap<string, unknown> | Readonly<Record<string, unknown>>;
};

/** Exact vector documents bundled with the published Node package. */
export const FROZEN_VECTOR_DIRECTORY_URL = new URL("./vectors/", import.meta.url);

type Material = {
  canonical: Uint8Array;
  header?: Uint8Array;
  core?: Uint8Array;
  envelopeHash?: string;
  actionId?: string;
  transferId?: string;
  transferDigest?: string;
  rootHash?: string;
  envelopePreimage?: Uint8Array;
  caseMaterials?: Material[];
  extraChecks?: VerificationCheck[];
};

export function verifyGoldenVector(
  value: unknown,
  context: GoldenVectorContext = {},
): GoldenVerificationResult {
  const vector = requireRecord(value, "golden vector");
  const vectorId = asString(vector.vector_id);
  const declaredValid = vector.valid === true;
  const checks: VerificationCheck[] = [];
  try {
    const material = recompute(vector, context);
    if (!declaredValid) {
      return {
        vectorId,
        status: "invalid",
        valid: false,
        canonicalHex: toHex(material.canonical),
        checks: [{ name: "declared_invalid_vector_rejected", passed: false }],
        error: {
          name: "ExpectedInvalidVector",
          code: null,
          message: "vector declared invalid but canonical encoding succeeded",
        },
      };
    }

    addCheck(checks, "canonical_hex", vector.canonical_hex, toHex(material.canonical));
    addCheck(checks, "canonical_length", vector.canonical_length, material.canonical.length);
    verifyRecordedHashes(vector, material, checks);
    if (material.extraChecks) checks.push(...material.extraChecks);
    const passed = checks.length > 0 && checks.every((check) => check.passed);
    return {
      vectorId,
      status: passed ? "verified" : "invalid",
      valid: passed,
      canonicalHex: toHex(material.canonical),
      checks,
      ...(passed
        ? {}
        : {
            error: {
              name: "GoldenVectorMismatch",
              code: null,
              message: "one or more independently recomputed values differ",
            },
          }),
    };
  } catch (error) {
    const normalized = normalizeError(error);
    if (!declaredValid) {
      const expected = requireRecord(vector.expected_error, "expected_error");
      const expectedCode = expected.code === null ? null : Number(expected.code);
      const matches = normalized.name === expected.name && normalized.code === expectedCode;
      return {
        vectorId,
        status: "invalid",
        valid: false,
        canonicalHex: null,
        checks: [
          {
            name: "expected_invalid_vector_error",
            passed: matches,
            expected: `${String(expected.name)}:${String(expectedCode)}`,
            observed: `${normalized.name}:${String(normalized.code)}`,
          },
        ],
        error: normalized,
      };
    }
    return {
      vectorId,
      status: "invalid",
      valid: false,
      canonicalHex: null,
      checks: [{ name: "canonical_recomputation_completed", passed: false }],
      error: normalized,
    };
  }
}

function recompute(vector: Record<string, unknown>, context: GoldenVectorContext): Material {
  const kind = asString(vector.kind);
  const input = requireRecord(vector.typed_input, "typed_input");
  switch (kind) {
    case "envelope_header_v3": {
      const fields = input.fields;
      const values = fieldsToRecord(fields, HEADER_SCHEMA);
      validateHeader(values);
      return { canonical: encodeEnvelopeHeader(fields) };
    }
    case "native_transfer_v1":
    case "native_transfer_v1_relationship":
      return recomputeNative(input, vector, context);
    case "official_x402_settlement_v1":
    case "official_x402_settlement_v1_relationship":
      return recomputeX402(input, vector, context);
    case "preauthorization_evidence_manifest_v1": {
      const encoded = encodeEvidenceManifest(input);
      return {
        canonical: encoded.canonical,
        rootHash: toHex(blake2b256(concatBytes(DOMAINS.evidence, encoded.canonical))),
        extraChecks: checkOrder(vector.canonical_entry_order, encoded.order),
      };
    }
    case "authorized_metadata_manifest_v1": {
      const encoded = encodeMetadataManifest(input);
      return {
        canonical: encoded.canonical,
        rootHash: toHex(blake2b256(concatBytes(DOMAINS.metadata, encoded.canonical))),
        extraChecks: checkOrder(vector.canonical_entry_order, encoded.order),
      };
    }
    case "execution_argument_manifest_v1": {
      const canonical = encodeExecutionArguments(input);
      return {
        canonical,
        rootHash: toHex(blake2b256(concatBytes(DOMAINS.execArgs, canonical))),
      };
    }
    default:
      throw new EncodingError("UnknownVectorKind", `unsupported golden vector kind ${kind}`);
  }
}

function recomputeNative(
  input: Record<string, unknown>,
  vector: Record<string, unknown>,
  context: GoldenVectorContext,
): Material {
  const cases = Array.isArray(input.cases) ? input.cases : [input];
  const materials = cases.map((entry) => nativeMaterial(requireRecord(entry, "native case")));
  const selected = materials.at(-1);
  if (!selected) throw new EncodingError("InvalidFields", "native vector contains no cases");
  const extraChecks: VerificationCheck[] = [];
  let comparisonMaterials = materials;
  if (materials.length === 1 && isRecord(vector.comparison)) {
    const baseline = contextVector(context, "GV-NT-01");
    if (baseline && isRecord(baseline.typed_input)) {
      comparisonMaterials = [nativeMaterial(baseline.typed_input), selected];
    }
  }
  const [left, right] = comparisonMaterials;
  if (left && right && isRecord(vector.comparison) && isRecord(vector.comparison.assertions)) {
    verifyRelationshipAssertions(vector.comparison.assertions, left, right, extraChecks);
  }
  return { ...selected, caseMaterials: materials, extraChecks };
}

function nativeMaterial(input: Record<string, unknown>): Material {
  const header = fieldsToRecord(input.header, HEADER_SCHEMA);
  const body = fieldsToRecord(input.body, NATIVE_SCHEMA);
  validateHeader(header);
  validateNativeBody(header, body);
  const coreSchema = NATIVE_SCHEMA.filter(([name]) => NATIVE_CORE_NAMES.includes(name));
  const core = encodeRecord(body, coreSchema);
  const computedActionId = actionId(1, body.action_nonce, core);
  const computedTransfer = transferId(asString(header.proposal_id), header.proposal_nonce, computedActionId);
  if (header.action_id !== computedActionId) {
    throw new EncodingError("InvalidActionField", "header action_id does not match native action core", 16);
  }
  if (String(body.transfer_id) !== computedTransfer.decimal) {
    throw new EncodingError("InvalidActionField", "native transfer_id does not match proposal binding", 16);
  }
  const headerBytes = encodeRecord(header, HEADER_SCHEMA);
  const bodyBytes = encodeRecord(body, NATIVE_SCHEMA);
  const envelopeHash = toHex(
    blake2b256(concatBytes(DOMAINS.envelope, headerBytes, bodyBytes)),
  );
  const envelopePreimage = concatBytes(DOMAINS.envelope, headerBytes, bodyBytes);
  return {
    canonical: bodyBytes,
    header: headerBytes,
    core,
    actionId: computedActionId,
    transferId: computedTransfer.decimal,
    transferDigest: computedTransfer.digestHex,
    envelopeHash,
    envelopePreimage,
  };
}

function recomputeX402(
  input: Record<string, unknown>,
  vector: Record<string, unknown>,
  context: GoldenVectorContext,
): Material {
  if (!Array.isArray(input.header)) {
    const body = fieldsToRecord(input.body, X402_SCHEMA);
    validateX402Body(body);
    return { canonical: encodeOfficialX402Settlement(input.body) };
  }
  const header = fieldsToRecord(input.header, HEADER_SCHEMA);
  const body = fieldsToRecord(input.body, X402_SCHEMA);
  validateHeader(header);
  validateX402Body(body, header);
  const x402CoreNames = new Set<string>(X402_CORE_NAMES);
  const coreSchema = X402_SCHEMA.filter(([name]) => x402CoreNames.has(name));
  const core = encodeRecord(body, coreSchema);
  const computedActionId = actionId(2, body.action_nonce, core);
  if (header.action_id !== computedActionId) {
    throw new EncodingError("InvalidActionField", "header action_id does not match x402 action core", 16);
  }
  const headerBytes = encodeRecord(header, HEADER_SCHEMA);
  const bodyBytes = encodeRecord(body, X402_SCHEMA);
  const envelopePreimage = concatBytes(DOMAINS.envelope, headerBytes, bodyBytes);
  const envelopeHash = toHex(blake2b256(envelopePreimage));
  const extraChecks = verifyX402Projection(vector, body);
  if (isRecord(vector.comparison)) {
    const baseline = contextVector(context, "GV-X4-01");
    if (baseline && isRecord(baseline.typed_input)) {
      const baselineMaterial = x402MaterialFromInput(baseline.typed_input);
      for (const [name, expected] of Object.entries(vector.comparison)) {
        let observed: unknown;
        if (name === "baseline_action_id") observed = baselineMaterial.actionId;
        else if (name === "changed_action_id") observed = computedActionId;
        else if (name === "action_id_differs") observed = baselineMaterial.actionId !== computedActionId;
        else if (name === "envelope_hash_differs") observed = baselineMaterial.envelopeHash !== envelopeHash;
        else continue;
        addCheck(extraChecks, `comparison_${name}`, expected, observed);
      }
    }
  }
  return {
    canonical: bodyBytes,
    header: headerBytes,
    core,
    actionId: computedActionId,
    envelopeHash,
    envelopePreimage,
    extraChecks,
  };
}

function x402MaterialFromInput(input: Record<string, unknown>): Material {
  const header = fieldsToRecord(input.header, HEADER_SCHEMA);
  const body = fieldsToRecord(input.body, X402_SCHEMA);
  validateHeader(header);
  validateX402Body(body, header);
  const x402CoreNames = new Set<string>(X402_CORE_NAMES);
  const coreSchema = X402_SCHEMA.filter(([name]) => x402CoreNames.has(name));
  const core = encodeRecord(body, coreSchema);
  const computedActionId = actionId(2, body.action_nonce, core);
  if (header.action_id !== computedActionId) {
    throw new EncodingError("InvalidActionField", "header action_id does not match x402 action core", 16);
  }
  const headerBytes = encodeRecord(header, HEADER_SCHEMA);
  const bodyBytes = encodeRecord(body, X402_SCHEMA);
  const envelopePreimage = concatBytes(DOMAINS.envelope, headerBytes, bodyBytes);
  return {
    canonical: bodyBytes,
    header: headerBytes,
    core,
    actionId: computedActionId,
    envelopeHash: toHex(blake2b256(envelopePreimage)),
    envelopePreimage,
  };
}

function verifyX402Projection(
  vector: Record<string, unknown>,
  body: Record<string, unknown>,
): VerificationCheck[] {
  if (!isRecord(vector.x402_binding_projection)) return [];
  const projection = vector.x402_binding_projection;
  const preimages = requireRecord(projection.preimages, "x402 preimages");
  const hashes = requireRecord(projection.hashes, "x402 hashes");
  const resource = requireRecord(projection.resource, "x402 resource");
  const report = requireRecord(projection.report, "x402 report");
  const paymentPayload = requireRecord(projection.payment_payload, "x402 payment payload");
  const payload = requireRecord(paymentPayload.payload, "x402 nested payload");
  const authorization = requireRecord(payload.authorization, "x402 authorization");
  const requirementsPreimage = paymentRequirementsPreimage(body, 300);
  const resourcePreimage = concatBytes(DOMAINS.resourceUrl, lengthPrefixed(asString(resource.url)));
  const reportBytes = hexBytes(report.exact_bytes_hex);
  const reportPreimage = concatBytes(DOMAINS.x402Report, lengthPrefixed(reportBytes));
  const publicKey = hexBytes(payload.publicKey);
  if (publicKey.length !== 33) throw new EncodingError("InvalidPublicKey", "invalid projected public key");
  const signedPayloadPreimage = concatBytes(
    DOMAINS.signedPaymentPayload,
    fixedUnsigned(paymentPayload.x402Version, 32),
    lengthPrefixed(asString(resource.url)),
    lengthPrefixed(asString(resource.description)),
    lengthPrefixed(asString(resource.mimeType)),
    hexBytes(body.payment_requirements_hash, 32),
    lengthPrefixed(hexBytes(payload.signature)),
    publicKey,
    untagAccount(authorization.from),
    untagAccount(authorization.to),
    fixedUnsigned(authorization.value, 256),
    fixedUnsigned(authorization.validAfter, 64),
    fixedUnsigned(authorization.validBefore, 64),
    hexBytes(authorization.nonce, 32),
    fixedUnsigned(0, 32),
  );
  const actual: Record<string, Uint8Array> = {
    resource_url_hash: resourcePreimage,
    report_hash: reportPreimage,
    payment_requirements_hash: requirementsPreimage,
    signed_payment_payload_hash: signedPayloadPreimage,
  };
  const checks: VerificationCheck[] = [];
  for (const [name, preimage] of Object.entries(actual)) {
    addCheck(checks, `${name}_preimage`, preimages[name], toHex(preimage));
    addCheck(checks, name, hashes[name], toHex(blake2b256(preimage)));
    addCheck(checks, `${name}_body_binding`, body[name], toHex(blake2b256(preimage)));
  }
  return checks;
}

function paymentRequirementsPreimage(
  body: Record<string, unknown>,
  maxTimeoutSeconds: number,
): Uint8Array {
  return concatBytes(
    DOMAINS.paymentRequirements,
    lengthPrefixed(asString(body.scheme)),
    lengthPrefixed(asString(body.caip2_network)),
    hexBytes(body.wcspr_package, 32),
    fixedUnsigned(body.value, 256),
    hexBytes(body.payee, 32),
    fixedUnsigned(maxTimeoutSeconds, 32),
    lengthPrefixed(asString(body.token_name)),
    lengthPrefixed(asString(body.eip712_domain_version)),
    fixedUnsigned(body.token_decimals, 8),
    lengthPrefixed(asString(body.token_symbol)),
  );
}

function untagAccount(value: unknown): Uint8Array {
  const text = asString(value);
  if (!text.startsWith("00")) throw new EncodingError("InvalidAccountHash", "account key tag must be 00");
  return hexBytes(text.slice(2), 32);
}

function verifyRecordedHashes(
  vector: Record<string, unknown>,
  material: Material,
  checks: VerificationCheck[],
): void {
  const hashes = requireRecord(vector.hashes, "hashes");
  for (const [name, expected] of Object.entries(hashes)) {
    let observed: string | undefined;
    switch (name) {
      case "canonical_blake2b256":
        observed = toHex(blake2b256(material.canonical));
        break;
      case "action_core_blake2b256":
        observed = material.core ? toHex(blake2b256(material.core)) : undefined;
        break;
      case "action_id":
        observed = material.actionId;
        break;
      case "transfer_derivation_blake2b256":
        observed = material.transferDigest;
        break;
      case "envelope_hash":
        observed = material.envelopeHash;
        break;
      case "preauth_evidence_root":
      case "authorized_metadata_root":
      case "execution_argument_root":
        observed = material.rootHash;
        break;
      case "case_a_envelope_hash":
        observed = material.caseMaterials?.[0]?.envelopeHash;
        break;
      case "case_b_envelope_hash":
        observed = material.caseMaterials?.[1]?.envelopeHash;
        break;
      default:
        observed = undefined;
    }
    addCheck(checks, name, expected, observed);
  }
  if (material.header && vector.header_canonical_hex !== undefined) {
    addCheck(checks, "header_canonical_hex", vector.header_canonical_hex, toHex(material.header));
  }
  if (material.core && vector.action_core_hex !== undefined) {
    addCheck(checks, "action_core_hex", vector.action_core_hex, toHex(material.core));
  }
  if (material.header && vector.envelope_preimage_hex !== undefined) {
    addCheck(
      checks,
      "envelope_preimage_hex",
      vector.envelope_preimage_hex,
      material.envelopePreimage ? toHex(material.envelopePreimage) : undefined,
    );
  }
}

function verifyRelationshipAssertions(
  assertions: Record<string, unknown>,
  left: Material,
  right: Material,
  checks: VerificationCheck[],
): void {
  for (const [name, expected] of Object.entries(assertions)) {
    let observed: unknown;
    if (name === "action_id_equal") observed = left.actionId === right.actionId;
    else if (name === "action_id_differs") observed = left.actionId !== right.actionId;
    else if (name === "transfer_id_differs") observed = left.transferId !== right.transferId;
    else if (name === "envelope_hash_differs") observed = left.envelopeHash !== right.envelopeHash;
    else continue;
    addCheck(checks, `relationship_${name}`, expected, observed);
  }
}

function contextVector(
  context: GoldenVectorContext,
  vectorId: string,
): Record<string, unknown> | null {
  const vectors = context.vectors;
  const value =
    vectors instanceof Map
      ? vectors.get(vectorId)
      : (vectors as Readonly<Record<string, unknown>> | undefined)?.[vectorId];
  return isRecord(value) ? value : null;
}

function checkOrder(expected: unknown, observed: string[]): VerificationCheck[] {
  if (expected === undefined) return [];
  return [
    {
      name: "canonical_entry_order",
      passed: JSON.stringify(expected) === JSON.stringify(observed),
      expected: JSON.stringify(expected),
      observed: JSON.stringify(observed),
    },
  ];
}

function addCheck(
  checks: VerificationCheck[],
  name: string,
  expected: unknown,
  observed: unknown,
): void {
  checks.push({
    name,
    passed: expected === observed,
    expected: scalar(expected),
    observed: scalar(observed),
  });
}

function scalar(value: unknown): string | number | boolean | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  return JSON.stringify(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new EncodingError("InvalidFields", `${label} must be an object`);
  return value;
}

function normalizeError(error: unknown): { name: string; code: number | null; message: string } {
  if (error instanceof EncodingError) {
    return { name: error.name, code: error.code, message: error.message };
  }
  if (error instanceof Error) return { name: error.name, code: null, message: error.message };
  return { name: "VerificationError", code: null, message: String(error) };
}
