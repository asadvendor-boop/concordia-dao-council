import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  HEADER_SCHEMA,
  NATIVE_SCHEMA,
  X402_SCHEMA,
  fieldsToRecord,
  validateHeader,
  validateNativeBody,
  validateX402Body,
} from "../dist/index.js";

const ROOT = new URL("../../../tests/golden/envelope_v3/", import.meta.url);
const ZERO32 = "00".repeat(32);
const MAX_U512 = (2n ** 512n - 1n).toString();

async function load(relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, ROOT), "utf8"));
}

function records(vector) {
  return {
    header: fieldsToRecord(vector.typed_input.header, HEADER_SCHEMA),
    body: fieldsToRecord(vector.typed_input.body, vector.kind.startsWith("native") ? NATIVE_SCHEMA : X402_SCHEMA),
  };
}

function expectEncodingError(fn, name, code) {
  assert.throws(fn, (error) => error?.name === name && error?.code === code);
}

test("common-header validation matches every frozen v3 decision and action invariant", async () => {
  const vector = await load("native_transfer/GV-NT-01.json");
  const baseline = records(vector).header;
  const invalid = [
    ["casper_chain_name", "casper-testnet", "InvalidEnvelopeField", 15],
    ["decision_code", "0", "InvalidEnvelopeField", 15],
    ["decision_code", "3", "InvalidEnvelopeField", 15],
    ["decision_code", "4", "InvalidEnvelopeField", 15],
    ["action_version", "2", "InvalidActionField", 16],
    ["action_kind", "0", "InvalidActionField", 16],
    ["action_kind", "3", "InvalidActionField", 16],
  ];
  for (const [field, value, name, code] of invalid) {
    expectEncodingError(() => validateHeader({ ...baseline, [field]: value }), name, code);
  }

  expectEncodingError(
    () => validateHeader({ ...baseline, decision_code: "1", approved_allocation_bps: "800" }),
    "InvalidEnvelopeField",
    15,
  );
  expectEncodingError(
    () => validateHeader({ ...baseline, decision_code: "2", approved_allocation_bps: "3000" }),
    "InvalidEnvelopeField",
    15,
  );
});

test("native validation rejects zero nonce, wrong action kind, and U512 multiplication overflow", async () => {
  const vector = await load("native_transfer/GV-NT-01.json");
  const { header, body } = records(vector);

  expectEncodingError(
    () => validateNativeBody(header, { ...body, action_nonce: ZERO32 }),
    "InvalidActionField",
    16,
  );
  expectEncodingError(
    () => validateNativeBody({ ...header, action_kind: "2" }, body),
    "InvalidActionField",
    16,
  );
  expectEncodingError(
    () =>
      validateNativeBody(
        {
          ...header,
          decision_code: "1",
          requested_allocation_bps: "10000",
          approved_allocation_bps: "10000",
        },
        {
          ...body,
          amount_motes: MAX_U512,
          treasury_snapshot_balance_motes: MAX_U512,
        },
      ),
    "InvalidActionField",
    16,
  );
});

test("official x402 validation binds the exact frozen WCSPR identity and nonzero fields", async () => {
  const vector = await load("x402_settlement/GV-X4-01.json");
  const { header, body } = records(vector);
  validateX402Body(body, header);

  const invalidMutations = {
    wcspr_package: "11".repeat(32),
    wcspr_contract: "22".repeat(32),
    token_name: "Wrapped Casper",
    token_symbol: "wCSPR",
    eip712_domain_version: "2",
    token_decimals: "18",
    resource_url_hash: ZERO32,
    report_hash: ZERO32,
    payment_requirements_hash: ZERO32,
    signed_payment_payload_hash: ZERO32,
    eip712_auth_nonce: ZERO32,
    action_nonce: ZERO32,
  };
  for (const [field, value] of Object.entries(invalidMutations)) {
    expectEncodingError(
      () => validateX402Body({ ...body, [field]: value }, header),
      "InvalidActionField",
      16,
    );
  }
  expectEncodingError(
    () => validateX402Body(body, { ...header, action_kind: "1" }),
    "InvalidActionField",
    16,
  );
});
