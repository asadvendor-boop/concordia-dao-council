import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import {
  FROZEN_VECTOR_DIRECTORY_URL,
  encodeCanonicalValue,
  verifyGoldenVector,
} from "../dist/index.js";

const VECTOR_ROOT = fileURLToPath(
  new URL("../../../tests/golden/envelope_v3/", import.meta.url),
);

async function vectorPaths(directory = VECTOR_ROOT) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const child = path.join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await vectorPaths(child)));
    if (entry.isFile() && entry.name.endsWith(".json")) paths.push(child);
  }
  return paths.sort();
}

test("all 21 frozen vectors independently reproduce their canonical result", async () => {
  const paths = await vectorPaths();
  assert.equal(paths.length, 21);

  const vectors = new Map();
  for (const vectorPath of paths) {
    const vector = JSON.parse(await readFile(vectorPath, "utf8"));
    vectors.set(vector.vector_id, vector);
  }

  for (const vector of vectors.values()) {
    const result = verifyGoldenVector(vector, { vectors });
    assert.equal(result.vectorId, vector.vector_id, vector.vector_id);

    if (vector.valid) {
      assert.equal(result.status, "verified", vector.vector_id);
      assert.equal(result.valid, true, vector.vector_id);
      assert.equal(result.canonicalHex, vector.canonical_hex, vector.vector_id);
      assert.ok(result.checks.length > 0, vector.vector_id);
      assert.ok(result.checks.every((check) => check.passed), vector.vector_id);
    } else {
      assert.equal(result.status, "invalid", vector.vector_id);
      assert.equal(result.valid, false, vector.vector_id);
      assert.equal(result.error?.name, vector.expected_error.name, vector.vector_id);
      assert.equal(result.error?.code ?? null, vector.expected_error.code, vector.vector_id);
    }
  }
});

test("the distributable package carries byte-identical copies of all frozen vectors", async () => {
  const sourcePaths = await vectorPaths();
  const packagedPaths = await vectorPaths(fileURLToPath(FROZEN_VECTOR_DIRECTORY_URL));
  assert.equal(packagedPaths.length, 21);
  assert.deepEqual(
    await Promise.all(packagedPaths.map((file) => readFile(file, "utf8"))),
    await Promise.all(sourcePaths.map((file) => readFile(file, "utf8"))),
  );
});

test("relationship hashes and assertions are recomputed rather than echoed", async () => {
  const paths = await vectorPaths();
  const vectors = new Map();
  for (const vectorPath of paths) {
    const vector = JSON.parse(await readFile(vectorPath, "utf8"));
    vectors.set(vector.vector_id, vector);
  }

  const native = structuredClone(vectors.get("GV-NT-04"));
  native.hashes.case_a_envelope_hash = "00".repeat(32);
  assert.equal(verifyGoldenVector(native, { vectors }).status, "invalid");

  const x402 = structuredClone(vectors.get("GV-X4-02"));
  x402.comparison.action_id_differs = false;
  assert.equal(verifyGoldenVector(x402, { vectors }).status, "invalid");
});

test("canonical scalar encoding covers every frozen additional scalar case", async () => {
  const vector = JSON.parse(
    await readFile(path.join(VECTOR_ROOT, "exec_args/GV-EA-02.json"), "utf8"),
  );
  const coverage = vector.additional_scalar_coverage;
  const cases = [
    ["Key", coverage.key_hash],
    ["List<Key>", coverage.list_key],
    ["PublicKey", coverage.public_key_secp256k1],
    ["Option<u64>", coverage.option_u64_none],
  ];
  for (const [type, fixture] of cases) {
    assert.equal(
      Buffer.from(encodeCanonicalValue(type, fixture.typed_value)).toString("hex"),
      fixture.canonical_hex,
      type,
    );
  }
});

test("out-of-range integers and non-canonical hashes fail closed", () => {
  assert.throws(() => encodeCanonicalValue("u8", "256"), /outside u8 range/);
  assert.throws(() => encodeCanonicalValue("Bytes32", "aa"), /exactly 32 bytes/);
  assert.throws(() => encodeCanonicalValue("String", "snowman-☃"), /ASCII/);
  assert.throws(() => encodeCanonicalValue("String", "line\nbreak"), /printable ASCII/);
  assert.throws(() => encodeCanonicalValue("String", "delete-\u007f"), /printable ASCII/);
});
