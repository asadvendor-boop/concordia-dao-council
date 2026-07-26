import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

import {
  canonicalTranscriptJson,
  parseJsonStrict,
} from "../../dist/index.js";

const AUTHORITY_COMMIT = "b2cf53859b188de0bd250ea338b76fff575dee67";
const FIXTURES = Object.freeze({
  default: Object.freeze({
    file: "exact-v3-default.json.gz",
    sha256: "c767e3187305da2dc8afa4a8196533e5b00b0c3c373669b33c1f73f7e0fdf4de",
  }),
  "mutated-3000": Object.freeze({
    file: "exact-v3-mutated-3000.json.gz",
    sha256: "01fda861cb35fe426c8dd58353ff5fddf2cf54632a5bb1d5b7bd5316772e68be",
  }),
  treasury: Object.freeze({
    file: "exact-v3-treasury.json.gz",
    sha256: "dc53b20f887ab0ae6c9acb6bd0ca2ecfd4689cdad27f183f533fb2acc0708cb1",
  }),
});

function exactKeys(value, expected, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join("\0") !== [...expected].sort().join("\0")
  ) {
    throw new Error(`${label} has an unexpected field set`);
  }
  return value;
}

function requireCurrentReadback(proof) {
  const current = structuredClone(proof);
  const readback = current.readback;
  const runReadback = current.run?.readback;
  if (
    readback?.schema_id !== "concordia.v3-chain-readback.v1" ||
    !Array.isArray(readback.transcripts) ||
    readback.transcripts.length !== 17 ||
    typeof readback.facts?.owner !== "string" ||
    !/^[0-9a-f]{64}$/.test(readback.facts.owner) ||
    runReadback?.artifact_sha256 !== readback.artifact_sha256
  ) {
    throw new Error("Python v3 fixture is not the deployed current shape");
  }
  const dictionary = readback.transcripts.slice(2);
  if (dictionary.length !== 15) {
    throw new Error("Python v3 fixture dictionary inventory differs");
  }
  for (const transcript of dictionary) {
    exactKeys(
      transcript,
      [
        "rpc_url_identity_or_node_id",
        "method",
        "params",
        "request",
        "response",
        "canonical_sha256",
      ],
      "current dictionary transcript",
    );
    if (transcript.method !== "state_get_dictionary_item") {
      throw new Error("current dictionary transcript method differs");
    }
    exactKeys(
      transcript.params,
      ["state_root_hash", "dictionary_identifier"],
      "current dictionary params",
    );
    const identifier = exactKeys(
      transcript.params.dictionary_identifier,
      ["ContractNamedKey"],
      "current dictionary identifier",
    );
    const namedKey = exactKeys(
      identifier.ContractNamedKey,
      ["key", "dictionary_name", "dictionary_item_key"],
      "current ContractNamedKey",
    );
    if (
      namedKey.dictionary_name !== "state" ||
      typeof namedKey.key !== "string" ||
      !namedKey.key.startsWith("hash-") ||
      typeof namedKey.dictionary_item_key !== "string" ||
      !/^[0-9a-f]{64}$/.test(namedKey.dictionary_item_key) ||
      canonicalTranscriptJson(
        transcript.request?.params,
        "current dictionary request params",
      ) !== canonicalTranscriptJson(
        transcript.params,
        "current dictionary params",
      )
    ) {
      throw new Error("current dictionary target differs");
    }
  }
  return current;
}

export function loadExactV3ProofFixture(name = "default") {
  const fixture = FIXTURES[name];
  if (!fixture) {
    throw new Error(`unknown exact-v3 proof fixture: ${name}`);
  }
  const compressed = readFileSync(
    new URL(`../fixtures/${fixture.file}`, import.meta.url),
  );
  const bytes = gunzipSync(compressed);
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== fixture.sha256) {
    throw new Error(`exact-v3 ${name} fixture SHA-256 differs`);
  }
  const raw = bytes.toString("utf8");
  const proof = requireCurrentReadback(parseJsonStrict(raw));
  const canonical = canonicalTranscriptJson(proof, `exact-v3 ${name} fixture`);
  if (raw !== `${canonical}\n`) {
    throw new Error(`exact-v3 ${name} fixture is not canonical JSON`);
  }
  if (proof.deployment?.source_commit !== AUTHORITY_COMMIT) {
    throw new Error(`exact-v3 ${name} fixture source authority differs`);
  }
  return {
    proof,
    raw: canonical,
    sourceCommit: proof.deployment.source_commit,
  };
}
