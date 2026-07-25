import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  canonicalTranscriptJson,
  parseJsonStrict,
} from "../../dist/index.js";

const REPOSITORY = fileURLToPath(new URL("../../../../", import.meta.url));

const GENERATORS = Object.freeze({
  default: Object.freeze([
    "import json",
    "from tests.test_clvalue_roundtrip import _bound_v3_proof",
    "proof, _, _ = _bound_v3_proof()",
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ]),
  "mutated-3000": Object.freeze([
    "import json",
    "import tests.test_clvalue_roundtrip as fixtures",
    "from shared.actions_v3 import build_native_material",
    "document = fixtures._native_document()",
    "document['header']['requested_allocation_bps'] = '4000'",
    "document['header']['approved_allocation_bps'] = '3000'",
    "document['body']['amount_motes'] = '187500000000'",
    "document['header'], document['body'], _ = build_native_material(document['header'], document['body'])",
    "fixtures._native_document = lambda: document",
    "proof, _, _ = fixtures._bound_v3_proof()",
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ]),
  treasury: Object.freeze([
    "import json",
    "from pathlib import Path",
    "import tests.test_clvalue_roundtrip as fixtures",
    "core = json.loads(Path('packages/verify/test/fixtures/native-treasury-core.json').read_text())",
    "document = {'schema_id': 'concordia.exact-envelope-v3.input.v1', 'action': 'NativeTransferV1', 'header': core['authorization']['typed_header'], 'body': core['authorization']['typed_body']}",
    "fixtures._native_document = lambda: document",
    "proof, _, _ = fixtures._bound_v3_proof()",
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ]),
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
  const generator = GENERATORS[name];
  if (!generator) {
    throw new Error(`unknown exact-v3 proof fixture: ${name}`);
  }
  const raw = execFileSync(
    "uv",
    [
      "run",
      "--frozen",
      "--python",
      "python3.12",
      "python",
      "-c",
      generator.join("\n"),
    ],
    {
      cwd: REPOSITORY,
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const proof = requireCurrentReadback(parseJsonStrict(raw));
  return {
    proof,
    raw: canonicalTranscriptJson(proof, `exact-v3 ${name} fixture`),
    sourceCommit: proof.deployment.source_commit,
  };
}
