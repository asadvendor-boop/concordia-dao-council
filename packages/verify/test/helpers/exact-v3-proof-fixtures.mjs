import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  blake2b256,
  canonicalTranscriptJson,
  parseJsonStrict,
} from "../../dist/index.js";

const REPOSITORY = fileURLToPath(new URL("../../../../", import.meta.url));
const OWNER = "06".repeat(32);
const LEGACY_INDEXES = Object.freeze([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 15, 16]);
const CURRENT_INDEXES = Object.freeze([2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17]);

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

function canonicalSha256(value, label) {
  return createHash("sha256")
    .update(canonicalTranscriptJson(value, label), "ascii")
    .digest("hex");
}

function concatBytes(...values) {
  return Buffer.concat(values.map((value) => Buffer.from(value)));
}

function littleU32(value) {
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32LE(value);
  return encoded;
}

function stateDictionaryKey(index, mappingKey = Buffer.alloc(0)) {
  if (!Number.isInteger(index) || index < 0 || index > 255) {
    throw new Error("fixture Odra storage index is invalid");
  }
  const path = index <= 15
    ? Buffer.from([0, 0, 0, index])
    : Buffer.from([0xff, 1, index]);
  return Buffer.from(blake2b256(concatBytes(path, mappingKey))).toString("hex");
}

function mappingKey(index, proposalKey, actionKey) {
  if ([11, 12, 14, 15].includes(index)) return proposalKey;
  if (index === 16) return actionKey;
  return Buffer.alloc(0);
}

function rewriteDictionaryTranscript(transcript, index, keyMaterial, options = {}) {
  const source = structuredClone(transcript);
  exactKeys(
    source,
    [
      "rpc_url_identity_or_node_id",
      "method",
      "params",
      "request",
      "response",
      "canonical_sha256",
    ],
    "legacy dictionary transcript",
  );
  if (source.method !== "state_get_dictionary_item") {
    throw new Error("legacy dictionary transcript method differs");
  }
  exactKeys(
    source.params,
    ["state_root_hash", "dictionary_identifier", "dictionary_item_key"],
    "legacy dictionary params",
  );
  const identifier = exactKeys(
    source.params.dictionary_identifier,
    ["ContractNamedKey"],
    "legacy dictionary identifier",
  );
  const namedKey = exactKeys(
    identifier.ContractNamedKey,
    ["key", "dictionary_name"],
    "legacy ContractNamedKey",
  );
  if (
    namedKey.dictionary_name !== "state" ||
    typeof namedKey.key !== "string" ||
    !namedKey.key.startsWith("hash-")
  ) {
    throw new Error("legacy dictionary target differs");
  }

  const id = options.id ?? source.request.id;
  const params = {
    state_root_hash: source.params.state_root_hash,
    dictionary_identifier: {
      ContractNamedKey: {
        key: namedKey.key,
        dictionary_name: namedKey.dictionary_name,
        dictionary_item_key: stateDictionaryKey(index, keyMaterial),
      },
    },
  };
  const request = { ...source.request, id, params };
  const response = { ...structuredClone(options.response ?? source.response), id };
  return {
    ...source,
    params,
    request,
    response,
    canonical_sha256: canonicalSha256(
      { request, response },
      "upgraded v3 dictionary transcript",
    ),
  };
}

function upgradeReadback(proof) {
  const upgraded = structuredClone(proof);
  const readback = structuredClone(upgraded.readback);
  const runReadback = upgraded.run?.readback;
  if (
    readback?.schema_id !== "concordia.v3-chain-readback.v1" ||
    !Array.isArray(readback.transcripts) ||
    readback.transcripts.length !== 16 ||
    readback.facts?.owner !== undefined ||
    runReadback?.artifact_sha256 !== readback.artifact_sha256
  ) {
    throw new Error("Python v3 fixture is not the reviewed legacy shape");
  }

  const dictionary = readback.transcripts.slice(2);
  if (dictionary.length !== LEGACY_INDEXES.length) {
    throw new Error("Python v3 fixture dictionary inventory differs");
  }
  const proposalBytes = Buffer.from(readback.expected.proposal_id, "ascii");
  const proposalKey = concatBytes(littleU32(proposalBytes.length), proposalBytes);
  const actionKey = Buffer.from(readback.expected.action_id, "hex");
  if (actionKey.length !== 32) {
    throw new Error("Python v3 fixture action identity differs");
  }

  for (let position = 0; position < dictionary.length; position += 1) {
    const index = LEGACY_INDEXES[position];
    const expected = stateDictionaryKey(
      index,
      mappingKey(index, proposalKey, actionKey),
    );
    if (dictionary[position].params.dictionary_item_key !== expected) {
      throw new Error("Python v3 fixture legacy storage layout differs");
    }
  }

  const ownerResponse = structuredClone(dictionary[0].response);
  ownerResponse.result.stored_value.CLValue = {
    cl_type: { List: "U8" },
    bytes: `20000000${OWNER}`,
    parsed: Array(32).fill(6),
  };
  const owner = rewriteDictionaryTranscript(
    dictionary[0],
    1,
    Buffer.alloc(0),
    { id: "fixture-owner", response: ownerResponse },
  );
  const current = dictionary.map((transcript, position) => {
    const legacyIndex = LEGACY_INDEXES[position];
    return rewriteDictionaryTranscript(
      transcript,
      CURRENT_INDEXES[position],
      mappingKey(legacyIndex, proposalKey, actionKey),
    );
  });

  readback.transcripts = [
    readback.transcripts[0],
    readback.transcripts[1],
    owner,
    ...current,
  ];
  readback.facts = { ...readback.facts, owner: OWNER };
  const withoutHash = {};
  for (const [key, value] of Object.entries(readback)) {
    if (key !== "artifact_sha256") withoutHash[key] = value;
  }
  readback.artifact_sha256 = canonicalSha256(
    withoutHash,
    "upgraded v3 readback artifact",
  );
  upgraded.readback = readback;
  upgraded.run.readback = structuredClone(readback);
  return upgraded;
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
  const proof = upgradeReadback(parseJsonStrict(raw));
  return {
    proof,
    raw: canonicalTranscriptJson(proof, `exact-v3 ${name} fixture`),
    sourceCommit: proof.deployment.source_commit,
  };
}
