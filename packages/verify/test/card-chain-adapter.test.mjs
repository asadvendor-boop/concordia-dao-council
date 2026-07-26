import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  parseJsonStrict,
  verifyCardChainArtifact,
} from "../dist/index.js";

const PROPOSAL_ID = "DAO-PROP-6CB25C";
const CAPTURED_AT = "2026-07-23T01:00:00Z";

function sha256Utf8(value) {
  return createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");
}

function fixture() {
  const first = JSON.stringify({
    card_type: "ProposalCard",
    previous_card_hash: null,
    sequence_number: 1,
    signal_id: PROPOSAL_ID,
    summary: "An AI requested 30%.",
  });
  const firstHash = sha256Utf8(first);
  const second = JSON.stringify({
    card_type: "TriageDecision",
    previous_card_hash: firstHash,
    proposal_id: PROPOSAL_ID,
    sequence_number: 2,
    severity: "high",
  });
  const secondHash = sha256Utf8(second);
  const third = JSON.stringify({
    card_type: "CasperExecutionReceipt",
    previous_card_hash: secondHash,
    proposal_id: PROPOSAL_ID,
    sequence_number: 3,
    status: "accepted",
  });
  const thirdHash = sha256Utf8(third);
  return {
    artifact: {
      schema_version: "concordia.card_chain.v1",
      proposal_id: PROPOSAL_ID,
      captured_at: CAPTURED_AT,
      source_url: `https://concordia.example/proof-artifacts/v1/${PROPOSAL_ID}/card-chain`,
      cards: [
        {
          sequence_number: 1,
          card_type: "ProposalCard",
          card_hash: firstHash,
          canonical_card_json: first,
          published_at: "2026-06-01T10:00:00Z",
        },
        {
          sequence_number: 2,
          card_type: "TriageDecision",
          card_hash: secondHash,
          canonical_card_json: second,
          published_at: "2026-06-01T10:01:00Z",
        },
        {
          sequence_number: 3,
          card_type: "CasperExecutionReceipt",
          card_hash: thirdHash,
          canonical_card_json: third,
          published_at: null,
        },
      ],
    },
    firstHash,
    secondHash,
    thirdHash,
  };
}

test("card-chain adapter recomputes exact UTF-8 preimages and linkage", () => {
  const { artifact, firstHash, secondHash, thirdHash } = fixture();
  const facts = verifyCardChainArtifact(artifact, { expectedFinalCardHash: thirdHash });
  assert.deepEqual(facts, {
    schemaVersion: "concordia.card_chain.v1",
    proposalId: PROPOSAL_ID,
    capturedAt: CAPTURED_AT,
    sourceUrl: artifact.source_url,
    cardCount: 3,
    firstCardHash: firstHash,
    finalCardHash: thirdHash,
    cardHashes: [firstHash, secondHash, thirdHash],
  });
});

test("card-chain adapter hashes the exact string instead of reserializing parsed JSON", () => {
  const { artifact } = fixture();
  const tampered = structuredClone(artifact);
  tampered.cards[1].canonical_card_json = tampered.cards[1].canonical_card_json.replace(
    '{"card_type"',
    '{ "card_type"',
  );
  assert.throws(() => verifyCardChainArtifact(tampered), /card 2 hash/i);
});

test("card-chain adapter rejects wrapper, link, identity and forbidden-hash mutations", () => {
  const mutations = [
    ["wrapper sequence", (value) => { value.cards[1].sequence_number = 7; }, /sequence/i],
    ["wrapper type", (value) => { value.cards[1].card_type = "Assessment"; }, /card_type|type/i],
    ["broken previous hash", (value) => {
      const parsed = JSON.parse(value.cards[1].canonical_card_json);
      parsed.previous_card_hash = "f".repeat(64);
      value.cards[1].canonical_card_json = JSON.stringify(parsed);
      value.cards[1].card_hash = sha256Utf8(value.cards[1].canonical_card_json);
    }, /previous_card_hash|link/i],
    ["different proposal", (value) => {
      const parsed = JSON.parse(value.cards[1].canonical_card_json);
      parsed.proposal_id = "DAO-PROP-OTHER";
      value.cards[1].canonical_card_json = JSON.stringify(parsed);
      value.cards[1].card_hash = sha256Utf8(value.cards[1].canonical_card_json);
    }, /proposal/i],
    ["transplanted first card", (value) => {
      const parsed = JSON.parse(value.cards[0].canonical_card_json);
      parsed.signal_id = "DAO-PROP-OTHER";
      value.cards[0].canonical_card_json = JSON.stringify(parsed);
      value.cards[0].card_hash = sha256Utf8(value.cards[0].canonical_card_json);
    }, /signal_id|proposal/i],
    ["forbidden embedded card hash", (value) => {
      const parsed = JSON.parse(value.cards[2].canonical_card_json);
      parsed.card_hash = "a".repeat(64);
      value.cards[2].canonical_card_json = JSON.stringify(parsed);
      value.cards[2].card_hash = sha256Utf8(value.cards[2].canonical_card_json);
    }, /card_hash/i],
    ["wrong expected terminal", () => {}, /terminal|final/i, "e".repeat(64)],
  ];
  for (const [label, mutate, pattern, expectedFinalCardHash] of mutations) {
    const { artifact } = fixture();
    mutate(artifact);
    assert.throws(
      () => verifyCardChainArtifact(artifact, expectedFinalCardHash ? { expectedFinalCardHash } : {}),
      pattern,
      label,
    );
  }
});

test("card-chain adapter rejects non-exact schemas and invalid metadata", () => {
  const cases = [
    ["empty", (value) => { value.cards = []; }, /non-empty/i],
    ["wrong first card", (value) => { value.cards[0].card_type = "Assessment"; }, /first card.*ProposalCard/i],
    ["unknown top-level", (value) => { value.verified = true; }, /unknown/i],
    ["unknown card field", (value) => { value.cards[0].passed = true; }, /unknown/i],
    ["bad source", (value) => { value.source_url = "http://localhost/evidence"; }, /HTTPS/i],
    ["wrong source path", (value) => { value.source_url = "https://concordia.example/evidence"; }, /HTTPS|source_url/i],
    ["source query", (value) => { value.source_url += "?verified=true"; }, /HTTPS|source_url/i],
    ["bad capture time", (value) => { value.captured_at = "2026-02-31T00:00:00Z"; }, /captured_at/i],
    ["bad publication time", (value) => { value.cards[0].published_at = "yesterday"; }, /published_at/i],
    ["wrong schema", (value) => { value.schema_version = "concordia.card_chain.v2"; }, /schema/i],
  ];
  for (const [label, mutate, pattern] of cases) {
    const { artifact } = fixture();
    mutate(artifact);
    assert.throws(() => verifyCardChainArtifact(artifact), pattern, label);
  }
});

test("strict parsing rejects duplicate wrapper and embedded preimage keys", () => {
  const { artifact } = fixture();
  const outer = JSON.stringify(artifact).replace(
    '"schema_version":"concordia.card_chain.v1"',
    '"schema_version":"concordia.card_chain.v1","schema_version":"concordia.card_chain.v1"',
  );
  assert.throws(() => parseJsonStrict(outer), /duplicate JSON key/i);

  const embedded = structuredClone(artifact);
  embedded.cards[0].canonical_card_json = embedded.cards[0].canonical_card_json.replace(
    '"sequence_number":1',
    '"sequence_number":1,"sequence_number":1',
  );
  embedded.cards[0].card_hash = sha256Utf8(embedded.cards[0].canonical_card_json);
  assert.throws(() => verifyCardChainArtifact(embedded), /duplicate JSON key/i);
});
