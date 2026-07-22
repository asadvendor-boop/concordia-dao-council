import { createHash, timingSafeEqual } from "node:crypto";

import { isRecord } from "../encoders.js";
import { parseJsonStrict } from "../json.js";

const SCHEMA_VERSION = "concordia.card_chain.v1";
const TOP_LEVEL_FIELDS = new Set([
  "schema_version",
  "proposal_id",
  "captured_at",
  "source_url",
  "cards",
]);
const CARD_FIELDS = new Set([
  "sequence_number",
  "card_type",
  "card_hash",
  "canonical_card_json",
  "published_at",
]);
const PROPOSAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CAPTURED_AT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const PUBLISHED_AT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|\+00:00)$/;
const MAX_CARDS = 256;
const MAX_CARD_JSON_BYTES = 1024 * 1024;
const MAX_TOTAL_CARD_JSON_BYTES = 8 * 1024 * 1024;

export type CardChainVerificationOptions = {
  expectedFinalCardHash?: string;
};

export type CardChainFacts = {
  schemaVersion: typeof SCHEMA_VERSION;
  proposalId: string;
  capturedAt: string;
  sourceUrl: string;
  cardCount: number;
  firstCardHash: string;
  finalCardHash: string;
  cardHashes: string[];
};

/**
 * Independently verifies the exact immutable card preimages emitted from the
 * SQLite cards.card_json rows. Asserted booleans and humanized snapshots are
 * deliberately outside this adapter's input contract.
 */
export function verifyCardChainArtifact(
  input: unknown,
  options: CardChainVerificationOptions = {},
): CardChainFacts {
  const artifact = requireExactRecord(input, TOP_LEVEL_FIELDS, "card-chain artifact");
  if (artifact.schema_version !== SCHEMA_VERSION) {
    throw new Error(`card-chain schema_version must equal ${SCHEMA_VERSION}`);
  }
  if (typeof artifact.proposal_id !== "string" || !PROPOSAL_ID.test(artifact.proposal_id)) {
    throw new Error("card-chain proposal_id is not canonical");
  }
  if (!isRfc3339Utc(artifact.captured_at, CAPTURED_AT)) {
    throw new Error("card-chain captured_at must be a valid RFC3339 UTC timestamp");
  }
  const sourceUrl = requireSourceUrl(
    artifact.source_url,
    artifact.proposal_id,
    "card-chain source_url",
  );
  if (!Array.isArray(artifact.cards) || artifact.cards.length === 0) {
    throw new Error("card-chain cards must be a non-empty array");
  }
  if (artifact.cards.length > MAX_CARDS) {
    throw new Error(`card-chain cards exceeds the ${MAX_CARDS}-card limit`);
  }
  const firstCard = artifact.cards[0];
  if (!isRecord(firstCard) || firstCard.card_type !== "ProposalCard") {
    throw new Error("card-chain first card must be ProposalCard");
  }

  const cardHashes: string[] = [];
  let previousHash: string | null = null;
  let totalPreimageBytes = 0;
  for (let index = 0; index < artifact.cards.length; index += 1) {
    const sequence = index + 1;
    const card = requireExactRecord(
      artifact.cards[index],
      CARD_FIELDS,
      `card-chain card ${sequence}`,
    );
    if (!Number.isSafeInteger(card.sequence_number) || card.sequence_number !== sequence) {
      throw new Error(`card-chain card ${sequence} sequence_number must equal ${sequence}`);
    }
    if (typeof card.card_type !== "string" || card.card_type.length === 0) {
      throw new Error(`card-chain card ${sequence} card_type is invalid`);
    }
    if (typeof card.card_hash !== "string" || !HEX64.test(card.card_hash)) {
      throw new Error(`card-chain card ${sequence} card_hash must be lowercase hex32`);
    }
    if (typeof card.canonical_card_json !== "string") {
      throw new Error(`card-chain card ${sequence} canonical_card_json must be a string`);
    }
    const preimage = Buffer.from(card.canonical_card_json, "utf8");
    if (preimage.byteLength > MAX_CARD_JSON_BYTES) {
      throw new Error(`card-chain card ${sequence} canonical_card_json exceeds its size limit`);
    }
    totalPreimageBytes += preimage.byteLength;
    if (totalPreimageBytes > MAX_TOTAL_CARD_JSON_BYTES) {
      throw new Error("card-chain canonical_card_json aggregate exceeds its size limit");
    }
    const observedHash = createHash("sha256").update(preimage).digest();
    const expectedHash = Buffer.from(card.card_hash, "hex");
    if (!timingSafeEqual(observedHash, expectedHash)) {
      throw new Error(`card-chain card ${sequence} hash does not match exact UTF-8 preimage`);
    }
    if (card.published_at !== null && !isRfc3339Utc(card.published_at, PUBLISHED_AT)) {
      throw new Error(`card-chain card ${sequence} published_at must be null or RFC3339 UTC`);
    }

    const parsed = parseJsonStrict(card.canonical_card_json);
    if (!isRecord(parsed)) {
      throw new Error(`card-chain card ${sequence} canonical_card_json must decode to an object`);
    }
    if (Object.hasOwn(parsed, "card_hash")) {
      throw new Error(`card-chain card ${sequence} canonical preimage must exclude card_hash`);
    }
    if (parsed.sequence_number !== sequence) {
      throw new Error(`card-chain card ${sequence} wrapper/preimage sequence_number mismatch`);
    }
    if (parsed.card_type !== card.card_type) {
      throw new Error(`card-chain card ${sequence} wrapper/preimage card_type mismatch`);
    }
    if (!Object.hasOwn(parsed, "previous_card_hash") || parsed.previous_card_hash !== previousHash) {
      throw new Error(`card-chain card ${sequence} previous_card_hash breaks chain linkage`);
    }
    if (sequence === 1) {
      if (parsed.signal_id !== artifact.proposal_id) {
        throw new Error("card-chain ProposalCard signal_id differs from artifact proposal_id");
      }
    } else {
      if (parsed.card_type === "ProposalCard") {
        throw new Error(`card-chain card ${sequence} cannot repeat ProposalCard`);
      }
      if (parsed.proposal_id !== artifact.proposal_id) {
        throw new Error(`card-chain card ${sequence} proposal_id differs from artifact proposal_id`);
      }
    }
    previousHash = card.card_hash;
    cardHashes.push(card.card_hash);
  }

  const finalCardHash = cardHashes.at(-1) as string;
  if (options.expectedFinalCardHash !== undefined) {
    if (!HEX64.test(options.expectedFinalCardHash)) {
      throw new Error("expected terminal final_card_hash must be lowercase hex32");
    }
    if (!timingSafeEqual(Buffer.from(finalCardHash, "hex"), Buffer.from(options.expectedFinalCardHash, "hex"))) {
      throw new Error("card-chain terminal hash differs from expected historical final_card_hash");
    }
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    proposalId: artifact.proposal_id,
    capturedAt: artifact.captured_at as string,
    sourceUrl,
    cardCount: cardHashes.length,
    firstCardHash: cardHashes[0] as string,
    finalCardHash,
    cardHashes,
  };
}

function requireExactRecord(
  value: unknown,
  expectedFields: ReadonlySet<string>,
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const missing = [...expectedFields].filter((field) => !Object.hasOwn(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.sort().join(",")}`);
  const unknown = Object.keys(value).filter((field) => !expectedFields.has(field));
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.sort().join(",")}`);
  return value;
}

function requireSourceUrl(value: unknown, proposalId: string, label: string): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 2_048) {
    throw new Error(`${label} must be an HTTPS URL`);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be an HTTPS URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.length === 0 ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.hash.length > 0 ||
    parsed.search.length > 0 ||
    parsed.pathname !== `/proof-artifacts/v1/${proposalId}/card-chain`
  ) {
    throw new Error(`${label} must be an HTTPS URL without credentials or fragment`);
  }
  return parsed.href;
}

function isRfc3339Utc(value: unknown, pattern: RegExp): value is string {
  if (typeof value !== "string") return false;
  const match = pattern.exec(value);
  if (match === null || match[1] === "0000") return false;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return false;
  const date = new Date(milliseconds);
  return (
    date.getUTCFullYear() === Number(match[1]) &&
    date.getUTCMonth() + 1 === Number(match[2]) &&
    date.getUTCDate() === Number(match[3]) &&
    date.getUTCHours() === Number(match[4]) &&
    date.getUTCMinutes() === Number(match[5]) &&
    date.getUTCSeconds() === Number(match[6])
  );
}
