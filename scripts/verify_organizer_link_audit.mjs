#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import process from "node:process";

import {
  GateFailure,
  canonicalJson,
  validateResultDocument,
} from "./organizer-link-gate-core.mjs";

const AUDIT_LIMIT = 32 * 1024 * 1024;

async function main(argv) {
  if (argv.length !== 1 || !argv[0]) {
    throw new GateFailure(
      "ARGUMENTS_INVALID",
      "usage: node scripts/verify_organizer_link_audit.mjs AUDIT.json",
    );
  }
  const metadata = await lstat(argv[0]);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new GateFailure(
      "AUDIT_FILE_INVALID",
      "organizer audit must be a regular non-symlink file",
    );
  }
  const raw = await readFile(argv[0]);
  if (raw.length === 0 || raw.length > AUDIT_LIMIT) {
    throw new GateFailure(
      "AUDIT_FILE_INVALID",
      "organizer audit size is invalid",
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new GateFailure(
      "AUDIT_JSON_INVALID",
      "organizer audit is not valid UTF-8 JSON",
    );
  }
  const validated = validateResultDocument(parsed);
  const expectedRaw = Buffer.from(`${canonicalJson(validated)}\n`, "utf8");
  if (!raw.equals(expectedRaw)) {
    throw new GateFailure(
      "AUDIT_CANONICAL_INVALID",
      "organizer audit is not canonical JSON",
    );
  }
  if (
    validated.collection_mode !== "live_incognito" ||
    validated.release_qualified !== true ||
    validated.verdict !== "PASS"
  ) {
    throw new GateFailure(
      "NON_QUALIFYING_AUDIT",
      "only a live-incognito PASS qualifies as release evidence",
    );
  }
  const projection = {
    schema_version: validated.schema_version,
    verdict: validated.verdict,
    release_qualified: validated.release_qualified,
    collection_mode: validated.collection_mode,
    audit_sha256: createHash("sha256").update(raw).digest("hex"),
  };
  process.stdout.write(`${canonicalJson(projection)}\n`);
}

main(process.argv.slice(2)).catch((error) => {
  const code =
    error instanceof GateFailure ? error.code : "UNEXPECTED_VERIFIER_FAILURE";
  process.stderr.write(`organizer audit verifier refused ${code}\n`);
  process.exitCode = 1;
});
