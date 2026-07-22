// Test-only proof-registry fixtures conforming to
// handoff/G1_CROSS_LANE_SCHEMAS.json (public_proof_registry_v1).
// Every hash below is a SYNTHETIC test vector (patterned hex) — these fixtures
// exist only for Playwright route mocks and are never shipped to the UI.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, name), "utf8"));
}

export const FIXTURES = {
  verified: "proof-registry-verified.json",
  unverified: "proof-registry-unverified.json",
  v3Failed: "proof-registry-v3-failed.json",
};
