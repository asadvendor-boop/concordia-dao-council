import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const source = new URL("../../../tests/golden/envelope_v3/", import.meta.url);
const destination = new URL("../dist/vectors/", import.meta.url);

await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true, force: true });

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const releaseRoot = new URL("../../../contracts/odra-governance-receipt-v3/", import.meta.url);
const releaseDestination = new URL("../dist/release/v3/", import.meta.url);
await mkdir(new URL("source/", releaseDestination), { recursive: true });
await mkdir(new URL("wasm/", releaseDestination), { recursive: true });
await mkdir(new URL("schema/", releaseDestination), { recursive: true });

// The frozen deployment manifest is copied verbatim (never rewritten). Its
// source/wasm/schema PINS reflect the historical build commit, not the live
// worktree — which on any branch whose contract crate has legitimately
// evolved no longer matches. To keep the packaged release snapshot internally
// consistent with the frozen manifest (the node analog of the Python
// split-API historical verifier), the source/wasm/schema/Cargo.lock bytes are
// exported from the exact commit whose blobs hash to the frozen pins, via
// argv-based `git show` plumbing — never fabricated, never the worktree copy.
const manifest = JSON.parse(await readFile(new URL("deployment.manifest.json", releaseRoot), "utf8"));
const crateRel = "contracts/odra-governance-receipt-v3";
const pins = {
  "src/lib.rs": manifest.source.lib_rs_sha256,
  "src/encoding.rs": manifest.source.encoding_rs_sha256,
  "Cargo.lock": manifest.source.cargo_lock_sha256,
  "wasm/GovernanceReceiptV3.wasm": manifest.build.wasm_sha256,
  "resources/casper_contract_schemas/governance_receiptv3_schema.json": manifest.build.schema_sha256,
};
function gitShow(commit, relpath) {
  return execFileSync("git", ["-C", repoRoot, "show", `${commit}:${crateRel}/${relpath}`], {
    maxBuffer: 64 * 1024 * 1024,
  });
}
function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
const commits = execFileSync("git", ["-C", repoRoot, "log", "--format=%H", "--", crateRel], {
  encoding: "utf8",
})
  .split("\n")
  .filter(Boolean);
let historicalCommit = null;
for (const commit of commits) {
  let ok = true;
  for (const [relpath, expected] of Object.entries(pins)) {
    try {
      if (sha256(gitShow(commit, relpath)) !== expected) {
        ok = false;
        break;
      }
    } catch {
      ok = false;
      break;
    }
  }
  if (ok) {
    historicalCommit = commit;
    break;
  }
}
if (!historicalCommit) {
  throw new Error("no committed revision matches the frozen deployment manifest pins");
}

await cp(new URL("deployment.manifest.json", releaseRoot), new URL("deployment.manifest.json", releaseDestination));
await writeFile(new URL("wasm/GovernanceReceiptV3.wasm", releaseDestination), gitShow(historicalCommit, "wasm/GovernanceReceiptV3.wasm"));
await writeFile(
  new URL("schema/governance_receiptv3_schema.json", releaseDestination),
  gitShow(historicalCommit, "resources/casper_contract_schemas/governance_receiptv3_schema.json"),
);
await writeFile(new URL("source/lib.rs", releaseDestination), gitShow(historicalCommit, "src/lib.rs"));
await writeFile(new URL("source/encoding.rs", releaseDestination), gitShow(historicalCommit, "src/encoding.rs"));
await writeFile(new URL("source/Cargo.lock", releaseDestination), gitShow(historicalCommit, "Cargo.lock"));
await cp(
  new URL("../../../handoff/HISTORICAL_ODRA_SHA256.txt", import.meta.url),
  new URL("source/HISTORICAL_ODRA_SHA256.txt", releaseDestination),
);

const historicalDestination = new URL("../dist/release/historical/", import.meta.url);
await mkdir(historicalDestination, { recursive: true });
await cp(
  new URL("../../../handoff/HISTORICAL_ODRA_RECEIPTS_V1.json", import.meta.url),
  new URL("HISTORICAL_ODRA_RECEIPTS_V1.json", historicalDestination),
);
