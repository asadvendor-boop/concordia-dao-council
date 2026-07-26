import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const repositoryRoot = new URL("../../../", import.meta.url);

test("publication tolerates delayed npm provenance propagation without dereferencing a missing bundle", async () => {
  const verifier = await readFile(
    new URL("scripts/verify_published_release.mjs", repositoryRoot),
    "utf8",
  );
  const workflow = await readFile(
    new URL(".github/workflows/publish-verifier.yml", repositoryRoot),
    "utf8",
  );

  assert.match(verifier, /if \(!provenance\?\.bundle\?\.dsseEnvelope\?\.payload\)/);
  assert.match(verifier, /process\.exit\(75\)/);
  assert.match(workflow, /for attempt in \$\(seq 1 120\)/);
  assert.match(workflow, /sleep 5/);
});
