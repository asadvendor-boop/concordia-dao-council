import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { deterministicBuildId } from "../../scripts/deterministic-build-id.mjs";


async function createDashboardTree() {
  const root = await mkdtemp(path.join(os.tmpdir(), "concordia-build-id-"));
  await mkdir(path.join(root, "app", "_components"), { recursive: true });
  await mkdir(path.join(root, "public"), { recursive: true });
  await writeFile(path.join(root, "app", "page.js"), "export default function Page() {}\n");
  await writeFile(path.join(root, "app", "_components", "Panel.js"), "export const Panel = 1;\n");
  await writeFile(path.join(root, "public", "shield.svg"), "<svg></svg>\n");
  await writeFile(path.join(root, "next.config.mjs"), "export default {};\n");
  await writeFile(path.join(root, "package.json"), '{"name":"dashboard"}\n');
  await writeFile(path.join(root, "package-lock.json"), '{"lockfileVersion":3}\n');
  await mkdir(path.join(root, "scripts"));
  await writeFile(
    path.join(root, "scripts", "deterministic-build-id.mjs"),
    "export const marker = true;\n",
  );
  return root;
}


test("identical input bytes produce one stable lowercase build ID", async () => {
  const root = await createDashboardTree();

  const first = await deterministicBuildId(root);
  const second = await deterministicBuildId(root);

  assert.match(first, /^concordia-[0-9a-f]{64}$/);
  assert.equal(second, first);
});


test("changing one included source byte changes the build ID", async () => {
  const root = await createDashboardTree();
  const first = await deterministicBuildId(root);

  await writeFile(path.join(root, "app", "page.js"), "export default function Changed() {}\n");

  assert.notEqual(await deterministicBuildId(root), first);
});


test("generated, dependency, test, and editor outputs do not affect the build ID", async () => {
  const root = await createDashboardTree();
  const first = await deterministicBuildId(root);
  const excluded = [
    [".next", "BUILD_ID"],
    ["node_modules", "pkg", "index.js"],
    ["tests", "results", "trace.zip"],
    ["playwright-report", "index.html"],
    ["test-results", "result.json"],
    ["coverage", "lcov.info"],
    [".cache", "cache.bin"],
    [".idea", "workspace.xml"],
  ];
  for (const parts of excluded) {
    const target = path.join(root, ...parts);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, `ignored:${parts.join("/")}\n`);
  }

  assert.equal(await deterministicBuildId(root), first);
});


test("symlinked allowlisted entries fail closed", async () => {
  const root = await createDashboardTree();
  const outside = path.join(root, "outside.js");
  await writeFile(outside, "outside\n");
  await symlink(outside, path.join(root, "app", "linked.js"));

  await assert.rejects(
    deterministicBuildId(root),
    /symlink|regular file/i,
  );
});


test("non-regular allowlisted entries fail closed", async (t) => {
  if (process.platform === "win32") {
    t.skip("mkfifo is not available on Windows");
    return;
  }
  const root = await createDashboardTree();
  const fifo = path.join(root, "public", "unexpected.fifo");
  const result = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);

  await assert.rejects(
    deterministicBuildId(root),
    /regular file/i,
  );
});


test("the build wrapper computes the ID without importing filesystem code into Next config", async () => {
  const root = path.resolve(import.meta.dirname, "..", "..");
  const config = await readFile(path.join(root, "next.config.mjs"), "utf8");
  const packageJson = JSON.parse(
    await readFile(path.join(root, "package.json"), "utf8"),
  );

  assert.doesNotMatch(config, /deterministic-build-id/);
  assert.doesNotMatch(config, /node:path|node:url|fileURLToPath|turbopack:\s*\{/);
  assert.equal(
    packageJson.scripts.build,
    "node scripts/deterministic-build-id.mjs --next-build",
  );
});
