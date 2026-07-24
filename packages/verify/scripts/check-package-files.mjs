import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const result = spawnSync("npm", ["pack", "--json", "--dry-run"], {
  cwd: new URL("../", import.meta.url),
  encoding: "utf8",
  shell: false,
});

assert.equal(result.status, 0, result.stderr);
const packs = JSON.parse(result.stdout);
assert.equal(packs.length, 1, "npm pack must describe exactly one tarball");

const files = packs[0].files.map((entry) => entry.path).sort();
assert(files.includes("package.json"), "package.json is required");
assert(files.includes("README.md"), "README.md is required");
assert(files.includes("LICENSE"), "LICENSE is required");
assert(files.includes("dist/index.js"), "compiled entry point is required");
assert(files.includes("dist/cli.js"), "compiled CLI is required");

for (const file of files) {
  assert(
    file === "package.json" ||
      file === "README.md" ||
      file === "LICENSE" ||
      file.startsWith("dist/"),
    `unexpected file in public package: ${file}`,
  );
}

process.stdout.write(
  `${JSON.stringify(
    {
      name: packs[0].name,
      version: packs[0].version,
      file_count: files.length,
      files,
    },
    null,
    2,
  )}\n`,
);
