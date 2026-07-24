import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  deterministicBuildId,
  LIVE_E2E_BUILD_PURPOSE,
  PRODUCTION_CSPR_CLICK_APP_ID,
  productionPublicBuildInputs,
} from "../../scripts/deterministic-build-id.mjs";

const PRODUCTION_INPUTS = {
  NEXT_PUBLIC_GATEWAY_URL: "",
  NEXT_PUBLIC_CONCORDIA_MODE: "reviewer",
  NEXT_PUBLIC_CSPR_CLICK_APP_ID: PRODUCTION_CSPR_CLICK_APP_ID,
};

async function createDashboardTree() {
  const root = await mkdtemp(path.join(os.tmpdir(), "concordia-build-id-"));
  await mkdir(path.join(root, "app", "_components"), { recursive: true });
  await mkdir(path.join(root, "public"), { recursive: true });
  await writeFile(path.join(root, "app", "page.js"), "export default function Page() {}\n");
  await writeFile(path.join(root, "app", "_components", "Panel.js"), "export const Panel = 1;\n");
  await writeFile(path.join(root, "public", "shield.svg"), "<svg></svg>\n");
  await writeFile(path.join(root, "next.config.mjs"), "export default {};\n");
  await writeFile(path.join(root, "jsconfig.json"), '{"compilerOptions":{}}\n');
  await writeFile(path.join(root, "Dockerfile"), "FROM node:20-bookworm-slim\n");
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

  const first = await deterministicBuildId(root, PRODUCTION_INPUTS);
  const second = await deterministicBuildId(root, PRODUCTION_INPUTS);

  assert.match(first, /^concordia-[0-9a-f]{64}$/);
  assert.equal(second, first);
});


test("changing one included source byte changes the build ID", async () => {
  const root = await createDashboardTree();
  const first = await deterministicBuildId(root, PRODUCTION_INPUTS);

  await writeFile(path.join(root, "app", "page.js"), "export default function Changed() {}\n");

  assert.notEqual(await deterministicBuildId(root, PRODUCTION_INPUTS), first);
});

test("changing jsconfig or Dockerfile changes the build ID", async () => {
  const root = await createDashboardTree();
  const first = await deterministicBuildId(root, PRODUCTION_INPUTS);

  await writeFile(path.join(root, "jsconfig.json"), '{"compilerOptions":{"strict":true}}\n');
  const jsconfigChanged = await deterministicBuildId(root, PRODUCTION_INPUTS);
  assert.notEqual(jsconfigChanged, first);

  await writeFile(path.join(root, "Dockerfile"), "FROM node:22-bookworm-slim\n");
  assert.notEqual(
    await deterministicBuildId(root, PRODUCTION_INPUTS),
    jsconfigChanged,
  );
});

test("every production public build input changes the build ID", async () => {
  const root = await createDashboardTree();
  const first = await deterministicBuildId(root, PRODUCTION_INPUTS);
  const variants = [
    { ...PRODUCTION_INPUTS, NEXT_PUBLIC_GATEWAY_URL: "/gateway" },
    { ...PRODUCTION_INPUTS, NEXT_PUBLIC_CONCORDIA_MODE: "live" },
    {
      ...PRODUCTION_INPUTS,
      NEXT_PUBLIC_CSPR_CLICK_APP_ID: "0f892487-0a8c-45b5-8cea-bbe95c65",
    },
  ];

  for (const variant of variants) {
    assert.notEqual(await deterministicBuildId(root, variant), first);
  }
});

test("production public build inputs fail closed unless exact and explicit", () => {
  assert.deepEqual(
    productionPublicBuildInputs({ ...PRODUCTION_INPUTS }),
    PRODUCTION_INPUTS,
  );
  for (const invalid of [
    {},
    {
      ...PRODUCTION_INPUTS,
      NEXT_PUBLIC_CSPR_CLICK_APP_ID: "csprclick-template",
    },
    {
      ...PRODUCTION_INPUTS,
      NEXT_PUBLIC_CSPR_CLICK_APP_ID: "",
    },
    {
      ...PRODUCTION_INPUTS,
      NEXT_PUBLIC_CSPR_CLICK_APP_ID: (
        "0f892487-0a8c-45b5-8cea-bbe95c640001"
      ),
    },
    {
      ...PRODUCTION_INPUTS,
      NEXT_PUBLIC_CONCORDIA_MODE: "live",
    },
    {
      ...PRODUCTION_INPUTS,
      NEXT_PUBLIC_GATEWAY_URL: "https://example.invalid",
    },
  ]) {
    assert.throws(
      () => productionPublicBuildInputs(invalid),
      /production public build input/i,
    );
  }
  const liveInputs = {
    ...PRODUCTION_INPUTS,
    NEXT_PUBLIC_CONCORDIA_MODE: "live",
  };
  assert.throws(
    () => productionPublicBuildInputs(liveInputs),
    /production public build input/i,
  );
  assert.deepEqual(
    productionPublicBuildInputs({
      ...liveInputs,
      CONCORDIA_DASHBOARD_BUILD_PURPOSE: LIVE_E2E_BUILD_PURPOSE,
    }),
    liveInputs,
  );
});


test("generated, dependency, test, and editor outputs do not affect the build ID", async () => {
  const root = await createDashboardTree();
  const first = await deterministicBuildId(root, PRODUCTION_INPUTS);
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

  assert.equal(await deterministicBuildId(root, PRODUCTION_INPUTS), first);
});


test("symlinked allowlisted entries fail closed", async () => {
  const root = await createDashboardTree();
  const outside = path.join(root, "outside.js");
  await writeFile(outside, "outside\n");
  await symlink(outside, path.join(root, "app", "linked.js"));

  await assert.rejects(
    deterministicBuildId(root, PRODUCTION_INPUTS),
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
    deterministicBuildId(root, PRODUCTION_INPUTS),
    /regular file/i,
  );
});


test("Next config recomputes the ID and confines build tracing to dashboard", async () => {
  const root = path.resolve(import.meta.dirname, "..", "..");
  const config = await readFile(path.join(root, "next.config.mjs"), "utf8");
  const packageJson = JSON.parse(
    await readFile(path.join(root, "package.json"), "utf8"),
  );

  assert.match(config, /deterministicBuildId/);
  assert.match(config, /productionPublicBuildInputs/);
  assert.match(config, /generateBuildId:\s*async/);
  assert.match(config, /turbopack:\s*\{\s*root:/s);
  assert.match(config, /outputFileTracingRoot:/);
  assert.doesNotMatch(config, /CONCORDIA_DASHBOARD_BUILD_ID/);
  assert.equal(packageJson.scripts.build, "next build");
  assert.match(packageJson.scripts["build:e2e:live"], /CONCORDIA_MODE=live/);
  assert.match(
    packageJson.scripts["test:e2e:reviewer"],
    /CONCORDIA_MODE=reviewer/,
  );
  assert.match(
    packageJson.scripts["test:e2e:live"],
    /--grep-invert @reviewer-only/,
  );
  assert.equal(
    packageJson.scripts["test:unit"],
    "node --test tests/unit/*.test.mjs",
  );
});


test("Next config fails closed without the exact production public profile", () => {
  const root = path.resolve(import.meta.dirname, "..", "..");
  const env = { ...process.env };
  for (const name of Object.keys(PRODUCTION_INPUTS)) {
    delete env[name];
  }
  const missing = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", "await import('./next.config.mjs')"],
    { cwd: root, env, encoding: "utf8" },
  );
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /production public build input/i);

  const exact = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", "await import('./next.config.mjs')"],
    { cwd: root, env: { ...env, ...PRODUCTION_INPUTS }, encoding: "utf8" },
  );
  assert.equal(exact.status, 0, exact.stderr);
});
