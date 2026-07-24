import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const destination = process.argv[2];
if (
  process.argv.length !== 3 ||
  typeof destination !== "string" ||
  !path.isAbsolute(destination)
) {
  throw new Error("usage: node install-browser.mjs <absolute-empty-destination>");
}

const runtimeRoot = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(runtimeRoot, "node_modules", "playwright", "cli.js");
const result = spawnSync(process.execPath, [cli, "install", "chromium"], {
  cwd: runtimeRoot,
  env: {
    ...process.env,
    PLAYWRIGHT_BROWSERS_PATH: destination,
  },
  stdio: "inherit",
});
if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  throw new Error(`Playwright Chromium installation failed: ${result.status}`);
}
