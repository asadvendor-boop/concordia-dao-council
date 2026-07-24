import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";


const DOMAIN = Buffer.from("CONCORDIA_DASHBOARD_BUILD_ID_V2\0", "ascii");
const ROOT_FILES = [
  "Dockerfile",
  "jsconfig.json",
  "next.config.mjs",
  "package-lock.json",
  "package.json",
  "scripts/deterministic-build-id.mjs",
];
const ROOT_DIRECTORIES = ["app", "public"];
const PUBLIC_BUILD_INPUT_NAMES = [
  "NEXT_PUBLIC_GATEWAY_URL",
  "NEXT_PUBLIC_CONCORDIA_MODE",
  "NEXT_PUBLIC_CSPR_CLICK_APP_ID",
];
export const PRODUCTION_CSPR_CLICK_APP_ID = "0f892487-0a8c-45b5-8cea-bbe95c64";
export const LIVE_E2E_BUILD_PURPOSE = "e2e-live";


function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}


function encodeU32(value) {
  const encoded = Buffer.alloc(4);
  encoded.writeUInt32BE(value);
  return encoded;
}


function encodeU64(value) {
  const encoded = Buffer.alloc(8);
  encoded.writeBigUInt64BE(BigInt(value));
  return encoded;
}


async function requireDirectory(directory) {
  const metadata = await lstat(directory);
  if (metadata.isSymbolicLink()) {
    throw new Error(`allowlisted path is a symlink: ${directory}`);
  }
  if (!metadata.isDirectory()) {
    throw new Error(`allowlisted path is not a directory: ${directory}`);
  }
}


async function collectDirectoryFiles(root, directory, output) {
  await requireDirectory(directory);
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => compareUtf8(left.name, right.name));
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`allowlisted path is a symlink: ${absolute}`);
    }
    if (entry.isDirectory()) {
      await collectDirectoryFiles(root, absolute, output);
      continue;
    }
    if (!entry.isFile()) {
      throw new Error(`allowlisted path is not a regular file: ${absolute}`);
    }
    output.push(path.relative(root, absolute).split(path.sep).join("/"));
  }
}


async function readRegularFile(root, relative) {
  const absolute = path.join(root, ...relative.split("/"));
  const before = await lstat(absolute);
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new Error(`allowlisted path is not a regular file: ${relative}`);
  }

  const flags = fsConstants.O_RDONLY
    | (fsConstants.O_NOFOLLOW ?? 0)
    | (fsConstants.O_CLOEXEC ?? 0);
  const handle = await open(absolute, flags);
  try {
    const opened = await handle.stat();
    if (!opened.isFile()) {
      throw new Error(`allowlisted path is not a regular file: ${relative}`);
    }
    if (opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error(`allowlisted path changed while reading: ${relative}`);
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}


function normalizePublicBuildInputs(inputs) {
  if (inputs === null || typeof inputs !== "object" || Array.isArray(inputs)) {
    throw new Error("public build inputs must be an exact object");
  }
  const keys = Object.keys(inputs).sort(compareUtf8);
  const expected = [...PUBLIC_BUILD_INPUT_NAMES].sort(compareUtf8);
  if (
    keys.length !== expected.length
    || keys.some((key, index) => key !== expected[index])
  ) {
    throw new Error("public build inputs must contain the exact frozen keys");
  }
  const normalized = {};
  for (const name of PUBLIC_BUILD_INPUT_NAMES) {
    const value = inputs[name];
    if (
      typeof value !== "string"
      || value.includes("\0")
      || Buffer.byteLength(value, "utf8") > 4096
    ) {
      throw new Error(`public build input ${name} is malformed`);
    }
    normalized[name] = value;
  }
  return normalized;
}


export function productionPublicBuildInputs(environment) {
  let inputs;
  try {
    inputs = normalizePublicBuildInputs({
      NEXT_PUBLIC_GATEWAY_URL: environment?.NEXT_PUBLIC_GATEWAY_URL,
      NEXT_PUBLIC_CONCORDIA_MODE: environment?.NEXT_PUBLIC_CONCORDIA_MODE,
      NEXT_PUBLIC_CSPR_CLICK_APP_ID:
        environment?.NEXT_PUBLIC_CSPR_CLICK_APP_ID,
    });
  } catch {
    throw new Error("production public build inputs are missing or malformed");
  }
  const commonInputsAreExact = (
    inputs.NEXT_PUBLIC_GATEWAY_URL === ""
    && inputs.NEXT_PUBLIC_CSPR_CLICK_APP_ID === PRODUCTION_CSPR_CLICK_APP_ID
  );
  const isProduction = (
    commonInputsAreExact
    && inputs.NEXT_PUBLIC_CONCORDIA_MODE === "reviewer"
    && environment?.CONCORDIA_DASHBOARD_BUILD_PURPOSE === undefined
  );
  const isLiveE2e = (
    commonInputsAreExact
    && inputs.NEXT_PUBLIC_CONCORDIA_MODE === "live"
    && environment?.CONCORDIA_DASHBOARD_BUILD_PURPOSE === LIVE_E2E_BUILD_PURPOSE
  );
  if (!isProduction && !isLiveE2e) {
    throw new Error("production public build inputs are missing or malformed");
  }
  return Object.freeze(inputs);
}


export async function deterministicBuildId(root, publicBuildInputs) {
  const absoluteRoot = path.resolve(root);
  await requireDirectory(absoluteRoot);
  const inputs = normalizePublicBuildInputs(publicBuildInputs);

  const files = [...ROOT_FILES];
  for (const directory of ROOT_DIRECTORIES) {
    await collectDirectoryFiles(
      absoluteRoot,
      path.join(absoluteRoot, directory),
      files,
    );
  }
  files.sort(compareUtf8);

  const hash = createHash("sha256");
  hash.update(DOMAIN);
  hash.update(encodeU32(files.length));
  for (const relative of files) {
    const normalized = Buffer.from(relative, "utf8");
    const bytes = await readRegularFile(absoluteRoot, relative);
    hash.update(encodeU32(normalized.length));
    hash.update(normalized);
    hash.update(encodeU64(bytes.length));
    hash.update(bytes);
  }
  hash.update(encodeU32(PUBLIC_BUILD_INPUT_NAMES.length));
  for (const name of PUBLIC_BUILD_INPUT_NAMES) {
    const encodedName = Buffer.from(name, "ascii");
    const encodedValue = Buffer.from(inputs[name], "utf8");
    hash.update(encodeU32(encodedName.length));
    hash.update(encodedName);
    hash.update(encodeU64(encodedValue.length));
    hash.update(encodedValue);
  }
  return `concordia-${hash.digest("hex")}`;
}
