import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";


const DOMAIN = Buffer.from("CONCORDIA_DASHBOARD_BUILD_ID_V1\0", "ascii");
const ROOT_FILES = [
  "next.config.mjs",
  "package-lock.json",
  "package.json",
  "scripts/deterministic-build-id.mjs",
];
const ROOT_DIRECTORIES = ["app", "public"];


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


export async function deterministicBuildId(root) {
  const absoluteRoot = path.resolve(root);
  await requireDirectory(absoluteRoot);

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
  return `concordia-${hash.digest("hex")}`;
}


async function runNextBuild() {
  if (process.argv.length !== 3 || process.argv[2] !== "--next-build") {
    throw new Error("usage: deterministic-build-id.mjs --next-build");
  }
  const root = path.resolve(import.meta.dirname, "..");
  const buildId = await deterministicBuildId(root);
  const nextExecutable = path.join(root, "node_modules", ".bin", "next");
  const child = spawn(nextExecutable, ["build"], {
    cwd: root,
    env: {
      ...process.env,
      CONCORDIA_DASHBOARD_BUILD_ID: buildId,
    },
    shell: false,
    stdio: "inherit",
  });
  const forward = new Map();
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    const handler = () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill(signal);
      }
    };
    forward.set(signal, handler);
    process.on(signal, handler);
  }
  const result = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  for (const [signal, handler] of forward) {
    process.off(signal, handler);
  }
  if (result.signal !== null) {
    throw new Error(`next build terminated by ${result.signal}`);
  }
  if (result.code !== 0) {
    process.exitCode = result.code ?? 1;
  }
}


const invokedAsScript = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) {
  await runNextBuild();
}
