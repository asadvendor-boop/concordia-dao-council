import { constants } from "node:fs";
import { open, realpath, stat, type FileHandle } from "node:fs/promises";
import path from "node:path";

import { isRecord } from "../encoders.js";
import { parseJsonStrict, StrictJsonError } from "../json.js";
import { verifyProofRegistry } from "../registry.js";
import { modeFailure, withMode, type ModeResult } from "./common.js";

const MAX_REGISTRY_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_REGISTRY_ITEMS = 128;
const MAX_UNIQUE_ARTIFACTS = 128;
const MAX_TOTAL_ARTIFACT_BYTES = 128 * 1024 * 1024;
const FILE_READ_CHUNK_BYTES = 64 * 1024;
const SAFE_READ_FLAGS =
  constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW;

class LocalInputError extends Error {
  constructor(
    readonly status: "invalid" | "unavailable",
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "LocalInputError";
  }
}

export async function verifyLocal(
  registryPath: string,
  options: { now?: string } = {},
): Promise<ModeResult> {
  try {
    const absolute = path.resolve(registryPath);
    const raw = await readRegistry(absolute);
    const registry = parseJsonStrict(Buffer.from(raw).toString("utf8"));
    validateRegistryResourceBounds(registry);
    const artifacts = await loadArtifacts(registry, path.dirname(absolute));
    return withMode(
      verifyProofRegistry(registry, {
        artifacts,
        ...(options.now ? { now: options.now } : {}),
      }),
      "local",
    );
  } catch (error) {
    if (error instanceof LocalInputError) {
      return modeFailure("local", error.status, error.code, error.message);
    }
    if (error instanceof StrictJsonError) {
      return modeFailure("local", "invalid", error.code, error.message);
    }
    if (isNodeError(error) && error.code === "ENOENT") {
      return modeFailure("local", "unavailable", "input_unavailable", "local input is unavailable");
    }
    return modeFailure("local", "unavailable", "local_read_failed", safeErrorMessage(error));
  }
}

async function readRegistry(absolute: string): Promise<Uint8Array> {
  const handle = await open(absolute, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) {
      throw new LocalInputError(
        "invalid",
        "registry_not_regular_file",
        "registry must be a regular file",
      );
    }
    return await readBoundedHandle(
      handle,
      MAX_REGISTRY_BYTES,
      "registry_too_large",
      "registry exceeds 8 MiB",
      metadata.size,
    );
  } finally {
    await handle.close();
  }
}

async function loadArtifacts(
  registry: unknown,
  baseDirectory: string,
): Promise<Record<string, Uint8Array>> {
  const result: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
  if (!isRecord(registry) || !Array.isArray(registry.items)) return result;

  const canonicalBase = await realpath(baseDirectory);
  const attemptedPaths = new Set<string>();
  let aggregateBytes = 0;
  for (const raw of registry.items) {
    if (!isRecord(raw) || typeof raw.artifact_path !== "string") continue;
    const relative = raw.artifact_path;
    if (attemptedPaths.has(relative)) continue;
    attemptedPaths.add(relative);
    const lexicalTarget = path.resolve(canonicalBase, relative);
    if (!isPathInside(canonicalBase, lexicalTarget)) continue;

    let canonicalTarget: string;
    try {
      canonicalTarget = await realpath(lexicalTarget);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") continue;
      throw new LocalInputError(
        "unavailable",
        "artifact_read_failed",
        safeErrorMessage(error),
      );
    }
    if (!isPathInside(canonicalBase, canonicalTarget)) {
      throw new LocalInputError(
        "invalid",
        "unsafe_artifact_path",
        `artifact path escapes the registry directory: ${relative}`,
      );
    }

    let handle: FileHandle;
    try {
      handle = await open(canonicalTarget, SAFE_READ_FLAGS);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") continue;
      throw new LocalInputError(
        "unavailable",
        "artifact_read_failed",
        safeErrorMessage(error),
      );
    }
    try {
      const openedMetadata = await handle.stat();
      if (!openedMetadata.isFile()) {
        throw new LocalInputError(
          "invalid",
          "artifact_not_regular_file",
          `artifact must be a regular file: ${relative}`,
        );
      }

      const stableTarget = await realpath(canonicalTarget);
      const currentMetadata = await stat(stableTarget);
      if (
        stableTarget !== canonicalTarget ||
        !isPathInside(canonicalBase, stableTarget) ||
        openedMetadata.dev !== currentMetadata.dev ||
        openedMetadata.ino !== currentMetadata.ino
      ) {
        throw new LocalInputError(
          "invalid",
          "unsafe_artifact_path",
          `artifact path changed while it was opened: ${relative}`,
        );
      }

      if (openedMetadata.size > MAX_TOTAL_ARTIFACT_BYTES - aggregateBytes) {
        throw new LocalInputError(
          "invalid",
          "artifact_aggregate_too_large",
          "aggregate artifact bytes exceed 128 MiB",
        );
      }
      const bytes = await readBoundedHandle(
        handle,
        MAX_ARTIFACT_BYTES,
        "artifact_too_large",
        `artifact exceeds 64 MiB: ${relative}`,
        openedMetadata.size,
      );
      if (bytes.byteLength > MAX_TOTAL_ARTIFACT_BYTES - aggregateBytes) {
        throw new LocalInputError(
          "invalid",
          "artifact_aggregate_too_large",
          "aggregate artifact bytes exceed 128 MiB",
        );
      }
      aggregateBytes += bytes.byteLength;
      result[relative] = bytes;
    } finally {
      await handle.close();
    }
  }
  return result;
}

function validateRegistryResourceBounds(registry: unknown): void {
  if (!isRecord(registry) || !Array.isArray(registry.items)) return;
  const uniqueArtifactPaths = new Set<string>();
  for (const raw of registry.items) {
    if (isRecord(raw) && typeof raw.artifact_path === "string") {
      uniqueArtifactPaths.add(raw.artifact_path);
    }
  }
  if (uniqueArtifactPaths.size > MAX_UNIQUE_ARTIFACTS) {
    throw new LocalInputError(
      "invalid",
      "artifact_count_exceeded",
      "proof registry references more than 128 unique artifacts",
    );
  }
  if (registry.items.length > MAX_REGISTRY_ITEMS) {
    throw new LocalInputError(
      "invalid",
      "too_many_items",
      "proof registry contains more than 128 items",
    );
  }
}

async function readBoundedHandle(
  handle: FileHandle,
  maximumBytes: number,
  errorCode: string,
  errorMessage: string,
  initialSize: number,
): Promise<Uint8Array> {
  if (initialSize > maximumBytes) {
    throw new LocalInputError("invalid", errorCode, errorMessage);
  }

  const chunks: Buffer[] = [];
  let position = 0;
  while (position <= maximumBytes) {
    const capacity = Math.min(FILE_READ_CHUNK_BYTES, maximumBytes - position + 1);
    const chunk = Buffer.allocUnsafe(capacity);
    const { bytesRead } = await handle.read(chunk, 0, capacity, position);
    if (bytesRead === 0) break;
    position += bytesRead;
    if (position > maximumBytes) {
      throw new LocalInputError("invalid", errorCode, errorMessage);
    }
    chunks.push(chunk.subarray(0, bytesRead));
  }
  return Buffer.concat(chunks, position);
}

function isPathInside(baseDirectory: string, target: string): boolean {
  const relative = path.relative(baseDirectory, target);
  return relative === "" || (
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function isNodeError(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error && "code" in value;
}

function safeErrorMessage(value: unknown): string {
  return value instanceof Error ? value.message : "local verification failed";
}
