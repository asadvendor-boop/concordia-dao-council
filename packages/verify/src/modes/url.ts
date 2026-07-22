import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { Readable } from "node:stream";

import { isRecord } from "../encoders.js";
import { parseJsonStrict, StrictJsonError } from "../json.js";
import { verifyProofRegistry } from "../registry.js";
import { modeFailure, withMode, type ModeResult, type VerificationMode } from "./common.js";

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export type DnsLookupLike = (hostname: string) => Promise<readonly string[]>;

export type UrlVerificationOptions = {
  fetchImpl?: FetchLike;
  dnsLookup?: DnsLookupLike;
  timeoutMs?: number;
  now?: string;
  mode?: Extract<VerificationMode, "url" | "proposal" | "live">;
};

type ResourceKind = "registry" | "artifact";

type RemoteResource = {
  status: number;
  ok: boolean;
  bytes?: Uint8Array;
};

export type RemoteProofBundle = {
  registry: unknown;
  artifacts: Readonly<Record<string, Uint8Array>>;
};

const RAW_PROOF_BUNDLE: unique symbol = Symbol("concordia.raw-proof-bundle");

export function getRawProofBundle(result: ModeResult): RemoteProofBundle | undefined {
  return (result as ModeResult & { [RAW_PROOF_BUNDLE]?: RemoteProofBundle })[RAW_PROOF_BUNDLE];
}

const MAX_REGISTRY_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_REGISTRY_ITEMS = 128;
const MAX_UNIQUE_ARTIFACTS = 128;
const MAX_TOTAL_ARTIFACT_BYTES = 128 * 1024 * 1024;

const RESTRICTED_IPV4 = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const;

const RESTRICTED_IPV6 = [
  ["::", 96],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
  ["5f00::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
] as const;

const restrictedIpv4 = new BlockList();
const restrictedIpv6 = new BlockList();
for (const [network, prefix] of RESTRICTED_IPV4) {
  restrictedIpv4.addSubnet(network, prefix, "ipv4");
  restrictedIpv6.addSubnet(`::ffff:${network}`, 96 + prefix, "ipv6");
}
for (const [network, prefix] of RESTRICTED_IPV6) {
  restrictedIpv6.addSubnet(network, prefix, "ipv6");
}

class RemoteModeError extends Error {
  constructor(
    readonly status: "invalid" | "unavailable",
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RemoteModeError";
  }
}

export async function verifyUrl(
  registryUrl: string,
  options: UrlVerificationOptions = {},
): Promise<ModeResult> {
  const mode = options.mode ?? "url";
  let url: URL;
  try {
    url = requireHttpsUrl(registryUrl);
  } catch (error) {
    if (error instanceof RemoteModeError) {
      return modeFailure(mode, error.status, error.code, error.message);
    }
    return modeFailure(mode, "invalid", "invalid_url", safeErrorMessage(error));
  }

  const fetchImpl = options.fetchImpl;
  if (fetchImpl !== undefined && options.dnsLookup === undefined) {
    return modeFailure(
      mode,
      "invalid",
      "custom_fetch_dns_required",
      "a custom fetch implementation requires an explicit DNS resolver",
    );
  }
  const dnsLookup = options.dnsLookup ??
    (options.fetchImpl === undefined ? systemDnsLookup : undefined);
  const timeoutMs = options.timeoutMs ?? 10_000;
  const controller = new AbortController();
  const deadline = { timedOut: false };
  const timer = setTimeout(() => {
    deadline.timedOut = true;
    controller.abort(new Error("URL verification timed out"));
  }, timeoutMs);

  try {
    const response = await fetchBoundedResource(
      fetchImpl,
      url,
      "registry",
      MAX_REGISTRY_BYTES,
      dnsLookup,
      controller,
      deadline,
    );
    if (response.status === 404) {
      return modeFailure(mode, "unknown", "proposal_not_found", "proof registry returned 404");
    }
    if (!response.ok) {
      return modeFailure(
        mode,
        "unavailable",
        "registry_http_error",
        `proof registry returned HTTP ${response.status}`,
      );
    }
    if (response.bytes === undefined) {
      throw new RemoteModeError(
        "unavailable",
        "registry_read_failed",
        "proof registry response body is unavailable",
      );
    }

    const registry = parseJsonStrict(Buffer.from(response.bytes).toString("utf8"));
    validateRegistryResourceBounds(registry);
    const structural = verifyProofRegistry(registry, {
      ...(options.now ? { now: options.now } : {}),
    });
    if (structural.status === "invalid") return withMode(structural, mode);
    const artifacts = await fetchArtifacts(
      registry,
      url,
      fetchImpl,
      dnsLookup,
      controller,
      deadline,
    );
    const result = withMode(
      verifyProofRegistry(registry, {
        artifacts,
        ...(options.now ? { now: options.now } : {}),
      }),
      mode,
    );
    Object.defineProperty(result, RAW_PROOF_BUNDLE, {
      value: { registry, artifacts } satisfies RemoteProofBundle,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    return result;
  } catch (error) {
    if (error instanceof StrictJsonError) {
      return modeFailure(mode, "invalid", error.code, error.message);
    }
    if (error instanceof RemoteModeError) {
      return modeFailure(mode, error.status, error.code, error.message);
    }
    return modeFailure(mode, "unavailable", "registry_fetch_failed", safeErrorMessage(error));
  } finally {
    clearTimeout(timer);
  }
}

async function fetchArtifacts(
  registry: unknown,
  registryUrl: URL,
  fetchImpl: FetchLike | undefined,
  dnsLookup: DnsLookupLike | undefined,
  controller: AbortController,
  deadline: { timedOut: boolean },
): Promise<Record<string, Uint8Array>> {
  const artifacts: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
  if (!isRecord(registry) || !Array.isArray(registry.items)) return artifacts;

  const artifactUrls = new Map<string, URL>();
  for (const raw of registry.items) {
    if (!isRecord(raw) || typeof raw.artifact_path !== "string" || !Array.isArray(raw.links)) {
      continue;
    }
    for (const link of raw.links) {
      if (
        !isRecord(link) ||
        (link.kind !== "artifact" && link.kind !== "download") ||
        typeof link.href !== "string"
      ) {
        continue;
      }
      let artifactUrl: URL;
      try {
        artifactUrl = requireHttpsUrl(link.href);
      } catch (error) {
        if (error instanceof RemoteModeError) throw error;
        throw new RemoteModeError(
          "invalid",
          "invalid_artifact_url",
          `artifact URL is invalid for ${raw.artifact_path}`,
        );
      }
      if (artifactUrl.origin !== registryUrl.origin) {
        throw new RemoteModeError(
          "invalid",
          "artifact_origin_mismatch",
          `artifact URL must use the proof registry origin: ${raw.artifact_path}`,
        );
      }
      const previous = artifactUrls.get(raw.artifact_path);
      if (previous !== undefined && previous.href !== artifactUrl.href) {
        throw new RemoteModeError(
          "invalid",
          "artifact_link_conflict",
          `artifact path has conflicting URLs: ${raw.artifact_path}`,
        );
      }
      artifactUrls.set(raw.artifact_path, artifactUrl);
    }
  }

  let aggregateBytes = 0;
  for (const [artifactPath, artifactUrl] of artifactUrls) {
    const response = await fetchBoundedResource(
      fetchImpl,
      artifactUrl,
      "artifact",
      MAX_ARTIFACT_BYTES,
      dnsLookup,
      controller,
      deadline,
    );
    if (!response.ok || response.bytes === undefined) continue;
    if (response.bytes.byteLength > MAX_TOTAL_ARTIFACT_BYTES - aggregateBytes) {
      throw new RemoteModeError(
        "invalid",
        "artifact_aggregate_too_large",
        "aggregate artifact bytes exceed 128 MiB",
      );
    }
    aggregateBytes += response.bytes.byteLength;
    artifacts[artifactPath] = response.bytes;
  }
  return artifacts;
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
    throw new RemoteModeError(
      "invalid",
      "artifact_count_exceeded",
      "proof registry references more than 128 unique artifacts",
    );
  }
  if (registry.items.length > MAX_REGISTRY_ITEMS) {
    throw new RemoteModeError(
      "invalid",
      "too_many_items",
      "proof registry contains more than 128 items",
    );
  }
}

async function fetchBoundedResource(
  fetchImpl: FetchLike | undefined,
  url: URL,
  kind: ResourceKind,
  maximumBytes: number,
  dnsLookup: DnsLookupLike | undefined,
  controller: AbortController,
  deadline: { timedOut: boolean },
): Promise<RemoteResource> {
  let resolvedAddresses: readonly string[];
  try {
    resolvedAddresses = await ensureSafeResolvedHost(
      url,
      dnsLookup,
      controller.signal,
    );
    if (fetchImpl === undefined && resolvedAddresses.length === 0) {
      throw new Error("DNS lookup returned no addresses");
    }
  } catch (error) {
    if (error instanceof RemoteModeError) throw error;
    throw new RemoteModeError(
      "unavailable",
      `${kind}_dns_failed`,
      deadline.timedOut ? `${kind} DNS lookup timed out` : safeErrorMessage(error),
    );
  }

  let response: Response;
  try {
    const headers = {
      accept: kind === "registry"
        ? "application/json"
        : "application/octet-stream, application/json;q=0.9",
    };
    const request = fetchImpl === undefined
      ? pinnedHttpsGet(
          url,
          headers,
          controller.signal,
          resolvedAddresses[0] as string,
        )
      : fetchImpl(url, {
          method: "GET",
          headers,
          redirect: "error",
          signal: controller.signal,
        });

    response = await raceWithAbort(request, controller.signal);
  } catch (error) {
    if (error instanceof RemoteModeError) throw error;
    throw new RemoteModeError(
      "unavailable",
      `${kind}_fetch_failed`,
      deadline.timedOut ? `${kind} request timed out` : safeErrorMessage(error),
    );
  }

  if (response.redirected || isRedirectStatus(response.status) || responseUrlChanged(response, url)) {
    await cancelResponseBody(response);
    throw new RemoteModeError(
      "unavailable",
      `${kind}_redirect_rejected`,
      `${kind} redirects are not allowed`,
    );
  }
  if (!response.ok) {
    await cancelResponseBody(response);
    return { status: response.status, ok: false };
  }

  try {
    const bytes = await readBoundedBody(
      response,
      maximumBytes,
      kind,
      controller,
    );
    return { status: response.status, ok: true, bytes };
  } catch (error) {
    if (error instanceof RemoteModeError) throw error;
    throw new RemoteModeError(
      "unavailable",
      `${kind}_read_failed`,
      deadline.timedOut ? `${kind} response timed out` : safeErrorMessage(error),
    );
  }
}

async function readBoundedBody(
  response: Response,
  maximumBytes: number,
  kind: ResourceKind,
  controller: AbortController,
): Promise<Uint8Array> {
  const length = response.headers.get("content-length");
  if (length !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(length)) {
      await cancelResponseBody(response);
      throw new RemoteModeError(
        "unavailable",
        `${kind}_invalid_content_length`,
        `${kind} response has an invalid Content-Length`,
      );
    }
    if (BigInt(length) > BigInt(maximumBytes)) {
      await cancelResponseBody(response);
      controller.abort(new Error(`${kind} response exceeds its size limit`));
      throw sizeLimitError(kind);
    }
  }
  if (response.body === null) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await raceWithAbort(reader.read(), controller.signal);
      if (done) break;
      if (value === undefined) continue;
      if (value.byteLength > maximumBytes - total) {
        try {
          await reader.cancel("response exceeds verifier size limit");
        } catch {
          // The abort below still closes the underlying network request.
        }
        controller.abort(new Error(`${kind} response exceeds its size limit`));
        throw sizeLimitError(kind);
      }
      total += value.byteLength;
      chunks.push(value);
    }
  } catch (error) {
    if (controller.signal.aborted) {
      try {
        await reader.cancel(controller.signal.reason);
      } catch {
        // The associated fetch was already aborted.
      }
    }
    throw error;
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function ensureSafeResolvedHost(
  url: URL,
  dnsLookup: DnsLookupLike | undefined,
  signal: AbortSignal,
): Promise<readonly string[]> {
  const hostname = normalizeHostname(url.hostname);
  if (isIP(hostname) !== 0) return [hostname];
  if (dnsLookup === undefined) return [];
  const addresses = await raceWithAbort(dnsLookup(hostname), signal);
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new Error("DNS lookup returned no addresses");
  }
  for (const address of addresses) {
    if (typeof address !== "string" || isIP(normalizeHostname(address)) === 0) {
      throw new Error("DNS lookup returned an invalid address");
    }
    assertPublicAddress(normalizeHostname(address));
  }
  return addresses.map(normalizeHostname);
}

async function systemDnsLookup(hostname: string): Promise<readonly string[]> {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map(({ address }) => address);
}

function pinnedHttpsGet(
  url: URL,
  headers: Readonly<Record<string, string>>,
  signal: AbortSignal,
  address: string,
): Promise<Response> {
  const family = isIP(address);
  if (family !== 4 && family !== 6) {
    return Promise.reject(new Error("pinned HTTPS address is invalid"));
  }
  const pinnedLookup: LookupFunction = (_hostname, _options, callback) => {
    callback(null, address, family);
  };

  return new Promise<Response>((resolve, reject) => {
    const request = httpsRequest(
      url,
      {
        method: "GET",
        headers,
        signal,
        agent: false,
        lookup: pinnedLookup,
        family,
        rejectUnauthorized: true,
      },
      (incoming) => {
        try {
          const responseHeaders = new Headers();
          for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
            const name = incoming.rawHeaders[index];
            const value = incoming.rawHeaders[index + 1];
            if (name !== undefined && value !== undefined) {
              responseHeaders.append(name, value);
            }
          }
          const status = incoming.statusCode ?? 0;
          const body = status === 204 || status === 205 || status === 304
            ? null
            : Readable.toWeb(incoming) as ReadableStream<Uint8Array>;
          resolve(new Response(body, {
            status,
            headers: responseHeaders,
            ...(incoming.statusMessage === undefined
              ? {}
              : { statusText: incoming.statusMessage }),
          }));
        } catch (error) {
          incoming.destroy();
          reject(error);
        }
      },
    );
    request.once("error", reject);
    request.end();
  });
}

function requireHttpsUrl(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    hasExplicitUserInfo(value)
  ) {
    throw new Error("URL must use HTTPS without embedded credentials");
  }
  assertSafeHostname(url.hostname);
  return url;
}

function hasExplicitUserInfo(value: string): boolean {
  const authority = value.trim().match(
    /^[A-Za-z][A-Za-z0-9+.-]*:[\\/]{2}([^\\/?#]*)/,
  )?.[1];
  return authority?.includes("@") ?? false;
}

function assertSafeHostname(rawHostname: string): void {
  const hostname = normalizeHostname(rawHostname);
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname === "home.arpa" ||
    hostname.endsWith(".home.arpa")
  ) {
    throw unsafeHostError(hostname);
  }
  if (isIP(hostname) !== 0) assertPublicAddress(hostname);
}

function assertPublicAddress(address: string): void {
  const family = isIP(address);
  if (
    family === 0 ||
    (family === 4 && restrictedIpv4.check(address, "ipv4")) ||
    (family === 6 && restrictedIpv6.check(address, "ipv6"))
  ) {
    throw unsafeHostError(address);
  }
}

function unsafeHostError(hostname: string): RemoteModeError {
  return new RemoteModeError(
    "invalid",
    "unsafe_remote_host",
    `remote host is not publicly routable: ${hostname}`,
  );
}

function normalizeHostname(hostname: string): string {
  const withoutBrackets = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  return withoutBrackets.replace(/\.+$/, "").toLowerCase();
}

function sizeLimitError(kind: ResourceKind): RemoteModeError {
  return new RemoteModeError(
    "invalid",
    `${kind}_too_large`,
    `${kind} exceeds ${kind === "registry" ? "8" : "64"} MiB`,
  );
}

function isRedirectStatus(status: number): boolean {
  return status >= 300 && status < 400;
}

function responseUrlChanged(response: Response, requested: URL): boolean {
  if (response.url === "") return false;
  try {
    const actual = new URL(response.url);
    const expected = new URL(requested);
    actual.hash = "";
    expected.hash = "";
    return actual.href !== expected.href;
  } catch {
    return true;
  }
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (response.body === null || response.body.locked) return;
  try {
    await response.body.cancel("response is not accepted by verifier policy");
  } catch {
    // Best effort: callers still abort active requests on timeout/size limits.
  }
}

function raceWithAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function safeErrorMessage(value: unknown): string {
  return value instanceof Error ? value.message : "remote verification failed";
}
