import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { Readable } from "node:stream";

import { isRecord } from "../encoders.js";
import { parseJsonStrict } from "../json.js";
import { verifyProofRegistry } from "../registry.js";
import { canonicalTranscriptJson } from "../adapters/casper-state.js";

export type CasperRpcDnsLookup = (hostname: string) => Promise<readonly string[]>;
export type CasperRpcTransport = (
  endpoint: URL,
  body: string,
  signal: AbortSignal,
  pinnedAddress: string,
) => Promise<Response>;

export type CasperLiveOptions = {
  rpcEndpoints: readonly string[];
  dnsLookup?: CasperRpcDnsLookup;
  transport?: CasperRpcTransport;
  timeoutMs?: number;
  overallTimeoutMs?: number;
  maxResponseBytes?: number;
  now?: string;
};

export type CasperLiveCorroboration = {
  verificationScope: "live_casper_rpc_corroborated";
  observationSources: string[];
  observedAt: string;
  rpcObservationCount: number;
};

export class CasperLiveError extends Error {
  constructor(
    readonly status: "invalid" | "unavailable",
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "CasperLiveError";
  }
}

export type CasperProofBundle = {
  registry: unknown;
  artifacts: Readonly<Record<string, Uint8Array | string>>;
};

type ExpectedObservation = {
  method: string;
  params: unknown;
  expectedResult: unknown;
};

const READ_ONLY_METHODS = new Set([
  "info_get_deploy",
  "chain_get_block",
  "chain_get_state_root_hash",
  "query_global_state",
  "state_get_dictionary_item",
  "query_balance",
  "query_balance_details",
  "chain_get_block_transfers",
]);
const MAX_RPC_OBSERVATIONS = 128;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_OVERALL_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

const PAIRS = [
  ["request", "response"],
  ["transaction_request", "transaction_response"],
  ["canonical_block_request", "canonical_block_response"],
  ["block_request", "block_response"],
  ["block_request", "block"],
  ["balance_request", "balance_response"],
  ["transfers_request", "transfers_response"],
  ["state_root_request", "state_root_response"],
] as const;

const RESTRICTED_IPV4 = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const;
const RESTRICTED_IPV6 = [
  ["::", 96], ["::1", 128], ["64:ff9b::", 96], ["64:ff9b:1::", 48],
  ["100::", 64], ["2001::", 23], ["2001:db8::", 32], ["2002::", 16],
  ["3fff::", 20], ["5f00::", 16], ["fc00::", 7], ["fe80::", 10],
  ["fec0::", 10], ["ff00::", 8],
] as const;
const restrictedIpv4 = new BlockList();
const restrictedIpv6 = new BlockList();
for (const [network, prefix] of RESTRICTED_IPV4) {
  restrictedIpv4.addSubnet(network, prefix, "ipv4");
  restrictedIpv6.addSubnet(`::ffff:${network}`, 96 + prefix, "ipv6");
}
for (const [network, prefix] of RESTRICTED_IPV6) restrictedIpv6.addSubnet(network, prefix, "ipv6");

export async function corroborateCasperTestnetBundle(
  bundle: CasperProofBundle,
  options: CasperLiveOptions,
): Promise<CasperLiveCorroboration> {
  const observedAt = options.now ?? new Date().toISOString();
  const offline = verifyProofRegistry(bundle.registry, {
    artifacts: bundle.artifacts,
    now: observedAt,
  });
  if (offline.status !== "verified") {
    throw new CasperLiveError(
      offline.status === "invalid" ? "invalid" : "unavailable",
      "offline_bundle_not_verified",
      `live corroboration requires a verified offline bundle; observed ${offline.status}`,
    );
  }
  return corroborateCasperBundleObservations(bundle, options);
}

/**
 * Re-query a bundle's already-retained raw observations. This function does
 * not verify the proof registry; callers seeking a verified result must use
 * corroborateCasperTestnetBundle, which runs the offline adapters first.
 */
export async function corroborateCasperBundleObservations(
  bundle: CasperProofBundle,
  options: CasperLiveOptions,
): Promise<CasperLiveCorroboration> {
  const observedAt = options.now ?? new Date().toISOString();
  const endpoints = validateEndpoints(options.rpcEndpoints);
  const observations = collectBundleObservations(bundle);
  if (observations.length === 0) {
    throw new CasperLiveError(
      "unavailable",
      "no_live_chain_observations",
      "verified bundle has no supported exact-v3 or native-treasury chain observations",
    );
  }
  requireObservationKinds(observations);

  const transport = options.transport ?? pinnedHttpsPost;
  const dnsLookup = options.dnsLookup ?? (options.transport === undefined ? systemDnsLookup : undefined);
  if (dnsLookup === undefined) {
    throw new CasperLiveError(
      "invalid",
      "live_dns_policy_required",
      "a custom live RPC transport requires an explicit DNS resolver",
    );
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) {
    throw new CasperLiveError("invalid", "invalid_live_timeout", "live RPC timeout is invalid");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0 || maxResponseBytes > 64 * 1024 * 1024) {
    throw new CasperLiveError("invalid", "invalid_live_size_limit", "live RPC response limit is invalid");
  }
  const overallTimeoutMs = options.overallTimeoutMs ?? DEFAULT_OVERALL_TIMEOUT_MS;
  if (!Number.isSafeInteger(overallTimeoutMs) || overallTimeoutMs <= 0 || overallTimeoutMs > 5 * 60_000) {
    throw new CasperLiveError("invalid", "invalid_live_deadline", "live RPC overall deadline is invalid");
  }
  const deadline = Date.now() + overallTimeoutMs;
  const resolved = await Promise.all(endpoints.map(async (endpoint) => ({
    endpoint,
    address: await resolvePublicEndpoint(endpoint, dnsLookup, deadline),
  })));
  if (new Set(resolved.map(({ address }) => address)).size !== resolved.length) {
    throw new CasperLiveError(
      "invalid",
      "nonindependent_live_rpc_addresses",
      "trusted RPC endpoints must resolve to distinct pinned addresses",
    );
  }

  await Promise.all(resolved.map(({ endpoint, address }, index) =>
    queryRpc(
      endpoint,
      address,
      { method: "info_get_status", params: {}, expectedResult: null },
      `concordia-live-status-${index}`,
      transport,
      timeoutMs,
      maxResponseBytes,
      deadline,
      true,
    )
  ));

  let rpcObservationCount = 0;
  for (let index = 0; index < observations.length; index += 1) {
    const expected = observations[index] as ExpectedObservation;
    const results = await Promise.all(resolved.map(({ endpoint, address }, endpointIndex) =>
      queryRpc(
        endpoint,
        address,
        expected,
        `concordia-live-${index}-${endpointIndex}`,
        transport,
        timeoutMs,
        maxResponseBytes,
        deadline,
        false,
      )
    ));
    const first = results[0];
    if (first === undefined) throw new CasperLiveError("unavailable", "live_rpc_missing", "live RPC returned no observations");
    const firstCanonical = canonicalResult(first);
    for (const result of results.slice(1)) {
      if (canonicalResult(result) !== firstCanonical) {
        throw new CasperLiveError("invalid", "live_rpc_disagreement", `trusted RPC endpoints disagree for ${expected.method}`);
      }
    }
    if (firstCanonical !== canonicalResult(expected.expectedResult)) {
      throw new CasperLiveError(
        "invalid",
        "live_rpc_artifact_mismatch",
        `live ${expected.method} result differs from the artifact transcript`,
      );
    }
    rpcObservationCount += results.length;
  }

  return {
    verificationScope: "live_casper_rpc_corroborated",
    observationSources: endpoints.map((endpoint) => endpoint.href),
    observedAt,
    rpcObservationCount,
  };
}

function collectBundleObservations(bundle: CasperProofBundle): ExpectedObservation[] {
  if (!isRecord(bundle.registry) || !Array.isArray(bundle.registry.items)) return [];
  const byRequest = new Map<string, ExpectedObservation>();
  for (const item of bundle.registry.items) {
    if (
      !isRecord(item) ||
      (
        item.proof_type !== "exact_envelope_v3" &&
        item.proof_type !== "historical_odra_receipt_v2" &&
        item.proof_type !== "native_treasury_execution_v1"
      ) ||
      typeof item.artifact_path !== "string" ||
      !Object.hasOwn(bundle.artifacts, item.artifact_path)
    ) continue;
    const artifactBytes = bundle.artifacts[item.artifact_path];
    if (artifactBytes === undefined) continue;
    const text = typeof artifactBytes === "string"
      ? artifactBytes
      : Buffer.from(artifactBytes).toString("utf8");
    const artifact = parseJsonStrict(text);
    const itemObservations = new Map<string, ExpectedObservation>();
    collectTranscriptPairs(artifact, itemObservations, new Set<object>());
    requireProofObservationKinds(item.proof_type, [...itemObservations.values()]);
    for (const [key, observation] of itemObservations) {
      const existing = byRequest.get(key);
      if (
        existing !== undefined &&
        canonicalResult(existing.expectedResult) !== canonicalResult(observation.expectedResult)
      ) {
        throw new CasperLiveError(
          "invalid",
          "embedded_rpc_disagreement",
          `embedded evidence disagrees for ${observation.method}`,
        );
      }
      byRequest.set(key, observation);
    }
  }
  const observations = [...byRequest.values()];
  if (observations.length > MAX_RPC_OBSERVATIONS) {
    throw new CasperLiveError(
      "invalid",
      "too_many_live_observations",
      `live bundle exceeds the ${MAX_RPC_OBSERVATIONS}-observation limit`,
    );
  }
  return observations;
}

function collectTranscriptPairs(
  value: unknown,
  observations: Map<string, ExpectedObservation>,
  seen: Set<object>,
): void {
  if (Array.isArray(value)) {
    if (seen.has(value)) return;
    seen.add(value);
    for (const item of value) collectTranscriptPairs(item, observations, seen);
    return;
  }
  if (!isRecord(value)) return;
  if (seen.has(value)) return;
  seen.add(value);
  for (const [requestField, responseField] of PAIRS) {
    if (!Object.hasOwn(value, requestField) || !Object.hasOwn(value, responseField)) continue;
    const request = value[requestField];
    const response = value[responseField];
    if (!isRecord(request) || !isRecord(response) || !READ_ONLY_METHODS.has(String(request.method))) continue;
    if (request.jsonrpc !== "2.0" || !isRecord(request.params)) {
      throw new CasperLiveError("invalid", "invalid_embedded_rpc_request", "embedded read-only RPC request is malformed");
    }
    if (response.jsonrpc !== "2.0" || response.id !== request.id || !Object.hasOwn(response, "result")) {
      throw new CasperLiveError("invalid", "invalid_embedded_rpc_response", "embedded read-only RPC response is malformed");
    }
    const method = request.method as string;
    const params = request.params;
    const expectedResult = normalizeRpcResult(method, response.result);
    const key = canonicalTranscriptJson({ method, params }, "live RPC request identity");
    const existing = observations.get(key);
    if (existing !== undefined && canonicalResult(existing.expectedResult) !== canonicalResult(expectedResult)) {
      throw new CasperLiveError(
        "invalid",
        "embedded_rpc_disagreement",
        `embedded evidence disagrees for ${method} ${canonicalTranscriptJson(params, "embedded RPC params")}`,
      );
    }
    observations.set(key, { method, params, expectedResult });
  }
  for (const child of Object.values(value)) collectTranscriptPairs(child, observations, seen);
}

function requireObservationKinds(observations: readonly ExpectedObservation[]): void {
  const methods = new Set(observations.map(({ method }) => method));
  if (!methods.has("info_get_deploy") || !methods.has("chain_get_block")) {
    throw new CasperLiveError("invalid", "incomplete_live_observation_set", "live bundle lacks deploy/finality or block observations");
  }
  if (!["query_global_state", "state_get_dictionary_item", "query_balance", "query_balance_details"]
    .some((method) => methods.has(method))) {
    throw new CasperLiveError("invalid", "incomplete_live_observation_set", "live bundle lacks state observations");
  }
}

function requireProofObservationKinds(
  proofType: string,
  observations: readonly ExpectedObservation[],
): void {
  const counts = new Map<string, number>();
  for (const { method } of observations) counts.set(method, (counts.get(method) ?? 0) + 1);
  if (proofType === "historical_odra_receipt_v2") {
    const exact =
      observations.length === 5 &&
      counts.get("info_get_deploy") === 1 &&
      counts.get("chain_get_block") === 1 &&
      counts.get("chain_get_state_root_hash") === 1 &&
      counts.get("query_global_state") === 2 &&
      counts.size === 4;
    if (!exact) {
      throw new CasperLiveError(
        "invalid",
        "incomplete_historical_live_observation_set",
        "historical live evidence requires exactly deploy, block, state-root, package, and contract observations",
      );
    }
    return;
  }
  requireObservationKinds(observations);
}

function validateEndpoints(values: readonly string[]): URL[] {
  if (!Array.isArray(values) || values.length < 2 || values.length > 4) {
    throw new CasperLiveError("invalid", "live_rpc_endpoint_count", "live mode requires two to four trusted RPC endpoints");
  }
  const endpoints = values.map((value) => requirePublicHttpsEndpoint(value));
  if (new Set(endpoints.map(({ origin }) => origin)).size !== endpoints.length) {
    throw new CasperLiveError("invalid", "duplicate_live_rpc_origin", "trusted RPC endpoint origins must be distinct");
  }
  if (new Set(endpoints.map(({ hostname }) => normalizeHostname(hostname))).size !== endpoints.length) {
    throw new CasperLiveError("invalid", "nonindependent_live_rpc_hosts", "trusted RPC endpoints must use distinct DNS hostnames");
  }
  return endpoints;
}

function requirePublicHttpsEndpoint(value: string): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new CasperLiveError("invalid", "invalid_live_rpc_url", "trusted RPC endpoint is not a URL");
  }
  if (
    endpoint.protocol !== "https:" || endpoint.username !== "" || endpoint.password !== "" ||
    endpoint.hash !== "" || endpoint.search !== ""
  ) {
    throw new CasperLiveError("invalid", "invalid_live_rpc_url", "trusted RPC endpoints require credential-free HTTPS without query or fragment");
  }
  const hostname = normalizeHostname(endpoint.hostname);
  if (
    hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") ||
    hostname === "home.arpa" || hostname.endsWith(".home.arpa")
  ) throw new CasperLiveError("invalid", "unsafe_live_rpc_host", "trusted RPC endpoint is not publicly routable");
  if (isIP(hostname) !== 0) assertPublicAddress(hostname);
  return endpoint;
}

async function resolvePublicEndpoint(
  endpoint: URL,
  dnsLookup: CasperRpcDnsLookup,
  deadline: number,
): Promise<string> {
  if (Date.now() >= deadline) throw new CasperLiveError("unavailable", "live_rpc_timeout", "live RPC overall deadline exceeded");
  const hostname = normalizeHostname(endpoint.hostname);
  if (isIP(hostname) !== 0) return hostname;
  let addresses: readonly string[];
  try {
    addresses = await raceWithDeadline(dnsLookup(hostname), deadline);
  } catch (error) {
    if (error instanceof CasperLiveError) throw error;
    throw new CasperLiveError("unavailable", "live_rpc_dns_failed", "trusted RPC DNS lookup failed");
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new CasperLiveError("unavailable", "live_rpc_dns_failed", "trusted RPC DNS lookup returned no addresses");
  }
  for (const address of addresses) assertPublicAddress(normalizeHostname(address));
  return normalizeHostname(addresses[0] as string);
}

async function queryRpc(
  endpoint: URL,
  address: string,
  observation: ExpectedObservation,
  id: string,
  transport: CasperRpcTransport,
  timeoutMs: number,
  maximumBytes: number,
  deadline: number,
  statusQuery: boolean,
): Promise<unknown> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new CasperLiveError("unavailable", "live_rpc_timeout", "live RPC overall deadline exceeded");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("live RPC timed out")), Math.min(timeoutMs, remaining));
  try {
    const body = JSON.stringify({ jsonrpc: "2.0", id, method: observation.method, params: observation.params });
    let response: Response;
    try {
      response = await raceWithAbort(
        transport(endpoint, body, controller.signal, address),
        controller.signal,
      );
    } catch {
      throw new CasperLiveError("unavailable", "live_rpc_fetch_failed", "trusted RPC request failed or timed out");
    }
    if (response.redirected || (response.status >= 300 && response.status < 400) || responseUrlChanged(response, endpoint)) {
      await cancelBody(response);
      throw new CasperLiveError("invalid", "live_rpc_redirect_rejected", "trusted RPC redirects are not allowed");
    }
    if (!response.ok) {
      await cancelBody(response);
      throw new CasperLiveError("unavailable", "live_rpc_http_error", `trusted RPC returned HTTP ${response.status}`);
    }
    const bytes = await readBoundedBody(response, maximumBytes, controller.signal);
    let parsed: unknown;
    try {
      parsed = parseJsonStrict(Buffer.from(bytes).toString("utf8"));
    } catch {
      throw new CasperLiveError("invalid", "malformed_live_rpc_json", "trusted RPC returned malformed or duplicate-key JSON");
    }
    if (!isRecord(parsed) || parsed.jsonrpc !== "2.0" || parsed.id !== id || !Object.hasOwn(parsed, "result") || Object.hasOwn(parsed, "error")) {
      throw new CasperLiveError("invalid", "malformed_live_rpc_envelope", "trusted RPC returned an invalid JSON-RPC envelope");
    }
    const result = unwrapResult(parsed.result);
    if (statusQuery) {
      if (!isRecord(result) || result.chainspec_name !== "casper-test") {
        throw new CasperLiveError("invalid", "unsupported_live_network", "trusted RPC is not serving casper-test");
      }
      return result;
    }
    return normalizeRpcResult(observation.method, result);
  } finally {
    clearTimeout(timer);
  }
}

function unwrapResult(value: unknown): unknown {
  if (isRecord(value) && Object.keys(value).length === 2 && Object.hasOwn(value, "name") && Object.hasOwn(value, "value")) {
    return value.value;
  }
  return value;
}

function normalizeRpcResult(method: string, raw: unknown): unknown {
  const value = unwrapResult(raw);
  if (!isRecord(value)) {
    throw new CasperLiveError("invalid", "malformed_live_rpc_result", `${method} result must be an object`);
  }
  if (method === "info_get_deploy") {
    return {
      deploy: value.deploy,
      execution_info: value.execution_info,
    };
  }
  if (method === "chain_get_block") {
    const blockWithSignatures = value.block_with_signatures;
    if (!isRecord(blockWithSignatures) || !Object.hasOwn(blockWithSignatures, "block")) {
      throw new CasperLiveError("invalid", "malformed_live_rpc_result", "chain_get_block result lacks a block");
    }
    return { block: blockWithSignatures.block };
  }
  if (method === "chain_get_state_root_hash") {
    return { state_root_hash: value.state_root_hash };
  }
  if (method === "query_global_state" || method === "state_get_dictionary_item") {
    return { stored_value: value.stored_value };
  }
  if (method === "query_balance_details") {
    return {
      total_balance: value.total_balance,
      available_balance: value.available_balance,
    };
  }
  if (method === "query_balance") return { balance: value.balance };
  if (method === "chain_get_block_transfers") {
    return { block_hash: value.block_hash, transfers: value.transfers };
  }
  throw new CasperLiveError("invalid", "unsupported_live_rpc_method", `unsupported live RPC method ${method}`);
}

function canonicalResult(value: unknown): string {
  return canonicalTranscriptJson(value, "live RPC result");
}

async function systemDnsLookup(hostname: string): Promise<readonly string[]> {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map(({ address }) => address);
}

function assertPublicAddress(rawAddress: string): void {
  const address = normalizeHostname(rawAddress);
  const family = isIP(address);
  if (
    family === 0 ||
    (family === 4 && restrictedIpv4.check(address, "ipv4")) ||
    (family === 6 && restrictedIpv6.check(address, "ipv6"))
  ) throw new CasperLiveError("invalid", "unsafe_live_rpc_host", "trusted RPC endpoint is not publicly routable");
}

function normalizeHostname(hostname: string): string {
  const unwrapped = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return unwrapped.replace(/\.+$/, "").toLowerCase();
}

function pinnedHttpsPost(endpoint: URL, body: string, signal: AbortSignal, address: string): Promise<Response> {
  const family = isIP(address);
  if (family !== 4 && family !== 6) return Promise.reject(new Error("invalid pinned address"));
  const pinnedLookup: LookupFunction = (_hostname, _options, callback) => callback(null, address, family);
  return new Promise<Response>((resolve, reject) => {
    const request = httpsRequest(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body, "utf8"),
      },
      signal,
      agent: false,
      lookup: pinnedLookup,
      family,
      rejectUnauthorized: true,
    }, (incoming) => {
      try {
        const headers = new Headers();
        for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
          const name = incoming.rawHeaders[index];
          const value = incoming.rawHeaders[index + 1];
          if (name !== undefined && value !== undefined) headers.append(name, value);
        }
        const responseBody = incoming.statusCode === 204 ? null : Readable.toWeb(incoming) as ReadableStream<Uint8Array>;
        resolve(new Response(responseBody, { status: incoming.statusCode ?? 0, headers }));
      } catch (error) {
        incoming.destroy();
        reject(error);
      }
    });
    request.once("error", reject);
    request.end(body);
  });
}

async function readBoundedBody(response: Response, maximumBytes: number, signal: AbortSignal): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maximumBytes))) {
    await cancelBody(response);
    throw new CasperLiveError("invalid", "live_rpc_response_too_large", "trusted RPC response exceeds its size limit");
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      if (signal.aborted) throw signal.reason;
      const { done, value } = await raceWithAbort(reader.read(), signal);
      if (done) break;
      if (value === undefined) continue;
      if (value.byteLength > maximumBytes - total) {
        await reader.cancel("live RPC response exceeds size limit");
        throw new CasperLiveError("invalid", "live_rpc_response_too_large", "trusted RPC response exceeds its size limit");
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } catch (error) {
    if (error instanceof CasperLiveError) throw error;
    throw new CasperLiveError("unavailable", "live_rpc_read_failed", "trusted RPC response could not be read");
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

function responseUrlChanged(response: Response, requested: URL): boolean {
  if (response.url === "") return false;
  try {
    return new URL(response.url).href !== requested.href;
  } catch {
    return true;
  }
}

async function cancelBody(response: Response): Promise<void> {
  if (response.body === null || response.body.locked) return;
  try {
    await response.body.cancel("response rejected by live verifier policy");
  } catch {
    // Best effort; the request timeout still bounds resource use.
  }
}

function raceWithAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
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

function raceWithDeadline<T>(operation: Promise<T>, deadline: number): Promise<T> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    return Promise.reject(new CasperLiveError(
      "unavailable",
      "live_rpc_timeout",
      "live RPC overall deadline exceeded",
    ));
  }
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new CasperLiveError(
      "unavailable",
      "live_rpc_timeout",
      "live RPC overall deadline exceeded",
    )), remaining);
    operation.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
