/**
 * Live, fail-closed Casper chain observer for the official x402 service.
 *
 * Authoritative state comes from the pinned Casper Testnet JSON-RPC endpoint.
 * CSPR.cloud is used only as a bounded candidate index when a lost facilitator
 * response must be reconciled: every candidate it returns is independently
 * read back and validated through Casper RPC before it can be adopted.
 *
 * Security properties:
 *  - no endpoint is configurable at runtime;
 *  - CSPR.cloud receives the raw Authorization token (never Bearer);
 *  - non-2xx authenticated responses are never read, because CSPR.cloud can
 *    reflect the submitted Authorization value in its error body;
 *  - all bodies are size bounded and all requests have a hard timeout;
 *  - an unused nonce is reported only from a stable, signed, executed block
 *    state root and a confirmed `used_nonces` dictionary;
 *  - used-nonce recovery requires exactly one exact RPC-verified transaction.
 */

import { blake2b } from "blakejs";

import {
  REFUSAL_CODES,
  ServiceRefusal,
  upstreamMalformed,
  upstreamUnavailable,
} from "./errors.js";
import {
  SETTLEMENT_ENTRY_POINT,
  assertLocatorQuery,
} from "./chain.js";
import type {
  AuthorizationLocatorQuery,
  ChainTransport,
  PackageState,
  ReadbackArg,
  SettlementLocator,
  TransactionReadback,
} from "./types.js";

export const CASPER_TESTNET_RPC_URL =
  "https://node.testnet.casper.network/rpc";
export const CSPR_CLOUD_TESTNET_API_URL =
  "https://api.testnet.cspr.cloud";

const HEX64_RE = /^[0-9a-f]{64}$/;
const PUBLIC_KEY_RE = /^(?:01[0-9a-f]{64}|02[0-9a-f]{66})$/;
const UREF_RE = /^uref-[0-9a-f]{64}-00[0-7]$/;
const MAX_JSON_BYTES = 2_097_152;
const REQUEST_TIMEOUT_MS = 10_000;
const LOCATOR_PAGE_SIZE = 100;
const MAX_LOCATOR_PAGES = 2;

type JsonObject = Record<string, unknown>;

interface ChainFetchOptions {
  fetch?: typeof fetch;
  csprCloudToken: () => string;
  /** Test-harness reduction only; production omits this and uses the frozen cap. */
  requestTimeoutMs?: number;
}

interface StableBoundary {
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
}

class RpcResponseError extends Error {
  readonly code: number;

  constructor(code: number) {
    super("rpc_response_error");
    this.name = "RpcResponseError";
    this.code = code;
  }
}

function observationUnavailable(): ServiceRefusal {
  return upstreamUnavailable(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE);
}

function observationMalformed(): ServiceRefusal {
  return upstreamMalformed(REFUSAL_CODES.CHAIN_OBSERVATION_UNAVAILABLE);
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireHex64(value: unknown): string {
  if (typeof value !== "string" || !HEX64_RE.test(value)) {
    throw observationMalformed();
  }
  return value;
}

function stripPrefix(value: unknown, prefix: string): string {
  if (
    typeof value !== "string" ||
    !value.startsWith(prefix) ||
    !HEX64_RE.test(value.slice(prefix.length))
  ) {
    throw observationMalformed();
  }
  return value.slice(prefix.length);
}

function parseClType(value: unknown): string {
  if (
    value === "Key" ||
    value === "U256" ||
    value === "U64" ||
    value === "PublicKey"
  ) {
    return value;
  }
  if (
    isObject(value) &&
    Object.keys(value).length === 1 &&
    value["List"] === "U8"
  ) {
    return "List<U8>";
  }
  throw observationMalformed();
}

function parseLowerHexBytes(value: unknown): Buffer {
  if (
    typeof value !== "string" ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]*$/.test(value)
  ) {
    throw observationMalformed();
  }
  return Buffer.from(value, "hex");
}

function littleEndianUnsigned(bytes: Buffer): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

function decodeClValue(raw: unknown): ReadbackArg {
  if (!isObject(raw)) throw observationMalformed();
  const clType = parseClType(raw["cl_type"]);
  const bytes = parseLowerHexBytes(raw["bytes"]);
  if (clType === "Key") {
    if (bytes.length !== 33 || bytes[0] !== 0) {
      throw observationMalformed();
    }
    return {
      clType,
      value: `account-hash-${bytes.subarray(1).toString("hex")}`,
    };
  }
  if (clType === "U256") {
    const width = bytes[0];
    if (
      width === undefined ||
      width > 32 ||
      bytes.length !== width + 1
    ) {
      throw observationMalformed();
    }
    return {
      clType,
      value: littleEndianUnsigned(bytes.subarray(1)).toString(10),
    };
  }
  if (clType === "U64") {
    if (bytes.length !== 8) throw observationMalformed();
    return { clType, value: littleEndianUnsigned(bytes).toString(10) };
  }
  if (clType === "PublicKey") {
    const hex = bytes.toString("hex");
    if (!PUBLIC_KEY_RE.test(hex)) throw observationMalformed();
    return { clType, value: hex };
  }
  if (bytes.length < 4) throw observationMalformed();
  const length = bytes.readUInt32LE(0);
  if (bytes.length !== 4 + length) throw observationMalformed();
  return { clType, value: bytes.subarray(4).toString("hex") };
}

function decodeNamedArgs(
  raw: unknown,
): { argNames: string[]; args: Record<string, ReadbackArg> } {
  if (!isObject(raw) || !Array.isArray(raw["Named"])) {
    throw observationMalformed();
  }
  const argNames: string[] = [];
  const args: Record<string, ReadbackArg> = {};
  for (const item of raw["Named"]) {
    if (
      !Array.isArray(item) ||
      item.length !== 2 ||
      typeof item[0] !== "string" ||
      Object.hasOwn(args, item[0])
    ) {
      throw observationMalformed();
    }
    argNames.push(item[0]);
    args[item[0]] = decodeClValue(item[1]);
  }
  return { argNames, args };
}

function executionSucceeded(raw: unknown): boolean {
  if (!isObject(raw)) throw observationMalformed();
  if (isObject(raw["Version2"])) {
    const error = raw["Version2"]["error_message"];
    if (error !== null && typeof error !== "string") {
      throw observationMalformed();
    }
    return error === null;
  }
  if (isObject(raw["Success"])) return true;
  if (isObject(raw["Failure"])) return false;
  throw observationMalformed();
}

function parseBlockResult(raw: unknown): StableBoundary & { proofs: number } {
  if (!isObject(raw) || !isObject(raw["block_with_signatures"])) {
    throw observationMalformed();
  }
  const wrapper = raw["block_with_signatures"];
  if (!isObject(wrapper["block"]) || !Array.isArray(wrapper["proofs"])) {
    throw observationMalformed();
  }
  const block = wrapper["block"];
  const version =
    (isObject(block["Version2"]) && block["Version2"]) ||
    (isObject(block["Version1"]) && block["Version1"]);
  if (!version || !isObject(version["header"])) {
    throw observationMalformed();
  }
  const header = version["header"];
  const blockHeight = header["height"];
  if (
    typeof blockHeight !== "number" ||
    !Number.isSafeInteger(blockHeight) ||
    blockHeight < 0
  ) {
    throw observationMalformed();
  }
  return {
    blockHash: requireHex64(version["hash"]),
    blockHeight,
    stateRootHash: requireHex64(header["state_root_hash"]),
    proofs: wrapper["proofs"].length,
  };
}

function parseTargetAndArgs(
  transaction: unknown,
): {
  transactionHash: string;
  packageHash: string;
  requestedVersion: number | null;
  entryPoint: string;
  argNames: string[];
  args: Record<string, ReadbackArg>;
} {
  if (!isObject(transaction)) throw observationMalformed();
  if (isObject(transaction["Version1"])) {
    const value = transaction["Version1"];
    if (
      !isObject(value["payload"]) ||
      !isObject(value["payload"]["fields"])
    ) {
      throw observationMalformed();
    }
    const fields = value["payload"]["fields"];
    if (
      !isObject(fields["target"]) ||
      !isObject(fields["target"]["Stored"]) ||
      !isObject(fields["target"]["Stored"]["id"]) ||
      !isObject(fields["target"]["Stored"]["id"]["ByPackageHash"]) ||
      !isObject(fields["entry_point"]) ||
      typeof fields["entry_point"]["Custom"] !== "string"
    ) {
      throw observationMalformed();
    }
    const byPackage = fields["target"]["Stored"]["id"][
      "ByPackageHash"
    ] as JsonObject;
    const requestedVersionRaw = byPackage["version"];
    const requestedVersion =
      requestedVersionRaw === undefined || requestedVersionRaw === null
        ? null
        : requestedVersionRaw;
    if (
      requestedVersion !== null &&
      (typeof requestedVersion !== "number" ||
        !Number.isSafeInteger(requestedVersion) ||
        requestedVersion < 1)
    ) {
      throw observationMalformed();
    }
    return {
      transactionHash: requireHex64(value["hash"]),
      packageHash: requireHex64(byPackage["addr"]),
      requestedVersion,
      entryPoint: fields["entry_point"]["Custom"],
      ...decodeNamedArgs(fields["args"]),
    };
  }
  if (isObject(transaction["Deploy"])) {
    const value = transaction["Deploy"];
    if (
      !isObject(value["session"]) ||
      !isObject(value["session"]["StoredVersionedContractByHash"])
    ) {
      throw observationMalformed();
    }
    const stored = value["session"]["StoredVersionedContractByHash"];
    const versionRaw = stored["version"];
    const requestedVersion =
      versionRaw === undefined || versionRaw === null ? null : versionRaw;
    if (
      requestedVersion !== null &&
      (typeof requestedVersion !== "number" ||
        !Number.isSafeInteger(requestedVersion) ||
        requestedVersion < 1)
    ) {
      throw observationMalformed();
    }
    if (typeof stored["entry_point"] !== "string") {
      throw observationMalformed();
    }
    return {
      transactionHash: requireHex64(value["hash"]),
      packageHash: requireHex64(stored["hash"]),
      requestedVersion,
      entryPoint: stored["entry_point"],
      ...decodeNamedArgs(stored["args"]),
    };
  }
  throw observationMalformed();
}

function disabledVersionSet(raw: unknown): Set<string> {
  if (!Array.isArray(raw)) throw observationMalformed();
  const out = new Set<string>();
  for (const item of raw) {
    if (
      !Array.isArray(item) ||
      item.length !== 2 ||
      typeof item[0] !== "number" ||
      typeof item[1] !== "number" ||
      !Number.isSafeInteger(item[0]) ||
      !Number.isSafeInteger(item[1])
    ) {
      throw observationMalformed();
    }
    out.add(`${item[0]}:${item[1]}`);
  }
  return out;
}

function parsePackage(raw: unknown): PackageState {
  if (!isObject(raw) || !isObject(raw["package"])) {
    throw observationMalformed();
  }
  const wrapper = raw["package"];
  const pkg =
    (isObject(wrapper["ContractPackage"]) && wrapper["ContractPackage"]) ||
    (isObject(wrapper["Package"]) && wrapper["Package"]);
  if (
    !pkg ||
    !Array.isArray(pkg["versions"]) ||
    typeof pkg["lock_status"] !== "string"
  ) {
    throw observationMalformed();
  }
  const disabled = disabledVersionSet(pkg["disabled_versions"]);
  const active: Array<{
    protocolMajor: number;
    version: number;
    contractHash: string;
  }> = [];
  for (const item of pkg["versions"]) {
    if (
      !isObject(item) ||
      typeof item["protocol_version_major"] !== "number" ||
      typeof item["contract_version"] !== "number" ||
      !Number.isSafeInteger(item["protocol_version_major"]) ||
      !Number.isSafeInteger(item["contract_version"])
    ) {
      throw observationMalformed();
    }
    const protocolMajor = item["protocol_version_major"];
    const version = item["contract_version"];
    if (!disabled.has(`${protocolMajor}:${version}`)) {
      active.push({
        protocolMajor,
        version,
        contractHash: stripPrefix(item["contract_hash"], "contract-"),
      });
    }
  }
  if (active.length === 0) throw observationMalformed();
  active.sort(
    (left, right) =>
      right.version - left.version ||
      right.protocolMajor - left.protocolMajor,
  );
  const latest = active[0];
  if (latest === undefined) throw observationMalformed();
  const ambiguous = active.some(
    (item, index) =>
      index > 0 &&
      item.version === latest.version &&
      item.protocolMajor === latest.protocolMajor,
  );
  if (ambiguous) throw observationMalformed();
  return {
    lockStatus: pkg["lock_status"],
    enabledVersion: latest.version,
    enabledContractHash: latest.contractHash,
  };
}

function dictionarySeedFromEntity(raw: unknown): string {
  if (!isObject(raw) || !isObject(raw["entity"])) {
    throw observationMalformed();
  }
  const wrapper = raw["entity"];
  let namedKeys: unknown;
  if (
    isObject(wrapper["Contract"]) &&
    isObject(wrapper["Contract"]["contract"])
  ) {
    namedKeys = wrapper["Contract"]["contract"]["named_keys"];
  } else if (isObject(wrapper["AddressableEntity"])) {
    namedKeys = wrapper["AddressableEntity"]["named_keys"];
  }
  if (!Array.isArray(namedKeys)) throw observationMalformed();
  const matches = namedKeys.filter(
    (item) => isObject(item) && item["name"] === "used_nonces",
  );
  if (matches.length !== 1) throw observationMalformed();
  const key = (matches[0] as JsonObject)["key"];
  if (typeof key !== "string" || !UREF_RE.test(key)) {
    throw observationMalformed();
  }
  return key;
}

function usedNonceDictionaryKey(
  payerAccountHashHex: string,
  nonceHex: string,
): string {
  const length = Buffer.alloc(4);
  length.writeUInt32LE(32, 0);
  const preimage = Buffer.concat([
    Buffer.from([0]),
    Buffer.from(payerAccountHashHex, "hex"),
    length,
    Buffer.from(nonceHex, "hex"),
  ]);
  return Buffer.from(blake2b(preimage, undefined, 32)).toString("hex");
}

function parseUsedNonceValue(raw: unknown): boolean {
  if (
    !isObject(raw) ||
    !isObject(raw["stored_value"]) ||
    !isObject(raw["stored_value"]["CLValue"])
  ) {
    throw observationMalformed();
  }
  const cl = raw["stored_value"]["CLValue"];
  if (
    cl["cl_type"] !== "Bool" ||
    (cl["bytes"] !== "00" && cl["bytes"] !== "01") ||
    typeof cl["parsed"] !== "boolean" ||
    cl["parsed"] !== (cl["bytes"] === "01")
  ) {
    throw observationMalformed();
  }
  return cl["parsed"];
}

function cloudParsedValue(
  args: unknown,
  name: string,
): unknown {
  if (!isObject(args) || !isObject(args[name])) return undefined;
  return args[name]["parsed"];
}

function cloudNonceHex(value: unknown): string | undefined {
  if (typeof value === "string") {
    const normalized = value.startsWith("0x") ? value.slice(2) : value;
    return HEX64_RE.test(normalized) ? normalized : undefined;
  }
  if (
    Array.isArray(value) &&
    value.length === 32 &&
    value.every(
      (item) =>
        typeof item === "number" &&
        Number.isInteger(item) &&
        item >= 0 &&
        item <= 255,
    )
  ) {
    return Buffer.from(value as number[]).toString("hex");
  }
  return undefined;
}

function cloudCandidateHash(
  raw: unknown,
  query: AuthorizationLocatorQuery,
): string | undefined {
  if (
    !isObject(raw) ||
    raw["contract_package_hash"] !== query.packageHashHex ||
    raw["contract_hash"] !== query.contractHashHex ||
    raw["status"] !== "processed" ||
    raw["error_message"] !== null
  ) {
    return undefined;
  }
  const hash = raw["deploy_hash"];
  if (typeof hash !== "string" || !HEX64_RE.test(hash)) return undefined;
  const from = cloudParsedValue(raw["args"], "from");
  const nonce = cloudNonceHex(cloudParsedValue(raw["args"], "nonce"));
  const publicKey = cloudParsedValue(raw["args"], "public_key");
  if (
    from !== `account-hash-${query.payerAccountHashHex}` ||
    nonce !== query.authorizationNonceHex ||
    publicKey !== query.payerPublicKeyHex
  ) {
    return undefined;
  }
  return hash;
}

function exactLocatorReadback(
  readback: TransactionReadback,
  query: AuthorizationLocatorQuery,
): boolean {
  return (
    readback.finalized === true &&
    readback.executionSuccess === true &&
    readback.targetContractHash === query.contractHashHex &&
    readback.entryPoint === SETTLEMENT_ENTRY_POINT &&
    readback.args["from"]?.clType === "Key" &&
    readback.args["from"]?.value ===
      `account-hash-${query.payerAccountHashHex}` &&
    readback.args["nonce"]?.clType === "List<U8>" &&
    readback.args["nonce"]?.value === query.authorizationNonceHex &&
    readback.args["public_key"]?.clType === "PublicKey" &&
    readback.args["public_key"]?.value === query.payerPublicKeyHex
  );
}

export class CasperRpcChainTransport implements ChainTransport {
  readonly #fetch: typeof fetch;
  readonly #csprCloudToken: () => string;
  readonly #requestTimeoutMs: number;
  #rpcId = 0;

  constructor(options: ChainFetchOptions) {
    this.#fetch = options.fetch ?? fetch;
    this.#csprCloudToken = options.csprCloudToken;
    const timeout = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(timeout) ||
      timeout < 1 ||
      timeout > REQUEST_TIMEOUT_MS
    ) {
      throw observationUnavailable();
    }
    this.#requestTimeoutMs = timeout;
  }

  async #readBoundedJson(response: Response): Promise<unknown> {
    if (response.body === null) throw observationMalformed();
    const reader = response.body.getReader();
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > MAX_JSON_BYTES) {
          await reader.cancel();
          throw observationMalformed();
        }
        chunks.push(Buffer.from(part.value));
      }
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    } finally {
      reader.releaseLock();
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      throw observationMalformed();
    }
  }

  async #fetchJson(
    url: string,
    init: RequestInit,
    authenticated: boolean,
  ): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.#requestTimeoutMs,
    );
    timer.unref();
    try {
      const response = await this.#fetch(url, {
        ...init,
        signal: controller.signal,
      });
      if (!response.ok) {
        // Deliberately do not read authenticated failure bodies: CSPR.cloud can
        // reflect the raw Authorization value in them.
        if (authenticated && response.body !== null) {
          await response.body.cancel().catch(() => undefined);
        }
        throw observationUnavailable();
      }
      // Keep the same hard deadline active until the bounded body is complete.
      return await this.#readBoundedJson(response);
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    } finally {
      clearTimeout(timer);
    }
  }

  async #rpc(method: string, params: JsonObject): Promise<unknown> {
    const id = (this.#rpcId += 1);
    const raw = await this.#fetchJson(
      CASPER_TESTNET_RPC_URL,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method,
          params,
        }),
      },
      false,
    );
    if (
      !isObject(raw) ||
      raw["jsonrpc"] !== "2.0" ||
      raw["id"] !== id
    ) {
      throw observationMalformed();
    }
    if (isObject(raw["error"])) {
      const code = raw["error"]["code"];
      if (typeof code !== "number" || !Number.isInteger(code)) {
        throw observationMalformed();
      }
      throw new RpcResponseError(code);
    }
    if (!Object.hasOwn(raw, "result")) throw observationMalformed();
    return raw["result"];
  }

  async #resolvePackageAt(
    packageHashHex: string,
    blockHash?: string,
  ): Promise<PackageState> {
    if (!HEX64_RE.test(packageHashHex)) throw observationUnavailable();
    const params: JsonObject = {
      package_identifier: {
        ContractPackageHash: `contract-package-${packageHashHex}`,
      },
    };
    if (blockHash !== undefined) {
      params["block_identifier"] = { Hash: requireHex64(blockHash) };
    }
    try {
      return parsePackage(await this.#rpc("state_get_package", params));
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    }
  }

  resolveActivePackage(packageHashHex: string): Promise<PackageState> {
    return this.#resolvePackageAt(packageHashHex);
  }

  async getFinalizedTransaction(
    txHashHex: string,
  ): Promise<TransactionReadback> {
    if (!HEX64_RE.test(txHashHex)) throw observationUnavailable();
    let result: unknown;
    try {
      result = await this.#rpc("info_get_transaction", {
        transaction_hash: { Version1: txHashHex },
        finalized_approvals: true,
      });
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    }
    if (!isObject(result)) throw observationMalformed();
    const parsed = parseTargetAndArgs(result["transaction"]);
    if (parsed.transactionHash !== txHashHex) throw observationMalformed();
    const executionInfo = result["execution_info"];
    if (
      executionInfo === null ||
      executionInfo === undefined ||
      (isObject(executionInfo) &&
        (executionInfo["execution_result"] === null ||
          executionInfo["execution_result"] === undefined))
    ) {
      return {
        transactionHash: parsed.transactionHash,
        finalized: false,
        executionSuccess: false,
        targetContractHash: "",
        contractVersion: null,
        entryPoint: parsed.entryPoint,
        argNames: parsed.argNames,
        args: parsed.args,
      };
    }
    if (
      !isObject(executionInfo) ||
      typeof executionInfo["block_hash"] !== "string"
    ) {
      throw observationMalformed();
    }
    const blockHash = requireHex64(executionInfo["block_hash"]);
    let executionBlock: ReturnType<typeof parseBlockResult>;
    try {
      executionBlock = parseBlockResult(
        await this.#rpc("chain_get_block", {
          block_identifier: { Hash: blockHash },
        }),
      );
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    }
    const reportedHeight = executionInfo["block_height"];
    if (
      executionBlock.blockHash !== blockHash ||
      executionBlock.proofs < 1 ||
      (reportedHeight !== undefined &&
        (typeof reportedHeight !== "number" ||
          !Number.isSafeInteger(reportedHeight) ||
          reportedHeight !== executionBlock.blockHeight))
    ) {
      throw observationUnavailable();
    }
    const packageState = await this.#resolvePackageAt(
      parsed.packageHash,
      blockHash,
    );
    if (
      parsed.requestedVersion !== null &&
      parsed.requestedVersion !== packageState.enabledVersion
    ) {
      throw observationMalformed();
    }
    return {
      transactionHash: parsed.transactionHash,
      finalized: true,
      executionSuccess: executionSucceeded(executionInfo["execution_result"]),
      targetContractHash: packageState.enabledContractHash,
      contractVersion: packageState.enabledVersion,
      entryPoint: parsed.entryPoint,
      argNames: parsed.argNames,
      args: parsed.args,
    };
  }

  async #stableBoundary(): Promise<StableBoundary> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        const first = await this.#rpc("chain_get_state_root_hash", {});
        const block = parseBlockResult(await this.#rpc("chain_get_block", {}));
        const second = await this.#rpc("chain_get_state_root_hash", {});
        if (
          isObject(first) &&
          isObject(second) &&
          first["state_root_hash"] === block.stateRootHash &&
          second["state_root_hash"] === block.stateRootHash &&
          block.proofs > 0
        ) {
          return {
            blockHash: block.blockHash,
            blockHeight: block.blockHeight,
            stateRootHash: block.stateRootHash,
          };
        }
      } catch {
        // Retry only to obtain one internally consistent executed snapshot.
      }
    }
    throw observationUnavailable();
  }

  async #dictionarySeed(
    contractHashHex: string,
    blockHash: string,
  ): Promise<string> {
    try {
      return dictionarySeedFromEntity(
        await this.#rpc("state_get_entity", {
          entity_identifier: {
            ContractHash: `contract-${contractHashHex}`,
          },
          block_identifier: { Hash: blockHash },
          include_bytecode: false,
        }),
      );
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    }
  }

  async #nonceUsed(
    query: AuthorizationLocatorQuery,
    boundary: StableBoundary,
  ): Promise<boolean> {
    const packageState = await this.#resolvePackageAt(
      query.packageHashHex,
      boundary.blockHash,
    );
    if (packageState.enabledContractHash !== query.contractHashHex) {
      throw observationUnavailable();
    }
    const seed = await this.#dictionarySeed(
      query.contractHashHex,
      boundary.blockHash,
    );
    const dictionaryItemKey = usedNonceDictionaryKey(
      query.payerAccountHashHex,
      query.authorizationNonceHex,
    );
    try {
      return parseUsedNonceValue(
        await this.#rpc("state_get_dictionary_item", {
          state_root_hash: boundary.stateRootHash,
          dictionary_identifier: {
            URef: {
              seed_uref: seed,
              dictionary_item_key: dictionaryItemKey,
            },
          },
        }),
      );
    } catch (error) {
      // With the exact dictionary seed independently proven at this same
      // block, -32003 means this compound key has no stored value, i.e. the
      // contract's `get_or_default` result is false.
      if (error instanceof RpcResponseError && error.code === -32003) {
        return false;
      }
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    }
  }

  async #cloudPage(
    query: AuthorizationLocatorQuery,
    page: number,
  ): Promise<unknown> {
    let token: string;
    try {
      token = this.#csprCloudToken();
    } catch (error) {
      if (error instanceof ServiceRefusal) throw error;
      throw observationUnavailable();
    }
    if (token.length === 0) throw observationUnavailable();
    const url = new URL("/deploys", CSPR_CLOUD_TESTNET_API_URL);
    url.searchParams.set(
      "contract_package_hash",
      query.packageHashHex,
    );
    url.searchParams.set("contract_hash", query.contractHashHex);
    url.searchParams.set("page", String(page));
    url.searchParams.set("page_size", String(LOCATOR_PAGE_SIZE));
    return this.#fetchJson(
      url.toString(),
      {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: token,
        },
      },
      true,
    );
  }

  async #locateUsedNonce(
    query: AuthorizationLocatorQuery,
  ): Promise<string> {
    const exact = new Set<string>();
    let pages = 1;
    for (let page = 1; page <= Math.min(pages, MAX_LOCATOR_PAGES); page += 1) {
      const response = await this.#cloudPage(query, page);
      if (
        !isObject(response) ||
        !Array.isArray(response["data"]) ||
        typeof response["page_count"] !== "number" ||
        !Number.isSafeInteger(response["page_count"]) ||
        response["page_count"] < 0
      ) {
        throw observationMalformed();
      }
      pages = Math.max(1, response["page_count"]);
      for (const item of response["data"]) {
        const candidate = cloudCandidateHash(item, query);
        if (candidate === undefined || exact.has(candidate)) continue;
        let readback: TransactionReadback;
        try {
          readback = await this.getFinalizedTransaction(candidate);
        } catch {
          continue;
        }
        if (exactLocatorReadback(readback, query)) exact.add(candidate);
      }
    }
    if (exact.size !== 1) throw observationUnavailable();
    const found = exact.values().next().value;
    if (typeof found !== "string") throw observationUnavailable();
    return found;
  }

  async locateSettlementByAuthorization(
    query: AuthorizationLocatorQuery,
  ): Promise<SettlementLocator> {
    assertLocatorQuery(query);
    if (!PUBLIC_KEY_RE.test(query.payerPublicKeyHex)) {
      throw observationUnavailable();
    }
    const boundary = await this.#stableBoundary();
    const used = await this.#nonceUsed(query, boundary);
    if (!used) {
      return {
        found: false,
        observed: {
          finalized: true,
          blockHeight: boundary.blockHeight,
          stateRootHash: boundary.stateRootHash,
        },
      };
    }
    return {
      found: true,
      transactionHash: await this.#locateUsedNonce(query),
    };
  }
}
