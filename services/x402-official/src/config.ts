/**
 * Frozen configuration and secret loading (§12 "Official x402 local service v1").
 *
 * Production config loading is STRICT (WP5-4): every non-resource value is a
 * G1-frozen constant, and any environment variable that is set to anything
 * other than its frozen value is REJECTED at startup — a redirected facilitator
 * or Gateway origin, network, package/contract identity, token metadata, port,
 * ledger path, resources path, or secret-file path can never take effect. There
 * is no environment-proxy or arbitrary-origin override. Test/harness overrides
 * go through explicit injected constructors (`configForTest`, `resolveSecrets`,
 * `parseResourcesDocument`), never through production env parsing.
 *
 * Secrets are loaded ONLY from *_FILE paths; a configured-but-unreadable secret
 * file fails startup. Secret values live behind getter closures and are never
 * placed on the config object, so accidental serialization can never leak them.
 */

import { readFileSync } from "node:fs";

import { resourceUrlHash, reportHash } from "./hashes.js";
import {
  parseCanonicalU256,
  parseAccountAddress,
  validateCanonicalHttpsUrl,
} from "./validation.js";
import { invalidRequest, upstreamUnavailable } from "./errors.js";
import type { ConfiguredResource } from "./types.js";

const LOWER_HEX_64_RE = /^[0-9a-f]{64}$/;

/** Frozen public origin/path prefix every protected resource URL must share. */
export const FROZEN_PUBLIC_RESOURCE_PREFIX =
  "https://x402.concordiadao.xyz/resource/";

/** Maximum protected-report size (bytes). */
export const MAX_REPORT_BYTES = 1_048_576;

/** G1-frozen non-secret configuration constants (§12, G1_CROSS_LANE_SCHEMAS). */
export const FROZEN_CONFIG = {
  X402_OFFICIAL_PORT: "8787",
  X402_FACILITATOR_URL: "https://x402-facilitator.cspr.cloud",
  X402_NETWORK: "casper:casper-test",
  X402_SCHEME: "exact",
  X402_WCSPR_PACKAGE_HASH:
    "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e",
  X402_WCSPR_CONTRACT_HASH:
    "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
  X402_WCSPR_CONTRACT_VERSION: "8",
  X402_TOKEN_NAME: "Wrapped CSPR",
  X402_TOKEN_SYMBOL: "WCSPR",
  X402_TOKEN_DECIMALS: "9",
  X402_TOKEN_DOMAIN_VERSION: "1",
  X402_LEDGER_PATH: "/data/x402-official.db",
  X402_GATEWAY_INTERNAL_URL: "http://gateway:8000",
  X402_RESOURCES_FILE: "/run/config/x402-resources.json",
} as const;

/** G1-frozen secret-file paths (§12). */
export const FROZEN_SECRET_FILES = {
  X402_CSPR_CLOUD_TOKEN_FILE: "/run/secrets/x402_official_cspr_cloud_token",
  X402_SIGNER_FILE: "/run/secrets/x402_official_signer",
  X402_GATEWAY_TOKEN_FILE: "/run/secrets/x402_official_gateway_token",
} as const;

export const SETTLEMENT_STATES = {
  BLOCKED_FAIL_CLOSED: "blocked_fail_closed",
  BLOCKED_UPGRADE_DRIFT: "blocked_upgrade_drift",
  OFFICIAL_HOSTED_VERIFIED_LIVE: "official_hosted_verified_live",
} as const;

export type SettlementState =
  (typeof SETTLEMENT_STATES)[keyof typeof SETTLEMENT_STATES];

export interface ServiceConfig {
  port: number;
  facilitatorUrl: string;
  network: string;
  scheme: string;
  wcsprPackageHash: string;
  wcsprContractHash: string;
  wcsprContractVersion: number;
  tokenName: string;
  tokenSymbol: string;
  tokenDecimals: number;
  tokenDomainVersion: string;
  ledgerPath: string;
  gatewayInternalUrl: string;
  resources: ConfiguredResource[];
}

export interface SecretProviders {
  /** Raw CSPR.cloud facilitator token (sent as raw Authorization, never Bearer). */
  csprCloudToken: () => string;
  /** Internal proof-registry service token (X-Concordia-Service-Token). */
  gatewayToken: () => string;
  /** Signer material handle; held for the Codex-run live canary, unused locally. */
  signerAvailable: () => boolean;
}

export class ConfigError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "ConfigError";
  }
}

/**
 * Read a frozen scalar. If the env var is unset/empty, use the frozen value;
 * if it is set to ANYTHING other than the frozen value, reject (WP5-4).
 */
function frozenEnv(
  env: Record<string, string | undefined>,
  name: keyof typeof FROZEN_CONFIG,
): string {
  const frozen = FROZEN_CONFIG[name];
  const value = env[name];
  if (value === undefined || value === "") return frozen;
  if (value !== frozen) {
    throw new ConfigError(`config_override_rejected:${name}`);
  }
  return frozen;
}

interface RawResourceEntry {
  id?: unknown;
  url?: unknown;
  description?: unknown;
  mimeType?: unknown;
  amount?: unknown;
  payTo?: unknown;
  maxTimeoutSeconds?: unknown;
  reportBase64?: unknown;
  reportFile?: unknown;
}

const RESOURCE_ALLOWED_FIELDS = new Set([
  "id",
  "url",
  "description",
  "mimeType",
  "amount",
  "payTo",
  "maxTimeoutSeconds",
  "reportBase64",
  "reportFile",
]);

/**
 * Parse and validate the resources document (pure; the report-file reader is
 * injected so tests never touch disk). Rejects unknown fields, requires exactly
 * one of reportFile|reportBase64, caps report size, and pins the public
 * resource origin/path — reject, never normalize.
 */
export function parseResourcesDocument(
  raw: unknown,
  readReportFile: (path: string) => Buffer = (p) => readFileSync(p),
): ConfiguredResource[] {
  if (
    typeof raw !== "object" ||
    raw === null ||
    !Array.isArray((raw as { resources?: unknown }).resources)
  ) {
    throw new ConfigError("resources_file_invalid");
  }
  const out: ConfiguredResource[] = [];
  const seenIds = new Set<string>();
  const seenUrls = new Set<string>();
  for (const entry of (raw as { resources: RawResourceEntry[] }).resources) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new ConfigError("resources_file_invalid");
    }
    // Reject unknown resource-config fields (schema: unknown_fields=reject).
    for (const key of Object.keys(entry)) {
      if (!RESOURCE_ALLOWED_FIELDS.has(key)) {
        throw new ConfigError("resources_file_unknown_field");
      }
    }
    const { id, url, description, mimeType, amount, payTo, maxTimeoutSeconds } = entry;
    if (
      typeof id !== "string" ||
      !/^[a-z0-9][a-z0-9-]{0,63}$/.test(id) ||
      typeof url !== "string" ||
      typeof description !== "string" ||
      description.length === 0 ||
      typeof mimeType !== "string" ||
      mimeType.length === 0 ||
      typeof amount !== "string" ||
      typeof payTo !== "string" ||
      typeof maxTimeoutSeconds !== "number" ||
      !Number.isInteger(maxTimeoutSeconds) ||
      maxTimeoutSeconds < 1 ||
      maxTimeoutSeconds > 4294967295
    ) {
      throw new ConfigError("resources_file_invalid");
    }
    // Pin the public resource origin/path — reject, never normalize.
    if (!url.startsWith(FROZEN_PUBLIC_RESOURCE_PREFIX)) {
      throw new ConfigError("resource_url_origin_not_pinned");
    }
    if (seenIds.has(id) || seenUrls.has(url)) {
      throw new ConfigError("resources_file_duplicate");
    }
    seenIds.add(id);
    seenUrls.add(url);
    try {
      validateCanonicalHttpsUrl(url);
      const value = parseCanonicalU256(amount, "invalid_amount");
      if (value < 1n) throw invalidRequest("invalid_amount");
      parseAccountAddress(payTo, "invalid_payto");
    } catch {
      throw new ConfigError("resources_file_invalid");
    }
    // Exactly one of reportFile | reportBase64.
    const hasBase64 = typeof entry.reportBase64 === "string";
    const hasFile = typeof entry.reportFile === "string";
    if (hasBase64 === hasFile) {
      throw new ConfigError("resources_file_report_source_ambiguous");
    }
    let reportBytes: Buffer;
    if (hasBase64) {
      const b64 = entry.reportBase64 as string;
      reportBytes = Buffer.from(b64, "base64");
      // Canonical round-trip: reject sloppy base64.
      if (reportBytes.toString("base64") !== b64) {
        throw new ConfigError("resources_file_invalid");
      }
    } else {
      try {
        reportBytes = readReportFile(entry.reportFile as string);
      } catch {
        throw new ConfigError("resource_report_unreadable");
      }
    }
    if (reportBytes.length === 0) throw new ConfigError("resources_file_invalid");
    if (reportBytes.length > MAX_REPORT_BYTES) {
      throw new ConfigError("resource_report_too_large");
    }
    out.push({
      id,
      url,
      description,
      mimeType,
      amount,
      payTo,
      maxTimeoutSeconds,
      reportBytes,
      reportHashHex: reportHash(reportBytes).toString("hex"),
      resourceUrlHashHex: resourceUrlHash(url).toString("hex"),
    });
  }
  return out;
}

function loadResources(
  env: Record<string, string | undefined>,
): ConfiguredResource[] {
  const path = frozenEnv(env, "X402_RESOURCES_FILE");
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new ConfigError("resources_file_unreadable");
  }
  return parseResourcesDocument(raw);
}

/**
 * Explicit test/harness constructor for a ServiceConfig. Production code never
 * calls this; it exists so tests inject overrides without going through the
 * strict production env parser.
 */
export function configForTest(overrides: Partial<ServiceConfig> = {}): ServiceConfig {
  return {
    port: 8787,
    facilitatorUrl: FROZEN_CONFIG.X402_FACILITATOR_URL,
    network: FROZEN_CONFIG.X402_NETWORK,
    scheme: FROZEN_CONFIG.X402_SCHEME,
    wcsprPackageHash: FROZEN_CONFIG.X402_WCSPR_PACKAGE_HASH,
    wcsprContractHash: FROZEN_CONFIG.X402_WCSPR_CONTRACT_HASH,
    wcsprContractVersion: 8,
    tokenName: FROZEN_CONFIG.X402_TOKEN_NAME,
    tokenSymbol: FROZEN_CONFIG.X402_TOKEN_SYMBOL,
    tokenDecimals: 9,
    tokenDomainVersion: FROZEN_CONFIG.X402_TOKEN_DOMAIN_VERSION,
    ledgerPath: ":memory:",
    gatewayInternalUrl: FROZEN_CONFIG.X402_GATEWAY_INTERNAL_URL,
    resources: [],
    ...overrides,
  };
}

export function loadConfig(
  env: Record<string, string | undefined> = process.env,
): ServiceConfig {
  const port = Number(frozenEnv(env, "X402_OFFICIAL_PORT"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigError("invalid_port");
  }
  const contractVersion = Number(frozenEnv(env, "X402_WCSPR_CONTRACT_VERSION"));
  if (!Number.isInteger(contractVersion) || contractVersion < 1) {
    throw new ConfigError("invalid_contract_version");
  }
  const decimals = Number(frozenEnv(env, "X402_TOKEN_DECIMALS"));
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new ConfigError("invalid_token_decimals");
  }
  const wcsprPackageHash = frozenEnv(env, "X402_WCSPR_PACKAGE_HASH");
  const wcsprContractHash = frozenEnv(env, "X402_WCSPR_CONTRACT_HASH");
  if (!LOWER_HEX_64_RE.test(wcsprPackageHash)) throw new ConfigError("invalid_package_hash");
  if (!LOWER_HEX_64_RE.test(wcsprContractHash)) throw new ConfigError("invalid_contract_hash");
  return {
    port,
    facilitatorUrl: frozenEnv(env, "X402_FACILITATOR_URL"),
    network: frozenEnv(env, "X402_NETWORK"),
    scheme: frozenEnv(env, "X402_SCHEME"),
    wcsprPackageHash,
    wcsprContractHash,
    wcsprContractVersion: contractVersion,
    tokenName: frozenEnv(env, "X402_TOKEN_NAME"),
    tokenSymbol: frozenEnv(env, "X402_TOKEN_SYMBOL"),
    tokenDecimals: decimals,
    tokenDomainVersion: frozenEnv(env, "X402_TOKEN_DOMAIN_VERSION"),
    ledgerPath: frozenEnv(env, "X402_LEDGER_PATH"),
    gatewayInternalUrl: frozenEnv(env, "X402_GATEWAY_INTERNAL_URL"),
    resources: loadResources(env),
  };
}

function loadSecretFile(path: string, name: string): string {
  let value: string;
  try {
    value = readFileSync(path, "utf8").trim();
  } catch {
    // Configured but unreadable: fail startup (§12).
    throw new ConfigError(`secret_file_unreadable:${name}`);
  }
  if (value.length === 0) throw new ConfigError(`secret_file_empty:${name}`);
  return value;
}

export interface SecretFilePaths {
  csprCloudTokenFile?: string | undefined;
  signerFile?: string | undefined;
  gatewayTokenFile?: string | undefined;
}

/**
 * Explicit injected secret constructor (the mechanism). A provided path is read
 * eagerly (unreadable → startup failure); an omitted path yields a provider
 * that refuses at call time (fail closed). Production wraps this behind frozen
 * path enforcement in `loadSecrets`.
 */
export function resolveSecrets(paths: SecretFilePaths): SecretProviders {
  const csprCloudToken =
    paths.csprCloudTokenFile !== undefined && paths.csprCloudTokenFile !== ""
      ? loadSecretFile(paths.csprCloudTokenFile, "X402_CSPR_CLOUD_TOKEN_FILE")
      : undefined;
  const gatewayToken =
    paths.gatewayTokenFile !== undefined && paths.gatewayTokenFile !== ""
      ? loadSecretFile(paths.gatewayTokenFile, "X402_GATEWAY_TOKEN_FILE")
      : undefined;
  const signer =
    paths.signerFile !== undefined && paths.signerFile !== ""
      ? loadSecretFile(paths.signerFile, "X402_SIGNER_FILE")
      : undefined;
  return {
    csprCloudToken: () => {
      if (csprCloudToken === undefined) {
        throw upstreamUnavailable("secret_unavailable");
      }
      return csprCloudToken;
    },
    gatewayToken: () => {
      if (gatewayToken === undefined) {
        throw upstreamUnavailable("secret_unavailable");
      }
      return gatewayToken;
    },
    signerAvailable: () => signer !== undefined,
  };
}

/**
 * If a secret-file env var is set, it must equal the frozen path (WP5-4); an
 * unset var means the secret is unconfigured (provider refuses at call time).
 */
function frozenSecretPath(
  env: Record<string, string | undefined>,
  name: keyof typeof FROZEN_SECRET_FILES,
): string | undefined {
  const value = env[name];
  if (value === undefined || value === "") return undefined;
  if (value !== FROZEN_SECRET_FILES[name]) {
    throw new ConfigError(`secret_path_override_rejected:${name}`);
  }
  return value;
}

/**
 * Load secrets from the three frozen *_FILE variables (production). A redirected
 * secret-file path is rejected before any read.
 */
export function loadSecrets(
  env: Record<string, string | undefined> = process.env,
): SecretProviders {
  return resolveSecrets({
    csprCloudTokenFile: frozenSecretPath(env, "X402_CSPR_CLOUD_TOKEN_FILE"),
    signerFile: frozenSecretPath(env, "X402_SIGNER_FILE"),
    gatewayTokenFile: frozenSecretPath(env, "X402_GATEWAY_TOKEN_FILE"),
  });
}
