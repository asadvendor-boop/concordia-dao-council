/**
 * Frozen configuration and secret loading (§12 "Official x402 local service v1").
 *
 * Non-secret variables are the exact frozen names with their frozen defaults.
 * Secrets are loaded ONLY from *_FILE paths; a configured-but-unreadable
 * secret file fails startup. Secret values live behind getter closures and
 * are never placed on the config object, so accidental serialization of the
 * config can never leak them.
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

function envString(
  env: Record<string, string | undefined>,
  name: string,
  frozenDefault: string,
): string {
  const value = env[name];
  return value === undefined || value === "" ? frozenDefault : value;
}

function requireLowerHex64(value: string, code: string): string {
  if (!LOWER_HEX_64_RE.test(value)) throw new ConfigError(code);
  return value;
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

function loadResources(
  env: Record<string, string | undefined>,
): ConfiguredResource[] {
  const path = env["X402_RESOURCES_FILE"];
  if (path === undefined || path === "") return [];
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new ConfigError("resources_file_unreadable");
  }
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
    const id = entry.id;
    const url = entry.url;
    const description = entry.description;
    const mimeType = entry.mimeType;
    const amount = entry.amount;
    const payTo = entry.payTo;
    const maxTimeoutSeconds = entry.maxTimeoutSeconds;
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
    let reportBytes: Buffer;
    if (typeof entry.reportBase64 === "string") {
      reportBytes = Buffer.from(entry.reportBase64, "base64");
      // Canonical round-trip: reject sloppy base64.
      if (reportBytes.toString("base64") !== entry.reportBase64) {
        throw new ConfigError("resources_file_invalid");
      }
    } else if (typeof entry.reportFile === "string") {
      try {
        reportBytes = readFileSync(entry.reportFile);
      } catch {
        throw new ConfigError("resource_report_unreadable");
      }
    } else {
      throw new ConfigError("resources_file_invalid");
    }
    if (reportBytes.length === 0) throw new ConfigError("resources_file_invalid");
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

export function loadConfig(
  env: Record<string, string | undefined> = process.env,
): ServiceConfig {
  const port = Number(envString(env, "X402_OFFICIAL_PORT", "8787"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigError("invalid_port");
  }
  const network = envString(env, "X402_NETWORK", "casper:casper-test");
  const scheme = envString(env, "X402_SCHEME", "exact");
  const contractVersion = Number(envString(env, "X402_WCSPR_CONTRACT_VERSION", "8"));
  if (!Number.isInteger(contractVersion) || contractVersion < 1) {
    throw new ConfigError("invalid_contract_version");
  }
  const decimals = Number(envString(env, "X402_TOKEN_DECIMALS", "9"));
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) {
    throw new ConfigError("invalid_token_decimals");
  }
  return {
    port,
    facilitatorUrl: envString(
      env,
      "X402_FACILITATOR_URL",
      "https://x402-facilitator.cspr.cloud",
    ),
    network,
    scheme,
    wcsprPackageHash: requireLowerHex64(
      envString(
        env,
        "X402_WCSPR_PACKAGE_HASH",
        "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e",
      ),
      "invalid_package_hash",
    ),
    wcsprContractHash: requireLowerHex64(
      envString(
        env,
        "X402_WCSPR_CONTRACT_HASH",
        "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
      ),
      "invalid_contract_hash",
    ),
    wcsprContractVersion: contractVersion,
    tokenName: envString(env, "X402_TOKEN_NAME", "Wrapped CSPR"),
    tokenSymbol: envString(env, "X402_TOKEN_SYMBOL", "WCSPR"),
    tokenDecimals: decimals,
    tokenDomainVersion: envString(env, "X402_TOKEN_DOMAIN_VERSION", "1"),
    ledgerPath: envString(env, "X402_LEDGER_PATH", "/data/x402-official.db"),
    gatewayInternalUrl: envString(
      env,
      "X402_GATEWAY_INTERNAL_URL",
      "http://gateway:8000",
    ),
    resources: loadResources(env),
  };
}

function loadSecretFile(
  env: Record<string, string | undefined>,
  name: string,
): string | undefined {
  const path = env[name];
  if (path === undefined || path === "") return undefined;
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

/**
 * Load secrets from the three frozen *_FILE variables. Values are captured in
 * closures; requesting a secret that was not configured throws a sanitized
 * refusal at call time (fail closed, zero upstream calls).
 */
export function loadSecrets(
  env: Record<string, string | undefined> = process.env,
): SecretProviders {
  const csprCloudToken = loadSecretFile(env, "X402_CSPR_CLOUD_TOKEN_FILE");
  const signer = loadSecretFile(env, "X402_SIGNER_FILE");
  const gatewayToken = loadSecretFile(env, "X402_GATEWAY_TOKEN_FILE");
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
