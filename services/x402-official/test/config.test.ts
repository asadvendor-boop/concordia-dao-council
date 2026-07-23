/**
 * Strict production configuration (§12, WP5-4). Any environment variable set to
 * anything other than its G1-frozen value is REJECTED — no facilitator/Gateway
 * origin, network, package/contract identity, token metadata, port, ledger
 * path, resources path, or secret-file path can be redirected. Resource config
 * rejects unknown fields, requires exactly one report source, caps report size,
 * and pins the public resource origin/path.
 */

import { describe, expect, it } from "vitest";

import {
  loadConfig,
  loadSecrets,
  parseResourcesDocument,
  ConfigError,
  FROZEN_CONFIG,
  MAX_REPORT_BYTES,
  FROZEN_PUBLIC_RESOURCE_PREFIX,
} from "../src/config.js";

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof ConfigError) return error.message;
    throw error;
  }
  throw new Error("expected a ConfigError");
}

describe("loadConfig — frozen production values (WP5-4)", () => {
  it.each([
    ["X402_FACILITATOR_URL", "https://x402-facilitator.evil.example"],
    ["X402_NETWORK", "casper:casper"],
    ["X402_WCSPR_PACKAGE_HASH", "ee".repeat(32)],
    ["X402_WCSPR_CONTRACT_HASH", "ee".repeat(32)],
    ["X402_WCSPR_CONTRACT_VERSION", "9"],
    ["X402_OFFICIAL_PORT", "9999"],
    ["X402_LEDGER_PATH", "/tmp/evil.db"],
    ["X402_GATEWAY_INTERNAL_URL", "http://evil.internal:8000"],
    ["X402_TOKEN_NAME", "Not WCSPR"],
    ["X402_TOKEN_SYMBOL", "EVIL"],
    ["X402_TOKEN_DECIMALS", "6"],
    ["X402_TOKEN_DOMAIN_VERSION", "2"],
    ["X402_SCHEME", "upto"],
    ["X402_RESOURCES_FILE", "/tmp/evil-resources.json"],
  ])("rejects a redirected %s", (name, value) => {
    expect(codeOf(() => loadConfig({ [name]: value }))).toBe(
      `config_override_rejected:${name}`,
    );
  });

  it("rejects a redirected secret-file path", () => {
    expect(
      codeOf(() => loadSecrets({ X402_GATEWAY_TOKEN_FILE: "/tmp/evil-token" })),
    ).toBe("secret_path_override_rejected:X402_GATEWAY_TOKEN_FILE");
  });

  it("exposes the frozen facilitator origin as a constant", () => {
    expect(FROZEN_CONFIG.X402_FACILITATOR_URL).toBe(
      "https://x402-facilitator.cspr.cloud",
    );
  });
});

const VALID_URL = `${FROZEN_PUBLIC_RESOURCE_PREFIX}finals-report-001`;
const PAYEE = `00${"ab".repeat(32)}`;

function resource(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "finals-report-001",
    url: VALID_URL,
    description: "Concordia finals protected report",
    mimeType: "application/json",
    amount: "1000000000",
    payTo: PAYEE,
    maxTimeoutSeconds: 600,
    reportBase64: Buffer.from("report-bytes", "utf8").toString("base64"),
    ...overrides,
  };
}

describe("parseResourcesDocument — resource-config hardening (WP5-4)", () => {
  it("accepts a single valid base64 resource", () => {
    const out = parseResourcesDocument({ resources: [resource()] });
    expect(out).toHaveLength(1);
    expect(out[0]!.id).toBe("finals-report-001");
  });

  it("rejects an unknown resource field", () => {
    const r = resource({ surprise: true });
    expect(codeOf(() => parseResourcesDocument({ resources: [r] }))).toBe(
      "resources_file_unknown_field",
    );
  });

  it("rejects both reportFile and reportBase64 present", () => {
    const r = resource({ reportFile: "/run/config/report.json" });
    expect(codeOf(() => parseResourcesDocument({ resources: [r] }))).toBe(
      "resources_file_report_source_ambiguous",
    );
  });

  it("rejects neither report source present", () => {
    const r = resource();
    delete r["reportBase64"];
    expect(codeOf(() => parseResourcesDocument({ resources: [r] }))).toBe(
      "resources_file_report_source_ambiguous",
    );
  });

  it("rejects an oversized report", () => {
    const r = resource();
    delete r["reportBase64"];
    r["reportFile"] = "/run/config/report.bin";
    const oversized = () => Buffer.alloc(MAX_REPORT_BYTES + 1, 0x41);
    expect(
      codeOf(() => parseResourcesDocument({ resources: [r] }, oversized)),
    ).toBe("resource_report_too_large");
  });

  it("rejects a resource URL outside the pinned public origin/path", () => {
    const r = resource({ url: "https://evil.example/resource/x" });
    expect(codeOf(() => parseResourcesDocument({ resources: [r] }))).toBe(
      "resource_url_origin_not_pinned",
    );
  });
});
