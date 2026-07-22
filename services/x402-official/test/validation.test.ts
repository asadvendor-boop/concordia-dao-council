/**
 * Strict local validation: canonical decimals, canonical URLs, payTo and
 * accepted/outer equality, signature/algorithm discipline, and the
 * account-hash derivation cross-check.
 */

import { describe, expect, it } from "vitest";
import casperSdk from "casper-js-sdk";

import { ServiceRefusal } from "../src/errors.js";
import { blake2b256 } from "../src/hashes.js";
import {
  parseCanonicalU64,
  parseCanonicalU256,
  validateCanonicalHttpsUrl,
  validateVerifySettleRequest,
} from "../src/validation.js";
import {
  generateSigner,
  makeConfig,
  makeSignedRequest,
  requirementsFor,
  signPayload,
} from "./helpers.js";

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof ServiceRefusal) return error.code;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("canonical decimal parsing (§6)", () => {
  it("accepts canonical unsigned decimals", () => {
    expect(parseCanonicalU256("0", "c")).toBe(0n);
    expect(parseCanonicalU256("1", "c")).toBe(1n);
    expect(parseCanonicalU256("1000000000", "c")).toBe(1000000000n);
    expect(parseCanonicalU256((2n ** 256n - 1n).toString(10), "c")).toBe(
      2n ** 256n - 1n,
    );
  });
  it.each([
    ["+1"],
    ["-1"],
    ["01"],
    [" 1"],
    ["1 "],
    ["1.0"],
    ["1e2"],
    ["1E2"],
    [""],
    ["0x10"],
    ["1_000"],
    ["00"],
  ])("rejects non-canonical %j", (value) => {
    expect(() => parseCanonicalU256(value, "c")).toThrow(ServiceRefusal);
  });
  it("rejects values above the type maximum", () => {
    expect(() => parseCanonicalU256((2n ** 256n).toString(10), "c")).toThrow();
    expect(() => parseCanonicalU64((2n ** 64n).toString(10), "c")).toThrow();
    expect(parseCanonicalU64((2n ** 64n - 1n).toString(10), "c")).toBe(2n ** 64n - 1n);
  });
  it("rejects non-string inputs", () => {
    expect(() => parseCanonicalU256(1000000000 as unknown as string, "c")).toThrow();
  });
});

describe("canonical HTTPS URL validation (§6, reject-never-normalize)", () => {
  it("accepts the canonical finals URL and query/trailing-slash variants", () => {
    validateCanonicalHttpsUrl("https://x402.concordiadao.xyz/resource/finals-report-001");
    validateCanonicalHttpsUrl("https://x402.concordiadao.xyz/r/");
    validateCanonicalHttpsUrl("https://x402.concordiadao.xyz/r?b=2&a=1");
    validateCanonicalHttpsUrl("https://x402.concordiadao.xyz/r%2Fx");
  });
  it.each([
    ["http://x402.concordiadao.xyz/r"],
    ["HTTPS://x402.concordiadao.xyz/r"],
    ["https://X402.concordiadao.xyz/r"],
    ["https://x402.concordiadao.xyz"],
    ["https://x402.concordiadao.xyz:443/r"],
    ["https://user@x402.concordiadao.xyz/r"],
    ["https://x402.concordiadao.xyz/r#frag"],
    ["https://x402.concordiadao.xyz/a/../b"],
    ["https://x402.concordiadao.xyz/./r"],
    ["https://x402.concordiadao.xyz/r\\x"],
    ["https://x402.concordiadao.xyz/r x"],
    ["https://x402.concordiadao.xyz/r%2fx"],
    ["https://x402.concordiadao.xyz/r%41"],
    ["https://x402.concordiadao.xyz/r%G1"],
    ["https://-bad.example/r"],
    ["https:///r"],
  ])("rejects non-canonical %j", (url) => {
    expect(() => validateCanonicalHttpsUrl(url)).toThrow(ServiceRefusal);
  });
});

describe("verify/settle request validation", () => {
  const config = makeConfig();

  it("accepts a fully valid officially-signed request and computes both hashes", async () => {
    const { payment } = await makeSignedRequest(config);
    expect(payment.paymentRequirementsHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(payment.signedPaymentPayloadHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(payment.resource.id).toBe("finals-report-001");
    expect(payment.valueAtomic).toBe(1000000000n);
  });

  it("rejects unknown top-level, payload, and authorization fields", async () => {
    const { request } = await makeSignedRequest(config);
    const r1 = structuredClone(request) as Record<string, unknown>;
    r1["extraField"] = 1;
    expect(codeOf(() => validateVerifySettleRequest(r1, config))).toBe(
      "invalid_request_body",
    );
    const r2 = structuredClone(request) as never as {
      paymentPayload: { payload: { authorization: Record<string, unknown> } };
    };
    r2.paymentPayload.payload.authorization["memo"] = "hi";
    expect(codeOf(() => validateVerifySettleRequest(r2, config))).toBe(
      "invalid_authorization",
    );
  });

  it("rejects a non-empty extensions object", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: Record<string, unknown>;
    };
    r.paymentPayload["extensions"] = { note: "x" };
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "invalid_payment_payload_extensions",
    );
  });

  it("rejects accepted != outer paymentRequirements, including extra drift", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { accepted: { extra: Record<string, string> } };
    };
    r.paymentPayload.accepted.extra["symbol"] = "WCSPR2";
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "accepted_requirements_mismatch",
    );
  });

  it("rejects payTo drift between authorization.to and requirements", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: {
        accepted: Record<string, unknown>;
        payload: { authorization: Record<string, unknown> };
      };
      paymentRequirements: Record<string, unknown>;
    };
    const otherPayee = `00${"cd".repeat(32)}`;
    r.paymentPayload.payload.authorization["to"] = otherPayee;
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "payto_mismatch",
    );
  });

  it("rejects a requirements payTo that differs from the configured resource", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { accepted: Record<string, unknown> };
      paymentRequirements: Record<string, unknown>;
    };
    const otherPayee = `00${"cd".repeat(32)}`;
    r.paymentRequirements["payTo"] = otherPayee;
    r.paymentPayload.accepted["payTo"] = otherPayee;
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "requirements_payto_mismatch",
    );
  });

  it("rejects amount drift between authorization.value and requirements.amount", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { payload: { authorization: Record<string, unknown> } };
    };
    r.paymentPayload.payload.authorization["value"] = "999999999";
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "authorization_amount_mismatch",
    );
  });

  it("rejects payer == payee", async () => {
    const signer = await generateSigner();
    // Configure the resource so its payee IS the signer's own account.
    const selfPayConfig = makeConfig();
    const resource = selfPayConfig.resources[0];
    if (resource === undefined) throw new Error("missing resource");
    resource.payTo = signer.accountAddress;
    const requirements = {
      ...requirementsFor(selfPayConfig),
      payTo: signer.accountAddress,
    };
    const payload = await signPayload(signer, requirements);
    const request = {
      x402Version: 2,
      paymentPayload: payload,
      paymentRequirements: requirements,
    };
    expect(codeOf(() => validateVerifySettleRequest(request, selfPayConfig))).toBe(
      "payer_equals_payee",
    );
  });

  it.each([
    ["129 hex chars", (s: string) => s.slice(0, 129)],
    ["128 hex chars (64 bytes)", (s: string) => s.slice(0, 128)],
    ["132 hex chars", (s: string) => `${s}aa`],
    ["uppercase hex", (s: string) => s.toUpperCase()],
    ["0x prefix", (s: string) => `0x${s.slice(2)}`],
  ])("rejects signature encoding: %s", async (_name, mutate) => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { payload: Record<string, unknown> };
    };
    r.paymentPayload.payload["signature"] = mutate(
      r.paymentPayload.payload["signature"] as string,
    );
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "invalid_signature_encoding",
    );
  });

  it("rejects a signature whose leading byte disagrees with the key algorithm tag", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { payload: Record<string, unknown> };
    };
    const sig = r.paymentPayload.payload["signature"] as string;
    r.paymentPayload.payload["signature"] = `02${sig.slice(2)}`;
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "signature_algorithm_mismatch",
    );
  });

  it("rejects a public key that does not hash to authorization.from", async () => {
    const config2 = makeConfig();
    const signerA = await generateSigner();
    const signerB = await generateSigner();
    const requirements = requirementsFor(config2);
    const payload = await signPayload(signerA, requirements, {
      fromOverride: signerB.accountAddress,
    });
    const request = {
      x402Version: 2,
      paymentPayload: payload,
      paymentRequirements: requirements,
    };
    expect(codeOf(() => validateVerifySettleRequest(request, config2))).toBe(
      "public_key_payer_mismatch",
    );
  });

  it("rejects zero and malformed authorization nonces", async () => {
    const { request } = await makeSignedRequest(config);
    for (const nonce of ["00".repeat(32), "AB".repeat(32), "ab".repeat(31), "xyz"]) {
      const r = structuredClone(request) as never as {
        paymentPayload: { payload: { authorization: Record<string, unknown> } };
      };
      r.paymentPayload.payload.authorization["nonce"] = nonce;
      expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
        "invalid_authorization_nonce",
      );
    }
  });

  it("rejects validBefore <= validAfter", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { payload: { authorization: Record<string, unknown> } };
    };
    const auth = r.paymentPayload.payload.authorization;
    auth["validBefore"] = auth["validAfter"];
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "invalid_validity_window",
    );
  });

  it("rejects an unknown resource", async () => {
    const { request } = await makeSignedRequest(config);
    const r = structuredClone(request) as never as {
      paymentPayload: { resource: Record<string, unknown> };
    };
    r.paymentPayload.resource["url"] = "https://x402.concordiadao.xyz/resource/other";
    expect(codeOf(() => validateVerifySettleRequest(r, config))).toBe(
      "unknown_resource",
    );
  });

  it("rejects x402Version other than 2 at both levels", async () => {
    const { request } = await makeSignedRequest(config);
    const r1 = structuredClone(request) as Record<string, unknown>;
    r1["x402Version"] = 1;
    expect(codeOf(() => validateVerifySettleRequest(r1, config))).toBe(
      "unsupported_x402_version",
    );
    const r2 = structuredClone(request) as never as {
      paymentPayload: Record<string, unknown>;
    };
    r2.paymentPayload["x402Version"] = 1;
    expect(codeOf(() => validateVerifySettleRequest(r2, config))).toBe(
      "unsupported_x402_version",
    );
  });
});

describe("account-hash derivation cross-check (§6)", () => {
  it("BLAKE2b-256(algo_name || 0x00 || raw_key) equals the pinned SDK accountHash", async () => {
    const signer = await generateSigner();
    const keyBytes = Buffer.from(signer.publicKeyHex, "hex");
    const derived = blake2b256(
      Buffer.concat([
        Buffer.from("ed25519", "ascii"),
        Buffer.from([0x00]),
        keyBytes.subarray(1),
      ]),
    );
    const sdkHash = casperSdk.PublicKey.fromHex(signer.publicKeyHex)
      .accountHash()
      .toHex();
    expect(derived.toString("hex")).toBe(sdkHash);
    // Hashing tag||key (the forbidden shortcut) must NOT match.
    const wrong = blake2b256(keyBytes);
    expect(wrong.toString("hex")).not.toBe(sdkHash);
  });

  it("matches the Python-computed constant for a fixed ed25519 key", () => {
    const derived = blake2b256(
      Buffer.concat([
        Buffer.from("ed25519", "ascii"),
        Buffer.from([0x00]),
        Buffer.alloc(32, 0x22),
      ]),
    );
    expect(derived.toString("hex")).toBe(
      "1a3e7bfe0c4e03e071cba1456ec8df57571ced5a51ca2d12672c09c28e0af5b0",
    );
  });
});
