/**
 * §12: /supported parsing as kinds/extensions/signers. A supported kind
 * requires x402Version=2, scheme "exact", network "casper:casper-test".
 * Unknown extra keys are preserved; token metadata is never inferred here.
 */

import { describe, expect, it } from "vitest";

import { parseSupportedDocument, supportsExactKind } from "../src/facilitator.js";
import { ServiceRefusal } from "../src/errors.js";
import { FROZEN } from "./helpers.js";

describe("parseSupportedDocument", () => {
  it("parses the frozen readback shape and preserves unknown kind keys", () => {
    const doc = parseSupportedDocument({
      kinds: [
        { x402Version: 2, scheme: "exact", network: "casper:casper" },
        {
          x402Version: 2,
          scheme: "exact",
          network: "casper:casper-test",
          extra: { feePayer: "opaque-facilitator-identity" },
        },
      ],
      extensions: { something: true },
      signers: { "casper:casper-test": ["opaque"] },
    });
    expect(doc.kinds).toHaveLength(2);
    expect(doc.kinds[1]?.["extra"]).toEqual({
      feePayer: "opaque-facilitator-identity",
    });
    expect(doc.extensions).toEqual({ something: true });
    expect(supportsExactKind(doc, FROZEN.network)).toBe(true);
  });

  it("rejects a document without a kinds array", () => {
    expect(() => parseSupportedDocument({ extensions: {}, signers: [] })).toThrow(
      ServiceRefusal,
    );
    expect(() => parseSupportedDocument("nope")).toThrow(ServiceRefusal);
    expect(() => parseSupportedDocument({ kinds: "nope" })).toThrow(ServiceRefusal);
  });

  it("rejects kind entries with missing or mistyped fields", () => {
    expect(() =>
      parseSupportedDocument({ kinds: [{ scheme: "exact", network: "x" }] }),
    ).toThrow(ServiceRefusal);
    expect(() =>
      parseSupportedDocument({
        kinds: [{ x402Version: "2", scheme: "exact", network: "x" }],
      }),
    ).toThrow(ServiceRefusal);
  });

  it("does not treat near-miss kinds as supported", () => {
    const doc = parseSupportedDocument({
      kinds: [
        { x402Version: 1, scheme: "exact", network: FROZEN.network },
        { x402Version: 2, scheme: "upto", network: FROZEN.network },
        { x402Version: 2, scheme: "exact", network: "casper:casper" },
        { x402Version: 2, scheme: "exact", network: "casper-testnet" },
      ],
      extensions: {},
      signers: [],
    });
    expect(supportsExactKind(doc, FROZEN.network)).toBe(false);
  });
});
