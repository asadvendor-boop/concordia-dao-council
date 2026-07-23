/**
 * Credentialed transport hardening (§11, §12, WP5-4). The facilitator and
 * Gateway origins are frozen; credentialed requests use raw Authorization, must
 * not follow redirects (token-exfiltration guard), are bounded in time and body
 * size, and never surface a non-2xx credentialed body. Upstream reason strings
 * are bounded and mapped to stable local codes.
 */

import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  HttpFacilitatorTransport,
  FROZEN_FACILITATOR_ORIGIN,
  boundFacilitatorReason,
} from "../src/facilitator.js";
import {
  HttpRegistryTransport,
  FROZEN_GATEWAY_ORIGIN,
} from "../src/registry.js";
import { ServiceRefusal } from "../src/errors.js";

const servers: Server[] = [];

function listen(server: Server): Promise<string> {
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))),
  );
});

describe("frozen credentialed origins (WP5-4)", () => {
  it("rejects a non-frozen facilitator origin (arbitrary-origin override)", () => {
    expect(() => new HttpFacilitatorTransport("https://evil.example", () => "t")).toThrow(
      ServiceRefusal,
    );
    // The exact frozen origin is accepted.
    expect(
      () => new HttpFacilitatorTransport(FROZEN_FACILITATOR_ORIGIN, () => "t"),
    ).not.toThrow();
  });

  it("rejects a non-frozen Gateway origin (arbitrary-origin override)", () => {
    expect(() => new HttpRegistryTransport("http://evil.internal:8000", () => "t")).toThrow(
      ServiceRefusal,
    );
    expect(() => new HttpRegistryTransport(FROZEN_GATEWAY_ORIGIN, () => "t")).not.toThrow();
  });
});

describe("credentialed fetch discipline", () => {
  it("never follows a redirect (a malicious Location can never receive the token)", async () => {
    let evilHitCount = 0;
    // The 'malicious' endpoint that a Location header would point to.
    const evil = createHttpServer((_req, res) => {
      evilHitCount += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    const evilBase = await listen(evil);
    const facil = createHttpServer((_req, res) => {
      res.writeHead(302, { location: `${evilBase}/steal` });
      res.end();
    });
    const facilBase = await listen(facil);
    const token = "credential-must-not-leak";
    const transport = new HttpFacilitatorTransport(facilBase, () => token, {
      allowUnfrozenOriginForTest: true,
    });
    await expect(transport.verify({ x402Version: 2 })).rejects.toMatchObject({
      code: "facilitator_unreachable",
    });
    // The redirect target must never have been contacted with the token.
    expect(evilHitCount).toBe(0);
  });

  it("rejects an oversized response body (bounded read)", async () => {
    const huge = "a".repeat(4096);
    const stub = createHttpServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ blob: huge }));
    });
    const base = await listen(stub);
    const transport = new HttpFacilitatorTransport(base, () => "t", {
      allowUnfrozenOriginForTest: true,
      maxResponseBytes: 256,
    });
    await expect(transport.supported()).rejects.toMatchObject({
      code: "malformed_facilitator_response",
    });
  });

  it("times out a hanging credentialed request without exposing the token", async () => {
    const logSpy = vi.spyOn(console, "log");
    const stub = createHttpServer(() => {
      /* never responds */
    });
    const base = await listen(stub);
    const token = "hang-token-do-not-log";
    const transport = new HttpFacilitatorTransport(base, () => token, {
      allowUnfrozenOriginForTest: true,
      timeoutMs: 40,
    });
    await expect(transport.verify({ x402Version: 2 })).rejects.toMatchObject({
      code: "facilitator_unreachable",
    });
    const logged = logSpy.mock.calls.flat().map(String).join("\n");
    expect(logged).not.toContain(token);
  });
});

describe("boundFacilitatorReason (map untrusted upstream text)", () => {
  it("passes only allowlisted grammar-conforming reasons", () => {
    expect(boundFacilitatorReason("insufficient_funds", "facilitator_declined")).toBe(
      "insufficient_funds",
    );
    expect(boundFacilitatorReason("expired", "facilitator_declined")).toBe("expired");
  });

  it("maps anything unknown/oversized/hostile to the bounded fallback", () => {
    expect(boundFacilitatorReason("nope", "facilitator_declined")).toBe("facilitator_declined");
    expect(boundFacilitatorReason("<script>alert(1)</script>", "facilitator_declined")).toBe(
      "facilitator_declined",
    );
    expect(boundFacilitatorReason("a".repeat(500), "facilitator_declined")).toBe(
      "facilitator_declined",
    );
    expect(boundFacilitatorReason(undefined, "facilitator_declined")).toBe("facilitator_declined");
    // A reflected credential-looking value never passes through.
    expect(
      boundFacilitatorReason("Authorization: secret-token-1234", "facilitator_declined"),
    ).toBe("facilitator_declined");
  });
});
