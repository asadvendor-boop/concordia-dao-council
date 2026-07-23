/**
 * Reviewer finding (WP5 merge blocker): the resource-route throttle was keyed
 * by req.socket.remoteAddress. Behind Caddy every external client shares the
 * Caddy container address, so one attacker could exhaust the shared quota —
 * a clean adversarial run reproduced client A receiving a 402 refusal and a
 * DISTINCT client B incorrectly receiving 429 at limit 1.
 *
 * These tests pin the fix:
 *  (a) distinct trusted identities (Caddy-set X-Concordia-Client-IP, G1 §12
 *      SafePay convention: strip + overwrite) have ISOLATED budgets — A at
 *      its limit never 429s B;
 *  (b) the SAME identity shares ONE budget across paid /resource attempts and
 *      POST /settle (both directions);
 *  (c) malformed/garbage header values on the DIRECT service (no Caddy) are
 *      never trusted — they fall back to the socket identity;
 *  (d) the throttle key map is strictly bounded under an attacker cycling
 *      identities, with expired-first / then-oldest eviction that preserves a
 *      recently-limited live key whenever possible.
 */

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { FixedWindowThrottle, createService } from "../src/server.js";
import {
  buildRegistryRecord,
  makeDeps,
  makeSignedRequest,
  readbackFor,
} from "./helpers.js";

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
  await Promise.all(
    servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))),
  );
});

function paymentSignatureFor(request: Record<string, unknown>): string {
  return Buffer.from(
    JSON.stringify(request["paymentPayload"]),
    "utf8",
  ).toString("base64");
}

describe("trusted client identity isolates throttle budgets (reviewer scenario)", () => {
  it("limit 1: client A's 402 refusal exhausts ONLY A's budget — distinct client B is NOT 429ed", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    // Ungoverned payload: every paid attempt is a 402 refusal, never a release.
    h.registry.result = { outcome: "not_found" };
    const base = await listen(
      createService(h.deps, { throttle: { limit: 1, windowMs: 60_000 } }),
    );
    const paymentSignature = paymentSignatureFor(request);
    const attempt = (clientIp: string) =>
      fetch(`${base}/resource/finals-report-001`, {
        headers: {
          "payment-signature": paymentSignature,
          "x-concordia-client-ip": clientIp,
        },
      });

    // Client A consumes its whole budget on a refused payment: 402, not 429.
    const firstA = await attempt("203.0.113.10");
    expect(firstA.status).toBe(402);
    expect(await firstA.json()).toEqual({ error: "ungoverned_payload" });

    // A is now at its limit: A's next paid attempt IS throttled...
    const secondA = await attempt("203.0.113.10");
    expect(secondA.status).toBe(429);
    expect(await secondA.json()).toEqual({ error: "rate_limited" });

    // ...but DISTINCT client B must NOT be (the reviewer's reproduction —
    // under the socket-keyed throttle both clients arrived as the same peer
    // and B received 429 here). B gets its own 402 refusal.
    const firstB = await attempt("203.0.113.11");
    expect(firstB.status).toBe(402);
    expect(await firstB.json()).toEqual({ error: "ungoverned_payload" });
  });

  it("the SAME trusted identity shares ONE budget across paid /resource and POST /settle (both directions)", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const base = await listen(
      createService(h.deps, { throttle: { limit: 1, windowMs: 60_000 } }),
    );
    const paymentSignature = paymentSignatureFor(request);
    const viaResource = (clientIp: string) =>
      fetch(`${base}/resource/finals-report-001`, {
        headers: {
          "payment-signature": paymentSignature,
          "x-concordia-client-ip": clientIp,
        },
      });
    const viaSettle = (clientIp: string) =>
      fetch(`${base}/settle`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-concordia-client-ip": clientIp,
        },
        body: JSON.stringify(request),
      });

    // Direction 1: a paid /resource attempt consumes the budget → /settle 429.
    expect((await viaResource("203.0.113.20")).status).toBe(402);
    const settleLimited = await viaSettle("203.0.113.20");
    expect(settleLimited.status).toBe(429);
    expect(await settleLimited.json()).toEqual({
      success: false,
      errorReason: "rate_limited",
      transaction: "",
      network: "casper:casper-test",
    });

    // Direction 2 (fresh identity): /settle consumes the budget → paid
    // /resource attempt 429. The /settle refusal itself keeps the frozen
    // protocol-shaped 200 wire contract.
    expect((await viaSettle("203.0.113.21")).status).toBe(200);
    const resourceLimited = await viaResource("203.0.113.21");
    expect(resourceLimited.status).toBe(429);
    expect(await resourceLimited.json()).toEqual({ error: "rate_limited" });

    // Unpaid discovery (402 + PAYMENT-REQUIRED) never consumes budget.
    const discovery = await fetch(`${base}/resource/finals-report-001`, {
      headers: { "x-concordia-client-ip": "203.0.113.21" },
    });
    expect(discovery.status).toBe(402);
    expect(discovery.headers.get("payment-required")).toBeTruthy();
  });

  it("isolated identities never block a real release: B still gets 200 with A at its limit", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    const TX = "cc".repeat(32);
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const base = await listen(
      createService(h.deps, { throttle: { limit: 1, windowMs: 60_000 } }),
    );
    const paymentSignature = paymentSignatureFor(request);
    const attempt = (clientIp: string) =>
      fetch(`${base}/resource/finals-report-001`, {
        headers: {
          "payment-signature": paymentSignature,
          "x-concordia-client-ip": clientIp,
        },
      });

    // A releases once, then hits its limit.
    expect((await attempt("198.51.100.1")).status).toBe(200);
    expect((await attempt("198.51.100.1")).status).toBe(429);
    // B's idempotent retry of the settled payment must still be served.
    expect((await attempt("198.51.100.2")).status).toBe(200);
  });
});

describe("malformed identity headers are never trusted (direct access, no Caddy)", () => {
  it("garbage/list/port/overlong values fall back to the SOCKET identity instead of minting fresh budgets", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const base = await listen(
      createService(h.deps, { throttle: { limit: 1, windowMs: 60_000 } }),
    );
    const paymentSignature = paymentSignatureFor(request);
    const attempt = (clientIp?: string) =>
      fetch(`${base}/resource/finals-report-001`, {
        headers: {
          "payment-signature": paymentSignature,
          ...(clientIp === undefined ? {} : { "x-concordia-client-ip": clientIp }),
        },
      });

    // First malformed value: falls back to the socket peer and consumes the
    // socket identity's entire limit-1 budget (402 refusal, not 429).
    expect((await attempt("203.0.113.30, 203.0.113.31")).status).toBe(402);

    // Every other malformed shape ALSO resolves to the socket identity, so if
    // any of them were trusted as a distinct identity it would get its own
    // fresh budget and return 402 here instead of 429.
    for (const garbage of [
      "not-an-ip",
      "203.0.113.99:8080",
      "999.999.999.999",
      "203.0.113.40, 203.0.113.41",
      "x".repeat(64),
    ]) {
      const limited = await attempt(garbage);
      expect(limited.status, `value ${JSON.stringify(garbage)} must not mint a budget`).toBe(429);
      expect(await limited.json()).toEqual({ error: "rate_limited" });
    }

    // The absent-header fallback is the SAME socket identity.
    expect((await attempt()).status).toBe(429);
  });
});

describe("throttle key map is strictly bounded under identity cycling", () => {
  it("HTTP: driving many distinct trusted identities past the cap never grows the map beyond it", async () => {
    const h = makeDeps();
    const throttle = new FixedWindowThrottle({ limit: 1, windowMs: 60_000 }, 32);
    const base = await listen(createService(h.deps, { throttle }));

    // An attacker cycling 200 distinct identities through the settlement
    // surface (the throttle is consulted before the body is read).
    for (let i = 0; i < 200; i += 1) {
      const ip = `10.0.${Math.floor(i / 250)}.${i % 250}`;
      const response = await fetch(`${base}/settle`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-concordia-client-ip": ip,
        },
        body: "{not json",
      });
      // Each identity is fresh, so none is throttled; the body then refuses.
      expect(response.status).toBe(400);
    }

    expect(throttle.trackedKeyCount).toBeLessThanOrEqual(32);
    // The map genuinely tracked identities up to the cap (not, say, zero).
    expect(throttle.trackedKeyCount).toBe(32);

    // The service is still functional after sustained eviction pressure.
    const after = await fetch(`${base}/health`);
    expect(after.status).toBe(200);
  });

  it("unit: eviction prefers expired windows and preserves a recently-limited live key", () => {
    const throttle = new FixedWindowThrottle({ limit: 1, windowMs: 1_000 }, 4);
    // Two windows that will be expired by eviction time.
    expect(throttle.allow("stale-1", 0)).toBe(true);
    expect(throttle.allow("stale-2", 0)).toBe(true);
    // A live key driven to its limit.
    expect(throttle.allow("hot", 900)).toBe(true);
    expect(throttle.allow("hot", 901)).toBe(false);
    // Fill to the cap.
    expect(throttle.allow("live-2", 950)).toBe(true);
    expect(throttle.trackedKeyCount).toBe(4);

    // A new identity at t=1100: both stale windows are expired and evicted;
    // the recently-limited live key is preserved.
    expect(throttle.allow("fresh", 1100)).toBe(true);
    expect(throttle.trackedKeyCount).toBe(3);
    // Eviction granted NO extra budget to the recently-limited key.
    expect(throttle.allow("hot", 1101)).toBe(false);
  });

  it("unit: with every window live, only the OLDEST is evicted, the cap holds, and newer spent budgets survive", () => {
    const throttle = new FixedWindowThrottle({ limit: 1, windowMs: 10_000 }, 3);
    expect(throttle.allow("a", 0)).toBe(true);
    expect(throttle.allow("b", 1)).toBe(true);
    expect(throttle.allow("c", 2)).toBe(true);

    // All live: inserting "d" evicts exactly the oldest window ("a").
    expect(throttle.allow("d", 3)).toBe(true);
    expect(throttle.trackedKeyCount).toBe(3);
    // Newer keys keep their spent budget — "b" is still at its limit.
    expect(throttle.allow("b", 4)).toBe(false);
    // The documented, honest trade-off: the evicted oldest key would get a
    // fresh window if it returned while the map is saturated with live keys.
    expect(throttle.allow("a", 5)).toBe(true);
    expect(throttle.trackedKeyCount).toBe(3);
  });
});
