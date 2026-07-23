/**
 * Durable upstream-settle journal: every credentialed `/settle` call is
 * journaled durably BEFORE network I/O, exactly one terminal event follows,
 * the journaled bytes are the sent bytes, no secret ever enters a row, and
 * the table is append-only at the schema layer.
 */

import DatabaseConstructor from "better-sqlite3";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HttpFacilitatorTransport } from "../src/facilitator.js";
import { ServiceRefusal } from "../src/errors.js";
import { runSettle } from "../src/pipeline.js";
import {
  JOURNALED_REQUEST_HEADERS_JSON,
  SETTLE_CALL_DOMAIN,
  SettleJournal,
  settleCallId,
  sha256Hex,
  type SettleCallStart,
} from "../src/settle-journal.js";
import type { SettleCallBinding } from "../src/types.js";
import {
  buildRegistryRecord,
  makeDeps,
  makeSignedRequest,
  readbackFor,
  tempDir,
} from "./helpers.js";

const ORIGIN = "https://facilitator.test.invalid";
const TOKEN = "supersecret-cspr-cloud-token-value";
const TX = "cc".repeat(32);

function binding(overrides: Partial<SettleCallBinding> = {}): SettleCallBinding {
  return {
    network: "casper:casper-test",
    wcsprContract: "aa".repeat(32),
    signedPaymentPayloadHash: "bb".repeat(32),
    payerAccountHash: "cd".repeat(32),
    authorizationNonce: "ee".repeat(32),
    resourceId: "resource-alpha",
    actionId: "1f".repeat(32),
    envelopeHash: "2f".repeat(32),
    ...overrides,
  };
}

function startFor(
  b: SettleCallBinding,
  body = `{"probe":true}`,
): SettleCallStart {
  const sha = sha256Hex(body);
  return {
    callId: settleCallId(b, sha),
    binding: b,
    requestMethod: "POST",
    requestUrl: `${ORIGIN}/settle`,
    requestBody: body,
    requestBodySha256: sha,
  };
}

function transport(journal: SettleJournal): HttpFacilitatorTransport {
  return new HttpFacilitatorTransport(ORIGIN, () => TOKEN, {
    allowUnfrozenOriginForTest: true,
    timeoutMs: 2_000,
    maxResponseBytes: 4_096,
    settleJournal: journal,
  });
}

function jsonResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "set-cookie": "session=leak-me-not",
      "x-upstream-authorization-echo": TOKEN,
    },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("schema: append-only and unique identities", () => {
  it("UPDATE and DELETE always abort", () => {
    const path = join(tempDir(), "journal.db");
    const journal = new SettleJournal(path);
    journal.recordRequestStarted(startFor(binding()));
    journal.close();
    const raw = new DatabaseConstructor(path);
    expect(() =>
      raw.prepare(`UPDATE x402_upstream_settle_calls SET network = 'x'`).run(),
    ).toThrow(/append_only/);
    expect(() =>
      raw.prepare(`DELETE FROM x402_upstream_settle_calls`).run(),
    ).toThrow(/append_only/);
    raw.close();
  });

  it("a second start for the same call, authorization, or payload refuses", () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const b = binding();
    journal.recordRequestStarted(startFor(b));
    // Same call identity.
    expect(() => journal.recordRequestStarted(startFor(b))).toThrow(
      ServiceRefusal,
    );
    // Same authorization identity, different payload hash.
    expect(() =>
      journal.recordRequestStarted(
        startFor(binding({ signedPaymentPayloadHash: "0b".repeat(32) })),
      ),
    ).toThrow(ServiceRefusal);
    // Same payload identity, different authorization nonce.
    expect(() =>
      journal.recordRequestStarted(
        startFor(binding({ authorizationNonce: "0e".repeat(32) })),
      ),
    ).toThrow(ServiceRefusal);
    expect(journal.listEvents()).toHaveLength(1);
    journal.close();
  });

  it("a terminal without a matching start (or with a drifted binding) aborts", () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const b = binding();
    const start = startFor(b);
    // No start yet → response_observed aborts (journal wraps into refusal).
    expect(() =>
      journal.recordResponseObserved(start, 200, "{}", `{"success":true}`),
    ).toThrow(ServiceRefusal);
    journal.recordRequestStarted(start);
    // Drifted binding field on the terminal aborts.
    const drifted: SettleCallStart = {
      ...start,
      binding: { ...b, envelopeHash: "3f".repeat(32) },
    };
    expect(() =>
      journal.recordResponseObserved(drifted, 200, "{}", `{"success":true}`),
    ).toThrow(ServiceRefusal);
    // The matching terminal lands, and a second terminal refuses.
    journal.recordResponseObserved(start, 200, "{}", `{"success":true}`);
    expect(() =>
      journal.recordResponseObserved(start, 200, "{}", `{"success":true}`),
    ).toThrow(ServiceRefusal);
    journal.close();
  });

  it("call_id is the domain-separated hash over the ordered fields", () => {
    // Pin the derivation inputs: changing ANY bound field or the request
    // body changes the id; the domain separator carries a trailing NUL.
    expect(SETTLE_CALL_DOMAIN.endsWith("\0")).toBe(true);
    const b = binding();
    const id = settleCallId(b, sha256Hex("{}"));
    expect(id).toMatch(/^[0-9a-f]{64}$/);
    expect(settleCallId(b, sha256Hex("{} "))).not.toBe(id);
    expect(
      settleCallId(binding({ resourceId: "resource-beta" }), sha256Hex("{}")),
    ).not.toBe(id);
  });
});

describe("transport: journal before network, exact bytes, no secrets", () => {
  it("journals the start durably BEFORE the fetch, with the exact sent bytes", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    let eventsAtFetchTime = -1;
    let sentBody: unknown;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init: RequestInit) => {
        eventsAtFetchTime = journal.listEvents().length;
        sentBody = init.body;
        return jsonResponse(
          JSON.stringify({ success: true, transaction: TX, network: binding().network }),
        );
      }),
    );
    const body = { x402Version: 2, paymentPayload: { p: 1 }, paymentRequirements: { r: 2 } };
    await transport(journal).settle(body, binding());
    // The start row existed before the network was touched…
    expect(eventsAtFetchTime).toBe(1);
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "response_observed",
    ]);
    // …and the journaled bytes are the SENT bytes, byte for byte.
    expect(events[0]?.requestBody).toBe(sentBody);
    expect(events[0]?.requestBody).toBe(JSON.stringify(body));
    expect(events[0]?.requestBodySha256).toBe(sha256Hex(JSON.stringify(body)));
    expect(events[0]?.requestUrl).toBe(`${ORIGIN}/settle`);
    journal.close();
  });

  it("if the start append fails, the network is never called", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const b = binding();
    journal.recordRequestStarted(startFor(b, `{"earlier":true}`));
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    // Same authorization identity → start append refuses → no fetch.
    await expect(transport(journal).settle({ second: true }, b)).rejects.toThrow(
      ServiceRefusal,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
    journal.close();
  });

  it("never journals the credential: request headers are the constant record, response headers pass the allowlist", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          JSON.stringify({ success: true, transaction: TX, network: binding().network }),
        ),
      ),
    );
    await transport(journal).settle({ a: 1 }, binding());
    const dump = JSON.stringify(journal.listEvents());
    expect(dump).not.toContain(TOKEN);
    expect(dump).not.toContain("set-cookie");
    expect(dump).not.toContain('"authorization":');
    const events = journal.listEvents();
    expect(events[0]?.requestHeadersJson).toBe(JOURNALED_REQUEST_HEADERS_JSON);
    expect(events[0]?.requestHeadersJson).toBe(
      JSON.stringify({ "content-type": "application/json" }),
    );
    const responseHeaders = JSON.parse(
      events[1]?.responseHeadersJson ?? "{}",
    ) as Record<string, string>;
    expect(Object.keys(responseHeaders)).toEqual(["content-type"]);
    journal.close();
  });

  it("journals the raw response BEFORE parsing: unparseable 2xx bytes are preserved", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const rawBytes = `{"success": true, "transaction": <NOT-JSON>`;
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(rawBytes)));
    await expect(transport(journal).settle({ a: 1 }, binding())).rejects.toThrow(
      ServiceRefusal,
    );
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "response_observed",
    ]);
    expect(events[1]?.responseBody).toBe(rawBytes);
    expect(events[1]?.responseBodySha256).toBe(sha256Hex(rawBytes));
    expect(events[1]?.responseStatus).toBe(200);
    journal.close();
  });

  it("bounded failure on non-2xx: status + allowlisted headers, NEVER the body", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(`credential-reflecting: ${TOKEN}`, 401)),
    );
    await expect(transport(journal).settle({ a: 1 }, binding())).rejects.toThrow(
      ServiceRefusal,
    );
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "request_failed",
    ]);
    expect(events[1]?.responseStatus).toBe(401);
    expect(events[1]?.responseBody).toBeNull();
    expect(events[1]?.responseBodySha256).toBeNull();
    expect(events[1]?.failureCode).toBe("facilitator_http_401");
    expect(JSON.stringify(events)).not.toContain(TOKEN);
    journal.close();
  });

  it("bounded failure on transport error: no status, no headers, no body", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("boom");
      }),
    );
    await expect(transport(journal).settle({ a: 1 }, binding())).rejects.toThrow(
      ServiceRefusal,
    );
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "request_failed",
    ]);
    expect(events[1]?.responseStatus).toBeNull();
    expect(events[1]?.responseHeadersJson).toBeNull();
    expect(events[1]?.responseBody).toBeNull();
    expect(events[1]?.failureCode).toBe("facilitator_unreachable");
    journal.close();
  });

  it("survives restart: events persist across close/reopen on the same file", () => {
    const path = join(tempDir(), "journal.db");
    const first = new SettleJournal(path);
    const b = binding();
    const start = startFor(b);
    first.recordRequestStarted(start);
    first.recordResponseObserved(start, 200, "{}", `{"success":true}`);
    first.close();
    const second = new SettleJournal(path);
    const events = second.listEvents();
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "response_observed",
    ]);
    // The reopened journal still refuses a duplicate start.
    expect(() => second.recordRequestStarted(start)).toThrow(ServiceRefusal);
    second.close();
  });
});

describe("pipeline: exactly one journaled start+success pair, ever", () => {
  it("idempotent retry re-serves the stored response without a second journaled call", async () => {
    const h = makeDeps();
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const fetchSpy = vi.fn(async (url: unknown) => {
      const path = new URL(String(url)).pathname;
      if (path === "/verify") {
        return jsonResponse(JSON.stringify({ isValid: true }));
      }
      return jsonResponse(
        JSON.stringify({ success: true, transaction: TX, network: h.config.network }),
      );
    });
    vi.stubGlobal("fetch", fetchSpy);
    h.deps.facilitator = transport(journal);

    const made = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(made.payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(made.payment, TX));

    const first = await runSettle(made.request, h.deps);
    expect(first.success).toBe(true);
    // Retry of the identical request: stored response, ZERO new upstream
    // calls, ZERO new journal rows — reconcile/retry paths never append.
    const second = await runSettle(made.request, h.deps);
    expect(second.success).toBe(true);
    const settleFetches = fetchSpy.mock.calls.filter(
      (call) => new URL(String(call[0])).pathname === "/settle",
    );
    expect(settleFetches).toHaveLength(1);
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "response_observed",
    ]);
    // The journal row is bound to the fulfillment identity the ledger holds.
    expect(events[0]?.signedPaymentPayloadHash).toBe(
      made.payment.signedPaymentPayloadHashHex,
    );
    expect(events[0]?.network).toBe(h.config.network);
    journal.close();
  });
});
