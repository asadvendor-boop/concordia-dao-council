/**
 * Durable upstream-settle journal, validated against the FROZEN release
 * contract (`UPSTREAM_SETTLE_JOURNAL_MIGRATION` in
 * `tests/test_release_official_x402_adapter.py`): exact migration bytes,
 * exact SQLite object names, start-before-network with byte-identical
 * sent/journaled request bytes, response bytes journaled before parsing,
 * status-200-only success, header/body-free bounded failures, NULL request
 * fields on every terminal row, append-only schema, and call-ID parity
 * with the frozen Python derivation.
 */

import DatabaseConstructor from "better-sqlite3";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  FROZEN_FACILITATOR_ORIGIN,
  HttpFacilitatorTransport,
} from "../src/facilitator.js";
import { ServiceRefusal } from "../src/errors.js";
import { runSettle } from "../src/pipeline.js";
import {
  JOURNALED_REQUEST_HEADERS,
  SETTLE_CALL_DOMAIN,
  SettleJournal,
  canonicalJsonBytes,
  migrationFilePath,
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

const TOKEN = "supersecret-cspr-cloud-token-value";
const TX = "cc".repeat(32);
const SETTLE_URL = `${FROZEN_FACILITATOR_ORIGIN}/settle`;

// Frozen values from tests/test_release_official_x402_adapter.py.
const FROZEN_MIGRATION_LENGTH = 5206;
const FROZEN_MIGRATION_SHA256 =
  "c660abcce78e05edfebb475661dd8ee636a699e822956ac05a990cbe1fb51c5f";
// sha256(b"CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\0" + bytes.fromhex("bb"*64)
//        + bytes.fromhex("ee"*64)) — computed with the frozen Python formula.
const FROZEN_CALL_ID_VECTOR =
  "05f10a9c738a161b6e7e15fd4b955ba93ac462e7f9dcd89a8d67cb8cd1c729dc";

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
  const bytes = Buffer.from(body, "utf8");
  return {
    callId: settleCallId(b),
    binding: b,
    requestMethod: "POST",
    requestUrl: SETTLE_URL,
    requestBody: bytes,
    requestBodySha256: sha256Hex(bytes),
  };
}

function transport(journal: SettleJournal): HttpFacilitatorTransport {
  // The frozen production origin — every fetch is stubbed, nothing leaves
  // the process; the frozen schema pins the journaled URL to this origin.
  return new HttpFacilitatorTransport(FROZEN_FACILITATOR_ORIGIN, () => TOKEN, {
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

/** Every string and decoded blob in the journal, for no-secret scans. */
function journalDump(journal: SettleJournal): string {
  return journal
    .listEvents()
    .map((e) =>
      [
        e.eventType,
        e.requestMethod ?? "",
        e.requestUrl ?? "",
        e.requestHeadersCanonicalJson?.toString("utf8") ?? "",
        e.requestBody?.toString("utf8") ?? "",
        e.responseHeadersCanonicalJson?.toString("utf8") ?? "",
        e.responseBody?.toString("utf8") ?? "",
        e.failureCode ?? "",
      ].join("\n"),
    )
    .join("\n");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("frozen contract", () => {
  it("the repository migration is byte-for-byte the frozen release migration", () => {
    const bytes = readFileSync(migrationFilePath());
    expect(bytes.byteLength).toBe(FROZEN_MIGRATION_LENGTH);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      FROZEN_MIGRATION_SHA256,
    );
  });

  it("creates exactly the frozen SQLite object names and types", () => {
    const path = join(tempDir(), "journal.db");
    new SettleJournal(path).close();
    const raw = new DatabaseConstructor(path);
    const objects = raw
      .prepare(
        `SELECT type, name FROM sqlite_master
         WHERE name LIKE 'x402_upstream_settle_calls%' ORDER BY name`,
      )
      .all() as { type: string; name: string }[];
    raw.close();
    expect(objects).toEqual([
      { type: "table", name: "x402_upstream_settle_calls" },
      { type: "index", name: "x402_upstream_settle_calls_authorization_once" },
      { type: "trigger", name: "x402_upstream_settle_calls_no_delete" },
      { type: "trigger", name: "x402_upstream_settle_calls_no_update" },
      { type: "index", name: "x402_upstream_settle_calls_one_start" },
      { type: "index", name: "x402_upstream_settle_calls_one_terminal" },
      { type: "index", name: "x402_upstream_settle_calls_payload_once" },
      { type: "trigger", name: "x402_upstream_settle_calls_terminal_binding" },
    ]);
  });

  it("call_id matches the frozen Python derivation exactly", () => {
    expect(SETTLE_CALL_DOMAIN).toBe("CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\0");
    // binding() uses payload bb×32 and nonce ee×32 — the vector's inputs.
    expect(settleCallId(binding())).toBe(FROZEN_CALL_ID_VECTOR);
    // Only the payload hash and nonce feed the id; a resource change does
    // not alter it, a nonce change does.
    expect(settleCallId(binding({ resourceId: "resource-beta" }))).toBe(
      FROZEN_CALL_ID_VECTOR,
    );
    expect(
      settleCallId(binding({ authorizationNonce: "0e".repeat(32) })),
    ).not.toBe(FROZEN_CALL_ID_VECTOR);
  });
});

describe("schema: append-only and unique identities", () => {
  it("UPDATE and DELETE always abort", () => {
    const path = join(tempDir(), "journal.db");
    const journal = new SettleJournal(path);
    journal.recordRequestStarted(startFor(binding()));
    journal.close();
    const raw = new DatabaseConstructor(path);
    expect(() =>
      raw.prepare(`UPDATE x402_upstream_settle_calls SET network = network`).run(),
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
    expect(() => journal.recordRequestStarted(startFor(b))).toThrow(
      ServiceRefusal,
    );
    // Same payload identity, different authorization nonce (distinct call
    // id) still refuses via the payload-once index.
    expect(() =>
      journal.recordRequestStarted(
        startFor(binding({ authorizationNonce: "0e".repeat(32) })),
      ),
    ).toThrow(ServiceRefusal);
    // Same authorization identity, different payload hash refuses via the
    // authorization-once index.
    expect(() =>
      journal.recordRequestStarted(
        startFor(binding({ signedPaymentPayloadHash: "0b".repeat(32) })),
      ),
    ).toThrow(ServiceRefusal);
    expect(journal.listEvents()).toHaveLength(1);
    journal.close();
  });

  it("a terminal without a matching start (or with a drifted binding) aborts", () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const b = binding();
    const start = startFor(b);
    const headers = canonicalJsonBytes({ "content-type": "application/json" });
    const body = Buffer.from(`{"success":true}`, "utf8");
    expect(() =>
      journal.recordResponseObserved(start, 200, headers, body),
    ).toThrow(ServiceRefusal);
    journal.recordRequestStarted(start);
    const drifted: SettleCallStart = {
      ...start,
      binding: { ...b, envelopeHash: "3f".repeat(32) },
    };
    expect(() =>
      journal.recordResponseObserved(drifted, 200, headers, body),
    ).toThrow(ServiceRefusal);
    journal.recordResponseObserved(start, 200, headers, body);
    expect(() =>
      journal.recordResponseObserved(start, 200, headers, body),
    ).toThrow(ServiceRefusal);
    journal.close();
  });

  it("terminal rows carry NULL for every request field", () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const start = startFor(binding());
    journal.recordRequestStarted(start);
    journal.recordResponseObserved(
      start,
      200,
      canonicalJsonBytes({ "content-type": "application/json" }),
      Buffer.from(`{"success":true}`, "utf8"),
    );
    const other = startFor(binding({
      signedPaymentPayloadHash: "4b".repeat(32),
      authorizationNonce: "4e".repeat(32),
    }));
    journal.recordRequestStarted(other);
    journal.recordRequestFailed(other, 503, "facilitator_http_503");
    const terminals = journal
      .listEvents()
      .filter((e) => e.eventType !== "request_started");
    expect(terminals).toHaveLength(2);
    for (const t of terminals) {
      expect(t.requestMethod).toBeNull();
      expect(t.requestUrl).toBeNull();
      expect(t.requestHeadersCanonicalJson).toBeNull();
      expect(t.requestBody).toBeNull();
      expect(t.requestBodySha256).toBeNull();
    }
    journal.close();
  });

  it("the schema refuses a non-200 response_observed row outright", () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const start = startFor(binding());
    journal.recordRequestStarted(start);
    expect(() =>
      journal.recordResponseObserved(
        start,
        201,
        canonicalJsonBytes({}),
        Buffer.from("{}", "utf8"),
      ),
    ).toThrow(ServiceRefusal);
    journal.close();
  });
});

describe("transport: journal before network, exact bytes, no secrets", () => {
  it("journals the start durably BEFORE the fetch, with byte-identical sent bytes", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    let eventsAtFetchTime = -1;
    let sentBody: Buffer | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: unknown, init: RequestInit) => {
        eventsAtFetchTime = journal.listEvents().length;
        sentBody = Buffer.from(init.body as Uint8Array);
        return jsonResponse(
          JSON.stringify({ success: true, transaction: TX, network: binding().network }),
        );
      }),
    );
    const body = { x402Version: 2, paymentPayload: { p: 1 }, paymentRequirements: { r: 2 } };
    await transport(journal).settle(body, binding());
    expect(eventsAtFetchTime).toBe(1);
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "response_observed",
    ]);
    // Byte identity: journaled request bytes === sent bytes === the single
    // serialization of the request body.
    expect(events[0]?.requestBody?.equals(sentBody as Buffer)).toBe(true);
    expect(events[0]?.requestBody?.toString("utf8")).toBe(JSON.stringify(body));
    expect(events[0]?.requestBodySha256).toBe(
      sha256Hex(Buffer.from(JSON.stringify(body), "utf8")),
    );
    expect(events[0]?.requestUrl).toBe(SETTLE_URL);
    journal.close();
  });

  it("if the start append fails, the network is never called", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    const b = binding();
    journal.recordRequestStarted(startFor(b, `{"earlier":true}`));
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    await expect(transport(journal).settle({ second: true }, b)).rejects.toThrow(
      ServiceRefusal,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
    journal.close();
  });

  it("never journals the credential: constant request-header record, allowlisted response headers", async () => {
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
    const dump = journalDump(journal);
    expect(dump).not.toContain(TOKEN);
    expect(dump).not.toContain("set-cookie");
    expect(dump).not.toContain("authorization");
    const events = journal.listEvents();
    expect(
      events[0]?.requestHeadersCanonicalJson?.equals(JOURNALED_REQUEST_HEADERS),
    ).toBe(true);
    expect(events[0]?.requestHeadersCanonicalJson?.toString("utf8")).toBe(
      `{"content-type":"application/json"}`,
    );
    const responseHeaders = JSON.parse(
      events[1]?.responseHeadersCanonicalJson?.toString("utf8") ?? "{}",
    ) as Record<string, string>;
    expect(Object.keys(responseHeaders)).toEqual(["content-type"]);
    journal.close();
  });

  it("journals the raw response bytes BEFORE parsing: unparseable 200 bytes are preserved", async () => {
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
    expect(events[1]?.responseBody?.toString("utf8")).toBe(rawBytes);
    expect(events[1]?.responseBodySha256).toBe(
      sha256Hex(Buffer.from(rawBytes, "utf8")),
    );
    expect(events[1]?.responseStatus).toBe(200);
    journal.close();
  });

  it("bounded failure on 4xx: status + code only, NEVER headers or body", async () => {
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
    expect(events[1]?.responseHeadersCanonicalJson).toBeNull();
    expect(events[1]?.responseBody).toBeNull();
    expect(events[1]?.responseBodySha256).toBeNull();
    expect(events[1]?.failureCode).toBe("facilitator_http_401");
    expect(journalDump(journal)).not.toContain(TOKEN);
    journal.close();
  });

  it("a 2xx status other than exactly 200 fails closed without reading the body", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.db"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(`should-never-be-stored ${TOKEN}`, 201)),
    );
    await expect(transport(journal).settle({ a: 1 }, binding())).rejects.toThrow(
      ServiceRefusal,
    );
    const events = journal.listEvents();
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "request_failed",
    ]);
    // 201 is outside the frozen 4xx/5xx failure-status range → NULL status.
    expect(events[1]?.responseStatus).toBeNull();
    expect(events[1]?.responseBody).toBeNull();
    expect(events[1]?.failureCode).toBe("unexpected_success_status");
    expect(journalDump(journal)).not.toContain(TOKEN);
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
    expect(events[1]?.responseHeadersCanonicalJson).toBeNull();
    expect(events[1]?.responseBody).toBeNull();
    expect(events[1]?.failureCode).toBe("facilitator_unreachable");
    journal.close();
  });

  it("survives restart: events persist across close/reopen on the same file", () => {
    const path = join(tempDir(), "journal.db");
    const first = new SettleJournal(path);
    const start = startFor(binding());
    first.recordRequestStarted(start);
    first.recordResponseObserved(
      start,
      200,
      canonicalJsonBytes({ "content-type": "application/json" }),
      Buffer.from(`{"success":true}`, "utf8"),
    );
    first.close();
    const second = new SettleJournal(path);
    const events = second.listEvents();
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.eventType)).toEqual([
      "request_started",
      "response_observed",
    ]);
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
    expect(events[0]?.signedPaymentPayloadHash).toBe(
      made.payment.signedPaymentPayloadHashHex,
    );
    expect(events[0]?.network).toBe(h.config.network);
    journal.close();
  });
});
