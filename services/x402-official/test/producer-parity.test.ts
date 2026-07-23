/**
 * Producer/release-adapter parity at the credentialed facilitator boundary.
 *
 * These tests intentionally exercise the real SQLite implementations and the
 * real HTTP transport with a stubbed fetch. Nothing reaches the network.
 */

import DatabaseConstructor from "better-sqlite3";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  FROZEN_FACILITATOR_ORIGIN,
  HttpFacilitatorTransport,
} from "../src/facilitator.js";
import { FulfillmentLedger, type FulfillmentBinding } from "../src/ledger.js";
import * as journalModule from "../src/settle-journal.js";
import {
  SettleJournal,
  canonicalJsonBytes,
} from "../src/settle-journal.js";
import type { SettleCallBinding } from "../src/types.js";
import { tempDir } from "./helpers.js";

const TOKEN = "producer-parity-token";
const TX = "cc".repeat(32);

function settleBinding(): SettleCallBinding {
  return {
    network: "casper:casper-test",
    wcsprContract: "aa".repeat(32),
    signedPaymentPayloadHash: "bb".repeat(32),
    payerAccountHash: "cd".repeat(32),
    authorizationNonce: "ee".repeat(32),
    resourceId: "resource-alpha",
    actionId: "1f".repeat(32),
    envelopeHash: "2f".repeat(32),
  };
}

function fulfillmentBinding(): FulfillmentBinding {
  return {
    network: "casper:casper-test",
    signedPaymentPayloadHash: "bb".repeat(32),
    resourceId: "resource-alpha",
    actionId: "1f".repeat(32),
    envelopeHash: "2f".repeat(32),
    resourceUrlHash: "3f".repeat(32),
    reportHash: "4f".repeat(32),
    paymentRequirementsHash: "5f".repeat(32),
    payerAccountHash: "cd".repeat(32),
    payeeAccountHash: "ab".repeat(32),
    valueAtomic: "1000000000",
    validAfter: "2026-07-23T00:00:00.000Z",
    validBefore: "2026-07-23T00:10:00.000Z",
    authorizationNonce: "ee".repeat(32),
    publicKey: `01${"11".repeat(32)}`,
    signature: `01${"22".repeat(64)}`,
    wcsprContract: "aa".repeat(32),
  };
}

function tableNames(path: string): string[] {
  const db = new DatabaseConstructor(path, { readonly: true });
  const names = (
    db
      .prepare(
        `SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name`,
      )
      .all() as { name: string }[]
  ).map((row) => row.name);
  db.close();
  return names;
}

function transport(journal?: SettleJournal): HttpFacilitatorTransport {
  return new HttpFacilitatorTransport(
    FROZEN_FACILITATOR_ORIGIN,
    () => TOKEN,
    {
      timeoutMs: 2_000,
      maxResponseBytes: 4_096,
      ...(journal === undefined ? {} : { settleJournal: journal }),
    },
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("production storage separation", () => {
  it("derives a deterministic sibling journal DB and keeps both stores usable", () => {
    const derive = (
      journalModule as unknown as {
        deriveSettleJournalPath?: (ledgerPath: string) => string;
      }
    ).deriveSettleJournalPath;
    expect(derive).toBeTypeOf("function");
    if (derive === undefined) return;

    const ledgerPath = join(tempDir(), "fulfillment-ledger.sqlite3");
    const journalPath = derive(ledgerPath);
    expect(journalPath).not.toBe(ledgerPath);
    expect(journalPath).toBe(`${ledgerPath}.settle-journal.sqlite3`);

    const ledger = new FulfillmentLedger(ledgerPath);
    const journal = new SettleJournal(journalPath);

    expect(tableNames(ledgerPath)).toEqual([
      "service_state",
      "x402_fulfillments",
    ]);
    expect(tableNames(journalPath)).toEqual([
      "x402_upstream_settle_calls",
    ]);

    const claim = ledger.claim(fulfillmentBinding());
    expect(claim.outcome).toBe("new");
    expect(
      ledger.get(
        fulfillmentBinding().network,
        fulfillmentBinding().signedPaymentPayloadHash,
      )?.state,
    ).toBe("claimed");
    expect(journal.listEvents()).toEqual([]);

    journal.close();
    ledger.close();
  });

  it("production entrypoint constructs the journal from the derived sibling path", () => {
    const source = readFileSync(
      new URL("../src/index.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain(
      "new SettleJournal(deriveSettleJournalPath(config.ledgerPath))",
    );
  });
});

describe("one canonical JSON serializer for every POST", () => {
  it("recursively sorts object keys while preserving array order", () => {
    const value = {
      z: 3,
      nested: { z: 2, a: 1 },
      array: [{ z: 2, a: 1 }, 7, "x"],
      a: true,
    };
    const serialize = canonicalJsonBytes as unknown as (
      input: unknown,
    ) => Buffer;
    expect(serialize(value).toString("utf8")).toBe(
      '{"a":true,"array":[{"a":1,"z":2},7,"x"],"nested":{"a":1,"z":2},"z":3}',
    );
  });

  it("matches Python ensure_ascii bytes for BMP and astral Unicode", () => {
    const value = {
      "\ue000": "bmp",
      "😀": "astral",
      label: "Café Ω 😀",
      nested: {
        "😀": "rocket🚀",
        "é": "accent",
      },
    };

    expect(canonicalJsonBytes(value).toString("utf8")).toBe(
      '{"label":"Caf\\u00e9 \\u03a9 \\ud83d\\ude00",' +
        '"nested":{"\\u00e9":"accent","\\ud83d\\ude00":"rocket\\ud83d\\ude80"},' +
        '"\\ue000":"bmp","\\ud83d\\ude00":"astral"}',
    );
  });

  it("sends canonical recursive bytes for verify and byte-identical bytes for settle", async () => {
    const sent = new Map<string, Buffer>();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: unknown, init: RequestInit) => {
        const path = new URL(String(url)).pathname;
        sent.set(path, Buffer.from(init.body as Uint8Array));
        if (path === "/verify") {
          return new Response('{"isValid":true}', {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            success: true,
            transaction: TX,
            network: "casper:casper-test",
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        );
      }),
    );

    const verifyBody = {
      z: { z: 2, a: 1 },
      a: [{ z: 2, a: 1 }],
    };
    await transport().verify(verifyBody);
    expect(sent.get("/verify")?.toString("utf8")).toBe(
      '{"a":[{"a":1,"z":2}],"z":{"a":1,"z":2}}',
    );

    const journal = new SettleJournal(join(tempDir(), "journal.sqlite3"));
    const settleBody = {
      z: { z: 2, a: 1 },
      a: [{ z: 2, a: 1 }],
    };
    await transport(journal).settle(settleBody, settleBinding());
    const journaled = journal.listEvents()[0]?.requestBody;
    expect(sent.get("/settle")?.toString("utf8")).toBe(
      '{"a":[{"a":1,"z":2}],"z":{"a":1,"z":2}}',
    );
    expect(journaled?.equals(sent.get("/settle") as Buffer)).toBe(true);
    journal.close();
  });
});

describe("settle response header contract", () => {
  it("journals the exact noncanonical upstream response bytes before parsing", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.sqlite3"));
    const raw =
      `{"transaction":"${TX}","network":"casper:casper-test",` +
      '"success":true,"memo":"\\ud83d\\ude00"}';
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(raw, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await transport(journal).settle({ a: 1 }, settleBinding());

    const observed = journal.listEvents()[1];
    expect(observed?.responseBody?.equals(Buffer.from(raw, "utf8"))).toBe(
      true,
    );
    expect(observed?.responseBodySha256).toBe(
      journalModule.sha256Hex(Buffer.from(raw, "utf8")),
    );
    journal.close();
  });

  it("journals exactly the required JSON content-type and drops every other header", async () => {
    const journal = new SettleJournal(join(tempDir(), "journal.sqlite3"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            success: true,
            transaction: TX,
            network: "casper:casper-test",
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              "content-length": "123",
              date: "Thu, 23 Jul 2026 00:00:00 GMT",
              server: "upstream",
              "x-request-id": "request-id",
            },
          },
        ),
      ),
    );

    await transport(journal).settle({ a: 1 }, settleBinding());
    expect(
      journal
        .listEvents()[1]
        ?.responseHeadersCanonicalJson?.toString("utf8"),
    ).toBe('{"content-type":"application/json"}');
    journal.close();
  });

  it.each([
    ["missing", {}],
    ["wrong", { "content-type": "text/plain" }],
    ["parameters", { "content-type": "application/json; charset=utf-8" }],
  ])("fails closed when content-type is %s", async (_case, headers) => {
    const journal = new SettleJournal(join(tempDir(), "journal.sqlite3"));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          Buffer.from(
            JSON.stringify({
              success: true,
              transaction: TX,
              network: "casper:casper-test",
            }),
            "utf8",
          ),
          { status: 200, headers },
        ),
      ),
    );

    await expect(
      transport(journal).settle({ a: 1 }, settleBinding()),
    ).rejects.toMatchObject({ code: "malformed_facilitator_response" });
    expect(journal.listEvents().map((event) => event.eventType)).toEqual([
      "request_started",
      "request_failed",
    ]);
    expect(journal.listEvents()[1]?.failureCode).toBe(
      "response_content_type_invalid",
    );
    journal.close();
  });
});
