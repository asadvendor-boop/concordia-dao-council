/**
 * Output-hygiene wording invariants (WP5 hardening). Untrusted upstream reason
 * strings are never echoed in a response body or a log line; every stable
 * refusal code conforms to a bounded lowercase grammar; and the source tree
 * contains no raw NUL bytes (Git must treat every file as text).
 */

import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { REFUSAL_CODES } from "../src/errors.js";
import { createService } from "../src/server.js";
import {
  buildRegistryRecord,
  makeDeps,
  makeSignedRequest,
} from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
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

const CODE_GRAMMAR = /^[a-z][a-z0-9_]{0,63}$/;

describe("stable refusal-code grammar", () => {
  it("every REFUSAL_CODES value is a bounded lowercase snake_case token", () => {
    for (const code of Object.values(REFUSAL_CODES)) {
      expect(code).toMatch(CODE_GRAMMAR);
    }
  });
});

describe("untrusted upstream text is never surfaced", () => {
  it("a hostile facilitator errorReason is mapped, never echoed in body or log", async () => {
    const hostile = "TOKEN=sk_live_51xLeakedCredential <script>alert(1)</script>";
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.facilitator.settleResponse = {
      success: false,
      errorReason: hostile,
      transaction: "",
      network: h.config.network,
    };
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const text = await response.text();
    expect(text).not.toContain("sk_live");
    expect(text).not.toContain("<script>");
    expect(JSON.parse(text).errorReason).toBe("facilitator_settlement_declined");
    const logged = logSpy.mock.calls.flat().map(String).join("\n");
    expect(logged).not.toContain("sk_live");
    expect(logged).not.toContain("<script>");
  });
});

describe("source tree is text-safe", () => {
  it("no test source file contains a raw NUL byte", () => {
    for (const entry of readdirSync(here)) {
      if (!entry.endsWith(".ts")) continue;
      const bytes = readFileSync(join(here, entry));
      expect(bytes.includes(0), `${entry} contains a NUL byte`).toBe(false);
    }
  });

  it("no service source file contains a raw NUL byte", () => {
    const srcDir = join(here, "..", "src");
    for (const entry of readdirSync(srcDir)) {
      if (!entry.endsWith(".ts")) continue;
      const bytes = readFileSync(join(srcDir, entry));
      expect(bytes.includes(0), `${entry} contains a NUL byte`).toBe(false);
    }
  });
});
