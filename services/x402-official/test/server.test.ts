/**
 * HTTP surface: health (no secrets), supported, 402 PAYMENT-REQUIRED,
 * paid resource release with PAYMENT-SIGNATURE/PAYMENT-RESPONSE, endpoint
 * refusal shapes, raw-Authorization facilitator header discipline (loopback
 * stub — the real facilitator is never contacted), and secret hygiene.
 */

import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import DatabaseConstructor from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";

import { loadSecrets, resolveSecrets, ConfigError } from "../src/config.js";
import { HttpFacilitatorTransport } from "../src/facilitator.js";
import { createService } from "../src/server.js";
import {
  REPORT_BYTES,
  buildRegistryRecord,
  generateSigner,
  readbackFor,
  makeDeps,
  makeSignedRequest,
  tempDir,
  writeTempSecret,
} from "./helpers.js";

const TX = "cc".repeat(32);
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
    servers.splice(0).map(
      (server) => new Promise((resolve) => server.close(resolve)),
    ),
  );
});

describe("service endpoints", () => {
  it("GET /health is minimal, reports the fail-closed state, and leaks no secrets", async () => {
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/health`);
    expect(response.status).toBe(200);
    const body = await response.json();
    // Liveness is green while responding; settlement readiness is NOT green in
    // the default fail-closed state (§11, WP5-6).
    expect(body).toEqual({
      status: "ok",
      settlement_state: "blocked_fail_closed",
      settlement_ready: false,
    });
  });

  it("GET /supported advertises exactly the frozen kind", async () => {
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/supported`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      kinds: [{ x402Version: 2, scheme: "exact", network: "casper:casper-test" }],
      extensions: {},
      signers: [],
    });
  });

  it("GET /resource/:id without payment: 402 with PAYMENT-REQUIRED header and exact requirements", async () => {
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/resource/finals-report-001`);
    expect(response.status).toBe(402);
    const header = response.headers.get("payment-required");
    expect(header).toBeTruthy();
    const decoded = JSON.parse(Buffer.from(header as string, "base64").toString("utf8"));
    const body = await response.json();
    expect(body).toEqual(decoded);
    expect(decoded.x402Version).toBe(2);
    expect(decoded.accepts).toHaveLength(1);
    expect(decoded.accepts[0]).toEqual({
      scheme: "exact",
      network: "casper:casper-test",
      asset: h.config.wcsprPackageHash,
      amount: "1000000000",
      payTo: `00${"ab".repeat(32)}`,
      maxTimeoutSeconds: 600,
      extra: { name: "Wrapped CSPR", version: "1", decimals: "9", symbol: "WCSPR" },
    });
    expect(decoded.resource).toEqual({
      url: "https://x402.concordiadao.xyz/resource/finals-report-001",
      description: "Concordia finals protected report",
      mimeType: "application/json",
    });
  });

  it("GET /resource/unknown: 404", async () => {
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/resource/nope`);
    expect(response.status).toBe(404);
  });

  it("paid flow: PAYMENT-SIGNATURE settles and releases the exact report; replay is idempotent", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const base = await listen(createService(h.deps));
    const paymentSignature = Buffer.from(
      JSON.stringify((request as Record<string, unknown>)["paymentPayload"]),
      "utf8",
    ).toString("base64");
    const response = await fetch(`${base}/resource/finals-report-001`, {
      headers: { "payment-signature": paymentSignature },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    const released = Buffer.from(await response.arrayBuffer());
    expect(released.equals(REPORT_BYTES)).toBe(true);
    const paymentResponse = JSON.parse(
      Buffer.from(
        response.headers.get("payment-response") as string,
        "base64",
      ).toString("utf8"),
    );
    expect(paymentResponse.success).toBe(true);
    expect(paymentResponse.transaction).toBe(TX);

    // Idempotent replay: same bytes, still exactly one settlement.
    const replay = await fetch(`${base}/resource/finals-report-001`, {
      headers: { "payment-signature": paymentSignature },
    });
    expect(replay.status).toBe(200);
    expect(Buffer.from(await replay.arrayBuffer()).equals(REPORT_BYTES)).toBe(true);
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("resource payment that fails settlement releases nothing", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.facilitator.settleResponse = {
      success: false,
      errorReason: "denied",
      transaction: "",
      network: h.config.network,
    };
    const base = await listen(createService(h.deps));
    const paymentSignature = Buffer.from(
      JSON.stringify((request as Record<string, unknown>)["paymentPayload"]),
      "utf8",
    ).toString("base64");
    const response = await fetch(`${base}/resource/finals-report-001`, {
      headers: { "payment-signature": paymentSignature },
    });
    expect(response.status).toBe(402);
    const body = (await response.json()) as { success: boolean };
    expect(body.success).toBe(false);
    expect(Buffer.from(JSON.stringify(body)).equals(REPORT_BYTES)).toBe(false);
  });

  it("POST /verify: ungoverned yields isValid:false ungoverned_payload with zero facilitator calls", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      isValid: false,
      invalidReason: "ungoverned_payload",
    });
    expect(h.facilitator.verifyCalls).toHaveLength(0);
  });

  it("POST /settle: ambiguous binding is a terminal 409 settle-shaped refusal", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "ambiguous" };
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      success: false,
      errorReason: "ambiguous_governance_binding",
      transaction: "",
      network: "casper:casper-test",
    });
  });

  it("POST /verify with malformed JSON: 400 without echoing input", async () => {
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/verify`, {
      method: "POST",
      body: "{not json",
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      isValid: false,
      invalidReason: "invalid_json",
    });
  });
});

/**
 * Reviewer finding (exact-commit audit of f550c93): the protected resource
 * route could return HTTP 200 with a JSON error body when runSettle() threw a
 * protocol-shaped ServiceRefusal(200) refusal (ungoverned payload, upgrade
 * drift, …) — an x402 client observed a successful status without paid bytes
 * or a PAYMENT-RESPONSE header. These tests pin the transport invariant: a
 * 2xx from /resource/:resourceId is possible ONLY when the exact protected
 * report bytes are released from a finalized, integrity-verified fulfillment
 * row (true success and the exact idempotent retry). Every non-release
 * outcome is non-2xx with no protected bytes, no PAYMENT-RESPONSE header,
 * and no report_released audit code.
 */
describe("protected resource transport invariant (no 2xx without released bytes)", () => {
  const TAMPERED_DIGEST = "11".repeat(32);

  function paymentSignatureFor(request: Record<string, unknown>): string {
    return Buffer.from(
      JSON.stringify(request["paymentPayload"]),
      "utf8",
    ).toString("base64");
  }

  function fetchResource(base: string, request: Record<string, unknown>): Promise<Response> {
    return fetch(`${base}/resource/finals-report-001`, {
      headers: { "payment-signature": paymentSignatureFor(request) },
    });
  }

  /** Non-release refusals must carry no bytes, no header, no release audit code. */
  async function assertNoRelease(
    response: Response,
    logSpy: { mock: { calls: unknown[][] } },
  ): Promise<Record<string, unknown>> {
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers.get("payment-response")).toBeNull();
    const body = Buffer.from(await response.arrayBuffer());
    expect(body.includes(REPORT_BYTES)).toBe(false);
    const logged = logSpy.mock.calls.flat().map(String).join("\n");
    expect(logged).not.toContain("report_released");
    return JSON.parse(body.toString("utf8")) as Record<string, unknown>;
  }

  it("ungoverned payload: 402 (never the protocol-shaped 200), no bytes, no PAYMENT-RESPONSE, no release audit code", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetchResource(base, request);
    expect(response.status).toBe(402);
    const body = await assertNoRelease(response, logSpy);
    expect(body).toEqual({ error: "ungoverned_payload" });
    expect(h.facilitator.settleCalls).toHaveLength(0);
  });

  it("package upgrade drift: 402 blocked_upgrade_drift, no bytes, no PAYMENT-RESPONSE", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    // The package now enables a different version: every settlement gate drifts.
    h.chain.packageStates = [
      {
        lockStatus: "Unlocked",
        enabledVersion: h.config.wcsprContractVersion + 1,
        enabledContractHash: h.config.wcsprContractHash,
      },
    ];
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetchResource(base, request);
    expect(response.status).toBe(402);
    const body = await assertNoRelease(response, logSpy);
    expect(body).toEqual({ error: "blocked_upgrade_drift" });
    expect(h.facilitator.settleCalls).toHaveLength(0);
  });

  it("post-settle readback mismatch: 402 settle-shaped failure, no bytes, no PAYMENT-RESPONSE", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    // Settlement succeeds but the finalized deploy reads back a different
    // entry point: terminal post_settle_readback_failed, never a release.
    h.chain.transactions.set(TX, readbackFor(payment, TX, { entryPoint: "transfer" }));
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetchResource(base, request);
    expect(response.status).toBe(402);
    const body = await assertNoRelease(response, logSpy);
    expect(body["success"]).toBe(false);
    expect(body["errorReason"]).toBe("post_settle_readback_failed");
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("finalized execution failure: 402 settlement_execution_failed, no bytes, no PAYMENT-RESPONSE", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(payment, TX, { executionSuccess: false }));
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetchResource(base, request);
    expect(response.status).toBe(402);
    const body = await assertNoRelease(response, logSpy);
    expect(body["success"]).toBe(false);
    expect(body["errorReason"]).toBe("settlement_execution_failed");
  });

  it("pending finality: 503 reconciliation_pending (retryable), no bytes, no PAYMENT-RESPONSE", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(payment, TX, { finalized: false }));
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetchResource(base, request);
    expect(response.status).toBe(503);
    const body = await assertNoRelease(response, logSpy);
    expect(body).toEqual({ error: "reconciliation_pending" });
  });

  it("terminal binding conflict (authorization nonce reuse): 409, no bytes, no PAYMENT-RESPONSE", async () => {
    const h = makeDeps();
    const signer = await generateSigner();
    const nonceHex = "77".repeat(32);
    const a = await makeSignedRequest(h.config, { nonceHex }, signer);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(a.payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(a.payment, TX));
    const base = await listen(createService(h.deps));
    const first = await fetchResource(base, a.request);
    expect(first.status).toBe(200);

    // A DIFFERENT signed payload reusing the same authorization nonce.
    const now = Math.floor(Date.now() / 1000);
    const b = await makeSignedRequest(
      h.config,
      { nonceHex, validAfter: now - 1200 },
      signer,
    );
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(b.payment, h.config),
    };
    const logSpy = vi.spyOn(console, "log");
    const second = await fetchResource(base, b.request);
    expect(second.status).toBe(409);
    const body = await assertNoRelease(second, logSpy);
    expect(body).toEqual({ error: "authorization_nonce_reused" });
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("ledger-integrity failure on replay: 500, no bytes, no PAYMENT-RESPONSE, no second settlement", async () => {
    const dir = tempDir();
    const path = join(dir, "x402-official.db");
    const h = makeDeps({}, path);
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const base = await listen(createService(h.deps));
    const first = await fetchResource(base, request);
    expect(first.status).toBe(200);

    // Tamper the durable row's response digest via an independent connection.
    const db = new DatabaseConstructor(path);
    db.prepare(
      `UPDATE x402_fulfillments SET settlement_response_hash = ?
       WHERE signed_payment_payload_hash = ?`,
    ).run(TAMPERED_DIGEST, payment.signedPaymentPayloadHashHex);
    db.close();

    const logSpy = vi.spyOn(console, "log");
    const replay = await fetchResource(base, request);
    expect(replay.status).toBe(500);
    const body = await assertNoRelease(replay, logSpy);
    expect(body).toEqual({ error: "ledger_terminal_invariant_violated" });
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("positive control: true success is 200 with the exact bytes, a valid PAYMENT-RESPONSE, and the report_released audit code", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const logSpy = vi.spyOn(console, "log");
    const base = await listen(createService(h.deps));
    const response = await fetchResource(base, request);
    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer()).equals(REPORT_BYTES)).toBe(true);
    const paymentResponse = JSON.parse(
      Buffer.from(
        response.headers.get("payment-response") as string,
        "base64",
      ).toString("utf8"),
    ) as Record<string, unknown>;
    expect(paymentResponse["success"]).toBe(true);
    expect(paymentResponse["transaction"]).toBe(TX);
    const logged = logSpy.mock.calls.flat().map(String).join("\n");
    expect(logged).toContain('"code":"report_released"');
  });

  it("positive control: exact idempotent retry is 200 with the same bytes and PAYMENT-RESPONSE, without a second settlement", async () => {
    const h = makeDeps();
    const { request, payment } = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(payment, TX));
    const base = await listen(createService(h.deps));
    expect((await fetchResource(base, request)).status).toBe(200);

    const replay = await fetchResource(base, request);
    expect(replay.status).toBe(200);
    expect(Buffer.from(await replay.arrayBuffer()).equals(REPORT_BYTES)).toBe(true);
    const paymentResponse = JSON.parse(
      Buffer.from(
        replay.headers.get("payment-response") as string,
        "base64",
      ).toString("utf8"),
    ) as Record<string, unknown>;
    expect(paymentResponse["success"]).toBe(true);
    expect(paymentResponse["transaction"]).toBe(TX);
    expect(h.facilitator.settleCalls).toHaveLength(1);
  });

  it("paid resource attempts share the settlement throttle: 429 beyond the limit, discovery 402 stays available", async () => {
    const h = makeDeps();
    const a = await makeSignedRequest(h.config);
    h.registry.result = {
      outcome: "found",
      record: buildRegistryRecord(a.payment, h.config),
    };
    h.chain.transactions.set(TX, readbackFor(a.payment, TX));
    const base = await listen(
      createService(h.deps, { throttle: { limit: 1, windowMs: 60_000 } }),
    );
    expect((await fetchResource(base, a.request)).status).toBe(200);

    const b = await makeSignedRequest(h.config);
    const logSpy = vi.spyOn(console, "log");
    const limited = await fetchResource(base, b.request);
    expect(limited.status).toBe(429);
    const body = await assertNoRelease(limited, logSpy);
    expect(body).toEqual({ error: "rate_limited" });
    // The throttle refused BEFORE the settlement pipeline: still one settle.
    expect(h.facilitator.settleCalls).toHaveLength(1);

    // The same per-client settlement budget also guards POST /settle.
    const viaSettle = await fetch(`${base}/settle`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(b.request),
    });
    expect(viaSettle.status).toBe(429);

    // Unpaid discovery (402 + PAYMENT-REQUIRED) never consumes settlement budget.
    const discovery = await fetch(`${base}/resource/finals-report-001`);
    expect(discovery.status).toBe(402);
    expect(discovery.headers.get("payment-required")).toBeTruthy();
  });
});

describe("public endpoint throttling (WP5 hardening)", () => {
  it("throttles /verify beyond the configured window limit with an endpoint-shaped 429", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const base = await listen(
      createService(h.deps, { throttle: { limit: 2, windowMs: 60_000 } }),
    );
    const send = () =>
      fetch(`${base}/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
    expect((await send()).status).toBe(200);
    expect((await send()).status).toBe(200);
    const limited = await send();
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ isValid: false, invalidReason: "rate_limited" });
  });

  it("throttles /settle beyond the limit with a settle-shaped 429", async () => {
    const h = makeDeps();
    const { request } = await makeSignedRequest(h.config);
    h.registry.result = { outcome: "not_found" };
    const base = await listen(
      createService(h.deps, { throttle: { limit: 1, windowMs: 60_000 } }),
    );
    const send = () =>
      fetch(`${base}/settle`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
    expect((await send()).status).toBe(200);
    const limited = await send();
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({
      success: false,
      errorReason: "rate_limited",
      transaction: "",
      network: "casper:casper-test",
    });
  });
});

describe("facilitator transport security", () => {
  it("sends the raw token in Authorization (never Bearer) and never logs bodies of non-2xx", async () => {
    const seen: { authorization: string | undefined }[] = [];
    const stub = createHttpServer((req, res) => {
      seen.push({ authorization: req.headers.authorization });
      if (req.url === "/verify") {
        // Reflect the credential the way the real 401 does — it must never
        // surface anywhere.
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: req.headers.authorization }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ kinds: [], extensions: {}, signers: [] }));
    });
    const base = await listen(stub);
    const token = "dummy-cspr-cloud-token-do-not-log";
    // Loopback stub for header-byte discipline: explicit test-only origin.
    const transport = new HttpFacilitatorTransport(base, () => token, {
      allowUnfrozenOriginForTest: true,
    });

    const logSpy = vi.spyOn(console, "log");
    const errorSpy = vi.spyOn(console, "error");

    await transport.supported();
    expect(seen[0]?.authorization).toBe(token); // raw — no "Bearer " prefix

    let thrown: unknown;
    try {
      await transport.verify({ x402Version: 2 });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeDefined();
    const message = (thrown as Error).message;
    expect(message).toBe("facilitator_http_401");
    expect(message).not.toContain(token);

    const allLogged = [...logSpy.mock.calls, ...errorSpy.mock.calls]
      .flat()
      .map(String)
      .join("\n");
    expect(allLogged).not.toContain(token);
  });
});

describe("secret loading (§12 *_FILE discipline)", () => {
  it("loads secrets from files and never from value-bearing variables", () => {
    const dir = tempDir();
    // Injected test constructor: arbitrary paths, never production env parsing.
    const secrets = resolveSecrets({
      csprCloudTokenFile: writeTempSecret(dir, "cspr", "tok-cloud\n"),
      gatewayTokenFile: writeTempSecret(dir, "gw", "tok-gateway"),
      signerFile: writeTempSecret(dir, "signer", "pem-bytes"),
    });
    expect(secrets.csprCloudToken()).toBe("tok-cloud");
    expect(secrets.gatewayToken()).toBe("tok-gateway");
    expect(secrets.signerAvailable()).toBe(true);
  });

  it("fails startup when a configured secret file is unreadable", () => {
    expect(() =>
      resolveSecrets({ csprCloudTokenFile: "/nonexistent/path/token" }),
    ).toThrow(ConfigError);
  });

  it("production loadSecrets REJECTS a redirected secret-file path (WP5-4)", () => {
    const dir = tempDir();
    // A non-frozen path — even a readable one — must be rejected outright so a
    // hostile env can never redirect where a credential is read from.
    expect(() =>
      loadSecrets({
        X402_CSPR_CLOUD_TOKEN_FILE: writeTempSecret(dir, "evil", "tok"),
      }),
    ).toThrow(ConfigError);
  });

  it("unconfigured secrets refuse at call time (fail closed), not at startup", () => {
    const secrets = loadSecrets({});
    expect(secrets.signerAvailable()).toBe(false);
    expect(() => secrets.csprCloudToken()).toThrow();
    expect(() => secrets.gatewayToken()).toThrow();
  });

  it("health output never contains configured secret values", async () => {
    const dir = tempDir();
    const secretValue = "super-secret-token-value-1234";
    resolveSecrets({ csprCloudTokenFile: writeTempSecret(dir, "cspr", secretValue) });
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/health`);
    const text = await response.text();
    expect(text).not.toContain(secretValue);
  });
});
