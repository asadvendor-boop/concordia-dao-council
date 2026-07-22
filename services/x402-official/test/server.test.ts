/**
 * HTTP surface: health (no secrets), supported, 402 PAYMENT-REQUIRED,
 * paid resource release with PAYMENT-SIGNATURE/PAYMENT-RESPONSE, endpoint
 * refusal shapes, raw-Authorization facilitator header discipline (loopback
 * stub — the real facilitator is never contacted), and secret hygiene.
 */

import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";

import { loadSecrets, ConfigError } from "../src/config.js";
import { HttpFacilitatorTransport } from "../src/facilitator.js";
import { createService } from "../src/server.js";
import {
  REPORT_BYTES,
  buildRegistryRecord,
  goodReadback,
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
    expect(body).toEqual({ status: "ok", settlement_state: "blocked_fail_closed" });
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
    h.chain.transactions.set(TX, goodReadback());
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
    const body = await response.json();
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

describe("facilitator transport security", () => {
  it("sends the raw token in Authorization (never Bearer) and never logs bodies of non-2xx", async () => {
    const seen: { authorization?: string }[] = [];
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
    const transport = new HttpFacilitatorTransport(base, () => token);

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
    const env = {
      X402_CSPR_CLOUD_TOKEN_FILE: writeTempSecret(dir, "cspr", "tok-cloud\n"),
      X402_GATEWAY_TOKEN_FILE: writeTempSecret(dir, "gw", "tok-gateway"),
      X402_SIGNER_FILE: writeTempSecret(dir, "signer", "pem-bytes"),
    };
    const secrets = loadSecrets(env);
    expect(secrets.csprCloudToken()).toBe("tok-cloud");
    expect(secrets.gatewayToken()).toBe("tok-gateway");
    expect(secrets.signerAvailable()).toBe(true);
  });

  it("fails startup when a configured secret file is unreadable", () => {
    expect(() =>
      loadSecrets({ X402_CSPR_CLOUD_TOKEN_FILE: "/nonexistent/path/token" }),
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
    const env = {
      X402_CSPR_CLOUD_TOKEN_FILE: writeTempSecret(dir, "cspr", secretValue),
    };
    loadSecrets(env);
    const h = makeDeps();
    const base = await listen(createService(h.deps));
    const response = await fetch(`${base}/health`);
    const text = await response.text();
    expect(text).not.toContain(secretValue);
  });
});
