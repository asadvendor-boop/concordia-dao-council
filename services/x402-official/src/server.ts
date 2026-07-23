/**
 * HTTP surface (§12): GET /health, GET /supported, GET /resource/:resourceId,
 * POST /verify, POST /settle. Emits PAYMENT-REQUIRED on 402 and accepts
 * PAYMENT-SIGNATURE; releases the protected report only from a finalized
 * fulfillment.
 *
 * Logging is sanitized by construction: one structured line per request with
 * method, route, status, and machine code only. No headers, bodies, tokens,
 * exception messages, or stack traces are ever logged.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { ServiceRefusal } from "./errors.js";
import { validateVerifySettleRequest } from "./validation.js";
import {
  buildPaymentRequired,
  buildPaymentRequirements,
  isSettlementReady,
  reportReleasableRow,
  runSettle,
  runVerify,
  type PipelineDeps,
} from "./pipeline.js";

const MAX_BODY_BYTES = 1_048_576;

export const PAYMENT_HEADERS = {
  required: "payment-required",
  signature: "payment-signature",
  response: "payment-response",
} as const;

export interface ThrottleOptions {
  limit: number;
  windowMs: number;
}

/** Frozen default throttle for the public /verify and /settle endpoints. */
export const DEFAULT_THROTTLE: ThrottleOptions = { limit: 120, windowMs: 60_000 };

/**
 * Minimal fixed-window per-client throttle for the public settlement surface.
 * Keyed by remote address + route; expired windows are pruned lazily so the map
 * cannot grow without bound.
 */
class FixedWindowThrottle {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();

  constructor(private readonly options: ThrottleOptions) {}

  allow(key: string, now: number): boolean {
    if (this.hits.size > 8192) {
      for (const [k, v] of this.hits) if (now >= v.resetAt) this.hits.delete(k);
    }
    const entry = this.hits.get(key);
    if (entry === undefined || now >= entry.resetAt) {
      this.hits.set(key, { count: 1, resetAt: now + this.options.windowMs });
      return true;
    }
    if (entry.count >= this.options.limit) return false;
    entry.count += 1;
    return true;
  }
}

function log(entry: Record<string, string | number>): void {
  // Only stable machine fields. Never free-form text from any request/error.
  console.log(JSON.stringify(entry));
}

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
  contentType = "application/json",
): void {
  const payload =
    Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": contentType,
    "content-length": String(payload.length),
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(payload);
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new ServiceRefusal(413, "request_too_large", "invalid_request");
    }
    chunks.push(buf);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ServiceRefusal(400, "invalid_json", "invalid_request");
  }
}

function refusalCode(error: unknown): { status: number; code: string } {
  if (error instanceof ServiceRefusal) {
    return { status: error.httpStatus, code: error.code };
  }
  return { status: 500, code: "internal_error" };
}

export function createService(
  deps: PipelineDeps,
  options: { throttle?: ThrottleOptions } = {},
): Server {
  const { config } = deps;
  const throttle = new FixedWindowThrottle(options.throttle ?? DEFAULT_THROTTLE);

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const clientKey = req.socket.remoteAddress ?? "unknown";
    let route = path;
    let status = 404;
    let code = "";
    try {
      if (method === "GET" && path === "/health") {
        route = "/health";
        // Liveness (always ok while responding) is reported separately from
        // settlement readiness, which is only green for a proven live gate
        // (§11, WP5-6). No secrets are ever included.
        status = 200;
        send(res, 200, {
          status: "ok",
          settlement_state: deps.ledger.getSettlementState(),
          settlement_ready: isSettlementReady(deps),
        });
        return;
      }
      if (method === "GET" && path === "/supported") {
        route = "/supported";
        status = 200;
        send(res, 200, {
          kinds: [{ x402Version: 2, scheme: "exact", network: config.network }],
          extensions: {},
          signers: [],
        });
        return;
      }
      if (method === "GET" && path.startsWith("/resource/")) {
        route = "/resource/:resourceId";
        const resourceId = path.slice("/resource/".length);
        const resource = config.resources.find((r) => r.id === resourceId);
        if (resource === undefined) {
          status = 404;
          code = "unknown_resource";
          send(res, 404, { error: "unknown_resource" });
          return;
        }
        const signatureHeader = req.headers[PAYMENT_HEADERS.signature];
        if (signatureHeader === undefined || Array.isArray(signatureHeader)) {
          const paymentRequired = buildPaymentRequired(resource, config);
          status = 402;
          code = "payment_required";
          send(res, 402, paymentRequired, {
            [PAYMENT_HEADERS.required]: Buffer.from(
              JSON.stringify(paymentRequired),
              "utf8",
            ).toString("base64"),
          });
          return;
        }
        let paymentPayload: unknown;
        try {
          paymentPayload = JSON.parse(
            Buffer.from(signatureHeader, "base64").toString("utf8"),
          );
        } catch {
          throw new ServiceRefusal(400, "invalid_payment_signature_header", "invalid_request");
        }
        const settleRequest = {
          x402Version: 2,
          paymentPayload,
          paymentRequirements: buildPaymentRequirements(resource, config),
        };
        // Validate first so the payload provably binds to THIS resource.
        const validated = validateVerifySettleRequest(settleRequest, config);
        if (validated.resource.id !== resource.id) {
          throw new ServiceRefusal(409, "cross_binding_rejected", "terminal_conflict");
        }
        const settleResponse = await runSettle(settleRequest, deps);
        if (settleResponse.success !== true) {
          status = 402;
          code = settleResponse.errorReason ?? "settlement_failed";
          send(res, 402, settleResponse);
          return;
        }
        const row = reportReleasableRow(
          deps,
          resource,
          validated.signedPaymentPayloadHashHex,
        );
        if (row === undefined) {
          // success:true without a finalized row must never release bytes.
          status = 500;
          code = "report_not_releasable";
          send(res, 500, { error: "report_not_releasable" });
          return;
        }
        status = 200;
        code = "report_released";
        send(
          res,
          200,
          resource.reportBytes,
          {
            [PAYMENT_HEADERS.response]: Buffer.from(
              JSON.stringify(settleResponse),
              "utf8",
            ).toString("base64"),
          },
          resource.mimeType,
        );
        return;
      }
      if (method === "POST" && path === "/verify") {
        route = "/verify";
        if (!throttle.allow(`verify:${clientKey}`, Date.now())) {
          status = 429;
          code = "rate_limited";
          send(res, 429, { isValid: false, invalidReason: "rate_limited" });
          return;
        }
        try {
          const body = await readJsonBody(req);
          const verifyResponse = await runVerify(body, deps);
          status = 200;
          code = verifyResponse.isValid ? "is_valid" : verifyResponse.invalidReason ?? "invalid";
          send(res, 200, verifyResponse);
        } catch (error) {
          const mapped = refusalCode(error);
          status = mapped.status;
          code = mapped.code;
          if (mapped.status === 500) throw error;
          send(res, mapped.status, { isValid: false, invalidReason: mapped.code });
        }
        return;
      }
      if (method === "POST" && path === "/settle") {
        route = "/settle";
        if (!throttle.allow(`settle:${clientKey}`, Date.now())) {
          status = 429;
          code = "rate_limited";
          send(res, 429, {
            success: false,
            errorReason: "rate_limited",
            transaction: "",
            network: config.network,
          });
          return;
        }
        try {
          const body = await readJsonBody(req);
          const settleResponse = await runSettle(body, deps);
          status = 200;
          code = settleResponse.success
            ? "settled"
            : settleResponse.errorReason ?? "not_settled";
          send(res, 200, settleResponse);
        } catch (error) {
          const mapped = refusalCode(error);
          status = mapped.status;
          code = mapped.code;
          if (mapped.status === 500) throw error;
          send(res, mapped.status, {
            success: false,
            errorReason: mapped.code,
            transaction: "",
            network: config.network,
          });
        }
        return;
      }
      status = 404;
      code = "not_found";
      send(res, 404, { error: "not_found" });
    } catch (error) {
      const mapped = refusalCode(error);
      status = mapped.status;
      code = mapped.code;
      if (!res.headersSent) {
        send(res, mapped.status, { error: mapped.code });
      } else {
        res.destroy();
      }
    } finally {
      log({ event: "request", method, route, status, code });
    }
  };

  return createHttpServer((req, res) => {
    void handler(req, res);
  });
}
