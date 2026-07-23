/**
 * HTTP surface (§12): GET /health, GET /supported, GET /resource/:resourceId,
 * POST /verify, POST /settle. Emits PAYMENT-REQUIRED on 402 and accepts
 * PAYMENT-SIGNATURE; releases the protected report only from a finalized
 * fulfillment.
 *
 * Transport invariant (WP5 re-review): /verify and /settle keep the frozen
 * x402 wire contract (protocol-shaped 200 refusal bodies), but the protected
 * resource route can emit a 2xx ONLY when the exact report bytes are released
 * from a finalized, integrity-verified fulfillment row with the
 * PAYMENT-RESPONSE header; every non-release outcome is mapped to a non-2xx
 * status (402/409/429/503/500) and paid attempts draw from the same
 * settlement throttle as POST /settle. Throttle identity is the trusted
 * Caddy-set X-Concordia-Client-IP header (socket-peer fallback for direct
 * internal/test access) — see trustedClientIdentity for the WP5 merge-blocker
 * rationale — and the throttle key map is strictly bounded with eviction.
 *
 * Logging is sanitized by construction: one structured line per request with
 * method, route, status, and machine code only. No headers, bodies, tokens,
 * exception messages, or stack traces are ever logged.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";

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

/** Hard cap on distinct throttle keys tracked in memory (WP5 merge blocker). */
export const DEFAULT_MAX_TRACKED_KEYS = 10_000;

/**
 * Trusted client-identity header (G1 §12 — the same convention the SafePay
 * provider uses): Caddy STRIPS any caller-supplied `X-Concordia-Client-IP` on
 * the x402 vhost and overwrites it with the real remote peer. Behind Caddy the
 * socket peer is always the Caddy container, so this header — never the socket
 * address — is the client identity. The service accepts it ONLY because it is
 * never host-exposed: it sits behind Caddy on the internal network, and direct
 * access is internal/test-only.
 */
export const CLIENT_IP_HEADER = "x-concordia-client-ip";

/** Longest well-formed textual IP token (IPv4-mapped IPv6 with full IPv4 tail). */
const MAX_IP_TOKEN_LENGTH = 45;

/** Parse a single plausible textual IP token; undefined for anything else. */
function normalizeIpToken(value: string): string | undefined {
  if (value.length === 0 || value.length > MAX_IP_TOKEN_LENGTH) return undefined;
  if (isIP(value) === 0) return undefined;
  const lower = value.toLowerCase();
  // Collapse IPv4-mapped IPv6 so header-supplied and socket-observed forms of
  // the same peer always share one identity (G1 §12 convention).
  if (lower.startsWith("::ffff:") && isIP(lower.slice(7)) === 4) {
    return lower.slice(7);
  }
  return lower;
}

/**
 * Resolve the throttle identity for a request (reviewer finding, WP5 merge
 * blocker): keying by `req.socket.remoteAddress` behind Caddy collapsed every
 * external client into the single Caddy container address, letting one
 * attacker exhaust the shared quota (client A at the limit made a DISTINCT
 * client B receive 429).
 *
 * Precedence: a present, well-formed `X-Concordia-Client-IP` IS the client
 * identity — trustworthy only because Caddy strips and overwrites it with the
 * real remote peer before it can reach this service (a caller-supplied spoof
 * never survives the proxy). If the header is absent (direct internal/test
 * access), the socket peer is the identity. Defense in depth: the header must
 * be a single plausible IP token — exactly one value that parses as one
 * IPv4/IPv6 address (no lists, no ports, no garbage); anything else falls
 * back to the socket peer instead of being trusted.
 */
export function trustedClientIdentity(req: IncomingMessage): string {
  const rawSocket = req.socket.remoteAddress ?? "unknown";
  const socketIdentity = normalizeIpToken(rawSocket) ?? rawSocket;
  const raw = req.headers[CLIENT_IP_HEADER];
  // A repeated header arrives joined (or as an array) and fails IP parsing.
  if (typeof raw !== "string") return socketIdentity;
  return normalizeIpToken(raw.trim()) ?? socketIdentity;
}

interface WindowEntry {
  count: number;
  resetAt: number;
}

/**
 * Minimal fixed-window per-client throttle for the public settlement surface,
 * keyed by trusted client identity + route class. The key map is STRICTLY
 * BOUNDED: at most `maxTrackedKeys` windows are ever tracked, so an attacker
 * cycling identities cannot grow it without bound. When the map is full and a
 * new identity arrives, expired windows are evicted first; only if every
 * tracked window is still live is the OLDEST live window evicted.
 *
 * Trade-off, stated honestly: evicting a live window forgets that key's spent
 * budget, so a key that was at its limit could obtain a fresh window early.
 * That is reachable only when more than `maxTrackedKeys` distinct identities
 * appear inside one window — where the alternative (an unbounded map) is
 * memory exhaustion, a strictly worse failure. Expired-first eviction plus
 * oldest-window-first ordering evicts the window closest to expiring anyway,
 * so the extra budget granted is minimal and recently-limited keys with
 * fresher windows are preserved whenever possible.
 */
export class FixedWindowThrottle {
  /** Insertion order == window-start order: entries are (re)inserted only at window start. */
  private readonly hits = new Map<string, WindowEntry>();

  constructor(
    private readonly options: ThrottleOptions,
    private readonly maxTrackedKeys: number = DEFAULT_MAX_TRACKED_KEYS,
  ) {}

  allow(key: string, now: number): boolean {
    const entry = this.hits.get(key);
    if (entry !== undefined && now < entry.resetAt) {
      if (entry.count >= this.options.limit) return false;
      entry.count += 1;
      return true;
    }
    // Starting (or restarting) a window. Delete-before-insert keeps map
    // insertion order equal to window-start order, so "first" is oldest.
    if (entry !== undefined) {
      this.hits.delete(key);
    } else if (this.hits.size >= this.maxTrackedKeys) {
      this.evictForSpace(now);
    }
    this.hits.set(key, { count: 1, resetAt: now + this.options.windowMs });
    return true;
  }

  /** Make room for one new key: expired windows first, then the oldest live window. */
  private evictForSpace(now: number): void {
    for (const [key, entry] of this.hits) {
      if (now >= entry.resetAt) this.hits.delete(key);
    }
    if (this.hits.size < this.maxTrackedKeys) return;
    const oldest = this.hits.keys().next();
    if (!oldest.done) this.hits.delete(oldest.value);
  }

  /** Test-only visibility: number of tracked windows (bounded-map proof). */
  get trackedKeyCount(): number {
    return this.hits.size;
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

/**
 * Transport-boundary mapping for the protected resource route (reviewer
 * finding, WP5 re-review). The x402 wire contract deliberately uses
 * protocol-shaped 200 refusal bodies on /verify and /settle
 * (ServiceRefusal(200, …): ungoverned payload, package drift, execution
 * failure, failed readback, …). Those statuses must NEVER surface as a 2xx on
 * /resource/:resourceId — a 2xx there is possible only at the single release
 * site, with the exact protected report bytes from a finalized,
 * integrity-verified fulfillment row and the PAYMENT-RESPONSE header.
 *
 * Every refusal is remapped by kind:
 *  - verify_refusal / settle_refusal → 402 (payment/governance/settlement)
 *  - terminal_conflict → 409
 *  - upstream_unavailable (pending/retryable) → 503
 *  - internal (ledger integrity) → 500
 *  - invalid_request / upstream_malformed keep their already non-2xx status
 * Hard invariant: any status still below 400 is coerced (503 if retryable,
 * else 402) — the protected resource never emits a 2xx JSON error body.
 */
function resourceRefusal(error: unknown): { status: number; code: string } {
  if (!(error instanceof ServiceRefusal)) {
    return { status: 500, code: "internal_error" };
  }
  let status: number;
  switch (error.kind) {
    case "verify_refusal":
    case "settle_refusal":
      status = 402;
      break;
    case "terminal_conflict":
      status = 409;
      break;
    case "upstream_unavailable":
      status = 503;
      break;
    case "internal":
      status = 500;
      break;
    default:
      status = error.httpStatus;
      break;
  }
  if (status < 400) status = error.retryable ? 503 : 402;
  return { status, code: error.code };
}

export function createService(
  deps: PipelineDeps,
  options: { throttle?: ThrottleOptions | FixedWindowThrottle } = {},
): Server {
  const { config } = deps;
  const throttle =
    options.throttle instanceof FixedWindowThrottle
      ? options.throttle
      : new FixedWindowThrottle(options.throttle ?? DEFAULT_THROTTLE);

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const clientKey = trustedClientIdentity(req);
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
        // A paid attempt invokes the settlement pipeline, so it draws from the
        // SAME per-client settlement budget as POST /settle — the resource
        // route is never a throttle bypass. Unpaid discovery (the 402 above)
        // stays available regardless.
        if (!throttle.allow(`settle:${clientKey}`, Date.now())) {
          status = 429;
          code = "rate_limited";
          send(res, 429, { error: "rate_limited" });
          return;
        }
        try {
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
          // The ONLY 2xx this route can emit: the exact protected report
          // bytes from a finalized, integrity-verified fulfillment row, with
          // the PAYMENT-RESPONSE header (true success and exact idempotent
          // retry both land here — nowhere else).
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
        } catch (error) {
          // Non-release outcomes are ALWAYS non-2xx here: the protocol-shaped
          // ServiceRefusal(200) refusals of /verify//settle are remapped, and
          // nothing from this route reaches the status-preserving outer catch.
          const mapped = resourceRefusal(error);
          status = mapped.status;
          code = mapped.code;
          send(res, mapped.status, { error: mapped.code });
        }
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
      // The generic boundary never emits a success status with an error body.
      status = mapped.status >= 400 ? mapped.status : 500;
      code = mapped.code;
      if (!res.headersSent) {
        send(res, status, { error: mapped.code });
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
