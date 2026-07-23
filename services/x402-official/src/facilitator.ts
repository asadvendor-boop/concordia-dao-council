/**
 * Facilitator boundary.
 *
 * - HttpFacilitatorTransport talks to the hosted CSPR.cloud facilitator with
 *   raw `Authorization: <token>` (NEVER Bearer). It never logs tokens,
 *   headers, request objects, or response bodies; non-2xx bodies are never
 *   even buffered, because the 401 body reflects the supplied credential.
 * - Response validation is strict on required fields/types and ignores
 *   unknown fields (§12). A malformed 2xx is a terminal safe failure.
 * - localOfficialVerify runs the pinned official
 *   @make-software/casper-x402 facilitator scheme fully offline (stub signer)
 *   so the exact EIP-712 digest and 65-byte signature are checked with the
 *   official implementation before any ledger claim or credentialed call.
 */

import { ExactCasperScheme } from "@make-software/casper-x402/exact/facilitator";

import {
  upstreamMalformed,
  upstreamUnavailable,
  REFUSAL_CODES,
  ServiceRefusal,
} from "./errors.js";
import { readBoundedJson, readBoundedText } from "./http.js";
import {
  sanitizeResponseHeaders,
  settleCallId,
  sha256Hex,
  type SettleCallStart,
  type SettleJournal,
} from "./settle-journal.js";
import type {
  FacilitatorTransport,
  PaymentPayloadWire,
  PaymentRequirementsWire,
  SettleCallBinding,
  SettleResponseWire,
  SupportedDocumentWire,
  SupportedKindWire,
  VerifyResponseWire,
} from "./types.js";

/** Frozen production facilitator origin — no environment-proxy override (WP5-4). */
export const FROZEN_FACILITATOR_ORIGIN = "https://x402-facilitator.cspr.cloud";

const CREDENTIALED_FETCH_TIMEOUT_MS = 15_000;
const MAX_FACILITATOR_RESPONSE_BYTES = 65_536;

/**
 * Bounded allowlist of upstream facilitator reasons that may be echoed as
 * stable local codes. Anything else (arbitrary/oversized/credential-reflecting
 * text) collapses to a generic code and is never surfaced in a body or a log
 * (WP5 hardening: bound and map upstream reason strings).
 */
const ALLOWED_FACILITATOR_REASONS: ReadonlySet<string> = new Set([
  "insufficient_funds",
  "invalid_signature",
  "invalid_scheme",
  "invalid_network",
  "invalid_payload",
  "invalid_amount",
  "invalid_nonce",
  "expired",
  "unsupported",
]);

const REASON_GRAMMAR = /^[a-z][a-z0-9_]{0,47}$/;

/**
 * Map an untrusted upstream reason to a bounded, stable local code. Only a
 * grammar-conforming, explicitly allowlisted token is passed through; every
 * other value (including credential-reflecting or oversized text) becomes the
 * generic fallback.
 */
export function boundFacilitatorReason(
  raw: string | undefined,
  fallback: string,
): string {
  if (
    typeof raw === "string" &&
    REASON_GRAMMAR.test(raw) &&
    ALLOWED_FACILITATOR_REASONS.has(raw)
  ) {
    return raw;
  }
  return fallback;
}

/**
 * Test-only knobs. Production NEVER sets any of these; the origin is frozen and
 * the timeout/body caps take their frozen defaults (WP5-4).
 */
export interface FacilitatorTransportTestOptions {
  allowUnfrozenOriginForTest?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
  /**
   * The durable upstream-settle journal. REQUIRED for any `/settle` call:
   * without it, `settle()` refuses before any network I/O (fail closed).
   * Production wiring (index.ts) always provides it; only tests exercising
   * the credential-discipline paths of verify/supported may omit it.
   */
  settleJournal?: SettleJournal;
}

export class HttpFacilitatorTransport implements FacilitatorTransport {
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly settleJournal: SettleJournal | undefined;

  constructor(
    private readonly baseUrl: string,
    private readonly tokenProvider: () => string,
    options: FacilitatorTransportTestOptions = {},
  ) {
    // Freeze the credentialed origin: reject any non-frozen, non-HTTPS, or
    // path-bearing base URL so a redirected env can never exfiltrate the token.
    if (options.allowUnfrozenOriginForTest !== true && baseUrl !== FROZEN_FACILITATOR_ORIGIN) {
      throw new ServiceRefusal(
        500,
        "facilitator_origin_not_frozen",
        "internal",
      );
    }
    this.timeoutMs = options.timeoutMs ?? CREDENTIALED_FETCH_TIMEOUT_MS;
    this.maxResponseBytes = options.maxResponseBytes ?? MAX_FACILITATOR_RESPONSE_BYTES;
    this.settleJournal = options.settleJournal;
  }

  private async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const token = this.tokenProvider();
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          // Raw token. Never a "Bearer " prefix (§11).
          authorization: token,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        // A credentialed request must never follow a redirect (the Location
        // could exfiltrate the token to an attacker-chosen origin) and must be
        // bounded in time (WP5-4).
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      // No exception details propagate: fetch errors can embed request data,
      // and a redirect/timeout aborts here without ever exposing the token.
      throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
    }
    if (!response.ok) {
      // Never read a credentialed non-2xx body (401 reflects the token).
      try {
        await response.body?.cancel();
      } catch {
        /* discarded */
      }
      if (response.status >= 500) {
        throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
      }
      throw new ServiceRefusal(502, `facilitator_http_${response.status}`, "upstream_malformed");
    }
    try {
      return await readBoundedJson(response, this.maxResponseBytes);
    } catch {
      throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
    }
  }

  supported(): Promise<unknown> {
    return this.request("GET", "/supported");
  }

  verify(body: unknown): Promise<unknown> {
    return this.request("POST", "/verify", body);
  }

  /**
   * Credentialed `/settle` with the durable journal wrapped around it:
   *
   * 1. serialize the request body EXACTLY ONCE; those bytes are both
   *    journaled and sent — there is no second serialization to drift;
   * 2. append `request_started` durably (synchronous=FULL). If the append
   *    fails, the network is NEVER called;
   * 3. send. A transport failure or non-2xx appends a bounded
   *    `request_failed` (status + allowlisted headers only — a credentialed
   *    non-2xx body is never read, because it can reflect the token);
   * 4. on 2xx, read the raw bytes bounded and append `response_observed`
   *    BEFORE parsing. If that terminal append fails, this method never
   *    returns success — the reserved ledger row keeps recovery fail-closed.
   *
   * Retry/reconcile/cross-binding paths never reach this method (the
   * ledger's exclusive-submission CAS is the only caller), so the journal's
   * one-start-per-authorization indexes are an independent second enforcement
   * of the at-most-one-settle promise, not the primary one.
   */
  async settle(body: unknown, binding: SettleCallBinding): Promise<unknown> {
    // No journal, no settle: the durable evidence requirement is structural.
    const settleJournal = this.settleJournal;
    if (settleJournal === undefined) {
      throw new ServiceRefusal(500, "settle_journal_not_configured", "internal");
    }
    const token = this.tokenProvider();
    const requestBody = JSON.stringify(body);
    const start: SettleCallStart = {
      callId: "",
      binding,
      requestMethod: "POST",
      requestUrl: `${this.baseUrl}/settle`,
      requestBody,
      requestBodySha256: sha256Hex(requestBody),
    };
    start.callId = settleCallId(binding, start.requestBodySha256);

    // Durable start BEFORE any credentialed I/O; a failed append throws and
    // nothing is sent.
    settleJournal.recordRequestStarted(start);

    let response: Response;
    try {
      response = await fetch(start.requestUrl, {
        method: "POST",
        headers: {
          // Raw token. Never a "Bearer " prefix (§11). The journal records
          // only the constant content-type header — never this credential.
          authorization: token,
          "content-type": "application/json",
        },
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
        body: requestBody,
      });
    } catch {
      settleJournal.recordRequestFailed(
        start,
        null,
        null,
        "facilitator_unreachable",
      );
      throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
    }

    if (!response.ok) {
      // Never read a credentialed non-2xx body (401 reflects the token) —
      // and never store one: the journal gets status + allowlisted headers.
      try {
        await response.body?.cancel();
      } catch {
        /* discarded */
      }
      settleJournal.recordRequestFailed(
        start,
        response.status,
        sanitizeResponseHeaders(response.headers),
        `facilitator_http_${response.status}`,
      );
      if (response.status >= 500) {
        throw upstreamUnavailable(REFUSAL_CODES.FACILITATOR_UNREACHABLE);
      }
      throw new ServiceRefusal(
        502,
        `facilitator_http_${response.status}`,
        "upstream_malformed",
      );
    }

    let text: string;
    try {
      text = await readBoundedText(response, this.maxResponseBytes);
    } catch {
      settleJournal.recordRequestFailed(
        start,
        response.status,
        sanitizeResponseHeaders(response.headers),
        "response_too_large",
      );
      throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
    }

    // The raw bytes are evidence BEFORE they are interpretation: journal the
    // response first, then parse. If the append fails this throws and the
    // parsed result is never returned.
    settleJournal.recordResponseObserved(
      start,
      response.status,
      sanitizeResponseHeaders(response.headers),
      text,
    );

    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
    }
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function optionalString(obj: Record<string, unknown>, key: string): void {
  if (key in obj && obj[key] !== undefined && typeof obj[key] !== "string") {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
}

function optionalObject(obj: Record<string, unknown>, key: string): void {
  if (key in obj && obj[key] !== undefined && !isPlainObject(obj[key])) {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
}

/**
 * §12 verify response: {isValid:boolean, invalidReason?, invalidMessage?,
 * payer?, extensions?, extra?}. Unknown fields ignored; required fields
 * typed; malformed 2xx is a terminal safe failure.
 */
export function validateVerifyResponse(body: unknown): VerifyResponseWire {
  if (!isPlainObject(body) || typeof body["isValid"] !== "boolean") {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
  optionalString(body, "invalidReason");
  optionalString(body, "invalidMessage");
  optionalString(body, "payer");
  optionalObject(body, "extensions");
  optionalObject(body, "extra");
  const out: VerifyResponseWire = { isValid: body["isValid"] };
  if (typeof body["invalidReason"] === "string") out.invalidReason = body["invalidReason"];
  if (typeof body["invalidMessage"] === "string") out.invalidMessage = body["invalidMessage"];
  if (typeof body["payer"] === "string") out.payer = body["payer"];
  return out;
}

/**
 * §12 settle response: success:boolean plus transaction:string and
 * network:string are required; unknown fields ignored. HTTP 200 is never
 * success unless success===true AND the transfer later proves finalized on
 * chain — that chain proof is enforced by the pipeline, not here.
 */
export function validateSettleResponse(
  body: unknown,
  expectedNetwork: string,
): SettleResponseWire {
  if (!isPlainObject(body) || typeof body["success"] !== "boolean") {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
  if (typeof body["transaction"] !== "string" || typeof body["network"] !== "string") {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
  optionalString(body, "errorReason");
  optionalString(body, "errorMessage");
  optionalString(body, "payer");
  optionalString(body, "amount");
  optionalObject(body, "extensions");
  optionalObject(body, "extra");
  const success = body["success"];
  const transaction = body["transaction"];
  const network = body["network"];
  if (success === true) {
    if (network !== expectedNetwork) {
      throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
    }
    if (!/^[0-9a-f]{64}$/.test(transaction)) {
      throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
    }
  }
  const out: SettleResponseWire = { success, transaction, network };
  if (typeof body["errorReason"] === "string") out.errorReason = body["errorReason"];
  if (typeof body["errorMessage"] === "string") out.errorMessage = body["errorMessage"];
  if (typeof body["payer"] === "string") out.payer = body["payer"];
  if (typeof body["amount"] === "string") out.amount = body["amount"];
  return out;
}

/**
 * §12: GET /supported parses as kinds/extensions/signers. A supported kind
 * requires x402Version=2, scheme="exact", and the exact CAIP-2 network.
 * Unknown extra keys are preserved. Token metadata is NEVER inferred from
 * /supported.
 */
export function parseSupportedDocument(body: unknown): SupportedDocumentWire {
  if (!isPlainObject(body)) {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
  const kindsRaw = body["kinds"];
  if (!Array.isArray(kindsRaw)) {
    throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
  }
  const kinds: SupportedKindWire[] = kindsRaw.map((k) => {
    if (
      !isPlainObject(k) ||
      typeof k["x402Version"] !== "number" ||
      typeof k["scheme"] !== "string" ||
      typeof k["network"] !== "string"
    ) {
      throw upstreamMalformed(REFUSAL_CODES.MALFORMED_FACILITATOR_RESPONSE);
    }
    return k as unknown as SupportedKindWire;
  });
  const extensions = isPlainObject(body["extensions"]) ? body["extensions"] : {};
  const signersRaw = body["signers"];
  const signers =
    isPlainObject(signersRaw) || Array.isArray(signersRaw) ? signersRaw : {};
  return { kinds, extensions, signers } as SupportedDocumentWire;
}

/** Exact kind match — x402Version=2, scheme "exact", frozen network. */
export function supportsExactKind(
  doc: SupportedDocumentWire,
  network: string,
): boolean {
  return doc.kinds.some(
    (k) => k.x402Version === 2 && k.scheme === "exact" && k.network === network,
  );
}

interface StubNetworkConfig {
  chainName: string;
  rpcUrl: string;
}

function buildOfflineScheme(network: string, chainName: string): ExactCasperScheme {
  const refuse = (): never => {
    // The stub signer can never sign, submit, or observe anything.
    throw new Error("offline_stub_signer");
  };
  const stubSigner = {
    getNetworkConfig: async (requested: string): Promise<StubNetworkConfig> => {
      if (requested !== network) throw new Error("unsupported_network");
      return { chainName, rpcUrl: "http://offline.invalid" };
    },
    getAddresses: refuse,
    getPublicKeyHex: refuse,
    signTransaction: refuse,
    putTransaction: refuse,
    waitForTransaction: refuse,
  };
  return new ExactCasperScheme(stubSigner as never);
}

export interface LocalVerifier {
  verify(
    paymentPayload: PaymentPayloadWire,
    requirements: PaymentRequirementsWire,
  ): Promise<VerifyResponseWire>;
}

/**
 * Offline verifier backed by the pinned official facilitator scheme. This is
 * the §6 "signature must verify the exact EIP-712 digest" check — the
 * official implementation, not a reimplementation — and it also enforces the
 * official validity-window rules against the current clock.
 */
export function createLocalVerifier(network: string, chainName: string): LocalVerifier {
  const scheme = buildOfflineScheme(network, chainName);
  return {
    async verify(paymentPayload, requirements) {
      const result = await scheme.verify(
        paymentPayload as never,
        requirements as never,
      );
      return validateVerifyResponse(result);
    },
  };
}
