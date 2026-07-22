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
import type {
  FacilitatorTransport,
  PaymentPayloadWire,
  PaymentRequirementsWire,
  SettleResponseWire,
  SupportedDocumentWire,
  SupportedKindWire,
  VerifyResponseWire,
} from "./types.js";

export class HttpFacilitatorTransport implements FacilitatorTransport {
  constructor(
    private readonly baseUrl: string,
    private readonly tokenProvider: () => string,
  ) {}

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
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      // No exception details propagate: fetch errors can embed request data.
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
      return await response.json();
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

  settle(body: unknown): Promise<unknown> {
    return this.request("POST", "/settle", body);
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
