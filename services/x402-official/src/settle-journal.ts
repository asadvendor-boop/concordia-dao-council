/**
 * Durable append-only journal of every credentialed upstream `/settle` call.
 *
 * The SCHEMA IS FROZEN by the release contract
 * (`UPSTREAM_SETTLE_JOURNAL_MIGRATION` in
 * `tests/test_release_official_x402_adapter.py`): the repository migration
 * must match it byte-for-byte, and this module only PRODUCES rows the
 * frozen CHECKs accept:
 *
 * - `request_started` carries the full request record (method, frozen
 *   production URL, canonical-JSON header blob, exact body bytes, body
 *   hash) and is committed durably (synchronous=FULL) BEFORE any network
 *   I/O;
 * - `response_observed` requires upstream status EXACTLY 200 and carries
 *   the raw response bytes (journaled BEFORE parsing) with every request
 *   field NULL;
 * - `request_failed` carries ONLY a bounded failure code and an optional
 *   4xx/5xx status — never a body, never headers — with every request
 *   field NULL (a credentialed non-2xx body can reflect the token).
 *
 * UPDATE and DELETE always abort at the schema layer; partial unique
 * indexes pin one start and one terminal per call, one start per
 * authorization identity, and one start per signed payload.
 */

import DatabaseConstructor from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ServiceRefusal } from "./errors.js";
import type { SettleCallBinding } from "./types.js";

/** Frozen domain separator for the call identity hash (trailing NUL). */
export const SETTLE_CALL_DOMAIN = "CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\0";

export const SETTLE_EVENT_TYPES = [
  "request_started",
  "response_observed",
  "request_failed",
] as const;

export type SettleEventType = (typeof SETTLE_EVENT_TYPES)[number];

/**
 * Response headers that may enter the canonical journal record. Everything
 * else — any Set-Cookie, Authorization echo, or proxy token — is dropped.
 */
const RESPONSE_HEADER_ALLOWLIST: ReadonlySet<string> = new Set([
  "content-type",
  "content-length",
  "date",
  "retry-after",
  "server",
  "x-request-id",
]);

const BOUNDED_FAILURE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Canonical JSON bytes of a flat string map: lowercase keys sorted
 * lexicographically, compact separators — byte-compatible with the release
 * adapter's Python `_canonical` for the same map.
 */
export function canonicalJsonBytes(map: Record<string, string>): Buffer {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(map).sort()) {
    sorted[key] = map[key] as string;
  }
  return Buffer.from(JSON.stringify(sorted), "utf8");
}

/** The frozen request-header record: the credential is never journaled. */
export const JOURNALED_REQUEST_HEADERS: Buffer = canonicalJsonBytes({
  "content-type": "application/json",
});

/**
 * Frozen call identity:
 * `SHA256("CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\0" ||
 *   signed_payment_payload_hash_bytes || authorization_nonce_bytes)`.
 */
export function settleCallId(binding: SettleCallBinding): string {
  if (
    !HEX64.test(binding.signedPaymentPayloadHash) ||
    !HEX64.test(binding.authorizationNonce)
  ) {
    throw new ServiceRefusal(500, "settle_journal_binding_invalid", "internal");
  }
  return createHash("sha256")
    .update(Buffer.from(SETTLE_CALL_DOMAIN, "utf8"))
    .update(Buffer.from(binding.signedPaymentPayloadHash, "hex"))
    .update(Buffer.from(binding.authorizationNonce, "hex"))
    .digest("hex");
}

/** Allowlisted, lowercase-keyed, key-sorted canonical response headers. */
export function sanitizeResponseHeaders(headers: Headers): Buffer {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (RESPONSE_HEADER_ALLOWLIST.has(lower)) {
      out[lower] = value;
    }
  });
  return canonicalJsonBytes(out);
}

export interface SettleJournalEvent {
  sequence: number;
  eventType: SettleEventType;
  callId: string;
  network: string;
  wcsprContract: string;
  signedPaymentPayloadHash: string;
  payerAccountHash: string;
  authorizationNonce: string;
  resourceId: string;
  actionId: string;
  envelopeHash: string;
  requestMethod: string | null;
  requestUrl: string | null;
  requestHeadersCanonicalJson: Buffer | null;
  requestBody: Buffer | null;
  requestBodySha256: string | null;
  responseStatus: number | null;
  responseHeadersCanonicalJson: Buffer | null;
  responseBody: Buffer | null;
  responseBodySha256: string | null;
  failureCode: string | null;
  observedAt: string;
}

interface JournalDbRow {
  sequence: number;
  event_type: SettleEventType;
  call_id: string;
  network: string;
  wcspr_contract: string;
  signed_payment_payload_hash: string;
  payer_account_hash: string;
  authorization_nonce: string;
  resource_id: string;
  action_id: string;
  envelope_hash: string;
  request_method: string | null;
  request_url: string | null;
  request_headers_canonical_json: Buffer | null;
  request_body: Buffer | null;
  request_body_sha256: string | null;
  response_status: number | null;
  response_headers_canonical_json: Buffer | null;
  response_body: Buffer | null;
  response_body_sha256: string | null;
  failure_code: string | null;
  observed_at: string;
}

function toEvent(r: JournalDbRow): SettleJournalEvent {
  return {
    sequence: r.sequence,
    eventType: r.event_type,
    callId: r.call_id,
    network: r.network,
    wcsprContract: r.wcspr_contract,
    signedPaymentPayloadHash: r.signed_payment_payload_hash,
    payerAccountHash: r.payer_account_hash,
    authorizationNonce: r.authorization_nonce,
    resourceId: r.resource_id,
    actionId: r.action_id,
    envelopeHash: r.envelope_hash,
    requestMethod: r.request_method,
    requestUrl: r.request_url,
    requestHeadersCanonicalJson: r.request_headers_canonical_json,
    requestBody: r.request_body,
    requestBodySha256: r.request_body_sha256,
    responseStatus: r.response_status,
    responseHeadersCanonicalJson: r.response_headers_canonical_json,
    responseBody: r.response_body,
    responseBodySha256: r.response_body_sha256,
    failureCode: r.failure_code,
    observedAt: r.observed_at,
  };
}

/** Identity of one journaled call: the start row's request-side record. */
export interface SettleCallStart {
  callId: string;
  binding: SettleCallBinding;
  requestMethod: string;
  requestUrl: string;
  requestBody: Buffer;
  requestBodySha256: string;
}

function journalAppendFailure(): never {
  // A journal append that cannot commit means the call must not proceed
  // (for a start) or must never be reported as success (for a terminal).
  throw new ServiceRefusal(503, "settle_journal_append_failed", "upstream_unavailable");
}

export class SettleJournal {
  private readonly db: Database;

  constructor(path: string) {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.db = new DatabaseConstructor(path);
    // synchronous=FULL: the request_started row must be ON DISK before any
    // credentialed network I/O — a crash between fsync and fetch leaves a
    // start with no terminal (fail-closed evidence), never an unjournaled
    // upstream call.
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(loadMigrationSql());
  }

  close(): void {
    this.db.close();
  }

  /**
   * Durably journal the start of a credentialed `/settle` call. Throws (and
   * therefore forbids the network call) if the append cannot commit — which
   * includes a second start for the same call, authorization, or payload,
   * and any request record the frozen CHECKs reject.
   */
  recordRequestStarted(start: SettleCallStart): void {
    try {
      this.insert(start, {
        event_type: "request_started",
        request_method: start.requestMethod,
        request_url: start.requestUrl,
        request_headers_canonical_json: JOURNALED_REQUEST_HEADERS,
        request_body: start.requestBody,
        request_body_sha256: start.requestBodySha256,
        response_status: null,
        response_headers_canonical_json: null,
        response_body: null,
        response_body_sha256: null,
        failure_code: null,
      });
    } catch {
      journalAppendFailure();
    }
  }

  /**
   * Journal the raw 200 response bytes. MUST be called before the bytes are
   * parsed; a failed append here means the caller can never report success.
   * The frozen schema accepts ONLY status 200 here and forces every request
   * field to NULL on terminal rows.
   */
  recordResponseObserved(
    start: SettleCallStart,
    responseStatus: number,
    responseHeadersCanonicalJson: Buffer,
    responseBody: Buffer,
  ): void {
    try {
      this.insert(start, {
        event_type: "response_observed",
        request_method: null,
        request_url: null,
        request_headers_canonical_json: null,
        request_body: null,
        request_body_sha256: null,
        response_status: responseStatus,
        response_headers_canonical_json: responseHeadersCanonicalJson,
        response_body: responseBody,
        response_body_sha256: sha256Hex(responseBody),
        failure_code: null,
      });
    } catch {
      journalAppendFailure();
    }
  }

  /**
   * Journal a bounded failure: ONLY the bounded failure code and an
   * optional 4xx/5xx status — never a body, never headers (frozen CHECK).
   * Best-effort by design: the caller is already failing, and a journal
   * error here must not mask the original refusal.
   */
  recordRequestFailed(
    start: SettleCallStart,
    responseStatus: number | null,
    failureCode: string,
  ): void {
    const bounded = BOUNDED_FAILURE_CODE.test(failureCode)
      ? failureCode
      : "settle_call_failed";
    const status =
      responseStatus !== null && responseStatus >= 400 && responseStatus <= 599
        ? responseStatus
        : null;
    try {
      this.insert(start, {
        event_type: "request_failed",
        request_method: null,
        request_url: null,
        request_headers_canonical_json: null,
        request_body: null,
        request_body_sha256: null,
        response_status: status,
        response_headers_canonical_json: null,
        response_body: null,
        response_body_sha256: null,
        failure_code: bounded,
      });
    } catch {
      /* best effort — the caller is already throwing its own refusal */
    }
  }

  /** All events, in append order (tests and evidence export). */
  listEvents(callId?: string): SettleJournalEvent[] {
    const rows = (
      callId === undefined
        ? this.db
            .prepare(`SELECT * FROM x402_upstream_settle_calls ORDER BY sequence`)
            .all()
        : this.db
            .prepare(
              `SELECT * FROM x402_upstream_settle_calls
               WHERE call_id = ? ORDER BY sequence`,
            )
            .all(callId)
    ) as JournalDbRow[];
    return rows.map(toEvent);
  }

  private insert(
    start: SettleCallStart,
    row: {
      event_type: SettleEventType;
      request_method: string | null;
      request_url: string | null;
      request_headers_canonical_json: Buffer | null;
      request_body: Buffer | null;
      request_body_sha256: string | null;
      response_status: number | null;
      response_headers_canonical_json: Buffer | null;
      response_body: Buffer | null;
      response_body_sha256: string | null;
      failure_code: string | null;
    },
  ): void {
    this.db
      .prepare(
        `INSERT INTO x402_upstream_settle_calls (
           event_type, call_id, network, wcspr_contract,
           signed_payment_payload_hash, payer_account_hash,
           authorization_nonce, resource_id, action_id, envelope_hash,
           request_method, request_url, request_headers_canonical_json,
           request_body, request_body_sha256, response_status,
           response_headers_canonical_json, response_body,
           response_body_sha256, failure_code, observed_at
         ) VALUES (
           @event_type, @call_id, @network, @wcspr_contract,
           @signed_payment_payload_hash, @payer_account_hash,
           @authorization_nonce, @resource_id, @action_id, @envelope_hash,
           @request_method, @request_url, @request_headers_canonical_json,
           @request_body, @request_body_sha256, @response_status,
           @response_headers_canonical_json, @response_body,
           @response_body_sha256, @failure_code, @observed_at
         )`,
      )
      .run({
        ...row,
        call_id: start.callId,
        network: start.binding.network,
        wcspr_contract: start.binding.wcsprContract,
        signed_payment_payload_hash: start.binding.signedPaymentPayloadHash,
        payer_account_hash: start.binding.payerAccountHash,
        authorization_nonce: start.binding.authorizationNonce,
        resource_id: start.binding.resourceId,
        action_id: start.binding.actionId,
        envelope_hash: start.binding.envelopeHash,
        observed_at: new Date().toISOString(),
      });
  }
}

let migrationSqlCache: string | undefined;

function loadMigrationSql(): string {
  if (migrationSqlCache === undefined) {
    // src/… resolves to <service>/migrations in the repo; dist/… resolves to
    // /app/migrations in the runtime image (Dockerfile copies it there).
    const path = fileURLToPath(
      new URL("../migrations/0002_upstream_settle_journal.sql", import.meta.url),
    );
    migrationSqlCache = readFileSync(path, "utf8");
  }
  return migrationSqlCache;
}

/** Repo path of the frozen migration (for byte-exactness tests). */
export function migrationFilePath(): string {
  return fileURLToPath(
    new URL("../migrations/0002_upstream_settle_journal.sql", import.meta.url),
  );
}
