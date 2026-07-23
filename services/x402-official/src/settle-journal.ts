/**
 * Durable append-only journal of every credentialed upstream `/settle` call.
 *
 * The fulfillment ledger promises at most one facilitator `/settle` per
 * authorization; this journal is the EVIDENCE for that promise. Every call
 * appends `request_started` durably (synchronous=FULL) BEFORE any network
 * I/O, then exactly one terminal event: `response_observed` (the raw 2xx
 * bytes, recorded BEFORE parsing) or `request_failed` (bounded — a
 * credentialed non-2xx body is never stored, because it can reflect the
 * token). UPDATE and DELETE always abort at the schema layer.
 *
 * Secrets never enter the journal: request headers are recorded as the
 * constant `{"content-type":"application/json"}` (the Authorization header
 * is deliberately not part of the record), and response headers pass a safe
 * allowlist.
 */

import DatabaseConstructor from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ServiceRefusal } from "./errors.js";
import { lp } from "./hashes.js";
import type { SettleCallBinding } from "./types.js";

/** Domain separator for the call identity hash (trailing NUL included). */
export const SETTLE_CALL_DOMAIN = "CONCORDIA_X402_SETTLE_CALL_V1\0";

export const SETTLE_EVENT_TYPES = [
  "request_started",
  "response_observed",
  "request_failed",
] as const;

export type SettleEventType = (typeof SETTLE_EVENT_TYPES)[number];

/** The exact request-header record: the credential is never journaled. */
export const JOURNALED_REQUEST_HEADERS_JSON = JSON.stringify({
  "content-type": "application/json",
});

/**
 * Response headers that may be journaled. Everything else — including any
 * Set-Cookie, Authorization echo, or proxy token — is dropped, never stored.
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

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * call_id = SHA256("CONCORDIA_X402_SETTLE_CALL_V1\0" || lp(field)…) over the
 * length-prefixed UTF-8 fields, in order: network, WCSPR contract,
 * signed-payload hash, payer, nonce, resource ID, action ID, envelope hash,
 * request-body SHA256.
 */
export function settleCallId(
  binding: SettleCallBinding,
  requestBodySha256: string,
): string {
  const fields = [
    binding.network,
    binding.wcsprContract,
    binding.signedPaymentPayloadHash,
    binding.payerAccountHash,
    binding.authorizationNonce,
    binding.resourceId,
    binding.actionId,
    binding.envelopeHash,
    requestBodySha256,
  ];
  const hash = createHash("sha256");
  hash.update(Buffer.from(SETTLE_CALL_DOMAIN, "utf8"));
  for (const field of fields) {
    hash.update(lp(Buffer.from(field, "utf8")));
  }
  return hash.digest("hex");
}

/** Allowlisted, lowercase-keyed, key-sorted response-header record. */
export function sanitizeResponseHeaders(headers: Headers): string {
  const out: Record<string, string> = {};
  const keys: string[] = [];
  headers.forEach((_value, key) => {
    keys.push(key.toLowerCase());
  });
  for (const key of keys.sort()) {
    if (RESPONSE_HEADER_ALLOWLIST.has(key)) {
      out[key] = headers.get(key) ?? "";
    }
  }
  return JSON.stringify(out);
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
  requestMethod: string;
  requestUrl: string;
  requestHeadersJson: string;
  requestBody: string;
  requestBodySha256: string;
  responseStatus: number | null;
  responseHeadersJson: string | null;
  responseBody: string | null;
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
  request_method: string;
  request_url: string;
  request_headers_json: string;
  request_body: string;
  request_body_sha256: string;
  response_status: number | null;
  response_headers_json: string | null;
  response_body: string | null;
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
    requestHeadersJson: r.request_headers_json,
    requestBody: r.request_body,
    requestBodySha256: r.request_body_sha256,
    responseStatus: r.response_status,
    responseHeadersJson: r.response_headers_json,
    responseBody: r.response_body,
    responseBodySha256: r.response_body_sha256,
    failureCode: r.failure_code,
    observedAt: r.observed_at,
  };
}

/** Identity of one journaled call: the start row's request-side fields. */
export interface SettleCallStart {
  callId: string;
  binding: SettleCallBinding;
  requestMethod: string;
  requestUrl: string;
  requestBody: string;
  requestBodySha256: string;
}

function journalAppendFailure(): never {
  // A journal append that cannot commit means the call must not proceed (for
  // a start) or must never be reported as success (for a terminal). The code
  // is stable and secret-free.
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
   * includes a second start for the same call, authorization, or payload.
   */
  recordRequestStarted(start: SettleCallStart): void {
    try {
      this.insert({
        event_type: "request_started",
        start,
        response_status: null,
        response_headers_json: null,
        response_body: null,
        response_body_sha256: null,
        failure_code: null,
      });
    } catch {
      journalAppendFailure();
    }
  }

  /**
   * Journal the raw 2xx response bytes. MUST be called before the bytes are
   * parsed; a failed append here means the caller can never report success.
   */
  recordResponseObserved(
    start: SettleCallStart,
    responseStatus: number,
    responseHeadersJson: string,
    responseBody: string,
  ): void {
    try {
      this.insert({
        event_type: "response_observed",
        start,
        response_status: responseStatus,
        response_headers_json: responseHeadersJson,
        response_body: responseBody,
        response_body_sha256: sha256Hex(responseBody),
        failure_code: null,
      });
    } catch {
      journalAppendFailure();
    }
  }

  /**
   * Journal a bounded failure. A credentialed non-2xx body is NEVER stored —
   * only the status, allowlisted headers, and a bounded failure code.
   * Best-effort by design: the caller is already failing, and a journal
   * error here must not mask the original refusal.
   */
  recordRequestFailed(
    start: SettleCallStart,
    responseStatus: number | null,
    responseHeadersJson: string | null,
    failureCode: string,
  ): void {
    const bounded = BOUNDED_FAILURE_CODE.test(failureCode)
      ? failureCode
      : "settle_call_failed";
    try {
      this.insert({
        event_type: "request_failed",
        start,
        response_status: responseStatus,
        response_headers_json: responseHeadersJson,
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

  private insert(row: {
    event_type: SettleEventType;
    start: SettleCallStart;
    response_status: number | null;
    response_headers_json: string | null;
    response_body: string | null;
    response_body_sha256: string | null;
    failure_code: string | null;
  }): void {
    const { start } = row;
    this.db
      .prepare(
        `INSERT INTO x402_upstream_settle_calls (
           event_type, call_id, network, wcspr_contract,
           signed_payment_payload_hash, payer_account_hash,
           authorization_nonce, resource_id, action_id, envelope_hash,
           request_method, request_url, request_headers_json, request_body,
           request_body_sha256, response_status, response_headers_json,
           response_body, response_body_sha256, failure_code, observed_at
         ) VALUES (
           @event_type, @call_id, @network, @wcspr_contract,
           @signed_payment_payload_hash, @payer_account_hash,
           @authorization_nonce, @resource_id, @action_id, @envelope_hash,
           @request_method, @request_url, @request_headers_json,
           @request_body, @request_body_sha256, @response_status,
           @response_headers_json, @response_body, @response_body_sha256,
           @failure_code, @observed_at
         )`,
      )
      .run({
        event_type: row.event_type,
        call_id: start.callId,
        network: start.binding.network,
        wcspr_contract: start.binding.wcsprContract,
        signed_payment_payload_hash: start.binding.signedPaymentPayloadHash,
        payer_account_hash: start.binding.payerAccountHash,
        authorization_nonce: start.binding.authorizationNonce,
        resource_id: start.binding.resourceId,
        action_id: start.binding.actionId,
        envelope_hash: start.binding.envelopeHash,
        request_method: start.requestMethod,
        request_url: start.requestUrl,
        request_headers_json: JOURNALED_REQUEST_HEADERS_JSON,
        request_body: start.requestBody,
        request_body_sha256: start.requestBodySha256,
        response_status: row.response_status,
        response_headers_json: row.response_headers_json,
        response_body: row.response_body,
        response_body_sha256: row.response_body_sha256,
        failure_code: row.failure_code,
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
