/**
 * Durable fulfillment ledger (SQLite via pinned better-sqlite3).
 *
 * Frozen contract (G1 schemas → official_x402_service_v1.ledger):
 *  - table x402_fulfillments, primary key (network, signed_payment_payload_hash)
 *  - authorization uniqueness (network, wcspr_contract, payer_account_hash,
 *    authorization_nonce)
 *  - states: claimed → verified → submission_started → transaction_observed →
 *    finalized; failed_terminal is terminal. Transitions are durable and
 *    monotonic; submission_started is committed BEFORE the facilitator call.
 *  - same key + same binding: idempotent stored response
 *  - same key + different binding: terminal 409 (cross_binding_rejected)
 *  - same authorization key + different payload: terminal 409 before submission
 *  - restart reconciliation by (payer, authorization_nonce, recorded
 *    transaction hash); never a blind second settlement.
 *
 * Security addendum:
 *  - Terminal invariants are enforced on WRITE (inside the transition
 *    transaction, so a violating write rolls back) and on READ: a finalized
 *    row requires an exact 64-hex transaction hash, stored response bytes, a
 *    matching response digest, settled_at, and no failure reason; a
 *    failed_terminal row requires its bounded failure code and a matching
 *    stored failure response. Corrupt/impossible rows fail closed
 *    (ledger_terminal_invariant_violated) and are never replayed as success.
 *  - HARD INVARIANT: at most ONE facilitator `/settle` request per
 *    authorization, EVER. The durable verified→submission_started transition
 *    CAS is the single exclusive-submission gate: exactly one caller across
 *    all processes can ever journal `submission_started` for an
 *    authorization, states are monotonic, and NO code path resubmits after a
 *    lost response — a reserved row is resolved only by adopting the exact
 *    original transaction or by proven-expiry terminalization.
 *  - The recovery_lease_* columns are INERT legacy schema (retained additively
 *    for volumes written by the previous fix, cleared on every transition).
 *    The lease-claiming logic they once served existed only to serialize
 *    automatic resubmission, which has been removed entirely.
 */

import DatabaseConstructor from "better-sqlite3";
import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { integrityRefusal, terminalConflict, REFUSAL_CODES } from "./errors.js";
import { SETTLEMENT_STATES, type SettlementState } from "./config.js";

export const ROW_STATES = [
  "claimed",
  "verified",
  "submission_started",
  "transaction_observed",
  "finalized",
  "failed_terminal",
] as const;

export type RowState = (typeof ROW_STATES)[number];

const STATE_ORDER: Record<RowState, number> = {
  claimed: 0,
  verified: 1,
  submission_started: 2,
  transaction_observed: 3,
  finalized: 4,
  failed_terminal: 99,
};

/** Binding fields that must be identical for an idempotent retry. */
export interface FulfillmentBinding {
  network: string;
  signedPaymentPayloadHash: string;
  resourceId: string;
  actionId: string;
  envelopeHash: string;
  resourceUrlHash: string;
  reportHash: string;
  paymentRequirementsHash: string;
  payerAccountHash: string;
  payeeAccountHash: string;
  valueAtomic: string;
  validAfter: string;
  validBefore: string;
  authorizationNonce: string;
  publicKey: string;
  signature: string;
  wcsprContract: string;
}

export interface FulfillmentRow extends FulfillmentBinding {
  state: RowState;
  settlementTransactionHash: string | null;
  settlementResponseHash: string | null;
  responseJson: string | null;
  settledAt: string | null;
  failureReason: string | null;
  /**
   * INERT legacy columns (previous fix's resubmission lease). Retained only
   * for additive schema compatibility; never set, cleared on every transition.
   */
  recoveryLeaseId: string | null;
  recoveryLeaseExpiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type ClaimResult =
  | { outcome: "new"; row: FulfillmentRow }
  | { outcome: "existing"; row: FulfillmentRow };

const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS x402_fulfillments (
  network TEXT NOT NULL,
  signed_payment_payload_hash TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  envelope_hash TEXT NOT NULL,
  resource_url_hash TEXT NOT NULL,
  report_hash TEXT NOT NULL,
  payment_requirements_hash TEXT NOT NULL,
  payer_account_hash TEXT NOT NULL,
  payee_account_hash TEXT NOT NULL,
  value_atomic TEXT NOT NULL,
  valid_after TEXT NOT NULL,
  valid_before TEXT NOT NULL,
  authorization_nonce TEXT NOT NULL,
  public_key TEXT NOT NULL,
  signature TEXT NOT NULL,
  wcspr_contract TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN (
    'claimed','verified','submission_started','transaction_observed',
    'finalized','failed_terminal')),
  settlement_transaction_hash TEXT,
  settlement_response_hash TEXT,
  response_json TEXT,
  settled_at TEXT,
  failure_reason TEXT,
  recovery_lease_id TEXT,
  recovery_lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (network, signed_payment_payload_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS x402_fulfillments_authorization_unique
  ON x402_fulfillments (
    network, wcspr_contract, payer_account_hash, authorization_nonce);
CREATE TABLE IF NOT EXISTS service_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

interface DbRow {
  network: string;
  signed_payment_payload_hash: string;
  resource_id: string;
  action_id: string;
  envelope_hash: string;
  resource_url_hash: string;
  report_hash: string;
  payment_requirements_hash: string;
  payer_account_hash: string;
  payee_account_hash: string;
  value_atomic: string;
  valid_after: string;
  valid_before: string;
  authorization_nonce: string;
  public_key: string;
  signature: string;
  wcspr_contract: string;
  state: RowState;
  settlement_transaction_hash: string | null;
  settlement_response_hash: string | null;
  response_json: string | null;
  settled_at: string | null;
  failure_reason: string | null;
  recovery_lease_id: string | null;
  recovery_lease_expires_at: string | null;
  created_at: string;
  updated_at: string;
}

function toRow(r: DbRow): FulfillmentRow {
  return {
    network: r.network,
    signedPaymentPayloadHash: r.signed_payment_payload_hash,
    resourceId: r.resource_id,
    actionId: r.action_id,
    envelopeHash: r.envelope_hash,
    resourceUrlHash: r.resource_url_hash,
    reportHash: r.report_hash,
    paymentRequirementsHash: r.payment_requirements_hash,
    payerAccountHash: r.payer_account_hash,
    payeeAccountHash: r.payee_account_hash,
    valueAtomic: r.value_atomic,
    validAfter: r.valid_after,
    validBefore: r.valid_before,
    authorizationNonce: r.authorization_nonce,
    publicKey: r.public_key,
    signature: r.signature,
    wcsprContract: r.wcspr_contract,
    state: r.state,
    settlementTransactionHash: r.settlement_transaction_hash,
    settlementResponseHash: r.settlement_response_hash,
    responseJson: r.response_json,
    settledAt: r.settled_at,
    failureReason: r.failure_reason,
    recoveryLeaseId: r.recovery_lease_id,
    recoveryLeaseExpiresAt: r.recovery_lease_expires_at,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function bindingEquals(a: FulfillmentBinding, b: FulfillmentBinding): boolean {
  return (
    a.network === b.network &&
    a.signedPaymentPayloadHash === b.signedPaymentPayloadHash &&
    a.resourceId === b.resourceId &&
    a.actionId === b.actionId &&
    a.envelopeHash === b.envelopeHash &&
    a.resourceUrlHash === b.resourceUrlHash &&
    a.reportHash === b.reportHash &&
    a.paymentRequirementsHash === b.paymentRequirementsHash &&
    a.payerAccountHash === b.payerAccountHash &&
    a.payeeAccountHash === b.payeeAccountHash &&
    a.valueAtomic === b.valueAtomic &&
    a.validAfter === b.validAfter &&
    a.validBefore === b.validBefore &&
    a.authorizationNonce === b.authorizationNonce &&
    a.publicKey === b.publicKey &&
    a.signature === b.signature &&
    a.wcsprContract === b.wcsprContract
  );
}

export function responseHash(json: string): string {
  return createHash("sha256").update(json, "utf8").digest("hex");
}

const TRANSACTION_HEX64_RE = /^[0-9a-f]{64}$/;
const BOUNDED_FAILURE_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;

function terminalInvariantViolation(): never {
  throw integrityRefusal(REFUSAL_CODES.LEDGER_TERMINAL_INVARIANT_VIOLATED);
}

/**
 * Database terminal invariants (security addendum, item 4). Enforced on WRITE
 * (inside the transition transaction, so a violating write rolls back) and on
 * every READ. Corrupt or impossible terminal rows fail closed and are never
 * replayed as success — no fallback response is ever synthesized here.
 */
export function validateTerminalRowInvariants(row: FulfillmentRow): void {
  if (row.state !== "finalized" && row.state !== "failed_terminal") return;
  if (row.responseJson === null || row.settlementResponseHash === null) {
    terminalInvariantViolation();
  }
  if (responseHash(row.responseJson) !== row.settlementResponseHash) {
    terminalInvariantViolation();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.responseJson);
  } catch {
    terminalInvariantViolation();
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    terminalInvariantViolation();
  }
  const body = parsed as Record<string, unknown>;
  if (body["network"] !== row.network) terminalInvariantViolation();
  if (row.state === "finalized") {
    if (
      row.settlementTransactionHash === null ||
      !TRANSACTION_HEX64_RE.test(row.settlementTransactionHash)
    ) {
      terminalInvariantViolation();
    }
    if (row.settledAt === null) terminalInvariantViolation();
    if (row.failureReason !== null) terminalInvariantViolation();
    if (body["success"] !== true) terminalInvariantViolation();
    if (body["transaction"] !== row.settlementTransactionHash) {
      terminalInvariantViolation();
    }
    return;
  }
  // failed_terminal: bounded failure code + matching stored failure response.
  if (
    row.failureReason === null ||
    !BOUNDED_FAILURE_CODE_RE.test(row.failureReason)
  ) {
    terminalInvariantViolation();
  }
  if (row.settledAt !== null) terminalInvariantViolation();
  if (
    row.settlementTransactionHash !== null &&
    !TRANSACTION_HEX64_RE.test(row.settlementTransactionHash)
  ) {
    terminalInvariantViolation();
  }
  if (body["success"] !== false) terminalInvariantViolation();
  if (body["errorReason"] !== row.failureReason) terminalInvariantViolation();
  if (body["transaction"] !== (row.settlementTransactionHash ?? "")) {
    terminalInvariantViolation();
  }
}

export class FulfillmentLedger {
  private readonly db: Database;

  constructor(path: string) {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.db = new DatabaseConstructor(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(CREATE_SQL);
    // Additive migration for volumes created before the (now inert, legacy)
    // recovery-lease columns existed. The columns stay so older volumes and
    // this schema remain interchangeable; no logic reads or sets them.
    const columns = (
      this.db.prepare(`PRAGMA table_info(x402_fulfillments)`).all() as {
        name: string;
      }[]
    ).map((c) => c.name);
    if (!columns.includes("recovery_lease_id")) {
      this.db.exec(
        `ALTER TABLE x402_fulfillments ADD COLUMN recovery_lease_id TEXT`,
      );
    }
    if (!columns.includes("recovery_lease_expires_at")) {
      this.db.exec(
        `ALTER TABLE x402_fulfillments ADD COLUMN recovery_lease_expires_at TEXT`,
      );
    }
  }

  close(): void {
    this.db.close();
  }

  get(network: string, payloadHash: string): FulfillmentRow | undefined {
    const r = this.db
      .prepare(
        `SELECT * FROM x402_fulfillments
         WHERE network = ? AND signed_payment_payload_hash = ?`,
      )
      .get(network, payloadHash) as DbRow | undefined;
    if (r === undefined) return undefined;
    const row = toRow(r);
    // Terminal invariants are validated on EVERY read (and, because
    // transition() re-reads inside its transaction, on every write — a
    // violating terminal write rolls back). Fail closed, never replay corrupt
    // state as success.
    validateTerminalRowInvariants(row);
    return row;
  }

  /**
   * Atomically claim a fulfillment for this binding.
   *  - No row: insert state=claimed, return {outcome:"new"}.
   *  - Row with identical binding: return {outcome:"existing"} (idempotent path).
   *  - Row with different binding: terminal 409 cross_binding_rejected.
   *  - Different payload hash reusing the same authorization nonce key:
   *    terminal 409 authorization_nonce_reused, before any submission.
   */
  claim(binding: FulfillmentBinding): ClaimResult {
    const tx = this.db.transaction((): ClaimResult => {
      const existing = this.get(binding.network, binding.signedPaymentPayloadHash);
      if (existing !== undefined) {
        if (!bindingEquals(existing, binding)) {
          throw terminalConflict("cross_binding_rejected");
        }
        return { outcome: "existing", row: existing };
      }
      const nonceRow = this.db
        .prepare(
          `SELECT * FROM x402_fulfillments
           WHERE network = ? AND wcspr_contract = ?
             AND payer_account_hash = ? AND authorization_nonce = ?`,
        )
        .get(
          binding.network,
          binding.wcsprContract,
          binding.payerAccountHash,
          binding.authorizationNonce,
        ) as DbRow | undefined;
      if (nonceRow !== undefined) {
        throw terminalConflict("authorization_nonce_reused");
      }
      const now = new Date().toISOString();
      this.db
        .prepare(
          `INSERT INTO x402_fulfillments (
             network, signed_payment_payload_hash, resource_id, action_id,
             envelope_hash, resource_url_hash, report_hash,
             payment_requirements_hash, payer_account_hash, payee_account_hash,
             value_atomic, valid_after, valid_before, authorization_nonce,
             public_key, signature, wcspr_contract, state,
             created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'claimed', ?, ?)`,
        )
        .run(
          binding.network,
          binding.signedPaymentPayloadHash,
          binding.resourceId,
          binding.actionId,
          binding.envelopeHash,
          binding.resourceUrlHash,
          binding.reportHash,
          binding.paymentRequirementsHash,
          binding.payerAccountHash,
          binding.payeeAccountHash,
          binding.valueAtomic,
          binding.validAfter,
          binding.validBefore,
          binding.authorizationNonce,
          binding.publicKey,
          binding.signature,
          binding.wcsprContract,
          now,
          now,
        );
      const row = this.get(binding.network, binding.signedPaymentPayloadHash);
      if (row === undefined) throw new Error("ledger_insert_failed");
      return { outcome: "new", row };
    });
    return tx.immediate();
  }

  /**
   * Durable monotonic transition. Throws on any attempt to move backwards or
   * to leave failed_terminal / regress from finalized. A transition to a
   * terminal state is validated against the terminal invariants INSIDE the
   * transaction, so a violating write rolls back (enforced on write). The
   * inert legacy recovery_lease_* columns are cleared on every transition —
   * nothing sets them anymore.
   */
  transition(
    network: string,
    payloadHash: string,
    from: RowState[],
    to: RowState,
    extra?: {
      settlementTransactionHash?: string;
      settlementResponseHash?: string;
      responseJson?: string;
      settledAt?: string;
      failureReason?: string;
    },
  ): FulfillmentRow {
    const tx = this.db.transaction((): FulfillmentRow => {
      const row = this.get(network, payloadHash);
      if (row === undefined) throw new Error("ledger_row_missing");
      if (!from.includes(row.state)) {
        throw new Error("ledger_invalid_transition");
      }
      if (
        to !== "failed_terminal" &&
        STATE_ORDER[to] <= STATE_ORDER[row.state]
      ) {
        throw new Error("ledger_non_monotonic_transition");
      }
      if (row.state === "finalized" || row.state === "failed_terminal") {
        throw new Error("ledger_terminal_state");
      }
      const now = new Date().toISOString();
      this.db
        .prepare(
          `UPDATE x402_fulfillments SET
             state = ?,
             settlement_transaction_hash =
               COALESCE(?, settlement_transaction_hash),
             settlement_response_hash = COALESCE(?, settlement_response_hash),
             response_json = COALESCE(?, response_json),
             settled_at = COALESCE(?, settled_at),
             failure_reason = COALESCE(?, failure_reason),
             recovery_lease_id = NULL,
             recovery_lease_expires_at = NULL,
             updated_at = ?
           WHERE network = ? AND signed_payment_payload_hash = ?`,
        )
        .run(
          to,
          extra?.settlementTransactionHash ?? null,
          extra?.settlementResponseHash ?? null,
          extra?.responseJson ?? null,
          extra?.settledAt ?? null,
          extra?.failureReason ?? null,
          now,
          network,
          payloadHash,
        );
      // get() re-validates terminal invariants: a violating terminal write
      // throws here and the surrounding transaction rolls back.
      const updated = this.get(network, payloadHash);
      if (updated === undefined) throw new Error("ledger_row_missing");
      return updated;
    });
    return tx.immediate();
  }

  /** Rows that were in flight when the process last stopped. */
  pendingRows(): FulfillmentRow[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM x402_fulfillments
         WHERE state IN ('submission_started', 'transaction_observed')
         ORDER BY created_at ASC`,
      )
      .all() as DbRow[];
    return rows.map(toRow);
  }

  getSettlementState(): SettlementState {
    const row = this.db
      .prepare(`SELECT value FROM service_state WHERE key = 'settlement_state'`)
      .get() as { value: string } | undefined;
    const value = row?.value;
    if (
      value === SETTLEMENT_STATES.BLOCKED_UPGRADE_DRIFT ||
      value === SETTLEMENT_STATES.OFFICIAL_HOSTED_VERIFIED_LIVE
    ) {
      return value;
    }
    return SETTLEMENT_STATES.BLOCKED_FAIL_CLOSED;
  }

  setSettlementState(state: SettlementState): void {
    this.db
      .prepare(
        `INSERT INTO service_state (key, value) VALUES ('settlement_state', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      )
      .run(state);
  }
}
