"""Durable SafePay Lite supplemental v2 SQLite ledger.

Implements the G1-frozen storage and issuance/consumption contract from
handoff/G1_INTERFACE_SPEC.md section 12 and the safepay_v2 machine schema in
handoff/G1_CROSS_LANE_SCHEMAS.json:

- immutable ``safepay_quotes`` rows referencing content-addressed
  ``safepay_reports`` rows (SHA-256 key, fail-closed on hash conflict);
- an atomic ``payment_consumptions`` claim with ``UNIQUE(network,
  payment_hash)`` so exactly one redemption wins and every exact retry
  returns the stored immutable fulfillment;
- durable fixed-window rate limiting plus a two-phase reservation flow so
  expensive report work never happens before rate admission or while holding
  the SQLite write lock.

All timestamps are injected by the caller (integer Unix seconds) so tests
control the clock. Every write transaction is ``BEGIN IMMEDIATE``.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from shared.x402_payments import (
    SAFEPAY_V2_NETWORK,
    SAFEPAY_V2_REPORT_MEDIA_TYPE,
    SAFEPAY_V2_REPORT_VERSION,
    SAFEPAY_V2_SCHEMA_VERSION,
    safepay_v2_body_digest,
    safepay_v2_correlation_id,
    safepay_v2_error_body,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
)


_MIGRATION_PATH = Path(__file__).resolve().parent / "migrations" / "0001_safepay_v2.sql"


@dataclass(frozen=True)
class SafePayCaps:
    """Frozen production limits. Tests may pass smaller overrides; the
    defaults here are the G1-frozen numbers and must never change."""

    per_client_limit: int = 12
    per_client_window_seconds: int = 60
    global_limit: int = 120
    global_window_seconds: int = 60
    max_outstanding_quotes: int = 10_000
    max_retained_unconsumed_quotes: int = 20_000
    max_report_rows: int = 1_024
    max_report_total_decoded_bytes: int = 67_108_864
    max_report_decoded_bytes: int = 262_144
    max_inflight_reservations: int = 32
    reservation_ttl_seconds: int = 60
    report_resolution_timeout_seconds: float = 10.0
    quote_ttl_seconds: int = 900
    gc_eligible_after_expiry_seconds: int = 86_400
    gc_row_budget: int = 100


class SafePayLedgerError(Exception):
    """Base class for ledger failures."""


class QuoteRateLimited(SafePayLedgerError):
    """Fixed-window client or global attempt limit exceeded (HTTP 429)."""


class QuoteCapacityExhausted(SafePayLedgerError):
    """A frozen capacity cap or reservation constraint blocked issuance (HTTP 503)."""


class ReportConflict(SafePayLedgerError):
    """Content-addressed report hash conflict; issuance fails closed."""


class QuoteExpired(SafePayLedgerError):
    """Unconsumed quote at or past expires_at (terminal HTTP 410)."""


class CrossBindingRejected(SafePayLedgerError):
    """Payment already consumed for a different binding (terminal HTTP 409)."""


class QuoteBindingInvalid(SafePayLedgerError):
    """Persisted quote no longer matches the submitted quote (terminal HTTP 422)."""


class SafePayLedger:
    def __init__(self, path: str, caps: SafePayCaps | None = None) -> None:
        self.path = str(path)
        self.caps = caps or SafePayCaps()
        self._migrate()

    # -- connection management -------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _migrate(self) -> None:
        parent = Path(self.path).resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_MIGRATION_PATH.read_text(encoding="utf-8"))
        finally:
            conn.close()

    # -- quote issuance: phase one (preflight) ---------------------------------

    def preflight_reservation(
        self, *, client_key: str, proposal_id: str, resource_id: str, now: int
    ) -> str:
        """Admission control in one short BEGIN IMMEDIATE transaction.

        Bounded GC of stale rate/reservation rows, fixed-window limit checks,
        the hard in-flight reservation cap, then charging both attempt
        counters (never refunded) and inserting a pending reservation.
        """
        caps = self.caps
        now = int(now)
        window_start = (now // caps.per_client_window_seconds) * caps.per_client_window_seconds
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            budget = caps.gc_row_budget
            deleted = conn.execute(
                "DELETE FROM safepay_quote_rate_limits WHERE rowid IN ("
                "SELECT rowid FROM safepay_quote_rate_limits WHERE window_start < ? LIMIT ?)",
                (window_start, budget),
            ).rowcount
            budget = max(0, budget - max(0, deleted))
            if budget:
                conn.execute(
                    "DELETE FROM safepay_quote_issue_reservations WHERE reservation_id IN ("
                    "SELECT reservation_id FROM safepay_quote_issue_reservations "
                    "WHERE (state = 'pending' AND expires_at <= ?) "
                    "OR (state IN ('completed','failed') AND created_at + ? <= ?) LIMIT ?)",
                    (now, caps.gc_eligible_after_expiry_seconds, now, budget),
                )
            client_count = self._window_count(conn, "client", client_key, window_start)
            global_count = self._window_count(conn, "global", "global", window_start)
            if client_count >= caps.per_client_limit or global_count >= caps.global_limit:
                conn.execute("ROLLBACK")
                raise QuoteRateLimited()
            inflight = conn.execute(
                "SELECT COUNT(*) FROM safepay_quote_issue_reservations "
                "WHERE state = 'pending' AND expires_at > ?",
                (now,),
            ).fetchone()[0]
            if inflight >= caps.max_inflight_reservations:
                conn.execute("ROLLBACK")
                raise QuoteCapacityExhausted()
            for scope, key in (("client", client_key), ("global", "global")):
                conn.execute(
                    "INSERT INTO safepay_quote_rate_limits(scope, client_key, window_start, count) "
                    "VALUES(?, ?, ?, 1) "
                    "ON CONFLICT(scope, client_key, window_start) DO UPDATE SET count = count + 1",
                    (scope, key, window_start),
                )
            reservation_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO safepay_quote_issue_reservations("
                "reservation_id, client_key, proposal_id, resource_id, window_start, "
                "state, created_at, expires_at) VALUES(?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    reservation_id,
                    client_key,
                    proposal_id,
                    resource_id,
                    window_start,
                    now,
                    now + caps.reservation_ttl_seconds,
                ),
            )
            conn.execute("COMMIT")
            return reservation_id
        finally:
            conn.close()

    @staticmethod
    def _window_count(
        conn: sqlite3.Connection, scope: str, client_key: str, window_start: int
    ) -> int:
        row = conn.execute(
            "SELECT count FROM safepay_quote_rate_limits "
            "WHERE scope = ? AND client_key = ? AND window_start = ?",
            (scope, client_key, window_start),
        ).fetchone()
        return int(row["count"]) if row else 0

    def mark_reservation_failed(self, reservation_id: str, *, now: int) -> None:
        """Report-source or capacity failure: the attempt stays consumed."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE safepay_quote_issue_reservations SET state = 'failed' "
                "WHERE reservation_id = ?",
                (reservation_id,),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

    # -- quote issuance: phase two (final issue transaction) -------------------

    def finalize_quote(
        self,
        *,
        reservation_id: str,
        proposal_id: str,
        resource_id: str,
        payee_account_hash: str,
        amount_motes: str,
        report_bytes: bytes,
        clock,
    ) -> dict[str, Any]:
        """Second BEGIN IMMEDIATE transaction of the two-phase issuance.

        Samples the single ``issued_at``, reloads the pending reservation,
        performs bounded quote/report GC, rechecks every frozen capacity,
        inserts or exactly revalidates the content-addressed report, inserts
        the immutable quote, and marks the reservation completed.
        """
        caps = self.caps
        report_hash = hashlib.sha256(report_bytes).hexdigest()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            issued_at = int(clock())
            reservation = conn.execute(
                "SELECT * FROM safepay_quote_issue_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if (
                reservation is None
                or reservation["state"] != "pending"
                or int(reservation["expires_at"]) <= issued_at
                or reservation["proposal_id"] != proposal_id
                or reservation["resource_id"] != resource_id
            ):
                self._fail_reservation_in_txn(conn, reservation_id)
                conn.execute("COMMIT")
                raise QuoteCapacityExhausted()

            # Bounded GC: expired-for-86400s, unconsumed, unreferenced quotes.
            conn.execute(
                "DELETE FROM safepay_quotes WHERE quote_id IN ("
                "SELECT q.quote_id FROM safepay_quotes q "
                "WHERE q.expires_at + ? <= ? "
                "AND NOT EXISTS (SELECT 1 FROM payment_consumptions c WHERE c.quote_id = q.quote_id) "
                "LIMIT ?)",
                (caps.gc_eligible_after_expiry_seconds, issued_at, caps.gc_row_budget),
            )
            # Bounded GC: report rows referenced by no quote and no consumption.
            conn.execute(
                "DELETE FROM safepay_reports WHERE report_hash IN ("
                "SELECT r.report_hash FROM safepay_reports r "
                "WHERE NOT EXISTS (SELECT 1 FROM safepay_quotes q WHERE q.report_hash = r.report_hash) "
                "AND NOT EXISTS (SELECT 1 FROM payment_consumptions c WHERE c.report_hash = r.report_hash) "
                "LIMIT ?)",
                (caps.gc_row_budget,),
            )

            outstanding = conn.execute(
                "SELECT COUNT(*) FROM safepay_quotes q WHERE q.expires_at > ? "
                "AND NOT EXISTS (SELECT 1 FROM payment_consumptions c WHERE c.quote_id = q.quote_id)",
                (issued_at,),
            ).fetchone()[0]
            retained = conn.execute(
                "SELECT COUNT(*) FROM safepay_quotes q "
                "WHERE NOT EXISTS (SELECT 1 FROM payment_consumptions c WHERE c.quote_id = q.quote_id)"
            ).fetchone()[0]
            if outstanding >= caps.max_outstanding_quotes or retained >= caps.max_retained_unconsumed_quotes:
                self._fail_reservation_in_txn(conn, reservation_id)
                conn.execute("COMMIT")
                raise QuoteCapacityExhausted()

            existing = conn.execute(
                "SELECT report_media_type, report_bytes, decoded_length FROM safepay_reports "
                "WHERE report_hash = ?",
                (report_hash,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["report_media_type"] != SAFEPAY_V2_REPORT_MEDIA_TYPE
                    or bytes(existing["report_bytes"]) != report_bytes
                    or int(existing["decoded_length"]) != len(report_bytes)
                ):
                    self._fail_reservation_in_txn(conn, reservation_id)
                    conn.execute("COMMIT")
                    raise ReportConflict()
            else:
                report_rows = conn.execute("SELECT COUNT(*) FROM safepay_reports").fetchone()[0]
                total_bytes = conn.execute(
                    "SELECT COALESCE(SUM(decoded_length), 0) FROM safepay_reports"
                ).fetchone()[0]
                if (
                    report_rows >= caps.max_report_rows
                    or total_bytes + len(report_bytes) > caps.max_report_total_decoded_bytes
                ):
                    self._fail_reservation_in_txn(conn, reservation_id)
                    conn.execute("COMMIT")
                    raise QuoteCapacityExhausted()
                conn.execute(
                    "INSERT INTO safepay_reports("
                    "report_hash, report_media_type, report_bytes, decoded_length, created_at) "
                    "VALUES(?, ?, ?, ?, ?)",
                    (report_hash, SAFEPAY_V2_REPORT_MEDIA_TYPE, report_bytes, len(report_bytes), issued_at),
                )

            quote_id = str(uuid.uuid4())
            quote_nonce = secrets.token_bytes(32)
            while int.from_bytes(quote_nonce, "big") == 0:  # pragma: no cover - astronomically unlikely
                quote_nonce = secrets.token_bytes(32)
            correlation_id = safepay_v2_correlation_id(quote_id, proposal_id, resource_id, quote_nonce)
            expires_at = issued_at + caps.quote_ttl_seconds
            quote_hash = safepay_v2_quote_hash(
                quote_id=quote_id,
                proposal_id=proposal_id,
                resource_id=resource_id,
                network=SAFEPAY_V2_NETWORK,
                payee_account_hash=payee_account_hash,
                amount_motes=amount_motes,
                correlation_id=correlation_id,
                report_version=SAFEPAY_V2_REPORT_VERSION,
                report_hash=report_hash,
                expires_at=expires_at,
                quote_nonce=quote_nonce,
            )
            conn.execute(
                "INSERT INTO safepay_quotes("
                "quote_id, proposal_id, resource_id, network, payee_account_hash, amount_motes, "
                "correlation_id, report_version, report_hash, issued_at, expires_at, quote_nonce, quote_hash) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    quote_id,
                    proposal_id,
                    resource_id,
                    SAFEPAY_V2_NETWORK,
                    payee_account_hash,
                    amount_motes,
                    str(correlation_id),
                    SAFEPAY_V2_REPORT_VERSION,
                    report_hash,
                    issued_at,
                    expires_at,
                    quote_nonce.hex(),
                    quote_hash,
                ),
            )
            conn.execute(
                "UPDATE safepay_quote_issue_reservations SET state = 'completed' "
                "WHERE reservation_id = ?",
                (reservation_id,),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
        return {
            "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
            "quote_id": quote_id,
            "proposal_id": proposal_id,
            "resource_id": resource_id,
            "network": SAFEPAY_V2_NETWORK,
            "payee_account_hash": payee_account_hash,
            "amount_motes": amount_motes,
            "correlation_id": str(correlation_id),
            "report_version": SAFEPAY_V2_REPORT_VERSION,
            "report_hash": report_hash,
            "expires_at": expires_at,
            "quote_nonce": quote_nonce.hex(),
            "quote_hash": quote_hash,
        }

    @staticmethod
    def _fail_reservation_in_txn(conn: sqlite3.Connection, reservation_id: str) -> None:
        conn.execute(
            "UPDATE safepay_quote_issue_reservations SET state = 'failed' "
            "WHERE reservation_id = ? AND state = 'pending'",
            (reservation_id,),
        )

    # -- reads -----------------------------------------------------------------

    def load_quote(self, quote_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM safepay_quotes WHERE quote_id = ?", (quote_id,)
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def quote_wire_object(self, row: Mapping[str, Any]) -> dict[str, Any]:
        """Immutable quote object in the frozen field order from a ledger row."""
        return {
            "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
            "quote_id": row["quote_id"],
            "proposal_id": row["proposal_id"],
            "resource_id": row["resource_id"],
            "network": row["network"],
            "payee_account_hash": row["payee_account_hash"],
            "amount_motes": row["amount_motes"],
            "correlation_id": row["correlation_id"],
            "report_version": row["report_version"],
            "report_hash": row["report_hash"],
            "expires_at": int(row["expires_at"]),
            "quote_nonce": row["quote_nonce"],
            "quote_hash": row["quote_hash"],
        }

    def load_report(self, report_hash: str) -> tuple[str, bytes] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT report_media_type, report_bytes FROM safepay_reports WHERE report_hash = ?",
                (report_hash,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return row["report_media_type"], bytes(row["report_bytes"])

    def find_consumption(self, network: str, payment_hash: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM payment_consumptions WHERE network = ? AND payment_hash = ?",
                (network, payment_hash),
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def find_consumption_for_quote(self, quote_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM payment_consumptions WHERE quote_id = ?", (quote_id,)
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    # -- atomic consumption claim ---------------------------------------------

    def claim_consumption(
        self,
        *,
        quote_row: Mapping[str, Any],
        payment_hash: str,
        payment_observation: Mapping[str, Any],
        report_object: Mapping[str, Any],
        binding_checks: Mapping[str, Any],
        observed_at: str,
        now: int,
    ) -> tuple[dict[str, Any], str]:
        """Atomically claim ``(network, payment_hash)`` and persist the fulfillment.

        Returns ``(fulfillment, replay_disposition)``. Raises QuoteExpired,
        CrossBindingRejected, or QuoteBindingInvalid. No network I/O happens
        here; chain observation is completed by the caller beforehand.
        """
        now = int(now)
        network = quote_row["network"]
        quote_id = quote_row["quote_id"]
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            persisted = conn.execute(
                "SELECT * FROM safepay_quotes WHERE quote_id = ?", (quote_id,)
            ).fetchone()
            if persisted is None or any(
                persisted[key] != quote_row[key]
                for key in (
                    "proposal_id",
                    "resource_id",
                    "network",
                    "payee_account_hash",
                    "amount_motes",
                    "correlation_id",
                    "report_version",
                    "report_hash",
                    "quote_nonce",
                    "quote_hash",
                )
            ) or int(persisted["expires_at"]) != int(quote_row["expires_at"]):
                conn.execute("ROLLBACK")
                raise QuoteBindingInvalid()
            existing = conn.execute(
                "SELECT * FROM payment_consumptions WHERE network = ? AND payment_hash = ?",
                (network, payment_hash),
            ).fetchone()
            if existing is not None:
                conn.execute("ROLLBACK")
                if (
                    existing["quote_id"] == quote_id
                    and existing["resource_id"] == quote_row["resource_id"]
                    and existing["quote_hash"] == quote_row["quote_hash"]
                ):
                    return json.loads(existing["fulfillment_json"]), "idempotent_replay"
                raise CrossBindingRejected()
            other = conn.execute(
                "SELECT payment_hash FROM payment_consumptions WHERE quote_id = ?", (quote_id,)
            ).fetchone()
            if other is not None and other["payment_hash"] != payment_hash:
                conn.execute("ROLLBACK")
                raise CrossBindingRejected()
            if now >= int(persisted["expires_at"]):
                conn.execute("ROLLBACK")
                raise QuoteExpired()

            consumed_at = now
            response_hash = safepay_v2_response_hash(
                quote_hash=quote_row["quote_hash"],
                payment_hash=payment_hash,
                block_hash=payment_observation["block_hash"],
                block_height=int(payment_observation["block_height"]),
                report_hash=quote_row["report_hash"],
                consumed_at=consumed_at,
            )
            consumption = {
                "network": network,
                "payment_hash": payment_hash,
                "quote_id": quote_id,
                "resource_id": quote_row["resource_id"],
                "quote_hash": quote_row["quote_hash"],
                "response_hash": response_hash,
                "consumed_at": consumed_at,
            }
            fulfillment = {
                "quote": self.quote_wire_object(quote_row),
                "payment_observation": dict(payment_observation),
                "consumption": consumption,
                "report": dict(report_object),
                "binding_checks": dict(binding_checks),
                "observed_at": observed_at,
                "response_hash": response_hash,
            }
            conn.execute(
                "INSERT INTO payment_consumptions("
                "network, payment_hash, quote_id, proposal_id, resource_id, quote_hash, "
                "report_hash, correlation_id, fulfillment_json, response_hash, consumed_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    network,
                    payment_hash,
                    quote_id,
                    quote_row["proposal_id"],
                    quote_row["resource_id"],
                    quote_row["quote_hash"],
                    quote_row["report_hash"],
                    quote_row["correlation_id"],
                    json.dumps(fulfillment, separators=(",", ":"), sort_keys=False),
                    response_hash,
                    consumed_at,
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO safepay_redemption_observations("
                "kind, http_status, network, payment_hash, quote_id, resource_id, observed_at, "
                "response_digest, consumed_response_hash) "
                "VALUES('first_consumption', 200, ?, ?, ?, ?, ?, ?, ?)",
                (
                    network,
                    payment_hash,
                    quote_id,
                    quote_row["resource_id"],
                    now,
                    response_hash,
                    response_hash,
                ),
            )
            conn.execute("COMMIT")
            return fulfillment, "first_consumption"
        except sqlite3.IntegrityError:
            # A concurrent claim committed between our checks; resolve honestly.
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            existing = conn.execute(
                "SELECT * FROM payment_consumptions WHERE network = ? AND payment_hash = ?",
                (network, payment_hash),
            ).fetchone()
            if existing is not None and existing["quote_id"] == quote_id:
                return json.loads(existing["fulfillment_json"]), "idempotent_replay"
            raise CrossBindingRejected() from None
        finally:
            conn.close()

    # -- honest evidence -------------------------------------------------------

    def record_redemption_observation(
        self,
        *,
        kind: str,
        http_status: int,
        network: str,
        payment_hash: str,
        quote_id: str,
        resource_id: str,
        now: int,
        response_digest: str,
        consumed_response_hash: str,
    ) -> None:
        """Append-only observation powering honest artifact derivation.

        Every observation is BOUND to the response actually served:
        ``response_digest`` is the canonical digest of the exact HTTP body
        (for consumption/replay kinds, the frozen fulfillment
        ``response_hash``); ``consumed_response_hash`` is the ``response_hash``
        of the canonical consumption this observation evidences. The summary
        validates both against independently stored rows, so a bare
        kind/status row can never power ``duplicate_proof_rejected``.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT OR IGNORE INTO safepay_redemption_observations("
                "kind, http_status, network, payment_hash, quote_id, resource_id, observed_at, "
                "response_digest, consumed_response_hash) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    kind,
                    http_status,
                    network,
                    payment_hash,
                    quote_id,
                    resource_id,
                    int(now),
                    response_digest,
                    consumed_response_hash,
                ),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

    def summarize_quote_evidence(
        self, quote_id: str, claimed_artifact: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Provider-side evidence summary derived ONLY from ledger rows.

        Any booleans carried by ``claimed_artifact`` (for example a forged
        ``duplicate_proof_rejected`` or ``proof.valid``) are ignored entirely;
        nothing from the claimed artifact is copied into the summary.

        ``duplicate_proof_rejected`` is TRUE only when ALL of the following hold,
        computed from rows — never from a bare observation ``kind``:

        1. exactly one canonical consumption exists for this ``quote_id``;
        2. an append-only observation exists whose ``kind`` is
           ``cross_binding_rejected`` AND whose actually observed
           ``http_status`` is exactly ``409`` (the terminal conflict result);
        3. that observation is on the SAME ``(network, payment_hash)`` as the
           canonical consumption;
        4. it evidences a genuinely DIFFERENT binding — a different quote and/or
           resource than the consumed one (never a same-binding "replay");
        5. it was observed at or after the canonical consumption (chronology):
           a 409 predating the consumption cannot evidence a duplicate of it;
        6. its ``consumed_response_hash`` equals the canonical consumption's
           independently stored ``response_hash`` (the observation is bound to
           the actual consumed fulfillment); and
        7. its ``response_digest`` equals the recomputed canonical digest of
           the exact frozen 409 error body the provider serves for a
           cross-binding conflict (the observation is bound to the response
           actually served — a directly inserted kind/status row without this
           binding can never qualify).

        HTTP 200, same-binding, unrelated-payment, pre-consumption, and
        unbound/forged observations therefore never contribute.
        """
        del claimed_artifact  # never trusted, never read
        expected_409_digest = safepay_v2_body_digest(
            safepay_v2_error_body(
                "payment_already_consumed_for_other_binding", False, "cross_binding_rejected"
            )
        )
        conn = self._connect()
        try:
            consumptions = conn.execute(
                "SELECT network, payment_hash, resource_id, consumed_at, response_hash "
                "FROM payment_consumptions WHERE quote_id = ?",
                (quote_id,),
            ).fetchall()
            kinds = {
                row["kind"]
                for row in conn.execute(
                    "SELECT DISTINCT kind FROM safepay_redemption_observations WHERE quote_id = ?",
                    (quote_id,),
                )
            }
            cross_binding_rejected_observed = False
            if len(consumptions) == 1:
                consumption = consumptions[0]
                cross_binding_rejected_observed = (
                    conn.execute(
                        "SELECT COUNT(*) FROM safepay_redemption_observations o "
                        "WHERE o.kind = 'cross_binding_rejected' "
                        "AND o.http_status = 409 "
                        "AND o.network = ? "
                        "AND o.payment_hash = ? "
                        "AND (o.quote_id != ? OR o.resource_id != ?) "
                        "AND o.observed_at >= ? "
                        "AND o.consumed_response_hash = ? "
                        "AND o.response_digest = ?",
                        (
                            consumption["network"],
                            consumption["payment_hash"],
                            quote_id,
                            consumption["resource_id"],
                            int(consumption["consumed_at"]),
                            consumption["response_hash"],
                            expected_409_digest,
                        ),
                    ).fetchone()[0]
                    >= 1
                )
        finally:
            conn.close()
        consumption_recorded = len(consumptions) == 1
        idempotent_replay_observed = "idempotent_replay" in kinds
        return {
            "schema_version": "safepay-evidence-summary-v2",
            "quote_id": quote_id,
            "source": "ledger_rows",
            "consumption_recorded": consumption_recorded,
            "idempotent_replay_observed": idempotent_replay_observed,
            "cross_binding_rejected_observed": cross_binding_rejected_observed,
            "duplicate_proof_rejected": consumption_recorded and cross_binding_rejected_observed,
        }
