"""Durable, replay-safe execution for v3-authorized native transfers.

The v3 contract authorizes an exact action but does not custody the treasury or
broadcast a native transfer.  This module is the trusted executor boundary.  It
persists the exact signed deploy bytes and deploy hash before the first network
write, then reconciles every uncertain outcome by that hash.  It never rebuilds
a transfer after preparation.

The public methods are deliberately synchronous and dependency-injected.  The
live release path supplies a signer, broadcaster, and chain reconciler; local
tests supply deterministic callables and perform no network mutation.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterator

from shared.native_transfer_deploy import (
    DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    NativeTransferDeployError,
    validate_signed_native_transfer_deploy,
)
from shared.native_transfer_finality import (
    FinalizedNativeTransferProof,
    NativeTransferFinalityError,
    require_verified_finalized_native_transfer,
    verify_finalized_native_transfer,
)
from shared.casper_state_proof import (
    CasperStateProofError,
    VerifiedAccountBalance,
    require_verified_account_balance,
    verify_account_balance_at_block,
)
from shared.native_transfer_scan import (
    NativeTransferScanError,
    VerifiedNoDuplicateNativeTransfer,
    require_verified_no_duplicate_native_transfer,
    verify_no_duplicate_native_transfer_transcript,
)
from shared.post_transfer_proof import (
    PostTransferBalanceProof,
    PostTransferProofError,
    require_verified_post_transfer_balance,
    verify_post_transfer_balance,
)
from shared.v3_authorization import (
    V3AuthorizationError,
    VerifiedNativeAuthorization,
    validate_verified_authorization,
)


CASPER_TEST_NETWORK = "casper-test"
MAX_U64 = (1 << 64) - 1
MAX_U512 = (1 << 512) - 1
MAX_SIGNED_DEPLOY_BYTES = 4 * 1024 * 1024
MAX_FINALITY_EVIDENCE_BYTES = 4 * 1024 * 1024
PROPOSAL_ID_RE = re.compile(r"^[A-Z0-9-]{1,64}$")
DETAIL_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TreasuryExecutorError(RuntimeError):
    """Base class for fail-closed executor errors."""


class AuthorizationMismatch(TreasuryExecutorError):
    """The requested action does not match finalized on-chain authorization."""


class JournalConflict(TreasuryExecutorError):
    """A replay key was already bound to different immutable data."""


class InvalidTransition(TreasuryExecutorError):
    """The requested operation is not valid in the current durable state."""


class ExecutionState(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    PREPARED = "PREPARED"
    SUBMITTED = "SUBMITTED"
    AMBIGUOUS_SUBMITTED = "AMBIGUOUS_SUBMITTED"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    FINALIZED = "FINALIZED"
    PROVEN = "PROVEN"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"


@dataclass(frozen=True)
class ExecutionKey:
    network: str
    action_id: bytes
    envelope_hash: bytes


@dataclass(frozen=True)
class BroadcastResult:
    """Sanitized result of submitting already-persisted signed bytes."""

    status: str
    deploy_hash: str
    detail_code: str | None = None


@dataclass(frozen=True)
class FinalityEvidence:
    """Raw node evidence parsed by the executor's strict finality boundary."""

    node_observations: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ReconciliationResult:
    """Sanitized deploy-hash reconciliation result."""

    status: str
    deploy_hash: str
    finality_evidence: FinalityEvidence | None = None
    detail_code: str | None = None


@dataclass(frozen=True)
class JournalEntry:
    """One immutable action binding plus its durable execution progress."""

    authorization: VerifiedNativeAuthorization
    payment_amount_motes: int
    state: ExecutionState
    signed_bytes: bytes | None
    signed_bytes_sha256: str | None
    deploy_hash: str | None
    broadcast_attempts: int
    broadcast_inflight_until: float | None
    last_detail_code: str | None
    block_hash: str | None
    block_height: int | None
    state_root_hash: str | None
    gas_motes: int | None
    finality_rpc_method: str | None
    execution_result_kind: str | None
    block_inclusion_path: str | None
    finality_checks: tuple[str, ...]
    corroboration_count: int | None
    finality_node_observations_json: str | None
    finality_proof: FinalizedNativeTransferProof | None
    post_transfer_proof: PostTransferBalanceProof | None
    no_duplicate_proof: VerifiedNoDuplicateNativeTransfer | None
    post_balance_evidence_json: str | None
    no_duplicate_scan_json: str | None
    execution_proof_sha256: str | None
    created_at: str
    updated_at: str

    @property
    def key(self) -> ExecutionKey:
        return ExecutionKey(
            self.authorization.network,
            self.authorization.action_id,
            self.authorization.envelope_hash,
        )

    @property
    def amount_motes(self) -> int:
        return self.authorization.amount_motes


PrepareCallback = Callable[[VerifiedNativeAuthorization], bytes]
BroadcastCallback = Callable[[bytes, str], BroadcastResult]
ReconcileCallback = Callable[[str], ReconciliationResult]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS treasury_execution_journal (
    network TEXT NOT NULL,
    action_id BLOB NOT NULL CHECK(length(action_id) = 32),
    envelope_hash BLOB NOT NULL CHECK(length(envelope_hash) = 32),
    proposal_id TEXT NOT NULL,
    source_account BLOB NOT NULL CHECK(length(source_account) = 32),
    recipient_account BLOB NOT NULL CHECK(length(recipient_account) = 32),
    amount_motes TEXT NOT NULL,
    treasury_snapshot_balance_motes TEXT NOT NULL,
    approved_allocation_bps INTEGER NOT NULL,
    transfer_id TEXT NOT NULL,
    snapshot_block_hash BLOB NOT NULL CHECK(length(snapshot_block_hash) = 32),
    snapshot_block_height TEXT NOT NULL,
    snapshot_state_root_hash BLOB NOT NULL CHECK(length(snapshot_state_root_hash) = 32),
    snapshot_status_request_json TEXT NOT NULL,
    snapshot_status_json TEXT NOT NULL,
    snapshot_block_request_json TEXT NOT NULL,
    snapshot_block_json TEXT NOT NULL,
    snapshot_balance_request_json TEXT NOT NULL,
    snapshot_balance_response_json TEXT NOT NULL,
    snapshot_status_request_sha256 TEXT NOT NULL,
    snapshot_status_sha256 TEXT NOT NULL,
    snapshot_block_request_sha256 TEXT NOT NULL,
    snapshot_block_sha256 TEXT NOT NULL,
    snapshot_balance_request_sha256 TEXT NOT NULL,
    snapshot_balance_response_sha256 TEXT NOT NULL,
    finalization_block_hash BLOB NOT NULL CHECK(length(finalization_block_hash) = 32),
    finalization_block_height TEXT NOT NULL,
    finalization_state_root_hash BLOB NOT NULL CHECK(length(finalization_state_root_hash) = 32),
    package_hash BLOB NOT NULL CHECK(length(package_hash) = 32),
    contract_hash BLOB NOT NULL CHECK(length(contract_hash) = 32),
    deployment_domain BLOB NOT NULL CHECK(length(deployment_domain) = 32),
    source_sha256 BLOB NOT NULL CHECK(length(source_sha256) = 32),
    wasm_sha256 BLOB NOT NULL CHECK(length(wasm_sha256) = 32),
    schema_sha256 BLOB NOT NULL CHECK(length(schema_sha256) = 32),
    header_bytes BLOB NOT NULL,
    body_bytes BLOB NOT NULL,
    action_core_bytes BLOB NOT NULL,
    typed_header_json TEXT NOT NULL,
    typed_body_json TEXT NOT NULL,
    readback_artifact_json TEXT NOT NULL,
    readback_artifact_sha256 TEXT NOT NULL,
    verification_seal BLOB NOT NULL CHECK(length(verification_seal) = 32),
    payment_amount_motes TEXT NOT NULL,
    state TEXT NOT NULL,
    signed_bytes BLOB,
    signed_bytes_sha256 TEXT,
    deploy_hash TEXT,
    broadcast_attempts INTEGER NOT NULL DEFAULT 0,
    broadcast_inflight_until REAL,
    last_detail_code TEXT,
    block_hash TEXT,
    block_height TEXT,
    state_root_hash TEXT,
    gas_motes TEXT,
    finality_rpc_method TEXT,
    execution_result_kind TEXT,
    block_inclusion_path TEXT,
    finality_checks_json TEXT,
    corroboration_count INTEGER,
    finality_node_observations_json TEXT,
    post_balance_evidence_json TEXT,
    no_duplicate_scan_json TEXT,
    execution_proof_sha256 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (network, action_id, envelope_hash),
    UNIQUE (network, action_id)
) WITHOUT ROWID;
"""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _require_bytes32(name: str, value: object, *, nonzero: bool = False) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    if nonzero and value == bytes(32):
        raise ValueError(f"{name} must be non-zero")
    return value


def _require_uint(name: str, value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise ValueError(f"{name} must be an unsigned integer no greater than {maximum}")
    return value


def _safe_detail_code(value: object, fallback: str) -> str:
    if isinstance(value, str) and DETAIL_CODE_RE.fullmatch(value):
        return value
    return fallback


def _canonical_json(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise NativeTransferFinalityError("finality evidence is not canonical JSON") from exc
    if len(encoded.encode("utf-8")) > MAX_FINALITY_EVIDENCE_BYTES:
        raise NativeTransferFinalityError("finality evidence exceeds size limit")
    return encoded


def _validate_authorization(authorization: VerifiedNativeAuthorization) -> None:
    try:
        validate_verified_authorization(authorization)
    except V3AuthorizationError as exc:
        raise AuthorizationMismatch(str(exc)) from exc
    if authorization.network != CASPER_TEST_NETWORK:
        raise ValueError(f"network must be exactly {CASPER_TEST_NETWORK}")
    if not PROPOSAL_ID_RE.fullmatch(authorization.proposal_id):
        raise ValueError("proposal_id does not match the v3 ASCII grammar")
    _require_bytes32("action_id", authorization.action_id, nonzero=True)
    _require_bytes32("envelope_hash", authorization.envelope_hash, nonzero=True)
    _require_bytes32("source_account", authorization.source_account, nonzero=True)
    _require_bytes32("recipient_account", authorization.recipient_account, nonzero=True)
    if authorization.source_account == authorization.recipient_account:
        raise ValueError("source_account and recipient_account must differ")
    _require_bytes32("snapshot_block_hash", authorization.snapshot_block_hash, nonzero=True)
    _require_bytes32(
        "snapshot_state_root_hash", authorization.snapshot_state_root_hash, nonzero=True
    )
    amount = _require_uint("amount_motes", authorization.amount_motes, MAX_U512)
    balance = _require_uint(
        "treasury_snapshot_balance_motes",
        authorization.treasury_snapshot_balance_motes,
        MAX_U512,
    )
    bps = _require_uint("approved_allocation_bps", authorization.approved_allocation_bps, 10_000)
    if amount == 0 or balance == 0 or bps == 0:
        raise ValueError("amount, treasury snapshot, and approved bps must be non-zero")
    expected_amount = (balance * bps) // 10_000
    if amount != expected_amount:
        raise ValueError(
            "amount_motes must equal floor(treasury_snapshot_balance_motes "
            "* approved_allocation_bps / 10000)"
        )
    _require_uint("transfer_id", authorization.transfer_id, MAX_U64)
    _require_uint("snapshot_block_height", authorization.snapshot_block_height, MAX_U64)


_BALANCE_TRANSCRIPT_FIELDS = {
    "status_request": "status_request_json",
    "status": "status_json",
    "block_request": "block_request_json",
    "block": "block_json",
    "balance_request": "balance_request_json",
    "balance_response": "balance_response_json",
}


def _balance_bundle(proof: VerifiedAccountBalance) -> dict[str, object]:
    verified = require_verified_account_balance(proof)
    return {
        label: json.loads(getattr(verified, attribute))
        for label, attribute in _BALANCE_TRANSCRIPT_FIELDS.items()
    }


def _parse_balance_bundle(
    value: object,
    *,
    account_hash: bytes,
    block_hash: bytes,
    block_height: int,
    state_root_hash: bytes,
    expected_balance_motes: int | None = None,
) -> VerifiedAccountBalance:
    item = value if type(value) is dict else None
    if item is None or set(item) != set(_BALANCE_TRANSCRIPT_FIELDS):
        raise JournalConflict("persisted execution proof balance evidence is malformed")
    try:
        return verify_account_balance_at_block(
            chain_status_request=item["status_request"],
            chain_status_payload=item["status"],
            canonical_block_request=item["block_request"],
            canonical_block_payload=item["block"],
            balance_request=item["balance_request"],
            balance_response=item["balance_response"],
            expected_account_hash=account_hash,
            expected_block_hash=block_hash,
            expected_block_height=block_height,
            expected_state_root_hash=state_root_hash,
            expected_balance_motes=expected_balance_motes,
        )
    except CasperStateProofError as exc:
        raise JournalConflict("persisted execution proof balance evidence is invalid") from exc


def _execution_proof_digest(
    post_balance_evidence_json: str,
    no_duplicate_scan_json: str,
    deploy_hash: str,
) -> str:
    material = {
        "post_balance_evidence_sha256": hashlib.sha256(
            post_balance_evidence_json.encode("ascii")
        ).hexdigest(),
        "no_duplicate_scan_sha256": hashlib.sha256(
            no_duplicate_scan_json.encode("ascii")
        ).hexdigest(),
        "deploy_hash": deploy_hash,
    }
    return hashlib.sha256(_canonical_json(material).encode("ascii")).hexdigest()


class TreasuryExecutor:
    """SQLite-backed state machine for exactly-once trusted execution.

    ``prepare`` intentionally invokes the local signer while holding an
    immediate SQLite write transaction.  That makes preparation a single
    cross-process claim.  Signing must therefore be local and bounded; network
    I/O belongs exclusively in ``broadcast`` after the bytes are committed.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        payment_amount_motes: int = DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        inflight_lease_seconds: float = 30.0,
        clock: Callable[[], float] = time.time,
    ):
        self.database_path = Path(database_path)
        if str(database_path) == ":memory:":
            raise ValueError("the treasury executor requires a durable file-backed database")
        self.payment_amount_motes = _require_uint(
            "payment_amount_motes", payment_amount_motes, MAX_U512
        )
        if self.payment_amount_motes == 0:
            raise ValueError("payment_amount_motes must be non-zero")
        if not isinstance(inflight_lease_seconds, (int, float)) or isinstance(
            inflight_lease_seconds, bool
        ) or inflight_lease_seconds <= 0:
            raise ValueError("inflight_lease_seconds must be positive")
        self.inflight_lease_seconds = float(inflight_lease_seconds)
        self.clock = clock
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(
            self.database_path,
            timeout=30.0,
            isolation_level=None,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        db.execute("BEGIN IMMEDIATE")
        try:
            yield db
        except BaseException:
            db.execute("ROLLBACK")
            raise
        else:
            db.execute("COMMIT")
        finally:
            db.close()

    @staticmethod
    def _fetch(db: sqlite3.Connection, key: ExecutionKey) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM treasury_execution_journal "
            "WHERE network=? AND action_id=? AND envelope_hash=?",
            (key.network, key.action_id, key.envelope_hash),
        ).fetchone()
        if row is None:
            raise KeyError("treasury execution journal entry not found")
        return row

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> JournalEntry:
        authorization = VerifiedNativeAuthorization(
            network=str(row["network"]),
            proposal_id=str(row["proposal_id"]),
            action_id=bytes(row["action_id"]),
            envelope_hash=bytes(row["envelope_hash"]),
            source_account=bytes(row["source_account"]),
            recipient_account=bytes(row["recipient_account"]),
            amount_motes=int(row["amount_motes"]),
            treasury_snapshot_balance_motes=int(row["treasury_snapshot_balance_motes"]),
            approved_allocation_bps=int(row["approved_allocation_bps"]),
            transfer_id=int(row["transfer_id"]),
            snapshot_block_hash=bytes(row["snapshot_block_hash"]),
            snapshot_block_height=int(row["snapshot_block_height"]),
            snapshot_state_root_hash=bytes(row["snapshot_state_root_hash"]),
            snapshot_status_request_json=str(row["snapshot_status_request_json"]),
            snapshot_status_json=str(row["snapshot_status_json"]),
            snapshot_block_request_json=str(row["snapshot_block_request_json"]),
            snapshot_block_json=str(row["snapshot_block_json"]),
            snapshot_balance_request_json=str(row["snapshot_balance_request_json"]),
            snapshot_balance_response_json=str(row["snapshot_balance_response_json"]),
            snapshot_status_request_sha256=str(row["snapshot_status_request_sha256"]),
            snapshot_status_sha256=str(row["snapshot_status_sha256"]),
            snapshot_block_request_sha256=str(row["snapshot_block_request_sha256"]),
            snapshot_block_sha256=str(row["snapshot_block_sha256"]),
            snapshot_balance_request_sha256=str(row["snapshot_balance_request_sha256"]),
            snapshot_balance_response_sha256=str(row["snapshot_balance_response_sha256"]),
            finalization_block_hash=bytes(row["finalization_block_hash"]),
            finalization_block_height=int(row["finalization_block_height"]),
            finalization_state_root_hash=bytes(row["finalization_state_root_hash"]),
            package_hash=bytes(row["package_hash"]),
            contract_hash=bytes(row["contract_hash"]),
            deployment_domain=bytes(row["deployment_domain"]),
            source_sha256=bytes(row["source_sha256"]),
            wasm_sha256=bytes(row["wasm_sha256"]),
            schema_sha256=bytes(row["schema_sha256"]),
            header_bytes=bytes(row["header_bytes"]),
            body_bytes=bytes(row["body_bytes"]),
            action_core_bytes=bytes(row["action_core_bytes"]),
            typed_header_json=str(row["typed_header_json"]),
            typed_body_json=str(row["typed_body_json"]),
            readback_artifact_json=str(row["readback_artifact_json"]),
            readback_artifact_sha256=str(row["readback_artifact_sha256"]),
            verification_seal=bytes(row["verification_seal"]),
        )
        _validate_authorization(authorization)
        signed_bytes = row["signed_bytes"]
        signed_bytes = None if signed_bytes is None else bytes(signed_bytes)
        state = ExecutionState(row["state"])
        finality_checks = (
            ()
            if row["finality_checks_json"] is None
            else tuple(json.loads(str(row["finality_checks_json"])))
        )
        finality_node_observations_json = row["finality_node_observations_json"]
        verified_finality: FinalizedNativeTransferProof | None = None
        post_transfer_proof: PostTransferBalanceProof | None = None
        no_duplicate_proof: VerifiedNoDuplicateNativeTransfer | None = None
        if state in {ExecutionState.FINALIZED, ExecutionState.PROVEN}:
            if (
                signed_bytes is None
                or row["deploy_hash"] is None
                or finality_node_observations_json is None
            ):
                raise JournalConflict("finalized journal is missing strict node evidence")
            try:
                node_observations = json.loads(str(finality_node_observations_json))
                if type(node_observations) is not list or any(
                    type(item) is not dict for item in node_observations
                ):
                    raise TypeError("node observations must be a list of objects")
                verified_finality = verify_finalized_native_transfer(
                    requested_deploy_hash=str(row["deploy_hash"]),
                    node_observations=tuple(node_observations),
                    signed_deploy_bytes=signed_bytes,
                    expected_source_account_hash=authorization.source_account,
                    expected_recipient_account_hash=authorization.recipient_account,
                    expected_amount_motes=authorization.amount_motes,
                    expected_transfer_id=authorization.transfer_id,
                    expected_payment_amount_motes=int(row["payment_amount_motes"]),
                    max_payment_amount_motes=int(row["payment_amount_motes"]),
                )
                verified_finality = require_verified_finalized_native_transfer(
                    verified_finality
                )
            except (json.JSONDecodeError, TypeError, NativeTransferFinalityError) as exc:
                raise JournalConflict("persisted finality evidence is invalid") from exc
            stored_finality = (
                row["block_hash"],
                None if row["block_height"] is None else int(row["block_height"]),
                row["state_root_hash"],
                None if row["gas_motes"] is None else int(row["gas_motes"]),
                row["finality_rpc_method"],
                row["execution_result_kind"],
                row["block_inclusion_path"],
                finality_checks,
                None
                if row["corroboration_count"] is None
                else int(row["corroboration_count"]),
            )
            proven_finality = (
                verified_finality.block_hash,
                verified_finality.block_height,
                verified_finality.state_root_hash,
                verified_finality.gas_motes,
                verified_finality.rpc_method,
                verified_finality.execution_result_kind,
                verified_finality.block_inclusion_path,
                verified_finality.finality_checks,
                verified_finality.corroboration_count,
            )
            if stored_finality != proven_finality:
                raise JournalConflict("persisted finality fields do not match node evidence")
        post_balance_evidence_json = row["post_balance_evidence_json"]
        no_duplicate_scan_json = row["no_duplicate_scan_json"]
        execution_proof_sha256 = row["execution_proof_sha256"]
        if state is ExecutionState.PROVEN:
            if (
                verified_finality is None
                or post_balance_evidence_json is None
                or no_duplicate_scan_json is None
                or execution_proof_sha256 is None
            ):
                raise JournalConflict("proven journal is missing execution proof evidence")
            try:
                post_bundle = json.loads(str(post_balance_evidence_json))
                if type(post_bundle) is not dict or set(post_bundle) != {
                    "pre_source",
                    "pre_recipient",
                    "post_source",
                    "post_recipient",
                }:
                    raise TypeError("post-balance bundle fields are not exact")
                canonical_post = _canonical_json(post_bundle)
                if canonical_post != str(post_balance_evidence_json):
                    raise TypeError("post-balance bundle is not canonical")
                pre_source = _parse_balance_bundle(
                    post_bundle["pre_source"],
                    account_hash=authorization.source_account,
                    block_hash=authorization.snapshot_block_hash,
                    block_height=authorization.snapshot_block_height,
                    state_root_hash=authorization.snapshot_state_root_hash,
                    expected_balance_motes=(
                        authorization.treasury_snapshot_balance_motes
                    ),
                )
                pre_recipient = _parse_balance_bundle(
                    post_bundle["pre_recipient"],
                    account_hash=authorization.recipient_account,
                    block_hash=authorization.snapshot_block_hash,
                    block_height=authorization.snapshot_block_height,
                    state_root_hash=authorization.snapshot_state_root_hash,
                )
                finality_block = bytes.fromhex(verified_finality.block_hash)
                finality_root = bytes.fromhex(verified_finality.state_root_hash)
                post_source = _parse_balance_bundle(
                    post_bundle["post_source"],
                    account_hash=authorization.source_account,
                    block_hash=finality_block,
                    block_height=verified_finality.block_height,
                    state_root_hash=finality_root,
                )
                post_recipient = _parse_balance_bundle(
                    post_bundle["post_recipient"],
                    account_hash=authorization.recipient_account,
                    block_hash=finality_block,
                    block_height=verified_finality.block_height,
                    state_root_hash=finality_root,
                )
                post_transfer_proof = verify_post_transfer_balance(
                    pre_source_balance=pre_source,
                    pre_recipient_balance=pre_recipient,
                    post_source_balance=post_source,
                    post_recipient_balance=post_recipient,
                    finality_proof=verified_finality,
                    expected_source_account_hash=authorization.source_account,
                    expected_recipient_account_hash=authorization.recipient_account,
                    expected_amount_motes=authorization.amount_motes,
                )
                post_transfer_proof = require_verified_post_transfer_balance(
                    post_transfer_proof
                )
                no_duplicate_proof = verify_no_duplicate_native_transfer_transcript(
                    str(no_duplicate_scan_json),
                    finality_proof=verified_finality,
                )
                no_duplicate_proof = require_verified_no_duplicate_native_transfer(
                    no_duplicate_proof
                )
                if (
                    no_duplicate_proof.authorization_block_height
                    != authorization.finalization_block_height
                ):
                    raise NativeTransferScanError(
                        "scan does not begin at the v3 authorization block"
                    )
                digest = _execution_proof_digest(
                    canonical_post,
                    str(no_duplicate_scan_json),
                    verified_finality.deploy_hash,
                )
                if digest != execution_proof_sha256:
                    raise TypeError("execution proof digest does not match")
            except (
                json.JSONDecodeError,
                TypeError,
                ValueError,
                NativeTransferScanError,
                PostTransferProofError,
            ) as exc:
                if isinstance(exc, JournalConflict):
                    raise
                raise JournalConflict("persisted execution proof is invalid") from exc
        return JournalEntry(
            authorization=authorization,
            payment_amount_motes=int(row["payment_amount_motes"]),
            state=state,
            signed_bytes=signed_bytes,
            signed_bytes_sha256=row["signed_bytes_sha256"],
            deploy_hash=row["deploy_hash"],
            broadcast_attempts=int(row["broadcast_attempts"]),
            broadcast_inflight_until=(
                None
                if row["broadcast_inflight_until"] is None
                else float(row["broadcast_inflight_until"])
            ),
            last_detail_code=row["last_detail_code"],
            block_hash=row["block_hash"],
            block_height=None if row["block_height"] is None else int(row["block_height"]),
            state_root_hash=row["state_root_hash"],
            gas_motes=None if row["gas_motes"] is None else int(row["gas_motes"]),
            finality_rpc_method=row["finality_rpc_method"],
            execution_result_kind=row["execution_result_kind"],
            block_inclusion_path=row["block_inclusion_path"],
            finality_checks=finality_checks,
            corroboration_count=(
                None
                if row["corroboration_count"] is None
                else int(row["corroboration_count"])
            ),
            finality_node_observations_json=finality_node_observations_json,
            finality_proof=verified_finality,
            post_transfer_proof=post_transfer_proof,
            no_duplicate_proof=no_duplicate_proof,
            post_balance_evidence_json=post_balance_evidence_json,
            no_duplicate_scan_json=no_duplicate_scan_json,
            execution_proof_sha256=execution_proof_sha256,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def authorize(
        self,
        authorization: VerifiedNativeAuthorization,
    ) -> JournalEntry:
        """Persist only factory-verified exact-envelope authorization."""

        _validate_authorization(authorization)
        key = ExecutionKey(
            authorization.network,
            authorization.action_id,
            authorization.envelope_hash,
        )
        now = _utc_now()
        with self._write_transaction() as db:
            existing = db.execute(
                "SELECT * FROM treasury_execution_journal WHERE network=? AND action_id=?",
                (authorization.network, authorization.action_id),
            ).fetchone()
            if existing is not None:
                entry = self._row_to_entry(existing)
                if entry.authorization != authorization:
                    raise JournalConflict(
                        "action_id is already bound to different immutable authorization data"
                    )
                return entry
            try:
                db.execute(
                    "INSERT INTO treasury_execution_journal ("
                    "network, action_id, envelope_hash, proposal_id, source_account, "
                    "recipient_account, amount_motes, treasury_snapshot_balance_motes, "
                    "approved_allocation_bps, transfer_id, snapshot_block_hash, "
                    "snapshot_block_height, snapshot_state_root_hash, "
                    "snapshot_status_request_json, snapshot_status_json, "
                    "snapshot_block_request_json, snapshot_block_json, "
                    "snapshot_balance_request_json, snapshot_balance_response_json, "
                    "snapshot_status_request_sha256, snapshot_status_sha256, "
                    "snapshot_block_request_sha256, snapshot_block_sha256, "
                    "snapshot_balance_request_sha256, snapshot_balance_response_sha256, "
                    "finalization_block_hash, finalization_block_height, "
                    "finalization_state_root_hash, package_hash, contract_hash, "
                    "deployment_domain, source_sha256, wasm_sha256, schema_sha256, "
                    "header_bytes, body_bytes, action_core_bytes, typed_header_json, "
                    "typed_body_json, readback_artifact_json, readback_artifact_sha256, "
                    "verification_seal, "
                    "payment_amount_motes, state, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?, ?)",
                    (
                        authorization.network,
                        authorization.action_id,
                        authorization.envelope_hash,
                        authorization.proposal_id,
                        authorization.source_account,
                        authorization.recipient_account,
                        str(authorization.amount_motes),
                        str(authorization.treasury_snapshot_balance_motes),
                        authorization.approved_allocation_bps,
                        str(authorization.transfer_id),
                        authorization.snapshot_block_hash,
                        str(authorization.snapshot_block_height),
                        authorization.snapshot_state_root_hash,
                        authorization.snapshot_status_request_json,
                        authorization.snapshot_status_json,
                        authorization.snapshot_block_request_json,
                        authorization.snapshot_block_json,
                        authorization.snapshot_balance_request_json,
                        authorization.snapshot_balance_response_json,
                        authorization.snapshot_status_request_sha256,
                        authorization.snapshot_status_sha256,
                        authorization.snapshot_block_request_sha256,
                        authorization.snapshot_block_sha256,
                        authorization.snapshot_balance_request_sha256,
                        authorization.snapshot_balance_response_sha256,
                        authorization.finalization_block_hash,
                        str(authorization.finalization_block_height),
                        authorization.finalization_state_root_hash,
                        authorization.package_hash,
                        authorization.contract_hash,
                        authorization.deployment_domain,
                        authorization.source_sha256,
                        authorization.wasm_sha256,
                        authorization.schema_sha256,
                        authorization.header_bytes,
                        authorization.body_bytes,
                        authorization.action_core_bytes,
                        authorization.typed_header_json,
                        authorization.typed_body_json,
                        authorization.readback_artifact_json,
                        authorization.readback_artifact_sha256,
                        authorization.verification_seal,
                        str(self.payment_amount_motes),
                        ExecutionState.AUTHORIZED.value,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise JournalConflict("journal replay key already exists") from exc
            return self._row_to_entry(self._fetch(db, key))

    def prepare(self, key: ExecutionKey, prepare: PrepareCallback) -> JournalEntry:
        """Claim AUTHORIZED and commit exact signed bytes before any broadcast."""

        with self._write_transaction() as db:
            entry = self._row_to_entry(self._fetch(db, key))
            if entry.state is not ExecutionState.AUTHORIZED:
                return entry

            signed_bytes = prepare(entry.authorization)
            if not isinstance(signed_bytes, bytes) or not signed_bytes:
                raise ValueError("signed_bytes must be non-empty bytes")
            if len(signed_bytes) > MAX_SIGNED_DEPLOY_BYTES:
                raise ValueError("signed_bytes exceeds the executor size limit")
            try:
                facts = validate_signed_native_transfer_deploy(
                    signed_bytes,
                    expected_source_account_hash=entry.authorization.source_account,
                    expected_recipient_account_hash=entry.authorization.recipient_account,
                    expected_amount_motes=entry.authorization.amount_motes,
                    expected_transfer_id=entry.authorization.transfer_id,
                    expected_payment_amount_motes=entry.payment_amount_motes,
                    max_payment_amount_motes=entry.payment_amount_motes,
                )
            except NativeTransferDeployError as exc:
                raise AuthorizationMismatch(f"prepared signed deploy is invalid: {exc}") from exc
            deploy_hash = facts.deploy_hash_hex
            signed_hash = hashlib.sha256(signed_bytes).hexdigest()
            db.execute(
                "UPDATE treasury_execution_journal SET state=?, signed_bytes=?, "
                "signed_bytes_sha256=?, deploy_hash=?, last_detail_code=NULL, updated_at=? "
                "WHERE network=? AND action_id=? AND envelope_hash=? AND state=?",
                (
                    ExecutionState.PREPARED.value,
                    signed_bytes,
                    signed_hash,
                    deploy_hash,
                    _utc_now(),
                    key.network,
                    key.action_id,
                    key.envelope_hash,
                    ExecutionState.AUTHORIZED.value,
                ),
            )
            return self._row_to_entry(self._fetch(db, key))

    def broadcast(self, key: ExecutionKey, broadcast: BroadcastCallback) -> JournalEntry:
        """Broadcast only bytes already committed under the immutable replay key.

        The journal moves to ``AMBIGUOUS_SUBMITTED`` and commits before invoking
        the callback.  A process crash at any later instruction therefore
        recovers through deploy-hash reconciliation rather than rebuilding.
        """

        with self._write_transaction() as db:
            entry = self._row_to_entry(self._fetch(db, key))
            if entry.state not in {ExecutionState.PREPARED, ExecutionState.RETRYABLE_FAILURE}:
                return entry
            if entry.signed_bytes is None or entry.deploy_hash is None:
                raise InvalidTransition("prepared journal entry is missing signed bytes or hash")
            if (
                entry.signed_bytes_sha256 is None
                or hashlib.sha256(entry.signed_bytes).hexdigest()
                != entry.signed_bytes_sha256
            ):
                return self._set_failure(db, entry, "signed_bytes_digest_mismatch")
            try:
                facts = validate_signed_native_transfer_deploy(
                    entry.signed_bytes,
                    expected_source_account_hash=entry.authorization.source_account,
                    expected_recipient_account_hash=entry.authorization.recipient_account,
                    expected_amount_motes=entry.authorization.amount_motes,
                    expected_transfer_id=entry.authorization.transfer_id,
                    expected_payment_amount_motes=entry.payment_amount_motes,
                    max_payment_amount_motes=entry.payment_amount_motes,
                )
            except NativeTransferDeployError:
                return self._set_failure(db, entry, "signed_deploy_validation_failed")
            if facts.deploy_hash_hex != entry.deploy_hash:
                return self._set_failure(db, entry, "signed_deploy_hash_mismatch")
            db.execute(
                "UPDATE treasury_execution_journal SET state=?, broadcast_attempts=?, "
                "broadcast_inflight_until=?, last_detail_code=?, updated_at=? "
                "WHERE network=? AND action_id=? "
                "AND envelope_hash=? AND state=?",
                (
                    ExecutionState.AMBIGUOUS_SUBMITTED.value,
                    entry.broadcast_attempts + 1,
                    self.clock() + self.inflight_lease_seconds,
                    "broadcast_inflight",
                    _utc_now(),
                    key.network,
                    key.action_id,
                    key.envelope_hash,
                    entry.state.value,
                ),
            )
            claimed = self._row_to_entry(self._fetch(db, key))

        try:
            result = broadcast(claimed.signed_bytes or b"", claimed.deploy_hash or "")
            if not isinstance(result, BroadcastResult):
                raise TypeError("broadcast callback must return BroadcastResult")
        except Exception as exc:
            result = BroadcastResult(
                status="ambiguous",
                deploy_hash=claimed.deploy_hash or "",
                detail_code=f"broadcast_exception_{type(exc).__name__}",
            )
        return self._record_broadcast_result(key, result)

    def _record_broadcast_result(
        self,
        key: ExecutionKey,
        result: BroadcastResult,
    ) -> JournalEntry:
        state_by_status = {
            "accepted": ExecutionState.SUBMITTED,
            "ambiguous": ExecutionState.AMBIGUOUS_SUBMITTED,
            "retryable_failure": ExecutionState.RETRYABLE_FAILURE,
        }
        target_state = state_by_status.get(result.status)
        if result.status == "terminal_failure":
            target_state = ExecutionState.AMBIGUOUS_SUBMITTED
            detail = "unverified_broadcast_terminal_failure"
        elif target_state is None:
            target_state = ExecutionState.AMBIGUOUS_SUBMITTED
            detail = "invalid_broadcast_status"
        else:
            detail = _safe_detail_code(result.detail_code, f"broadcast_{result.status}")

        with self._write_transaction() as db:
            entry = self._row_to_entry(self._fetch(db, key))
            if entry.state is not ExecutionState.AMBIGUOUS_SUBMITTED:
                return entry
            if result.deploy_hash != entry.deploy_hash:
                target_state = ExecutionState.AMBIGUOUS_SUBMITTED
                detail = "broadcast_response_hash_mismatch"
            db.execute(
                "UPDATE treasury_execution_journal SET state=?, broadcast_inflight_until=NULL, "
                "last_detail_code=?, "
                "updated_at=? WHERE network=? AND action_id=? AND envelope_hash=? "
                "AND state=?",
                (
                    target_state.value,
                    detail,
                    _utc_now(),
                    key.network,
                    key.action_id,
                    key.envelope_hash,
                    ExecutionState.AMBIGUOUS_SUBMITTED.value,
                ),
            )
            return self._row_to_entry(self._fetch(db, key))

    def reconcile(self, key: ExecutionKey, reconcile: ReconcileCallback) -> JournalEntry:
        """Resolve an existing deploy by hash without constructing a transfer."""

        entry = self.get(key)
        if entry.state in {
            ExecutionState.FINALIZED,
            ExecutionState.PROVEN,
            ExecutionState.TERMINAL_FAILURE,
        }:
            return entry
        if entry.state not in {
            ExecutionState.SUBMITTED,
            ExecutionState.AMBIGUOUS_SUBMITTED,
            ExecutionState.RETRYABLE_FAILURE,
        }:
            raise InvalidTransition(f"cannot reconcile from {entry.state.value}")
        if entry.deploy_hash is None:
            raise InvalidTransition("submitted journal entry has no deploy hash")
        if (
            entry.state is ExecutionState.AMBIGUOUS_SUBMITTED
            and entry.broadcast_inflight_until is not None
            and entry.broadcast_inflight_until > self.clock()
        ):
            return entry
        try:
            result = reconcile(entry.deploy_hash)
            if not isinstance(result, ReconciliationResult):
                raise TypeError("reconcile callback must return ReconciliationResult")
        except Exception as exc:
            return self._record_reconcile_exception(key, type(exc).__name__)
        return self._record_reconciliation(key, result)

    def _record_reconcile_exception(self, key: ExecutionKey, error_name: str) -> JournalEntry:
        with self._write_transaction() as db:
            entry = self._row_to_entry(self._fetch(db, key))
            if entry.state in {
                ExecutionState.FINALIZED,
                ExecutionState.PROVEN,
                ExecutionState.TERMINAL_FAILURE,
            }:
                return entry
            db.execute(
                "UPDATE treasury_execution_journal SET broadcast_inflight_until=NULL, "
                "last_detail_code=?, updated_at=? "
                "WHERE network=? AND action_id=? AND envelope_hash=?",
                (
                    _safe_detail_code(
                        f"reconcile_exception_{error_name}",
                        "reconcile_exception",
                    ),
                    _utc_now(),
                    key.network,
                    key.action_id,
                    key.envelope_hash,
                ),
            )
            return self._row_to_entry(self._fetch(db, key))

    def prove_execution(
        self,
        key: ExecutionKey,
        *,
        pre_source_balance: VerifiedAccountBalance | None = None,
        pre_recipient_balance: VerifiedAccountBalance | None = None,
        post_source_balance: VerifiedAccountBalance | None = None,
        post_recipient_balance: VerifiedAccountBalance | None = None,
        no_duplicate_proof: VerifiedNoDuplicateNativeTransfer | None = None,
    ) -> JournalEntry:
        """Promote FINALIZED to PROVEN from persisted, independently parsed evidence.

        This transition has no network side effect.  It binds exact before/after
        balances and a contiguous, time-bounded transfer scan to the already
        persisted signed deploy and v3 authorization.
        """

        with self._write_transaction() as db:
            entry = self._row_to_entry(self._fetch(db, key))
            if entry.state is ExecutionState.PROVEN:
                return entry
            if entry.state is not ExecutionState.FINALIZED:
                raise InvalidTransition(f"cannot prove execution from {entry.state.value}")
            if entry.finality_proof is None:
                raise JournalConflict("finalized journal is missing parser-verified finality")
            try:
                pre_source = require_verified_account_balance(pre_source_balance)
                pre_recipient = require_verified_account_balance(pre_recipient_balance)
                post_source = require_verified_account_balance(post_source_balance)
                post_recipient = require_verified_account_balance(post_recipient_balance)
                scan = require_verified_no_duplicate_native_transfer(
                    no_duplicate_proof
                )
            except (CasperStateProofError, NativeTransferScanError) as exc:
                raise JournalConflict("execution proof input is not parser-verified") from exc

            authorization = entry.authorization
            if (
                pre_source.account_hash != authorization.source_account
                or pre_source.block_hash != authorization.snapshot_block_hash
                or pre_source.block_height != authorization.snapshot_block_height
                or pre_source.state_root_hash
                != authorization.snapshot_state_root_hash
                or pre_source.balance_motes
                != authorization.treasury_snapshot_balance_motes
            ):
                raise JournalConflict(
                    "pre-source evidence does not equal the authorization snapshot"
                )
            try:
                post_proof = verify_post_transfer_balance(
                    pre_source_balance=pre_source,
                    pre_recipient_balance=pre_recipient,
                    post_source_balance=post_source,
                    post_recipient_balance=post_recipient,
                    finality_proof=entry.finality_proof,
                    expected_source_account_hash=authorization.source_account,
                    expected_recipient_account_hash=authorization.recipient_account,
                    expected_amount_motes=authorization.amount_motes,
                )
                require_verified_post_transfer_balance(post_proof)
                reparsed_scan = verify_no_duplicate_native_transfer_transcript(
                    scan.transcript_json,
                    finality_proof=entry.finality_proof,
                )
                reparsed_scan = require_verified_no_duplicate_native_transfer(
                    reparsed_scan
                )
            except (PostTransferProofError, NativeTransferScanError) as exc:
                raise JournalConflict("execution proof does not match finalized action") from exc
            if (
                reparsed_scan.authorization_block_height
                != authorization.finalization_block_height
            ):
                raise JournalConflict(
                    "no-duplicate scan does not begin at the v3 authorization block"
                )

            post_bundle = {
                "pre_source": _balance_bundle(pre_source),
                "pre_recipient": _balance_bundle(pre_recipient),
                "post_source": _balance_bundle(post_source),
                "post_recipient": _balance_bundle(post_recipient),
            }
            post_json = _canonical_json(post_bundle)
            scan_json = reparsed_scan.transcript_json
            digest = _execution_proof_digest(
                post_json,
                scan_json,
                entry.finality_proof.deploy_hash,
            )
            db.execute(
                "UPDATE treasury_execution_journal SET state=?, "
                "post_balance_evidence_json=?, no_duplicate_scan_json=?, "
                "execution_proof_sha256=?, last_detail_code=?, updated_at=? "
                "WHERE network=? AND action_id=? AND envelope_hash=? AND state=?",
                (
                    ExecutionState.PROVEN.value,
                    post_json,
                    scan_json,
                    digest,
                    "execution_proven",
                    _utc_now(),
                    key.network,
                    key.action_id,
                    key.envelope_hash,
                    ExecutionState.FINALIZED.value,
                ),
            )
            return self._row_to_entry(self._fetch(db, key))

    def _record_reconciliation(
        self,
        key: ExecutionKey,
        result: ReconciliationResult,
    ) -> JournalEntry:
        with self._write_transaction() as db:
            entry = self._row_to_entry(self._fetch(db, key))
            if entry.state in {
                ExecutionState.FINALIZED,
                ExecutionState.PROVEN,
                ExecutionState.TERMINAL_FAILURE,
            }:
                return entry
            if result.deploy_hash != entry.deploy_hash:
                return self._retain_unverified(
                    db,
                    entry,
                    "reconcile_deploy_hash_mismatch",
                )

            if result.status != "finalized" and result.finality_evidence is not None:
                return self._retain_unverified(db, entry, "unexpected_finality_evidence")

            if result.status == "pending":
                target_state = ExecutionState.SUBMITTED
                detail = _safe_detail_code(result.detail_code, "deploy_pending")
            elif result.status == "retryable_absent":
                target_state = ExecutionState.RETRYABLE_FAILURE
                detail = _safe_detail_code(result.detail_code, "deploy_confirmed_absent")
            elif result.status == "terminal_failure":
                return self._retain_unverified(
                    db,
                    entry,
                    "unverified_reconcile_terminal_failure",
                )
            elif result.status == "finalized":
                if result.finality_evidence is None:
                    return self._retain_unverified(db, entry, "finality_evidence_missing")
                if entry.signed_bytes is None:
                    return self._set_failure(db, entry, "signed_bytes_missing")
                try:
                    proof = verify_finalized_native_transfer(
                        requested_deploy_hash=entry.deploy_hash or "",
                        node_observations=result.finality_evidence.node_observations,
                        signed_deploy_bytes=entry.signed_bytes,
                        expected_source_account_hash=entry.authorization.source_account,
                        expected_recipient_account_hash=entry.authorization.recipient_account,
                        expected_amount_motes=entry.authorization.amount_motes,
                        expected_transfer_id=entry.authorization.transfer_id,
                        expected_payment_amount_motes=entry.payment_amount_motes,
                        max_payment_amount_motes=entry.payment_amount_motes,
                    )
                    proof = require_verified_finalized_native_transfer(proof)
                except NativeTransferFinalityError:
                    return self._retain_unverified(db, entry, "finality_evidence_invalid")
                try:
                    finality_node_observations_json = _canonical_json(
                        list(result.finality_evidence.node_observations)
                    )
                except NativeTransferFinalityError:
                    return self._retain_unverified(db, entry, "finality_evidence_invalid")
                db.execute(
                    "UPDATE treasury_execution_journal SET state=?, "
                    "broadcast_inflight_until=NULL, last_detail_code=?, "
                    "block_hash=?, block_height=?, state_root_hash=?, gas_motes=?, "
                    "finality_rpc_method=?, execution_result_kind=?, "
                    "block_inclusion_path=?, finality_checks_json=?, "
                    "corroboration_count=?, finality_node_observations_json=?, updated_at=? "
                    "WHERE network=? AND action_id=? AND envelope_hash=?",
                    (
                        ExecutionState.FINALIZED.value,
                        _safe_detail_code(result.detail_code, "deploy_finalized"),
                        proof.block_hash,
                        str(proof.block_height),
                        proof.state_root_hash,
                        str(proof.gas_motes),
                        proof.rpc_method,
                        proof.execution_result_kind,
                        proof.block_inclusion_path,
                        json.dumps(
                            list(proof.finality_checks),
                            separators=(",", ":"),
                        ),
                        proof.corroboration_count,
                        finality_node_observations_json,
                        _utc_now(),
                        key.network,
                        key.action_id,
                        key.envelope_hash,
                    ),
                )
                return self._row_to_entry(self._fetch(db, key))
            else:
                return self._retain_unverified(
                    db,
                    entry,
                    "invalid_reconciliation_status",
                )

            db.execute(
                "UPDATE treasury_execution_journal SET state=?, "
                "broadcast_inflight_until=NULL, last_detail_code=?, "
                "updated_at=? WHERE network=? AND action_id=? AND envelope_hash=?",
                (
                    target_state.value,
                    detail,
                    _utc_now(),
                    key.network,
                    key.action_id,
                    key.envelope_hash,
                ),
            )
            return self._row_to_entry(self._fetch(db, key))

    @staticmethod
    def _retain_unverified(
        db: sqlite3.Connection,
        entry: JournalEntry,
        detail_code: str,
    ) -> JournalEntry:
        """Record unsupported callback truth without making it irreversible."""

        key = entry.key
        db.execute(
            "UPDATE treasury_execution_journal SET broadcast_inflight_until=NULL, "
            "last_detail_code=?, updated_at=? "
            "WHERE network=? AND action_id=? AND envelope_hash=?",
            (
                _safe_detail_code(detail_code, "unverified_observation"),
                _utc_now(),
                key.network,
                key.action_id,
                key.envelope_hash,
            ),
        )
        return TreasuryExecutor._row_to_entry(TreasuryExecutor._fetch(db, key))

    @staticmethod
    def _set_failure(
        db: sqlite3.Connection,
        entry: JournalEntry,
        detail_code: str,
    ) -> JournalEntry:
        key = entry.key
        db.execute(
            "UPDATE treasury_execution_journal SET state=?, broadcast_inflight_until=NULL, "
            "last_detail_code=?, "
            "updated_at=? WHERE network=? AND action_id=? AND envelope_hash=?",
            (
                ExecutionState.TERMINAL_FAILURE.value,
                _safe_detail_code(detail_code, "terminal_failure"),
                _utc_now(),
                key.network,
                key.action_id,
                key.envelope_hash,
            ),
        )
        row = TreasuryExecutor._fetch(db, key)
        return TreasuryExecutor._row_to_entry(row)

    def resume(
        self,
        key: ExecutionKey,
        *,
        prepare: PrepareCallback | None = None,
        broadcast: BroadcastCallback | None = None,
        reconcile: ReconcileCallback | None = None,
    ) -> JournalEntry:
        """Advance one safe state-machine edge after process restart."""

        entry = self.get(key)
        if entry.state in {
            ExecutionState.FINALIZED,
            ExecutionState.PROVEN,
            ExecutionState.TERMINAL_FAILURE,
        }:
            return entry
        if entry.state is ExecutionState.AUTHORIZED:
            return entry if prepare is None else self.prepare(key, prepare)
        if entry.state in {ExecutionState.PREPARED, ExecutionState.RETRYABLE_FAILURE}:
            return entry if broadcast is None else self.broadcast(key, broadcast)
        if entry.state in {ExecutionState.SUBMITTED, ExecutionState.AMBIGUOUS_SUBMITTED}:
            return entry if reconcile is None else self.reconcile(key, reconcile)
        raise InvalidTransition(f"unknown journal state {entry.state.value}")

    def get(self, key: ExecutionKey) -> JournalEntry:
        _validate_key(key)
        with closing(self._connect()) as db:
            return self._row_to_entry(self._fetch(db, key))

    def count(self) -> int:
        with closing(self._connect()) as db:
            row = db.execute("SELECT COUNT(*) FROM treasury_execution_journal").fetchone()
            return int(row[0])

    def integrity_check(self) -> str:
        with closing(self._connect()) as db:
            row = db.execute("PRAGMA integrity_check").fetchone()
            return str(row[0])


def _validate_key(key: ExecutionKey) -> None:
    if key.network != CASPER_TEST_NETWORK:
        raise ValueError(f"network must be exactly {CASPER_TEST_NETWORK}")
    _require_bytes32("action_id", key.action_id, nonzero=True)
    _require_bytes32("envelope_hash", key.envelope_hash, nonzero=True)


__all__ = [
    "AuthorizationMismatch",
    "BroadcastResult",
    "ExecutionKey",
    "ExecutionState",
    "FinalityEvidence",
    "InvalidTransition",
    "JournalConflict",
    "JournalEntry",
    "ReconciliationResult",
    "TreasuryExecutor",
    "TreasuryExecutorError",
]
