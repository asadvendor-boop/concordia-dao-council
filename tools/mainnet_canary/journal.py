"""Durable, hash-chained canary journal with reconcile-not-duplicate restarts.

The journal is an append-only JSONL file.  Every record carries the SHA-256
of the previous record and its own canonical hash, so any in-place edit,
deletion, or reordering is detected on load (``JOURNAL_TAMPERED``).

Per-step state machine (one economic action per step, forward-only):

    PLANNED -> STAGED -> AUTHORIZATION_VALIDATED -> SIGNED -> SUBMITTED
    SUBMITTED -> CONFIRMED_FINALIZED | FAILED_FINALIZED | SUBMISSION_UNKNOWN
    SUBMISSION_UNKNOWN -> RECONCILED_CONFIRMED | RECONCILED_FAILED

Restart semantics: a step observed in SIGNED, SUBMITTED, or
SUBMISSION_UNKNOWN is in flight.  The only permitted continuation is
reconciliation against the ORIGINAL deploy hash recorded at signing time —
re-staging or re-signing that step is refused (``DUPLICATE_ECONOMIC_ACTION``)
so a crash can never emit a second economic action.

In the preparation lane the journal never advances beyond
AUTHORIZATION_VALIDATED for real steps; the later states exist so the state
machine and its refusals are provable by tests today.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

JOURNAL_SCHEMA_ID = "concordia.mainnet-canary.journal.v1"
GENESIS_PREV_HASH = "0" * 64

STATES = (
    "PLANNED",
    "STAGED",
    "AUTHORIZATION_VALIDATED",
    "SIGNED",
    "SUBMITTED",
    "SUBMISSION_UNKNOWN",
    "CONFIRMED_FINALIZED",
    "FAILED_FINALIZED",
    "RECONCILED_CONFIRMED",
    "RECONCILED_FAILED",
)

_TRANSITIONS: dict[str | None, tuple[str, ...]] = {
    None: ("PLANNED",),
    "PLANNED": ("STAGED",),
    "STAGED": ("AUTHORIZATION_VALIDATED",),
    "AUTHORIZATION_VALIDATED": ("SIGNED",),
    "SIGNED": ("SUBMITTED",),
    "SUBMITTED": (
        "CONFIRMED_FINALIZED",
        "FAILED_FINALIZED",
        "SUBMISSION_UNKNOWN",
    ),
    "SUBMISSION_UNKNOWN": ("RECONCILED_CONFIRMED", "RECONCILED_FAILED"),
    "CONFIRMED_FINALIZED": (),
    "FAILED_FINALIZED": (),
    "RECONCILED_CONFIRMED": (),
    "RECONCILED_FAILED": (),
}

# States that mean "an economic action may already exist on chain".
IN_FLIGHT_STATES = ("SIGNED", "SUBMITTED", "SUBMISSION_UNKNOWN")
_RECONCILE_STATES = ("RECONCILED_CONFIRMED", "RECONCILED_FAILED")


def _canonical(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _record_hash(record: dict[str, object]) -> str:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(_canonical(body).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class StepStatus:
    step_id: str
    state: str
    deploy_hash: str | None
    signed_bytes_sha256: str | None = None


def _require_safe_journal_path(path: Path, *, must_exist: bool) -> None:
    """Symlink-safe journal placement.

    The threat is a symlink swapped in AT the journal — the file itself, or
    the directory it is opened relative to — redirecting appends somewhere
    else. That is what is checked here, and ``O_NOFOLLOW`` enforces it again
    at open time.

    Deliberately NOT walked to the filesystem root: an earlier version did,
    and refused every journal under a path with a symlinked SYSTEM ancestor.
    On macOS ``/var -> private/var`` and ``/tmp -> private/tmp``, so a
    journal in any normal scratch location was rejected with
    JOURNAL_PATH_UNSAFE. The suite missed it because pytest's ``tmp_path``
    is already resolved; running the real CLI exposed it. The deep walk also
    bought nothing: an attacker who controls a grandparent of the journal
    directory already controls the journal directory.
    """

    if path.is_symlink():
        raise CanaryRefusal(
            RefusalCode.JOURNAL_PATH_UNSAFE,
            "journal file may not be a symlink",
        )
    if path.parent.is_symlink():
        raise CanaryRefusal(
            RefusalCode.JOURNAL_PATH_UNSAFE,
            "journal directory may not be a symlink",
        )
    if must_exist and not path.is_file():
        raise CanaryRefusal(
            RefusalCode.JOURNAL_ABSENT, "journal file does not exist"
        )


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CanaryJournal:
    """Durable journal bound to one plan hash; one exclusive holder at a time."""

    def __init__(self, path: Path, records: list[dict[str, object]], lock_fd: int):
        self._path = path
        self._records = records
        self._lock_fd = lock_fd

    # -- exclusive OS lock ---------------------------------------------------

    @staticmethod
    def _acquire_lock(path: Path) -> int:
        """flock the sidecar lock; a dead process releases automatically."""

        lock_path = path.parent / (path.name + ".lock")
        fd = os.open(
            lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise CanaryRefusal(
                RefusalCode.JOURNAL_LOCK_HELD,
                "another live process holds this journal; a second executor "
                "may never run against the same durable state",
            ) from None
        return fd

    def close(self) -> None:
        """Release the exclusive lock (also released on process death)."""

        if self._lock_fd >= 0:
            os.close(self._lock_fd)
            self._lock_fd = -1

    # -- construction -------------------------------------------------------

    @classmethod
    def create(cls, path: Path, *, plan_hash: str, rc_tag: str) -> CanaryJournal:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _require_safe_journal_path(path, must_exist=False)
        if path.exists():
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT,
                "journal already exists; refusing to overwrite durable state",
            )
        lock_fd = cls._acquire_lock(path)
        try:
            # Atomic exclusive creation: a pre-existing (even partial) file
            # is durable state we must never clobber.
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            os.close(lock_fd)
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT,
                "journal already exists; refusing to overwrite durable state",
            ) from None
        os.close(fd)
        _fsync_dir(path.parent)
        journal = cls(path, [], lock_fd)
        journal._append(
            {
                "schema_id": JOURNAL_SCHEMA_ID,
                "kind": "genesis",
                "plan_hash": plan_hash,
                "rc_tag": rc_tag,
                "step_id": None,
                "state": None,
                "deploy_hash": None,
            }
        )
        return journal

    @classmethod
    def load(cls, path: Path) -> CanaryJournal:
        _require_safe_journal_path(path, must_exist=True)
        lock_fd = cls._acquire_lock(path)
        try:
            records: list[dict[str, object]] = []
            prev_hash = GENESIS_PREV_HASH
            for index, line in enumerate(
                path.read_text(encoding="utf-8").splitlines()
            ):
                if not line.strip():
                    raise CanaryRefusal(
                        RefusalCode.JOURNAL_TAMPERED, f"blank journal line {index}"
                    )
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CanaryRefusal(
                        RefusalCode.JOURNAL_TAMPERED,
                        f"journal line {index} is not valid JSON",
                    ) from exc
                if (
                    not isinstance(record, dict)
                    or record.get("seq") != index
                    or record.get("prev_hash") != prev_hash
                    or record.get("record_hash") != _record_hash(record)
                ):
                    raise CanaryRefusal(
                        RefusalCode.JOURNAL_TAMPERED,
                        f"journal hash chain broken at line {index}",
                    )
                records.append(record)
                prev_hash = str(record["record_hash"])
            if not records or records[0].get("kind") != "genesis":
                raise CanaryRefusal(
                    RefusalCode.JOURNAL_TAMPERED,
                    "journal is missing its genesis record",
                )
        except BaseException:
            os.close(lock_fd)
            raise
        return cls(path, records, lock_fd)

    # -- append -------------------------------------------------------------

    def _append(self, payload: dict[str, object]) -> None:
        prev_hash = (
            self._records[-1]["record_hash"] if self._records else GENESIS_PREV_HASH
        )
        record: dict[str, object] = {
            "seq": len(self._records),
            "prev_hash": prev_hash,
            **payload,
        }
        record["record_hash"] = _record_hash(record)
        line = _canonical(record) + "\n"
        # Durability before progress: fsync the appended record.
        with self._path.open("a", encoding="ascii") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self._records.append(record)

    # -- queries ------------------------------------------------------------

    @property
    def plan_hash(self) -> str:
        return str(self._records[0]["plan_hash"])

    def step_status(self, step_id: str) -> StepStatus | None:
        state: str | None = None
        deploy_hash: str | None = None
        signed_bytes: str | None = None
        for record in self._records:
            if record.get("kind") == "transition" and record.get("step_id") == step_id:
                state = str(record["state"])
                if record.get("deploy_hash") is not None:
                    deploy_hash = str(record["deploy_hash"])
                if record.get("signed_bytes_sha256") is not None:
                    signed_bytes = str(record["signed_bytes_sha256"])
        if state is None:
            return None
        return StepStatus(
            step_id=step_id,
            state=state,
            deploy_hash=deploy_hash,
            signed_bytes_sha256=signed_bytes,
        )

    def in_flight_steps(self) -> list[StepStatus]:
        seen: dict[str, StepStatus] = {}
        for record in self._records:
            if record.get("kind") == "transition":
                step_id = str(record["step_id"])
                status = self.step_status(step_id)
                if status is not None:
                    seen[step_id] = status
        return [
            status
            for status in seen.values()
            if status.state in IN_FLIGHT_STATES
        ]

    # -- transitions --------------------------------------------------------

    def transition(
        self,
        step_id: str,
        new_state: str,
        *,
        plan_hash: str,
        deploy_hash: str | None = None,
        signed_bytes_sha256: str | None = None,
        detail: str | None = None,
    ) -> None:
        if new_state not in STATES:
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT, f"unknown journal state {new_state}"
            )
        if plan_hash != self.plan_hash:
            raise CanaryRefusal(
                RefusalCode.PLAN_HASH_MISMATCH,
                "journal is bound to a different plan hash",
            )
        current = self.step_status(step_id)
        current_state = current.state if current is not None else None
        allowed = _TRANSITIONS.get(current_state, ())
        if new_state not in allowed:
            if current_state in IN_FLIGHT_STATES and new_state in (
                "PLANNED",
                "STAGED",
                "AUTHORIZATION_VALIDATED",
                "SIGNED",
                "SUBMITTED",
            ):
                raise CanaryRefusal(
                    RefusalCode.DUPLICATE_ECONOMIC_ACTION,
                    f"step {step_id} is in flight ({current_state}); only "
                    "reconciliation by its original deploy hash is permitted",
                )
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT,
                f"illegal transition {current_state} -> {new_state} "
                f"for step {step_id}",
            )
        if new_state == "SIGNED":
            # v2: SIGNED without the canonical signed-bytes digest and the
            # locally computed deploy hash is impossible — both are persisted
            # BEFORE any submission so a crash can always reconcile.
            if (
                not isinstance(deploy_hash, str)
                or _HEX64.match(deploy_hash) is None
                or not isinstance(signed_bytes_sha256, str)
                or _HEX64.match(signed_bytes_sha256) is None
            ):
                raise CanaryRefusal(
                    RefusalCode.JOURNAL_CONFLICT,
                    "SIGNED requires the canonical signed-bytes SHA-256 and "
                    "the locally computed deploy hash before any submission",
                )
        original = current.deploy_hash if current is not None else None
        if new_state == "SUBMITTED":
            if deploy_hash is None:
                raise CanaryRefusal(
                    RefusalCode.JOURNAL_CONFLICT,
                    "SUBMITTED requires the submitted deploy hash",
                )
            if deploy_hash != original:
                raise CanaryRefusal(
                    RefusalCode.DUPLICATE_ECONOMIC_ACTION,
                    f"step {step_id} may only submit the exact deploy whose "
                    "bytes were persisted at SIGNED; submitting different "
                    "bytes would be a second economic action",
                )
        if new_state in ("CONFIRMED_FINALIZED", "FAILED_FINALIZED"):
            if original is None or deploy_hash != original:
                raise CanaryRefusal(
                    RefusalCode.JOURNAL_CONFLICT,
                    f"step {step_id} finalization must bind the original "
                    "deploy hash recorded at signing time",
                )
        if new_state in _RECONCILE_STATES:
            if original is None or deploy_hash != original:
                raise CanaryRefusal(
                    RefusalCode.RECONCILIATION_REQUIRED,
                    f"step {step_id} may only reconcile against its original "
                    "deploy hash",
                )
        self._append(
            {
                "schema_id": JOURNAL_SCHEMA_ID,
                "kind": "transition",
                "step_id": step_id,
                "state": new_state,
                "deploy_hash": deploy_hash,
                "signed_bytes_sha256": signed_bytes_sha256,
                "detail": detail,
            }
        )

    def require_no_in_flight(self, *, context: str) -> None:
        in_flight = self.in_flight_steps()
        if in_flight:
            steps = sorted(status.step_id for status in in_flight)
            raise CanaryRefusal(
                RefusalCode.RECONCILIATION_REQUIRED,
                f"{context}: steps in flight after restart: {steps}; "
                "reconcile by original deploy hash before any new action",
            )
