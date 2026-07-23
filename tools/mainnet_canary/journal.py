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

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

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


class CanaryJournal:
    """Durable journal bound to one plan hash."""

    def __init__(self, path: Path, records: list[dict[str, object]]):
        self._path = path
        self._records = records

    # -- construction -------------------------------------------------------

    @classmethod
    def create(cls, path: Path, *, plan_hash: str, rc_tag: str) -> CanaryJournal:
        if path.exists():
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT,
                "journal already exists; refusing to overwrite durable state",
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        journal = cls(path, [])
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
        if not path.is_file():
            raise CanaryRefusal(
                RefusalCode.JOURNAL_ABSENT, "journal file does not exist"
            )
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
                RefusalCode.JOURNAL_TAMPERED, "journal is missing its genesis record"
            )
        return cls(path, records)

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
        for record in self._records:
            if record.get("kind") == "transition" and record.get("step_id") == step_id:
                state = str(record["state"])
                if record.get("deploy_hash") is not None:
                    deploy_hash = str(record["deploy_hash"])
        if state is None:
            return None
        return StepStatus(step_id=step_id, state=state, deploy_hash=deploy_hash)

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
        if new_state in _RECONCILE_STATES:
            original = current.deploy_hash if current is not None else None
            if original is None or deploy_hash != original:
                raise CanaryRefusal(
                    RefusalCode.RECONCILIATION_REQUIRED,
                    f"step {step_id} may only reconcile against its original "
                    "deploy hash",
                )
        if new_state == "SUBMITTED" and deploy_hash is None:
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT,
                "SUBMITTED requires the submitted deploy hash",
            )
        self._append(
            {
                "schema_id": JOURNAL_SCHEMA_ID,
                "kind": "transition",
                "step_id": step_id,
                "state": new_state,
                "deploy_hash": deploy_hash,
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
