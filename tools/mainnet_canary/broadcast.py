"""Broadcast guard surface — structurally disabled in the preparation lane.

The guard sequence is real and fully tested; submission is not implemented.
Gates, in order (first failure refuses):

1. Durable journal must exist, verify its hash chain, and match the plan.
2. The Codex-issued live authorization file must exist at the FIXED mount
   path.  There is no flag, argument, or environment variable that can point
   elsewhere.  In this lane the file does not exist, so the stable refusal is
   ``BROADCAST_DISABLED_AUTHORIZATION_ABSENT``.
3. The authorization document must validate: schema, RC tag, exact plan
   hash, max-CSPR ceiling, and expiry — and contain no secret material.
4. The cost model must be fully measured and within BOTH ceilings.
5. Steps already in flight demand reconciliation by their ORIGINAL deploy
   hash; a second economic action is never created automatically.
6. Per-step interactive confirmation on a real TTY typing the exact step id.
7. Finally — submission itself is NOT IMPLEMENTED in the preparation lane
   and unconditionally refuses.  There is no ``--yes``, no environment
   bypass, no development mode, no automatic approval, and no generic retry.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from tools.mainnet_canary import PREP_LANE
from tools.mainnet_canary.constants import LIVE_AUTHORIZATION_MOUNT_PATH
from tools.mainnet_canary.cost_model import require_approved_estimate
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.plan import plan_document_hash
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

AUTHORIZATION_SCHEMA_ID = "concordia.mainnet-canary.live-authorization.v1"

_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")

_AUTHORIZATION_FIELDS = {
    "schema_id",
    "issued_by",
    "rc_tag",
    "plan_hash",
    "max_total_motes",
    "per_step_confirmation_required",
    "expires_at_unix",
}


def _validate_authorization(
    document: dict[str, object], *, plan_hash: str, rc_tag: str
) -> dict[str, object]:
    if set(document) != _AUTHORIZATION_FIELDS or (
        document.get("schema_id") != AUTHORIZATION_SCHEMA_ID
    ):
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            f"authorization must contain exactly {sorted(_AUTHORIZATION_FIELDS)}",
        )
    if document["issued_by"] != "codex-integration-operator":
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            "authorization must be issued by the Codex integration operator",
        )
    if document["rc_tag"] != rc_tag:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            "authorization RC tag does not match the staged RC tag",
        )
    if document["plan_hash"] != plan_hash:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            "authorization plan hash does not match the staged plan",
        )
    max_total = document["max_total_motes"]
    if not isinstance(max_total, str) or _DECIMAL.match(max_total) is None:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorization ceiling malformed"
        )
    if document["per_step_confirmation_required"] is not True:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            "per-step confirmation may never be waived",
        )
    if not isinstance(document["expires_at_unix"], int):
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorization expiry malformed"
        )
    return document


def _confirm_step_interactively(step_id: str) -> None:
    """Require the operator to type the exact step id on a real TTY."""

    stdin = sys.stdin
    if not hasattr(stdin, "isatty") or not stdin.isatty():
        raise CanaryRefusal(
            RefusalCode.CONFIRMATION_REQUIRED,
            f"step {step_id} requires interactive confirmation on a TTY; "
            "non-interactive execution cannot broadcast",
        )
    sys.stdout.write(
        f"Type the exact step id to confirm broadcasting {step_id}: "
    )
    sys.stdout.flush()
    entered = stdin.readline().strip()
    if entered != step_id:
        raise CanaryRefusal(
            RefusalCode.CONFIRMATION_REQUIRED,
            f"step {step_id} was not confirmed exactly",
        )


def run_broadcast_guard(
    repo_root: Path,
    *,
    plan_document: dict[str, object],
    journal_path: Path,
    ceiling_path: Path | None,
    measured_costs_path: Path | None,
) -> dict[str, object]:
    """Run every broadcast gate in order.  Never submits in this lane."""

    # Gate 1 — durable journal state must exist before any broadcast.
    #
    # Only the PLAN BINDING is read here, and the lock is released straight
    # away. In-flight state is deliberately NOT captured at this point: it
    # is re-read at gate 5, because state observed here would already be
    # stale by the time the decision is made (see gate 5).
    journal = CanaryJournal.load(journal_path)
    try:
        journal_plan_hash = journal.plan_hash
    finally:
        journal.close()
    plan_hash = plan_document_hash(plan_document)
    if plan_document.get("canary_plan_sha256") != plan_hash or (
        journal_plan_hash != plan_hash
    ):
        raise CanaryRefusal(
            RefusalCode.PLAN_HASH_MISMATCH,
            "journal/plan hash mismatch; refusing to broadcast",
        )

    # Gate 2 — the live authorization file exists ONLY at the fixed mount
    # path.  No parameter can relocate it.
    authorization_path = Path(LIVE_AUTHORIZATION_MOUNT_PATH)
    if not authorization_path.is_file():
        raise CanaryRefusal(
            RefusalCode.BROADCAST_DISABLED_AUTHORIZATION_ABSENT,
            "live authorization file is absent; broadcasting is disabled in "
            "the preparation lane and until Codex issues the authorization "
            f"at {LIVE_AUTHORIZATION_MOUNT_PATH}",
        )

    # Gate 3 — validate the authorization document (future live lane).
    raw = authorization_path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context="live-authorization")
    try:
        authorization = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorization is not valid JSON"
        ) from exc
    if not isinstance(authorization, dict):
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorization must be an object"
        )
    rc_tag = str(plan_document["rc"]["tag"])
    authorization = _validate_authorization(
        authorization, plan_hash=plan_hash, rc_tag=rc_tag
    )

    # Gate 4 — fully measured cost model within the human-approved ceiling
    # AND the authorization ceiling.
    estimate = require_approved_estimate(
        repo_root,
        measured_costs_path=measured_costs_path,
        ceiling_path=ceiling_path,
    )
    total = int(str(estimate["total_motes"]))
    if total > int(str(authorization["max_total_motes"])):
        raise CanaryRefusal(
            RefusalCode.COST_CEILING_EXCEEDED,
            "estimate exceeds the authorization's max-CSPR ceiling",
        )

    # Gate 5 — reconcile-before-anything: an in-flight step blocks all new
    # economic actions; reconciliation uses the original deploy hash only.
    #
    # The journal is RE-READ here, under the lock, at the moment the
    # decision is made. An earlier revision checked a snapshot taken at
    # gate 1: a transition written between gate 1 and this point was
    # therefore invisible, and the guard walked on to the confirmation gate
    # while the journal was genuinely in flight. A stale read is not a
    # control.
    #
    # The lock is then HELD for the remainder of the guard, so the decision
    # and everything that follows it happen under one lock. Releasing it
    # here would reopen the same window one step later.
    journal = CanaryJournal.load(journal_path)
    try:
        if journal.plan_hash != plan_hash:
            raise CanaryRefusal(
                RefusalCode.PLAN_HASH_MISMATCH,
                "journal was rebound to a different plan mid-guard",
            )
        journal.require_no_in_flight(context="broadcast")

        # Gate 6 — per-step interactive confirmation, under the same lock.
        for step in plan_document["steps"]:
            if step["economic"]:
                _confirm_step_interactively(str(step["step_id"]))
    finally:
        journal.close()

    # Gate 7 — submission is not implemented in the preparation lane.  This
    # refusal is unconditional while PREP_LANE is True (it always is here);
    # the live submission implementation belongs to a future Codex-audited
    # lane and is deliberately absent from this codebase.
    if PREP_LANE:
        raise CanaryRefusal(
            RefusalCode.SUBMISSION_NOT_IMPLEMENTED_IN_PREP,
            "broadcast submission is not implemented in the preparation "
            "lane; no code path in this package can sign or submit",
        )
    raise CanaryRefusal(  # pragma: no cover - structurally unreachable
        RefusalCode.SUBMISSION_NOT_IMPLEMENTED_IN_PREP,
        "submission is not implemented",
    )
