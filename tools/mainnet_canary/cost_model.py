"""Explicit upper-bound CSPR budget — refuses while any line is UNKNOWN.

Costs may only be grounded in measured Testnet costs from EXACT equivalent
deploys of the v3 RC (install, propose, vote, pre-quorum refusal, finalize,
native transfer).  At the preparation base no such measurements exist: the v3
deployment manifest records ``built_uninstalled`` and the historical v1/v2
payment records are not equivalent deploys.  Every line is therefore UNKNOWN
and the estimate refuses approval.  Refusal proofs (the pre-quorum
``QuorumNotMet`` deploy and the optional wrong-envelope deploy) are never
treated as free: they consume fees and each carries its own line.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tools.mainnet_canary.constants import (
    BLOCKED_PENDING_LIVE_PROOF,
    COST_LINE_ITEMS,
    MEASURED_TESTNET_COSTS_RELPATH,
    PREP_BASE_SHA,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

MEASURED_COSTS_SCHEMA_ID = "concordia.mainnet-canary.testnet-measured-costs.v1"
CEILING_SCHEMA_ID = "concordia.mainnet-canary.spend-ceiling.v1"

_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")

# The safety buffer is a derived line: ceil(20%) of the measured subtotal.
SAFETY_BUFFER_NUMERATOR = 20
SAFETY_BUFFER_DENOMINATOR = 100


def _parse_motes(value: object, *, field: str) -> int:
    if not isinstance(value, str) or _DECIMAL.match(value) is None:
        raise CanaryRefusal(
            RefusalCode.COST_CEILING_INVALID,
            f"{field} must be a canonical unsigned decimal motes string",
        )
    return int(value, 10)


def load_measured_testnet_costs(
    repo_root: Path, *, measured_costs_path: Path | None = None
) -> dict[str, int] | None:
    """Load Codex's measured exact-equivalent Testnet costs, if published.

    Returns None when the measured-cost document does not exist (the state at
    the preparation base).  A malformed document refuses rather than
    degrading to guesses.
    """

    path = measured_costs_path or (repo_root / MEASURED_TESTNET_COSTS_RELPATH)
    if not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context="measured-costs")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.COST_LINE_UNKNOWN, "measured-cost document is not JSON"
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_id") != MEASURED_COSTS_SCHEMA_ID
        or not isinstance(document.get("measured_motes"), dict)
    ):
        raise CanaryRefusal(
            RefusalCode.COST_LINE_UNKNOWN,
            "measured-cost document does not match the frozen schema",
        )
    measured: dict[str, int] = {}
    for item, value in document["measured_motes"].items():
        if item not in COST_LINE_ITEMS:
            raise CanaryRefusal(
                RefusalCode.COST_LINE_UNKNOWN,
                f"measured-cost document contains unknown line {item}",
            )
        measured[item] = _parse_motes(value, field=f"measured_motes.{item}")
    return measured


def load_spend_ceiling(path: Path | None) -> dict[str, object] | None:
    """Load the human-approved public spending ceiling, if supplied."""

    if path is None or not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context="spend-ceiling")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.COST_CEILING_INVALID, "ceiling document is not JSON"
        ) from exc
    required = {
        "schema_id",
        "max_total_motes",
        "approved_by",
        "approval_reference",
        "wrong_envelope_refusal_approved",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required
        or document.get("schema_id") != CEILING_SCHEMA_ID
    ):
        raise CanaryRefusal(
            RefusalCode.COST_CEILING_INVALID,
            f"ceiling document must contain exactly {sorted(required)}",
        )
    _parse_motes(document["max_total_motes"], field="max_total_motes")
    if not isinstance(document["approved_by"], list) or not document["approved_by"]:
        raise CanaryRefusal(
            RefusalCode.COST_CEILING_INVALID, "approved_by must be non-empty"
        )
    if not isinstance(document["wrong_envelope_refusal_approved"], bool):
        raise CanaryRefusal(
            RefusalCode.COST_CEILING_INVALID,
            "wrong_envelope_refusal_approved must be a boolean",
        )
    return document


def build_estimate(
    repo_root: Path,
    *,
    measured_costs_path: Path | None = None,
    ceiling_path: Path | None = None,
) -> dict[str, object]:
    """Produce the deterministic cost report; approval only if fully grounded.

    The report never invents a number: a line without a measured equivalent is
    UNKNOWN, the total is null, and ``approval`` is REFUSED with stable codes.
    """

    measured = load_measured_testnet_costs(
        repo_root, measured_costs_path=measured_costs_path
    )
    ceiling = load_spend_ceiling(ceiling_path)

    refusal_codes: list[str] = []
    lines: list[dict[str, object]] = []
    subtotal = 0
    all_known = True
    wrong_envelope_approved = bool(
        ceiling is not None and ceiling["wrong_envelope_refusal_approved"]
    )
    for item in COST_LINE_ITEMS:
        if item == "safety_buffer":
            if all_known:
                buffer_motes = -(
                    -subtotal * SAFETY_BUFFER_NUMERATOR // SAFETY_BUFFER_DENOMINATOR
                )
                lines.append(
                    {
                        "item": item,
                        "status": "DERIVED",
                        "motes": str(buffer_motes),
                        "source": "ceil(20% of measured subtotal)",
                    }
                )
                subtotal += buffer_motes
            else:
                lines.append(
                    {
                        "item": item,
                        "status": "UNKNOWN",
                        "motes": None,
                        "source": None,
                    }
                )
            continue
        if item == "wrong_envelope_refusal_optional" and not wrong_envelope_approved:
            lines.append(
                {
                    "item": item,
                    "status": "EXCLUDED_NOT_SEPARATELY_APPROVED",
                    "motes": "0",
                    "source": "requires explicit approval in the ceiling document",
                }
            )
            continue
        if measured is not None and item in measured:
            lines.append(
                {
                    "item": item,
                    "status": "MEASURED",
                    "motes": str(measured[item]),
                    "source": MEASURED_TESTNET_COSTS_RELPATH,
                }
            )
            subtotal += measured[item]
        else:
            all_known = False
            lines.append(
                {"item": item, "status": "UNKNOWN", "motes": None, "source": None}
            )

    unknown_items = [line["item"] for line in lines if line["status"] == "UNKNOWN"]
    if unknown_items:
        refusal_codes.append(RefusalCode.COST_LINE_UNKNOWN)
    if ceiling is None:
        refusal_codes.append(RefusalCode.COST_CEILING_ABSENT)

    total: str | None = None
    if not unknown_items:
        total = str(subtotal)
        if ceiling is not None and subtotal > _parse_motes(
            ceiling["max_total_motes"], field="max_total_motes"
        ):
            refusal_codes.append(RefusalCode.COST_CEILING_EXCEEDED)

    return {
        "schema_id": "concordia.mainnet-canary.cost-estimate.v1",
        "prep_base_sha": PREP_BASE_SHA,
        "network_execution_status": BLOCKED_PENDING_LIVE_PROOF,
        "lines": lines,
        "total_motes": total,
        "ceiling_max_total_motes": (
            None if ceiling is None else ceiling["max_total_motes"]
        ),
        "approval": "REFUSED" if refusal_codes else "WITHIN_CEILING",
        "refusal_codes": sorted(set(refusal_codes)),
        "unknown_items": unknown_items,
    }


def require_approved_estimate(
    repo_root: Path,
    *,
    measured_costs_path: Path | None = None,
    ceiling_path: Path | None = None,
) -> dict[str, object]:
    """Gate used by stage/broadcast: refuse unless fully measured and capped."""

    report = build_estimate(
        repo_root,
        measured_costs_path=measured_costs_path,
        ceiling_path=ceiling_path,
    )
    if report["approval"] != "WITHIN_CEILING":
        codes = report["refusal_codes"] or [RefusalCode.COST_LINE_UNKNOWN]
        raise CanaryRefusal(
            str(codes[0]),
            "cost estimate is not approvable: "
            + ", ".join(str(code) for code in codes),
        )
    return report
