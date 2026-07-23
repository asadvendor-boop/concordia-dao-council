"""Failure-first tests for the refuse-while-unknown cost model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mc_support import make_ceiling, make_measured_costs, write_json
from tools.mainnet_canary.cost_model import (
    build_estimate,
    require_approved_estimate,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

REAL_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_no_measured_costs_exist_at_the_preparation_base() -> None:
    """The real repo carries no exact-equivalent v3 Testnet measurements, so
    every line is UNKNOWN and the estimate refuses."""

    report = build_estimate(REAL_REPO_ROOT)
    assert report["approval"] == "REFUSED"
    assert RefusalCode.COST_LINE_UNKNOWN in report["refusal_codes"]
    assert RefusalCode.COST_CEILING_ABSENT in report["refusal_codes"]
    assert report["total_motes"] is None
    unknown = set(report["unknown_items"])
    # Refusal proofs are never free: the pre-quorum line must exist and be
    # UNKNOWN rather than silently zero.
    assert "prequorum_finalize_refusal" in unknown
    assert "contract_install" in unknown
    assert "native_transfer" in unknown


def test_unknown_line_refuses_even_with_ceiling(tmp_path: Path) -> None:
    ceiling = write_json(tmp_path / "ceiling.json", make_ceiling())
    with pytest.raises(CanaryRefusal) as refusal:
        require_approved_estimate(REAL_REPO_ROOT, ceiling_path=ceiling)
    assert refusal.value.code == RefusalCode.COST_LINE_UNKNOWN


def test_partial_measurements_still_refuse(tmp_path: Path) -> None:
    document = make_measured_costs()
    del document["measured_motes"]["native_transfer"]
    measured = write_json(tmp_path / "measured.json", document)
    ceiling = write_json(tmp_path / "ceiling.json", make_ceiling())
    report = build_estimate(
        REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=ceiling
    )
    assert report["approval"] == "REFUSED"
    assert report["unknown_items"] == ["native_transfer", "safety_buffer"]


def test_fully_measured_within_ceiling_is_approvable(tmp_path: Path) -> None:
    measured = write_json(tmp_path / "measured.json", make_measured_costs())
    ceiling = write_json(tmp_path / "ceiling.json", make_ceiling())
    report = require_approved_estimate(
        REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=ceiling
    )
    assert report["approval"] == "WITHIN_CEILING"
    # subtotal 167600000000 + ceil(20%) buffer 33520000000
    assert report["total_motes"] == "201120000000"
    buffer_line = [
        line for line in report["lines"] if line["item"] == "safety_buffer"
    ][0]
    assert buffer_line["status"] == "DERIVED"


def test_missing_ceiling_refuses_even_when_measured(tmp_path: Path) -> None:
    measured = write_json(tmp_path / "measured.json", make_measured_costs())
    with pytest.raises(CanaryRefusal) as refusal:
        require_approved_estimate(REAL_REPO_ROOT, measured_costs_path=measured)
    assert refusal.value.code == RefusalCode.COST_CEILING_ABSENT


def test_cost_above_ceiling_is_refused(tmp_path: Path) -> None:
    measured = write_json(tmp_path / "measured.json", make_measured_costs())
    ceiling = write_json(
        tmp_path / "ceiling.json", make_ceiling(max_total_motes="1000")
    )
    with pytest.raises(CanaryRefusal) as refusal:
        require_approved_estimate(
            REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=ceiling
        )
    assert refusal.value.code == RefusalCode.COST_CEILING_EXCEEDED


def test_wrong_envelope_refusal_needs_separate_approval(tmp_path: Path) -> None:
    measured_doc = make_measured_costs(
        wrong_envelope_refusal_optional="5000000000"
    )
    measured = write_json(tmp_path / "measured.json", measured_doc)
    unapproved = write_json(tmp_path / "ceiling-a.json", make_ceiling())
    report = build_estimate(
        REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=unapproved
    )
    line = [
        item
        for item in report["lines"]
        if item["item"] == "wrong_envelope_refusal_optional"
    ][0]
    assert line["status"] == "EXCLUDED_NOT_SEPARATELY_APPROVED"

    approved = write_json(
        tmp_path / "ceiling-b.json",
        make_ceiling(wrong_envelope_refusal_approved=True),
    )
    report_b = build_estimate(
        REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=approved
    )
    line_b = [
        item
        for item in report_b["lines"]
        if item["item"] == "wrong_envelope_refusal_optional"
    ][0]
    assert line_b["status"] == "MEASURED"
    assert int(report_b["total_motes"]) > int(report["total_motes"])


def test_estimate_output_is_deterministic(tmp_path: Path) -> None:
    measured = write_json(tmp_path / "measured.json", make_measured_costs())
    ceiling = write_json(tmp_path / "ceiling.json", make_ceiling())
    first = build_estimate(
        REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=ceiling
    )
    second = build_estimate(
        REAL_REPO_ROOT, measured_costs_path=measured, ceiling_path=ceiling
    )
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_malformed_measured_document_refuses(tmp_path: Path) -> None:
    measured = write_json(
        tmp_path / "measured.json",
        {"schema_id": "wrong", "measured_motes": {}},
    )
    with pytest.raises(CanaryRefusal) as refusal:
        build_estimate(REAL_REPO_ROOT, measured_costs_path=measured)
    assert refusal.value.code == RefusalCode.COST_LINE_UNKNOWN


def test_unknown_measured_line_name_refuses(tmp_path: Path) -> None:
    document = make_measured_costs()
    document["measured_motes"]["surprise_item"] = "1"
    measured = write_json(tmp_path / "measured.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        build_estimate(REAL_REPO_ROOT, measured_costs_path=measured)
    assert refusal.value.code == RefusalCode.COST_LINE_UNKNOWN


def test_non_canonical_motes_are_refused(tmp_path: Path) -> None:
    ceiling = write_json(
        tmp_path / "ceiling.json", make_ceiling(max_total_motes="01")
    )
    with pytest.raises(CanaryRefusal) as refusal:
        build_estimate(REAL_REPO_ROOT, ceiling_path=ceiling)
    assert refusal.value.code == RefusalCode.COST_CEILING_INVALID
