"""SafePay judge-facing truth must come only from the verified proof registry."""

from __future__ import annotations

import json
from pathlib import Path

from shared.proof_registry import REQUIRED_CHECKS_BY_PROOF_TYPE
from shared.proof_runtime import (
    CANONICAL_PROPOSAL_ID,
    CANONICAL_X402_PAYMENT_HASH,
    build_invariant_runner,
    build_safepay_lite,
)


NOW = "2026-07-23T01:00:00Z"
SOURCE_COMMIT = "1" * 40
DEPLOYMENT_COMMIT = "2" * 40
CURRENT_PAYMENT = "3" * 64
REPORT_HASH = "4" * 64
ARTIFACT_HASH = "5" * 64


def _safepay_item(*, failed_check: str | None = None) -> dict[str, object]:
    return {
        "proof_id": "safepay-current-v2",
        "proof_type": "safepay_v2",
        "generation": "v2",
        "lineage": "supplemental",
        "observation_mode": "live",
        "temporal_scope": "current",
        "verification_status": "verified",
        "execution_outcome": "accepted",
        "claim_scope": "One exact Casper payment was consumed once and replayed idempotently.",
        "enforcement_scope": "Provider ledger and exact native-transfer verification.",
        "proposal_id": CANONICAL_PROPOSAL_ID,
        "action_id": None,
        "envelope_hash": None,
        "artifact_path": "artifacts/live/safepay-lite-replaysafe-v2.json",
        "artifact_sha256": ARTIFACT_HASH,
        "source_commit": SOURCE_COMMIT,
        "deployment_commit": DEPLOYMENT_COMMIT,
        "network": "casper:casper-test",
        "package_hash": None,
        "contract_hash": None,
        "schema_version": "safepay-v2",
        "captured_at": NOW,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "report_hash": REPORT_HASH,
        "settlement_transaction": CURRENT_PAYMENT,
        "checks": [
            {
                "name": name,
                "required": True,
                "passed": name != failed_check,
                "source": "artifacts/live/safepay-lite-replaysafe-v2.json",
                "observed_at": NOW,
            }
            for name in REQUIRED_CHECKS_BY_PROOF_TYPE["safepay_v2"]
        ],
        "links": [],
    }


def _write_registry(root: Path, item: dict[str, object]) -> None:
    root.mkdir(parents=True)
    (root / "registry.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "public_items": [item],
                "internal_records": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_safepay_runtime_uses_one_green_registry_item(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry = tmp_path / "registry"
    _write_registry(registry, _safepay_item())
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry))
    monkeypatch.chdir(tmp_path)

    safepay = build_safepay_lite({"proposal_id": CANONICAL_PROPOSAL_ID})

    assert safepay["status"] == "verified"
    assert safepay["payment_hash"] == CURRENT_PAYMENT
    assert safepay["historical_payment_hash"] == CANONICAL_X402_PAYMENT_HASH
    assert safepay["payment_verified"] is True
    assert safepay["report_hash"] == REPORT_HASH
    assert safepay["report_hash_verified"] is True
    assert safepay["duplicate_proof_rejected"] is True
    assert safepay["included_in_governance_proof"] is True


def test_safepay_runtime_ignores_historical_handshake_and_forged_boolean(
    tmp_path: Path,
    monkeypatch,
) -> None:
    live = tmp_path / "artifacts" / "live"
    live.mkdir(parents=True)
    (live / "x402-provider-happy-path-verified.json").write_text(
        json.dumps(
            {
                "duplicate_proof_rejected": True,
                "checks": {
                    "gateway_402": {"status_code": 402},
                    "gateway_paid": {"status_code": 200},
                    "provider_402": {"status_code": 402},
                    "provider_paid": {"status_code": 200},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(tmp_path / "missing"))
    monkeypatch.chdir(tmp_path)

    safepay = build_safepay_lite({"proposal_id": CANONICAL_PROPOSAL_ID})

    assert safepay["status"] == "unverified"
    assert safepay["payment_hash"] == CANONICAL_X402_PAYMENT_HASH
    assert safepay["payment_verified"] is False
    assert safepay["duplicate_proof_rejected"] is False
    assert safepay["included_in_governance_proof"] is False


def test_safepay_runtime_failed_required_check_never_turns_green(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry = tmp_path / "registry"
    _write_registry(
        registry,
        _safepay_item(failed_check="cross_binding_reuse_returned_terminal_409"),
    )
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry))
    monkeypatch.chdir(tmp_path)

    safepay = build_safepay_lite({"proposal_id": CANONICAL_PROPOSAL_ID})

    assert safepay["status"] == "unverified"
    assert safepay["duplicate_proof_rejected"] is False


def test_invariant_runner_ignores_caller_supplied_safepay_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(tmp_path / "missing"))

    result = build_invariant_runner(
        {"proposal_id": CANONICAL_PROPOSAL_ID, "cards": []},
        {
            "status": "verified",
            "duplicate_proof_rejected": True,
            "duplicate_rejection_reason": "caller says so",
        },
    )
    replay = next(
        check
        for check in result["checks"]
        if check["id"] == "duplicate_x402_proof_rejected"
    )

    assert replay["passed"] is False
