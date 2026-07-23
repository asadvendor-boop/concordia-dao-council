from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import shared.proof_pack as proof_pack
import shared.proof_runtime as proof_runtime
from shared.proof_registry import REQUIRED_CHECKS_BY_PROOF_TYPE


CAPTURED_AT = "2026-07-22T20:00:00Z"
HEX32 = "ab" * 32
GIT_SHA = "1" * 40


def _canonical_evidence() -> dict:
    return {
        "proposal_id": proof_runtime.CANONICAL_PROPOSAL_ID,
        "state": "RESOLVED",
        "casper_receipt": {
            "approved_allocation_bps": 800,
            "policy_hash": "11" * 32,
            "plan_hash": "22" * 32,
            "final_card_hash": "33" * 32,
        },
        "cards": [
            {
                "data": {
                    "evidence": {
                        "policy_evaluation": {
                            "requested_allocation_bps": 3000,
                            "approved_allocation_bps": 800,
                        }
                    }
                }
            }
        ],
    }


def _exact_v3_item(*, failed_check: str | None = None) -> dict:
    return {
        "proof_id": "exact_envelope_v3",
        "proof_type": "exact_envelope_v3",
        "generation": "v3",
        "lineage": "supplemental",
        "observation_mode": "live",
        "temporal_scope": "current",
        "verification_status": "verified",
        "execution_outcome": "accepted",
        "claim_scope": "Typed exact-envelope v3 proof.",
        "enforcement_scope": "Exact v3 contract and deployment domain.",
        "proposal_id": proof_runtime.CANONICAL_PROPOSAL_ID,
        "action_id": "01" * 32,
        "envelope_hash": "02" * 32,
        "artifact_path": "artifacts/live/exact-v3.json",
        "artifact_sha256": HEX32,
        "source_commit": GIT_SHA,
        "deployment_commit": "2" * 40,
        "network": "casper:casper-test",
        "package_hash": "03" * 32,
        "contract_hash": "04" * 32,
        "deployment_domain": "05" * 32,
        "schema_version": "concordia.v3-proof.v1",
        "captured_at": CAPTURED_AT,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "report_hash": None,
        "settlement_transaction": None,
        "checks": [
            {
                "name": name,
                "required": True,
                "passed": name != failed_check,
                "source": "artifacts/live/exact-v3.json",
                "observed_at": CAPTURED_AT,
            }
            for name in REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]
        ],
        "links": [
            {
                "rel": "artifact",
                "label": "Exact v3 artifact",
                "href": "/proof-artifacts/v1/DAO-PROP-6CB25C/exact-v3",
                "kind": "artifact",
            }
        ],
    }


def _write_registry(root: Path, items: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "public_items": items,
                "internal_records": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_quorum_invariant_requires_unique_green_exact_v3_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = tmp_path / "registry"
    _write_registry(registry, [_exact_v3_item()])
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry))

    checks = {
        check["id"]: check
        for check in proof_runtime.build_invariant_runner(_canonical_evidence())["checks"]
    }

    assert checks["quorum_required"]["passed"] is True
    assert "pre_quorum_finalize_reverted_with_code_8" in checks["quorum_required"]["evidence"]

    failed = _exact_v3_item(
        failed_check="pre_quorum_finalize_reverted_with_code_8"
    )
    _write_registry(registry, [failed])
    checks = {
        check["id"]: check
        for check in proof_runtime.build_invariant_runner(_canonical_evidence())["checks"]
    }
    assert checks["quorum_required"]["passed"] is False

    _write_registry(registry, [_exact_v3_item(), copy.deepcopy(_exact_v3_item())])
    checks = {
        check["id"]: check
        for check in proof_runtime.build_invariant_runner(_canonical_evidence())["checks"]
    }
    assert checks["quorum_required"]["passed"] is False


def test_legacy_quorum_and_topology_artifact_strings_never_self_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = tmp_path / "artifacts" / "live"
    live.mkdir(parents=True)
    (live / "odra-quorum-exercise-plan.json").write_text(
        json.dumps(
            {
                "proposal_id": proof_runtime.CANONICAL_PROPOSAL_ID,
                "schema": "concordia.odra-quorum-exercise-proof.v1",
                "status": "live_complete",
                "live_deploys": {
                    "final_store_governance_receipt": (
                        proof_runtime.CANONICAL_QUORUM_RECEIPT_HASH
                    )
                },
                "acceptance_criteria": {
                    "pre_quorum_execution_blocked": {"status": "verified"},
                    "final_receipt_after_quorum": {
                        "status": "verified",
                        "deploy_hash": proof_runtime.CANONICAL_QUORUM_RECEIPT_HASH,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    (live / "odra-topology-genesis-proof.json").write_text(
        json.dumps(
            {
                "proposal_id": proof_runtime.CANONICAL_PROPOSAL_ID,
                "schema": "concordia.odra-topology-genesis-proof.v1",
                "status": "live_complete",
                "modules": {
                    "CouncilRegistry": {},
                    "TreasuryPolicy": {},
                    "CardIndexLedger": {},
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "CONCORDIA_PROOF_REGISTRY_DIR", str(tmp_path / "missing-registry")
    )

    quorum = proof_pack.load_odra_quorum_proof()
    topology = proof_pack.load_odra_topology_genesis_proof()

    assert quorum is not None
    assert quorum["artifact_reported_status"] == "live_complete"
    assert quorum["status"] == "unavailable"
    assert topology is not None
    assert topology["artifact_reported_status"] == "live_complete"
    assert topology["status"] == "unavailable"

    registry = tmp_path / "registry"
    _write_registry(registry, [_exact_v3_item()])
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry))
    quorum = proof_pack.load_odra_quorum_proof()

    assert quorum is not None
    assert quorum["status"] == "unavailable"
    assert quorum["current_quorum_verification_status"] == "verified"


def test_audit_packet_does_not_promote_unverified_quorum_or_topology_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        proof_pack,
        "load_odra_quorum_proof",
        lambda: {
            "status": "unavailable",
            "artifact_reported_status": "live_complete",
            "live_deploys": {
                "final_store_governance_receipt": (
                    proof_runtime.CANONICAL_QUORUM_RECEIPT_HASH
                )
            },
        },
    )
    monkeypatch.setattr(
        proof_pack,
        "load_odra_topology_genesis_proof",
        lambda: {
            "status": "unavailable",
            "artifact_reported_status": "live_complete",
            "modules": {
                "CouncilRegistry": {},
                "TreasuryPolicy": {},
                "CardIndexLedger": {},
            },
        },
    )

    packet = proof_pack.build_audit_packet(_canonical_evidence())
    rows = packet["proof_center"]["compact_proof_table"]
    quorum = next(row for row in rows if "quorum" in row["claim"].lower())
    topology = next(row for row in rows if "topology" in row["claim"].lower())

    assert quorum["status"] == "unavailable"
    assert topology["status"] == "unavailable"
    assert packet["proof_center"]["locke_execution_firewall"].get(
        "on_chain_quorum_enforced"
    ) is not True


def test_missing_live_gateway_validation_never_defaults_true() -> None:
    result = proof_pack.build_adversarial_safety_demo(
        {
            **_canonical_evidence(),
            "adversarial_safety_attempt": {
                "status": "blocked",
                "proof_mode": "stored_gateway_attempt",
                "approved_allocation_bps": 800,
                "attempted_allocation_bps": 3000,
            },
        }
    )

    assert result["live_gateway_validation"] is False


def test_below_cap_replay_is_safe_preview_with_separate_envelope_binding_signal() -> None:
    result = proof_runtime.build_interactive_adversarial_replay(
        _canonical_evidence(), "move 5% of the treasury"
    )

    assert result["attempted_allocation_bps"] == 500
    assert result["status"] == "within_policy_preview"
    assert result["invariant_result"] == "within_cap"
    assert result["locke_result"] == "preview_only_no_execution"
    assert result["envelope_binding_demonstrated"] is True


def test_rwa_artifact_reported_processed_status_is_not_a_verified_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "rwa.json"
    artifact.write_text(
        json.dumps(
            {
                "proposal_id": proof_runtime.SUPPLEMENTAL_RWA_PROPOSAL_ID,
                "status": "processed",
                "deploy_hash": proof_runtime.SUPPLEMENTAL_RWA_RECEIPT_HASH,
                "transaction_hash": proof_runtime.SUPPLEMENTAL_RWA_RECEIPT_HASH,
                "contract_hash": proof_runtime.CANONICAL_CONTRACT_HASH,
                "entry_point": "store_governance_receipt",
                "scope": "supplemental_rwa_run",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(proof_runtime, "RWA_EXECUTION_PROOF", artifact)

    result = proof_runtime.build_rwa_evidence_run()

    assert result["artifact_reported_status"] == "processed"
    assert result["supplemental_receipt_status"] == "unavailable"
    assert "independently verified" in result["supplemental_receipt_reason"]
