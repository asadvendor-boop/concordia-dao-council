from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import shared.proof_pack as proof_pack
import shared.proof_runtime as proof_runtime
from scripts.verify_concordia_receipt import _quorum_failures_for_packet
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


def test_adversarial_safety_demo_does_not_call_safe_below_cap_preview_blocked() -> None:
    evidence = _canonical_evidence()
    evidence["cards"][0]["data"]["evidence"]["policy_evaluation"][
        "requested_allocation_bps"
    ] = 500

    result = proof_pack.build_adversarial_safety_demo(evidence)

    assert result["attempted_allocation_bps"] == 500
    assert result["status"] == "within_policy_preview"
    assert result["locke_result"] == "preview_only_no_execution"
    assert result["poisoned_input_rejected"] is False
    assert result["llm_cannot_inject_numbers"] is False
    assert "within" in result["reason"].lower()


def test_judge_quorum_step_fails_closed_without_registry_and_verifies_exact_item(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = tmp_path / "registry"
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry))

    walkthrough = proof_runtime.build_judge_walkthrough(_canonical_evidence())
    quorum_step = next(
        step for step in walkthrough["steps"] if step["step"] == 7
    )

    assert quorum_step["status"] == "unavailable"
    assert "no unique green" in quorum_step["summary"].lower()
    assert "proof_id" not in quorum_step

    _write_registry(registry, [_exact_v3_item()])
    walkthrough = proof_runtime.build_judge_walkthrough(_canonical_evidence())
    quorum_step = next(
        step for step in walkthrough["steps"] if step["step"] == 7
    )

    assert quorum_step["status"] == "verified"
    assert quorum_step["proof_id"] == "exact_envelope_v3"
    assert "independently verified" in quorum_step["summary"].lower()


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


def test_public_packet_removes_legacy_asserted_quorum_and_topology_booleans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        proof_pack,
        "load_odra_quorum_proof",
        lambda: {
            "schema": "concordia.odra-quorum-exercise-proof.v1",
            "status": "unavailable",
            "verification_status": "unavailable",
            "current_quorum_verification_status": "unavailable",
            "artifact_reported_status": "live_complete",
            "summary": {
                "pre_quorum_blocked": True,
                "two_signers_approved": True,
            },
            "acceptance_criteria": {
                "pre_quorum_execution_blocked": {"status": "verified"}
            },
            "live_deploys": {"final_store_governance_receipt": "11" * 32},
            "registry_proof": None,
        },
    )
    monkeypatch.setattr(
        proof_pack,
        "load_odra_topology_genesis_proof",
        lambda: {
            "schema": "concordia.odra-topology-genesis-proof.v1",
            "status": "unavailable",
            "verification_status": "unavailable",
            "artifact_reported_status": "live_complete",
            "acceptance": {"canonical_receipt_unchanged": True},
            "modules": {
                "CouncilRegistry": {"status": "live_complete", "success": True},
                "TreasuryPolicy": {"status": "live_complete", "success": True},
                "CardIndexLedger": {"status": "live_complete", "success": True},
            },
            "registry_proof": None,
        },
    )

    packet = proof_pack.build_audit_packet(_canonical_evidence())
    quorum = packet["odra_quorum_exercise"]
    topology = packet["odra_topology_genesis"]

    assert quorum["verification_status"] == "unavailable"
    assert "summary" not in quorum
    assert "acceptance_criteria" not in quorum
    assert "live_deploys" not in quorum
    assert topology["verification_status"] == "unavailable"
    assert "acceptance" not in topology
    assert topology["module_names"] == [
        "CardIndexLedger",
        "CouncilRegistry",
        "TreasuryPolicy",
    ]
    assert "modules" not in topology


def test_legacy_quorum_boolean_and_hash_summary_cannot_satisfy_verifier() -> None:
    fabricated = {
        "odra_quorum_exercise": {
            "summary": {
                "pre_quorum_blocked": True,
                "two_signers_approved": True,
                "final_receipt_after_threshold": True,
                "backend_signed_final_receipt_after_quorum": True,
            },
            "live_deploys": {
                "configure_quorum": "01" * 32,
                "propose_envelope": "02" * 32,
                "pre_quorum_expected_failure": "03" * 32,
                "approve_envelope_server": "04" * 32,
                "approve_envelope_browser_wallet": "05" * 32,
                "final_store_governance_receipt": "06" * 32,
                "backend_final_store_governance_receipt": "07" * 32,
            },
            "option1_backend_signed_receipt": {
                "deploy_hash": "07" * 32,
                "entry_point": "store_governance_receipt",
                "finality": {"success": True},
            },
        }
    }

    failures = _quorum_failures_for_packet(fabricated)

    assert any("derived proof-registry" in failure.lower() for failure in failures)
    assert _quorum_failures_for_packet(
        {
            "odra_quorum_exercise": {
                "verification_status": "unavailable",
                "registry_proof": None,
            }
        }
    ) == []
    assert _quorum_failures_for_packet(
        {
            "odra_quorum_exercise": {
                "verification_status": "verified",
                "registry_proof": _exact_v3_item(),
            }
        }
    ) == []
