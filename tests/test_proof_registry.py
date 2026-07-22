from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from shared.proof_registry import (
    AmbiguousGovernanceBinding,
    ProofRegistryRepository,
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    build_public_registry,
    normalize_proof_item,
    proof_item_is_green,
    validate_internal_record,
)


NOW = "2026-07-22T20:00:00Z"
HEX32 = "ab" * 32
OTHER_HEX32 = "cd" * 32
GIT_SHA = "1" * 40


def _checks(proof_type: str, *, failed: str | None = None) -> list[dict]:
    return [
        {
            "name": name,
            "required": True,
            "passed": name != failed,
            "source": "artifacts/live/example.json",
            "observed_at": NOW,
        }
        for name in REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]
    ]


def _snapshot_item() -> dict:
    return {
        "proof_id": "snapshot-current",
        "proof_type": "snapshot",
        "generation": "none",
        "lineage": "supplemental",
        "observation_mode": "snapshot",
        "temporal_scope": "current",
        "verification_status": "verified",
        "execution_outcome": "not_applicable",
        "claim_scope": "Dated snapshot of one public proof source.",
        "enforcement_scope": "Evidence capture only; no execution authority.",
        "proposal_id": "DAO-PROP-TEST",
        "action_id": None,
        "envelope_hash": None,
        "artifact_path": "artifacts/live/example.json",
        "artifact_sha256": HEX32,
        "source_commit": GIT_SHA,
        "deployment_commit": None,
        "network": None,
        "package_hash": None,
        "contract_hash": None,
        "deployment_domain": None,
        "schema_version": "snapshot-v1",
        "captured_at": NOW,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "report_hash": None,
        "settlement_transaction": None,
        "checks": _checks("snapshot"),
        "links": [
            {
                "rel": "source",
                "label": "Source artifact",
                "href": "/dashboard/proof",
                "kind": "ui",
            }
        ],
    }


def _internal_record(*, kind: str = "OfficialX402SettlementV1") -> dict:
    x402 = kind == "OfficialX402SettlementV1"
    return {
        "schema_version": 1,
        "proposal_id": "DAO-PROP-TEST",
        "proposal_hash": "01" * 32,
        "proposal_nonce": "02" * 32,
        "action_id": "03" * 32,
        "action_kind": kind,
        "action_version": 1,
        "envelope_hash": "04" * 32,
        "deployment_domain": "05" * 32,
        "network": "casper:casper-test",
        "package_hash": "06" * 32,
        "contract_hash": "07" * 32,
        "v3_finalized_exact": True,
        "finalization_transaction": "08" * 32,
        "finalized_at": NOW,
        "resource_url_hash": "09" * 32 if x402 else None,
        "report_hash": "0a" * 32 if x402 else None,
        "payment_requirements_hash": "0b" * 32 if x402 else None,
        "signed_payment_payload_hash": "0c" * 32 if x402 else None,
        "verification_status": "verified",
        "observed_at": NOW,
        "checks": _checks("exact_envelope_v3"),
    }


def _write_registry(root: Path, public_items: list[dict], internal_records: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "public_items": public_items,
                "internal_records": internal_records,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_reg_01_every_public_item_keeps_all_provenance_dimensions() -> None:
    item = _snapshot_item()

    document = build_public_registry("DAO-PROP-TEST", [item], generated_at=NOW)

    assert document == {
        "schema_version": 1,
        "generated_at": NOW,
        "proposal_id": "DAO-PROP-TEST",
        "items": [item],
    }
    assert proof_item_is_green(document["items"][0]) is True


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("verification_status", "pending"),
        ("verification_status", "stale"),
        ("verification_status", "unavailable"),
        ("verification_status", "invalid"),
        ("observation_mode", "unavailable"),
        ("execution_outcome", "unknown"),
        ("execution_outcome", "not_attempted"),
        ("execution_outcome", "unexpected_rejection"),
    ],
)
def test_reg_02_unknown_stale_missing_or_failed_proof_never_turns_green(
    mutation: str,
    value: str,
) -> None:
    item = _snapshot_item()
    item[mutation] = value
    item["passed"] = True
    item["verified"] = True

    assert proof_item_is_green(item) is False


def test_reg_02_duplicate_or_missing_required_checks_fail_closed() -> None:
    duplicate = _snapshot_item()
    duplicate["checks"].append(copy.deepcopy(duplicate["checks"][0]))
    missing = _snapshot_item()
    missing["checks"].pop()
    failed = _snapshot_item()
    failed["checks"][0]["passed"] = False

    assert proof_item_is_green(duplicate) is False
    assert normalize_proof_item(duplicate)["verification_status"] == "invalid"
    assert proof_item_is_green(missing) is False
    assert normalize_proof_item(missing)["verification_status"] == "invalid"
    assert proof_item_is_green(failed) is False


def test_reg_03_historical_proof_retains_narrow_non_retroactive_semantics() -> None:
    item = _snapshot_item()
    item.update(
        {
            "proof_id": "historical-quorum-v2",
            "proof_type": "historical_odra_receipt_v2",
            "generation": "v2",
            "lineage": "supplemental",
            "observation_mode": "snapshot",
            "temporal_scope": "historical",
            "execution_outcome": "accepted",
            "claim_scope": "The v2 contract rejected receipt storage before quorum and accepted it after quorum.",
            "enforcement_scope": "Historical quorum-gated receipt storage only; no retroactive exact-envelope or custody claim.",
            "checks": _checks("historical_odra_receipt_v2"),
        }
    )

    normalized = normalize_proof_item(item)

    assert normalized["temporal_scope"] == "historical"
    assert "no retroactive" in normalized["enforcement_scope"].lower()
    assert proof_item_is_green(normalized) is True


def test_reg_04_each_current_artifact_class_has_a_distinct_required_check_set() -> None:
    expected = {
        "exact_envelope_v3",
        "native_treasury_execution_v1",
        "safepay_v2",
        "official_x402_settlement_v1",
    }

    assert expected <= set(REQUIRED_CHECKS_BY_PROOF_TYPE)
    assert len({tuple(REQUIRED_CHECKS_BY_PROOF_TYPE[name]) for name in expected}) == 4


def test_reg_04b_treasury_checks_state_the_bounded_rpc_observation_scope() -> None:
    checks = REQUIRED_CHECKS_BY_PROOF_TYPE["native_treasury_execution_v1"]

    assert "snapshot_block_hash_height_and_state_root_observed_from_casper_rpc" in checks
    assert (
        "source_balance_observed_at_snapshot_root_equals_treasury_snapshot_balance_motes"
        in checks
    )
    assert "successful_inclusion_observed_by_two_named_casper_rpc_nodes" in checks
    assert "no_second_native_transaction_observed_through_block" in checks
    assert all("for_action_id" not in check for check in checks)


@pytest.mark.parametrize("proof_type", ["exact_envelope_v3", "native_treasury_execution_v1"])
def test_reg_04c_v3_execution_items_require_deployment_domain(proof_type: str) -> None:
    item = _snapshot_item()
    item.update(
        {
            "proof_id": f"{proof_type}-current",
            "proof_type": proof_type,
            "generation": "v3",
            "observation_mode": "live",
            "execution_outcome": "accepted",
            "proposal_id": "DAO-PROP-TEST",
            "action_id": "01" * 32,
            "envelope_hash": "02" * 32,
            "network": "casper:casper-test",
            "package_hash": "03" * 32,
            "contract_hash": "04" * 32,
            "deployment_domain": "05" * 32,
            "deployment_commit": "2" * 40,
            "checks": _checks(proof_type),
        }
    )
    assert proof_item_is_green(item) is True

    item["deployment_domain"] = None
    assert proof_item_is_green(item) is False
    assert normalize_proof_item(item)["verification_status"] == "invalid"


@pytest.mark.parametrize(
    ("proof_type", "field", "invalid_value"),
    [
        ("exact_envelope_v3", "generation", "v1"),
        ("exact_envelope_v3", "lineage", "canonical"),
        ("exact_envelope_v3", "temporal_scope", "historical"),
        ("exact_envelope_v3", "execution_outcome", "expected_rejection"),
        ("native_treasury_execution_v1", "generation", "v2"),
        ("native_treasury_execution_v1", "lineage", "canonical"),
        ("native_treasury_execution_v1", "temporal_scope", "historical"),
        ("native_treasury_execution_v1", "execution_outcome", "not_applicable"),
    ],
)
def test_reg_04d_current_v3_execution_provenance_cannot_be_relabelled(
    proof_type: str,
    field: str,
    invalid_value: str,
) -> None:
    item = _snapshot_item()
    item.update(
        {
            "proof_id": f"{proof_type}-current",
            "proof_type": proof_type,
            "generation": "v3",
            "lineage": "supplemental",
            "observation_mode": "live",
            "temporal_scope": "current",
            "verification_status": "verified",
            "execution_outcome": "accepted",
            "proposal_id": "DAO-PROP-TEST",
            "action_id": "01" * 32,
            "envelope_hash": "02" * 32,
            "network": "casper:casper-test",
            "package_hash": "03" * 32,
            "contract_hash": "04" * 32,
            "deployment_domain": "05" * 32,
            "deployment_commit": "2" * 40,
            "checks": _checks(proof_type),
        }
    )
    item[field] = invalid_value

    assert proof_item_is_green(item) is False
    assert normalize_proof_item(item)["verification_status"] == "invalid"


@pytest.mark.parametrize(
    ("proof_type", "generation"),
    [("safepay_v2", "v2"), ("official_x402_settlement_v1", "v3")],
)
def test_reg_04e_payment_proof_provenance_is_generation_bound(
    proof_type: str,
    generation: str,
) -> None:
    item = _snapshot_item()
    item.update(
        {
            "proof_id": f"{proof_type}-current",
            "proof_type": proof_type,
            "generation": generation,
            "lineage": "supplemental",
            "observation_mode": "live",
            "temporal_scope": "current",
            "verification_status": "verified",
            "execution_outcome": "accepted",
            "deployment_commit": "2" * 40,
            "checks": _checks(proof_type),
        }
    )
    if proof_type == "official_x402_settlement_v1":
        item.update(
            {
                "action_id": "01" * 32,
                "envelope_hash": "02" * 32,
                "network": "casper:casper-test",
                "package_hash": "03" * 32,
                "contract_hash": "04" * 32,
                "deployment_domain": "05" * 32,
                "payment_requirements_hash": "06" * 32,
                "signed_payment_payload_hash": "07" * 32,
                "report_hash": "08" * 32,
                "settlement_transaction": "09" * 32,
            }
        )
    assert proof_item_is_green(item) is True

    item["generation"] = "v1"
    assert proof_item_is_green(item) is False
    assert normalize_proof_item(item)["verification_status"] == "invalid"


@pytest.mark.parametrize(
    ("proof_type", "generation", "field", "invalid_value"),
    [
        ("safepay_v2", "v2", "lineage", "canonical"),
        ("safepay_v2", "v2", "observation_mode", "unavailable"),
        ("safepay_v2", "v2", "temporal_scope", "historical"),
        ("safepay_v2", "v2", "execution_outcome", "expected_rejection"),
        ("official_x402_settlement_v1", "v3", "lineage", "canonical"),
        ("official_x402_settlement_v1", "v3", "observation_mode", "unavailable"),
        ("official_x402_settlement_v1", "v3", "temporal_scope", "historical"),
        ("official_x402_settlement_v1", "v3", "execution_outcome", "expected_rejection"),
    ],
)
def test_reg_04f_payment_proof_provenance_cannot_be_relabelled(
    proof_type: str,
    generation: str,
    field: str,
    invalid_value: str,
) -> None:
    item = _snapshot_item()
    item.update(
        {
            "proof_id": f"{proof_type}-current",
            "proof_type": proof_type,
            "generation": generation,
            "lineage": "supplemental",
            "observation_mode": "live",
            "temporal_scope": "current",
            "verification_status": "verified",
            "execution_outcome": "accepted",
            "deployment_commit": "2" * 40,
            "checks": _checks(proof_type),
        }
    )
    if proof_type == "official_x402_settlement_v1":
        item.update(
            {
                "action_id": "01" * 32,
                "envelope_hash": "02" * 32,
                "network": "casper:casper-test",
                "package_hash": "03" * 32,
                "contract_hash": "04" * 32,
                "deployment_domain": "05" * 32,
                "payment_requirements_hash": "06" * 32,
                "signed_payment_payload_hash": "07" * 32,
                "report_hash": "08" * 32,
                "settlement_transaction": "09" * 32,
            }
        )
    item[field] = invalid_value

    assert proof_item_is_green(item) is False
    assert normalize_proof_item(item)["verification_status"] == "invalid"


@pytest.mark.parametrize(
    "field",
    [
        "proposal_id",
        "action_id",
        "envelope_hash",
        "network",
        "package_hash",
        "contract_hash",
        "deployment_domain",
    ],
)
def test_reg_04g_official_x402_requires_exact_v3_execution_identity(field: str) -> None:
    item = _snapshot_item()
    item.update(
        {
            "proof_id": "official-x402-current",
            "proof_type": "official_x402_settlement_v1",
            "generation": "v3",
            "lineage": "supplemental",
            "observation_mode": "live",
            "temporal_scope": "current",
            "verification_status": "verified",
            "execution_outcome": "accepted",
            "action_id": "01" * 32,
            "envelope_hash": "02" * 32,
            "network": "casper:casper-test",
            "package_hash": "03" * 32,
            "contract_hash": "04" * 32,
            "deployment_domain": "05" * 32,
            "payment_requirements_hash": "06" * 32,
            "signed_payment_payload_hash": "07" * 32,
            "report_hash": "08" * 32,
            "settlement_transaction": "09" * 32,
            "deployment_commit": "2" * 40,
            "checks": _checks("official_x402_settlement_v1"),
        }
    )
    assert proof_item_is_green(item) is True

    item[field] = None
    assert proof_item_is_green(item) is False
    assert normalize_proof_item(item)["verification_status"] == "invalid"


def test_reg_05_snapshot_requires_capture_source_hash_and_staleness_observations() -> None:
    assert REQUIRED_CHECKS_BY_PROOF_TYPE["snapshot"] == (
        "artifact_sha256_recomputed",
        "capture_time_present",
        "source_https_url_present",
        "staleness_check_passed",
    )
    item = _snapshot_item()
    item["captured_at"] = None

    assert normalize_proof_item(item)["verification_status"] == "invalid"


def test_reg_05b_check_observation_cannot_follow_item_capture() -> None:
    item = _snapshot_item()
    item["captured_at"] = "2026-07-22T20:00:00Z"
    item["checks"][0]["observed_at"] = "2026-07-22T20:00:01Z"

    assert proof_item_is_green(item) is False
    assert normalize_proof_item(item)["verification_status"] == "invalid"


def test_reg_05c_item_capture_cannot_follow_registry_generation() -> None:
    item = _snapshot_item()
    item["captured_at"] = "2026-07-22T20:00:01Z"

    document = build_public_registry(
        "DAO-PROP-TEST",
        [item],
        generated_at="2026-07-22T20:00:00Z",
        reference_time="2026-07-22T20:00:02Z",
    )

    assert document["items"][0]["verification_status"] == "invalid"
    assert proof_item_is_green(document["items"][0]) is False


def test_reg_05d_registry_generation_cannot_be_in_the_verifier_future() -> None:
    with pytest.raises(ValueError, match="generated_at cannot be after reference_time"):
        build_public_registry(
            "DAO-PROP-TEST",
            [_snapshot_item()],
            generated_at="2099-01-01T00:00:00Z",
            reference_time="2026-07-22T20:00:00Z",
        )


@pytest.mark.parametrize("artifact_path", ["/tmp/secret.json", "../secret.json", "artifacts/../secret.json"])
def test_reg_05_artifact_paths_are_repository_relative_without_traversal(artifact_path: str) -> None:
    item = _snapshot_item()
    item["artifact_path"] = artifact_path

    assert normalize_proof_item(item)["verification_status"] == "invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("link", "javascript:alert(1)"),
        ("check_source", "http://insecure.example/proof"),
        ("check_source", "../outside.json"),
    ],
)
def test_reg_05_links_and_check_sources_accept_only_safe_locations(field: str, value: str) -> None:
    item = _snapshot_item()
    if field == "link":
        item["links"][0]["href"] = value
    else:
        item["checks"][0]["source"] = value

    assert normalize_proof_item(item)["verification_status"] == "invalid"


def test_reg_06_internal_record_recomputes_authorization_and_ignores_boolean_claims() -> None:
    record = _internal_record(kind="NativeTransferV1")
    record["checks"][0]["passed"] = False
    record["v3_finalized_exact"] = True

    validated = validate_internal_record(record)

    assert validated["v3_finalized_exact"] is False
    assert validated["verification_status"] == "invalid"


def test_reg_06_internal_record_rejects_unknown_fields() -> None:
    record = _internal_record()
    record["forged_verified"] = True

    validated = validate_internal_record(record)

    assert validated["v3_finalized_exact"] is False
    assert validated["verification_status"] == "invalid"


def test_internal_x402_lookup_rejects_ambiguous_current_verified_bindings(tmp_path: Path) -> None:
    one = _internal_record()
    two = copy.deepcopy(one)
    two["action_id"] = "0d" * 32
    repository = ProofRegistryRepository(tmp_path)
    _write_registry(tmp_path, [], [one, two])

    with pytest.raises(AmbiguousGovernanceBinding):
        repository.by_signed_payment_payload_hash(one["signed_payment_payload_hash"])


def test_registry_repository_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text(
        '{"schema_version":1,"schema_version":1,"public_items":[],"internal_records":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON key"):
        ProofRegistryRepository(tmp_path).public_document("DAO-PROP-TEST", known=True, generated_at=NOW)


def test_gateway_public_and_internal_registry_routes_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = _snapshot_item()
    internal = _internal_record()
    registry_root = tmp_path / "registry"
    _write_registry(registry_root, [item], [internal])
    token_file = tmp_path / "token"
    token_file.write_text("service-secret", encoding="utf-8")
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry_root))
    monkeypatch.setenv("X402_GATEWAY_TOKEN_FILE", str(token_file))

    with TestClient(create_app(db_path=":memory:")) as client:
        public = client.get("/proof-registry/v1/DAO-PROP-TEST")
        missing_auth = client.get(
            f"/internal/proof-registry/v1/actions/{internal['action_id']}"
        )
        wrong_auth = client.get(
            f"/internal/proof-registry/v1/actions/{internal['action_id']}",
            headers={"X-Concordia-Service-Token": "wrong-secret"},
        )
        authorized = client.get(
            f"/internal/proof-registry/v1/actions/{internal['action_id']}",
            headers={"X-Concordia-Service-Token": "service-secret"},
        )

    assert public.status_code == 200
    assert public.json()["items"][0]["proof_id"] == "snapshot-current"
    assert missing_auth.status_code == 403
    assert wrong_auth.status_code == 403
    assert authorized.status_code == 200
    assert authorized.json()["v3_finalized_exact"] is True


def test_gateway_registry_unknown_proposal_and_noncanonical_hash_are_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("service-secret", encoding="utf-8")
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(tmp_path / "missing"))
    monkeypatch.setenv("X402_GATEWAY_TOKEN_FILE", str(token_file))

    with TestClient(create_app(db_path=":memory:")) as client:
        unknown = client.get("/proof-registry/v1/DAO-PROP-UNKNOWN")
        bad_hash = client.get(
            "/internal/proof-registry/v1/actions/ABC",
            headers={"X-Concordia-Service-Token": "service-secret"},
        )

    assert unknown.status_code == 404
    assert unknown.json() == {"error": "proposal_not_found"}
    assert bad_hash.status_code == 404
    assert bad_hash.json() == {"error": "action_not_found"}
