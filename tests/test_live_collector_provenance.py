from __future__ import annotations

import copy
import hashlib
import json
import pytest

from scripts import bound_live_proof_collector
from shared.live_collector_provenance import (
    COLLECTOR_RECEIPT_SCHEMA_VERSION,
    CollectorProvenanceError,
    LIVE_COLLECTOR_ARTIFACT_PATHS,
    LIVE_COLLECTOR_PLAN_PATHS,
    LIVE_COLLECTOR_RAW_PATHS,
    build_collector_receipt,
    required_acquisition_ids,
    validate_collector_receipt,
)


PROOF_ID = "safepay_v2"
STARTED_AT = "2026-07-24T01:00:00Z"
ENDED_AT = "2026-07-24T01:04:00Z"
RUNNER_COMMIT = "ab" * 20
RUNNER_SHA256 = "cd" * 32
PLAN_COMMIT = "12" * 20
PLAN_SHA256 = "13" * 32
ASSEMBLER_COMMIT = "14" * 20
ASSEMBLER_TREE_SHA256 = "15" * 32
HOST_AUTHORITY_SHA256 = "16" * 32


@pytest.mark.parametrize(
    "proof_id", ("safepay_v2", "official_x402_settlement_v1")
)
def test_receipt_and_worker_share_one_exact_acquisition_order(
    proof_id: str,
) -> None:
    assert required_acquisition_ids(proof_id) == (
        bound_live_proof_collector._required_ids(proof_id)
    )


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _tool_identity() -> dict[str, object]:
    return {
        "schema_version": "concordia.bound_tool_identity.v1",
        "tool_id": "python",
        "resolution": "accepted_host_toolchain",
        "resolved_path_sha256": "01" * 32,
        "symlink_chain_sha256": "02" * 32,
        "source_sha256": "03" * 32,
        "source_size": 123,
        "source_mode": 0o100755,
        "source_owner_uid": 0,
        "version": "Python 3.12.11",
        "dependencies": {},
    }


def _command_assets() -> list[dict[str, object]]:
    return [
        {
            "kind": "python_package",
            "schema_version": "concordia.bound_tool_tree.v1",
            "tree_sha256": "04" * 32,
            "entry_count": 16,
            "file_count": 12,
            "total_file_bytes": 4567,
            "immutable_system": False,
            "entrypoint_relative_sha256": "05" * 32,
            "entrypoint_sha256": RUNNER_SHA256,
            "entrypoint_size": 456,
        },
        {
            "kind": "data",
            "path_sha256": "06" * 32,
            "sha256": "07" * 32,
            "size": 789,
        },
    ]


def _acquisitions() -> list[dict[str, object]]:
    return [
        {
            "acquisition_id": acquisition_id,
            "transport": (
                "docker_restart"
                if acquisition_id == "service_restart"
                else "casper_rpc"
                if "_rpc_" in acquisition_id or acquisition_id.startswith("wcspr_")
                else "sqlite_row"
                if acquisition_id.startswith("fulfillment_")
                else "https"
                if acquisition_id.startswith("service_health_")
                else
                "sqlite_backup"
                if acquisition_id.startswith(("ledger_", "journal_"))
                else "docker_inspect"
                if acquisition_id.startswith("runtime_")
                else "https"
            ),
            "request_sha256": hashlib.sha256(
                f"request:{acquisition_id}".encode()
            ).hexdigest(),
            "response_sha256": hashlib.sha256(
                f"response:{acquisition_id}".encode()
            ).hexdigest(),
            "observed_at": "2026-07-24T01:02:00Z",
        }
        for acquisition_id in required_acquisition_ids(PROOF_ID)
    ]


def _receipt(
    *,
    bundle_path: str = LIVE_COLLECTOR_RAW_PATHS[PROOF_ID],
    artifact_path: str = LIVE_COLLECTOR_ARTIFACT_PATHS[PROOF_ID],
) -> tuple[dict[str, object], bytes, bytes]:
    bundle = _canonical({"bundle_version": "test.bundle.v1", "raw": "observed"})
    artifact = _canonical(
        {
            "schema_version": "test.artifact.v1",
            "captured_at": ENDED_AT,
            "source_commit": "11" * 20,
            "deployment_commit": "22" * 20,
        }
    )
    document = build_collector_receipt(
        proof_id=PROOF_ID,
        started_at=STARTED_AT,
        ended_at=ENDED_AT,
        runner_path="scripts/bound_live_proof_collector.py",
        runner_commit=RUNNER_COMMIT,
        runner_sha256=RUNNER_SHA256,
        plan_path=LIVE_COLLECTOR_PLAN_PATHS[PROOF_ID],
        plan_commit=PLAN_COMMIT,
        plan_sha256=PLAN_SHA256,
        assembler_commit=ASSEMBLER_COMMIT,
        assembler_source_tree_sha256=ASSEMBLER_TREE_SHA256,
        host_authority_sha256=HOST_AUTHORITY_SHA256,
        tool_identity=_tool_identity(),
        command_assets=_command_assets(),
        raw_bundle_path=bundle_path,
        raw_bundle_bytes=bundle,
        artifact_path=artifact_path,
        artifact_bytes=artifact,
        acquisitions=_acquisitions(),
    )
    return document, bundle, artifact


def test_receipt_binds_exact_direct_collector_bytes_and_identity() -> None:
    document, bundle, artifact = _receipt()

    projection = validate_collector_receipt(
        document,
        expected_proof_id=PROOF_ID,
        expected_runner_path="scripts/bound_live_proof_collector.py",
        expected_runner_commit=RUNNER_COMMIT,
        expected_runner_sha256=RUNNER_SHA256,
        expected_plan_path=LIVE_COLLECTOR_PLAN_PATHS[PROOF_ID],
        expected_plan_commit=PLAN_COMMIT,
        expected_plan_sha256=PLAN_SHA256,
        expected_assembler_commit=ASSEMBLER_COMMIT,
        expected_assembler_source_tree_sha256=ASSEMBLER_TREE_SHA256,
        expected_host_authority_sha256=HOST_AUTHORITY_SHA256,
        expected_tool_identity=_tool_identity(),
        expected_command_assets=_command_assets(),
        raw_bundle_path=LIVE_COLLECTOR_RAW_PATHS[PROOF_ID],
        raw_bundle_bytes=bundle,
        artifact_path=LIVE_COLLECTOR_ARTIFACT_PATHS[PROOF_ID],
        artifact_bytes=artifact,
    )

    assert document["schema_version"] == COLLECTOR_RECEIPT_SCHEMA_VERSION
    assert projection == {
        "schema_version": COLLECTOR_RECEIPT_SCHEMA_VERSION,
        "proof_id": PROOF_ID,
        "capture_mode": "direct_fixed_io",
        "started_at": STARTED_AT,
        "ended_at": ENDED_AT,
        "raw_bundle_path": LIVE_COLLECTOR_RAW_PATHS[PROOF_ID],
        "raw_bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        "artifact_path": LIVE_COLLECTOR_ARTIFACT_PATHS[PROOF_ID],
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "runner_commit": RUNNER_COMMIT,
        "runner_sha256": RUNNER_SHA256,
        "plan_path": LIVE_COLLECTOR_PLAN_PATHS[PROOF_ID],
        "plan_commit": PLAN_COMMIT,
        "plan_sha256": PLAN_SHA256,
        "assembler_commit": ASSEMBLER_COMMIT,
        "assembler_source_tree_sha256": ASSEMBLER_TREE_SHA256,
        "host_authority_sha256": HOST_AUTHORITY_SHA256,
        "acquisition_transcript_sha256": document[
            "acquisition_transcript_sha256"
        ],
    }


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (
            lambda value: value.__setitem__("capture_mode", "operator_bundle"),
            "capture mode",
        ),
        (
            lambda value: value["acquisitions"].pop(),
            "acquisition inventory",
        ),
        (
            lambda value: value["acquisitions"][0].__setitem__(
                "response_sha256", "00" * 32
            ),
            "transcript digest",
        ),
        (
            lambda value: value["collector"].__setitem__(
                "runner_commit", "ff" * 20
            ),
            "runner identity",
        ),
        (
            lambda value: value["raw_bundle"].__setitem__(
                "sha256", "ff" * 32
            ),
            "raw bundle",
        ),
        (
            lambda value: value["artifact"].__setitem__("sha256", "ee" * 32),
            "artifact",
        ),
    ],
)
def test_receipt_fails_closed_on_self_labels_or_binding_mismatch(
    mutator: object, match: str
) -> None:
    document, bundle, artifact = _receipt()
    candidate = copy.deepcopy(document)
    mutator(candidate)  # type: ignore[operator]

    with pytest.raises(CollectorProvenanceError, match=match):
        validate_collector_receipt(
            candidate,
            expected_proof_id=PROOF_ID,
            expected_runner_path="scripts/bound_live_proof_collector.py",
            expected_runner_commit=RUNNER_COMMIT,
            expected_runner_sha256=RUNNER_SHA256,
            expected_plan_path=LIVE_COLLECTOR_PLAN_PATHS[PROOF_ID],
            expected_plan_commit=PLAN_COMMIT,
            expected_plan_sha256=PLAN_SHA256,
            expected_assembler_commit=ASSEMBLER_COMMIT,
            expected_assembler_source_tree_sha256=ASSEMBLER_TREE_SHA256,
            expected_host_authority_sha256=HOST_AUTHORITY_SHA256,
            expected_tool_identity=_tool_identity(),
            expected_command_assets=_command_assets(),
            raw_bundle_path=LIVE_COLLECTOR_RAW_PATHS[PROOF_ID],
            raw_bundle_bytes=bundle,
            artifact_path=LIVE_COLLECTOR_ARTIFACT_PATHS[PROOF_ID],
            artifact_bytes=artifact,
        )


def test_receipt_rejects_noncanonical_or_unconfined_paths() -> None:
    document, bundle, artifact = _receipt()
    document["raw_bundle"]["path"] = "../operator.json"

    with pytest.raises(CollectorProvenanceError, match="path"):
        validate_collector_receipt(
            document,
            expected_proof_id=PROOF_ID,
            expected_runner_path="scripts/bound_live_proof_collector.py",
            expected_runner_commit=RUNNER_COMMIT,
            expected_runner_sha256=RUNNER_SHA256,
            expected_plan_path=LIVE_COLLECTOR_PLAN_PATHS[PROOF_ID],
            expected_plan_commit=PLAN_COMMIT,
            expected_plan_sha256=PLAN_SHA256,
            expected_assembler_commit=ASSEMBLER_COMMIT,
            expected_assembler_source_tree_sha256=ASSEMBLER_TREE_SHA256,
            expected_host_authority_sha256=HOST_AUTHORITY_SHA256,
            expected_tool_identity=_tool_identity(),
            expected_command_assets=_command_assets(),
            raw_bundle_path=LIVE_COLLECTOR_RAW_PATHS[PROOF_ID],
            raw_bundle_bytes=bundle,
            artifact_path=LIVE_COLLECTOR_ARTIFACT_PATHS[PROOF_ID],
            artifact_bytes=artifact,
        )


def test_receipt_schema_is_exact_and_cannot_carry_operator_assertions() -> None:
    document, bundle, artifact = _receipt()
    document["verified"] = True

    with pytest.raises(CollectorProvenanceError, match="schema"):
        validate_collector_receipt(
            document,
            expected_proof_id=PROOF_ID,
            expected_runner_path="scripts/bound_live_proof_collector.py",
            expected_runner_commit=RUNNER_COMMIT,
            expected_runner_sha256=RUNNER_SHA256,
            expected_plan_path=LIVE_COLLECTOR_PLAN_PATHS[PROOF_ID],
            expected_plan_commit=PLAN_COMMIT,
            expected_plan_sha256=PLAN_SHA256,
            expected_assembler_commit=ASSEMBLER_COMMIT,
            expected_assembler_source_tree_sha256=ASSEMBLER_TREE_SHA256,
            expected_host_authority_sha256=HOST_AUTHORITY_SHA256,
            expected_tool_identity=_tool_identity(),
            expected_command_assets=_command_assets(),
            raw_bundle_path=LIVE_COLLECTOR_RAW_PATHS[PROOF_ID],
            raw_bundle_bytes=bundle,
            artifact_path=LIVE_COLLECTOR_ARTIFACT_PATHS[PROOF_ID],
            artifact_bytes=artifact,
        )


def test_acquisition_order_straddles_real_service_restart() -> None:
    safepay = required_acquisition_ids("safepay_v2")
    official = required_acquisition_ids("official_x402_settlement_v1")

    assert safepay.index("redemption_first_consumption") < safepay.index(
        "ledger_after_first_consumption"
    )
    assert safepay.index("ledger_after_first_consumption") < safepay.index(
        "service_restart"
    )
    assert safepay.index("service_restart") < safepay.index(
        "runtime_after_restart"
    )
    assert safepay.index("runtime_after_restart") < safepay.index(
        "redemption_exact_retry"
    )

    assert official.index("journal_after_first_release") < official.index(
        "service_restart"
    )
    assert official.index("service_restart") < official.index(
        "runtime_after_restart"
    )
    assert official.index("runtime_after_restart") < official.index(
        "journal_after_restart"
    )
    assert official.index("journal_after_restart") < official.index(
        "paid_exact_retry"
    )
