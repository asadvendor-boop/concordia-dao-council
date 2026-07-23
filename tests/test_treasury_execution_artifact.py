"""Frozen public artifact contract for one governed native transfer."""

from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from datetime import timedelta, datetime
from pathlib import Path

import pytest

from shared.treasury_execution_artifact import (
    TreasuryExecutionArtifactError,
    build_native_treasury_execution_artifact,
)
from shared.treasury_executor import ExecutionState
from tests.test_treasury_execution_proof import _proof_inputs
from tests.test_treasury_executor import _key


def _proven(tmp_path: Path):
    executor, authorization, proofs = _proof_inputs(tmp_path)
    return executor.prove_execution(_key(authorization), **proofs)


def _captured_after(entry: object) -> str:
    updated = datetime.fromisoformat(str(entry.updated_at).replace("Z", "+00:00"))
    return (updated + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")


def _build(entry):
    return build_native_treasury_execution_artifact(
        entry,
        captured_at=_captured_after(entry),
    )


def _execution_digest(post_json: str, scan_json: str, deploy_hash: str) -> str:
    material = {
        "post_balance_evidence_sha256": hashlib.sha256(
            post_json.encode("ascii")
        ).hexdigest(),
        "no_duplicate_scan_sha256": hashlib.sha256(
            scan_json.encode("ascii")
        ).hexdigest(),
        "deploy_hash": deploy_hash,
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def test_native_treasury_artifact_has_exact_outer_contract_and_is_canonical(
    tmp_path: Path,
) -> None:
    entry = _proven(tmp_path)
    encoded = _build(entry)
    artifact = json.loads(encoded)

    assert encoded == json.dumps(
        artifact,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert set(artifact) == {
        "schema_version",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "release_identity",
        "authorization",
        "executor_journal",
        "finality",
        "balance_evidence",
        "bounded_transfer_scan",
        "artifact_sha256_scope",
    }
    assert artifact["schema_version"] == "concordia.native_treasury_execution.v1"
    assert (
        artifact["artifact_sha256_scope"] == "canonical_json_without_release_manifest"
    )
    assert set(artifact["release_identity"]) == {
        "network",
        "package_hash",
        "contract_hash",
        "deployment_domain",
        "source_sha256",
        "wasm_sha256",
        "generated_schema_sha256",
    }
    assert set(artifact["authorization"]) == {
        "proposal_id",
        "action_id",
        "envelope_hash",
        "typed_header",
        "typed_body",
        "header_bytes_hex",
        "body_bytes_hex",
        "action_core_bytes_hex",
        "exact_v3_proof",
        "v3_readback",
        "snapshot",
    }
    assert set(artifact["executor_journal"]) == {
        "state",
        "signed_deploy_bytes_hex",
        "signed_deploy_sha256",
        "deploy_hash",
        "broadcast_attempts",
        "last_detail_code",
        "payment_amount_motes",
        "created_at",
        "updated_at",
        "execution_proof_sha256",
    }
    assert set(artifact["finality"]) == {
        "facts",
        "node_observations",
        "verification_scope",
    }
    assert artifact["executor_journal"]["state"] == "PROVEN"
    assert artifact["executor_journal"]["broadcast_attempts"] == 1
    assert artifact["bounded_transfer_scan"]["authorization_block_hash"] == (
        entry.authorization.finalization_block_hash.hex()
    )
    assert artifact["bounded_transfer_scan"]["observed_through_block_height"]
    assert artifact["bounded_transfer_scan"]["observed_through_block_hash"]
    assert artifact["bounded_transfer_scan"]["matched_transfer_count"] == 1
    assert (
        artifact["authorization"]["typed_header"]["proposal_id"]
        == entry.authorization.proposal_id
    )
    assert artifact["authorization"]["v3_readback"]
    assert artifact["balance_evidence"]["post_recipient"]
    assert "passed" not in artifact
    assert "verified" not in artifact


def test_native_treasury_artifact_rejects_non_proven_or_multiple_broadcasts(
    tmp_path: Path,
) -> None:
    entry = _proven(tmp_path)
    with pytest.raises(TreasuryExecutionArtifactError, match="PROVEN"):
        _build(replace(entry, state=ExecutionState.FINALIZED))
    with pytest.raises(TreasuryExecutionArtifactError, match="one broadcast"):
        _build(replace(entry, broadcast_attempts=2))


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"last_detail_code": "deploy_finalized"}, "execution_proven"),
        ({"created_at": "not-a-time"}, "timestamp"),
        ({"updated_at": "2000-01-01T00:00:00Z"}, "precedes"),
        ({"execution_proof_sha256": "00" * 32}, "execution proof digest"),
    ],
)
def test_native_treasury_artifact_rejects_contradictory_journal_metadata(
    tmp_path: Path,
    change: dict[str, object],
    error: str,
) -> None:
    entry = _proven(tmp_path)
    with pytest.raises(TreasuryExecutionArtifactError, match=error):
        _build(replace(entry, **change))


def test_native_treasury_artifact_reparses_emitted_finality_transcript(
    tmp_path: Path,
) -> None:
    entry = _proven(tmp_path)
    with pytest.raises(TreasuryExecutionArtifactError, match="finality"):
        _build(replace(entry, finality_node_observations_json="[]"))


def test_native_treasury_artifact_reparses_emitted_balance_transcript(
    tmp_path: Path,
) -> None:
    entry = _proven(tmp_path)
    post = json.loads(entry.post_balance_evidence_json or "{}")
    value = post["post_recipient"]["balance_response"]["result"]["value"]
    value["total_balance"] = str(int(value["total_balance"]) + 1)
    value["available_balance"] = str(int(value["available_balance"]) + 1)
    post_json = json.dumps(post, sort_keys=True, separators=(",", ":"))
    digest = _execution_digest(
        post_json,
        entry.no_duplicate_scan_json or "",
        entry.deploy_hash or "",
    )
    with pytest.raises(TreasuryExecutionArtifactError, match="balance"):
        _build(
            replace(
                entry,
                post_balance_evidence_json=post_json,
                execution_proof_sha256=digest,
            )
        )


def test_native_treasury_artifact_reparses_emitted_bounded_scan(
    tmp_path: Path,
) -> None:
    entry = _proven(tmp_path)
    scan = json.loads(entry.no_duplicate_scan_json or "{}")
    scan["authorization_block_height"] += 1
    scan_json = json.dumps(scan, sort_keys=True, separators=(",", ":"))
    digest = _execution_digest(
        entry.post_balance_evidence_json or "",
        scan_json,
        entry.deploy_hash or "",
    )
    with pytest.raises(TreasuryExecutionArtifactError, match="scan"):
        _build(
            replace(
                entry,
                no_duplicate_scan_json=scan_json,
                execution_proof_sha256=digest,
            )
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_commit", "not-a-commit"),
        ("deployment_commit", "A" * 40),
        ("captured_at", "2026-07-23 00:00:00"),
        ("captured_at", "2026-02-31T00:00:00Z"),
    ],
)
def test_native_treasury_artifact_rejects_invalid_release_metadata(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    entry = _proven(tmp_path)
    candidate = entry if field == "captured_at" else replace(entry, **{field: value})
    captured_at = value if field == "captured_at" else _captured_after(entry)
    with pytest.raises(TreasuryExecutionArtifactError):
        build_native_treasury_execution_artifact(
            candidate,
            captured_at=captured_at,
        )


def test_native_treasury_artifact_rejects_capture_before_journal_update(
    tmp_path: Path,
) -> None:
    entry = _proven(tmp_path)

    with pytest.raises(TreasuryExecutionArtifactError, match="capture timestamp"):
        build_native_treasury_execution_artifact(
            entry,
            captured_at="2000-01-01T00:00:00Z",
        )


def test_native_treasury_artifact_rejects_caller_constructed_lookalike() -> None:
    with pytest.raises(TreasuryExecutionArtifactError, match="journal entry"):
        build_native_treasury_execution_artifact(
            object(),
            captured_at="2000-01-01T00:00:00Z",
        )
