"""Exact receipt contract for bound live payment-evidence collectors.

This module validates the receipt emitted by the fixed collector runner.  It
does not grant authority to caller-supplied acquisition rows: production
admission additionally binds the receipt to the immutable runner commit, the
accepted host-toolchain identity, and the collector's descriptor-safe private
outputs.  Keeping the pure schema validator here lets both the registry
assembler and G12 replay exactly the same contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any


COLLECTOR_RECEIPT_SCHEMA_VERSION = "concordia.bound_live_collector_receipt.v2"
COLLECTOR_CAPTURE_MODE = "direct_fixed_io"
COLLECTOR_RUNNER_PATH = "scripts/bound_live_proof_collector.py"

LIVE_COLLECTOR_RECEIPT_PATHS = {
    "safepay_v2": (
        "release/captures/payment-safepay-v2/collector-receipt.json"
    ),
    "official_x402_settlement_v1": (
        "release/captures/payment-official-x402/collector-receipt.json"
    ),
}
LIVE_COLLECTOR_RAW_PATHS = {
    "safepay_v2": "release/captures/payment-safepay-v2/raw-bundle.json",
    "official_x402_settlement_v1": (
        "release/captures/payment-official-x402/raw-bundle.json"
    ),
}
LIVE_COLLECTOR_ARTIFACT_PATHS = {
    "safepay_v2": (
        "release/captures/payment-safepay-v2/artifact-candidate.json"
    ),
    "official_x402_settlement_v1": (
        "release/captures/payment-official-x402/artifact-candidate.json"
    ),
}
LIVE_COLLECTOR_PLAN_PATHS = {
    "safepay_v2": "release/capture-plans/safepay-v2.json",
    "official_x402_settlement_v1": (
        "release/capture-plans/official-x402-settlement-v1.json"
    ),
}
LIVE_COLLECTOR_IDS = {
    "safepay_v2": "concordia-safepay-v2-live-collector",
    "official_x402_settlement_v1": "concordia-official-x402-live-collector",
}

_SAFEPAY_ACQUISITIONS = (
    "runtime_before_restart",
    "redemption_first_consumption",
    "ledger_after_first_consumption",
    "service_restart",
    "runtime_after_restart",
    "service_health_after_restart",
    "redemption_exact_retry",
    "ledger_after_exact_retry",
    "redemption_cross_binding_reuse",
    "ledger_after_cross_binding_reuse",
    "casper_rpc_a_info_get_deploy",
    "casper_rpc_a_chain_get_block",
    "casper_rpc_a_info_get_status",
    "casper_rpc_b_info_get_deploy",
    "casper_rpc_b_chain_get_block",
    "casper_rpc_b_info_get_status",
)
_OFFICIAL_ACQUISITIONS = (
    "runtime_before_restart",
    "facilitator_supported",
    "wcspr_pre_verify",
    "facilitator_verify",
    "wcspr_pre_settle",
    "paid_first_release",
    "journal_after_first_release",
    "facilitator_settle",
    "fulfillment_first_row",
    "settlement_rpc_a_info_get_transaction",
    "settlement_rpc_a_chain_get_block",
    "settlement_rpc_a_info_get_status",
    "settlement_rpc_b_info_get_transaction",
    "settlement_rpc_b_chain_get_block",
    "settlement_rpc_b_info_get_status",
    "wcspr_post_settle",
    "service_restart",
    "runtime_after_restart",
    "service_health_after_restart",
    "journal_after_restart",
    "fulfillment_post_restart_row",
    "paid_exact_retry",
    "journal_after_exact_retry",
    "paid_cross_binding_reuse",
    "journal_after_cross_binding_reuse",
)
_ACQUISITION_IDS = {
    "safepay_v2": _SAFEPAY_ACQUISITIONS,
    "official_x402_settlement_v1": _OFFICIAL_ACQUISITIONS,
}

_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_GIT40 = re.compile(r"^[0-9a-f]{40}$")
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_TRANSPORTS = {
    "https",
    "casper_rpc",
    "sqlite_backup",
    "docker_inspect",
    "docker_restart",
    "sqlite_row",
}
_TOOL_IDENTITY_KEYS = {
    "schema_version",
    "tool_id",
    "resolution",
    "resolved_path_sha256",
    "symlink_chain_sha256",
    "source_sha256",
    "source_size",
    "source_mode",
    "source_owner_uid",
    "version",
    "dependencies",
}


class CollectorProvenanceError(ValueError):
    """A collector receipt is not an exact direct-acquisition binding."""


def _canonical(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CollectorProvenanceError("collector receipt is not canonical") from exc


def _hash32(value: object, label: str) -> str:
    if type(value) is not str or _HEX32.fullmatch(value) is None:
        raise CollectorProvenanceError(f"{label} is not a SHA-256 digest")
    return value


def _git40(value: object, label: str) -> str:
    if type(value) is not str or _GIT40.fullmatch(value) is None:
        raise CollectorProvenanceError(f"{label} is not a Git commit")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise CollectorProvenanceError(f"{label} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CollectorProvenanceError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC:
        raise CollectorProvenanceError(f"{label} is not UTC")
    return parsed


def _relative_path(value: object, label: str) -> str:
    if type(value) is not str:
        raise CollectorProvenanceError(f"{label} path is invalid")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CollectorProvenanceError(f"{label} path is not confined")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CollectorProvenanceError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise CollectorProvenanceError(f"{label} must be an array")
    return value


def _validate_tool_identity(value: object) -> dict[str, object]:
    identity = _mapping(value, "collector tool identity")
    if (
        set(identity) != _TOOL_IDENTITY_KEYS
        or identity.get("tool_id") != "python"
        or type(identity.get("schema_version")) is not str
        or type(identity.get("resolution")) is not str
        or type(identity.get("version")) is not str
        or type(identity.get("dependencies")) is not dict
        or type(identity.get("source_size")) is not int
        or identity.get("source_size", -1) < 1
        or type(identity.get("source_mode")) is not int
        or type(identity.get("source_owner_uid")) is not int
    ):
        raise CollectorProvenanceError("collector tool identity schema differs")
    for field in (
        "resolved_path_sha256",
        "symlink_chain_sha256",
        "source_sha256",
    ):
        _hash32(identity.get(field), f"collector tool {field}")
    return dict(identity)


def _validate_command_assets(value: object) -> list[dict[str, object]]:
    assets = _sequence(value, "collector command assets")
    if not assets:
        raise CollectorProvenanceError("collector command assets are empty")
    normalized: list[dict[str, object]] = []
    for raw in assets:
        asset = _mapping(raw, "collector command asset")
        kind = asset.get("kind")
        if kind not in {"python_package", "data"}:
            raise CollectorProvenanceError("collector command asset kind differs")
        if kind == "python_package":
            required = {
                "kind",
                "schema_version",
                "tree_sha256",
                "entry_count",
                "file_count",
                "total_file_bytes",
                "immutable_system",
                "entrypoint_relative_sha256",
                "entrypoint_sha256",
                "entrypoint_size",
            }
            if set(asset) != required:
                raise CollectorProvenanceError(
                    "collector command package schema differs"
                )
            for field in (
                "tree_sha256",
                "entrypoint_relative_sha256",
                "entrypoint_sha256",
            ):
                _hash32(asset.get(field), f"collector command package {field}")
            for field in (
                "entry_count",
                "file_count",
                "total_file_bytes",
                "entrypoint_size",
            ):
                if type(asset.get(field)) is not int or asset[field] < 0:
                    raise CollectorProvenanceError(
                        "collector command package count differs"
                    )
            if (
                asset.get("schema_version") != "concordia.bound_tool_tree.v1"
                or type(asset.get("immutable_system")) is not bool
            ):
                raise CollectorProvenanceError(
                    "collector command package identity differs"
                )
        else:
            if set(asset) != {"kind", "path_sha256", "sha256", "size"}:
                raise CollectorProvenanceError("collector data asset schema differs")
            _hash32(asset.get("path_sha256"), "collector data path digest")
            _hash32(asset.get("sha256"), "collector data digest")
            if type(asset.get("size")) is not int or asset["size"] < 1:
                raise CollectorProvenanceError("collector data size differs")
        normalized.append(dict(asset))
    if sum(1 for item in normalized if item["kind"] == "python_package") != 1:
        raise CollectorProvenanceError("collector command package inventory differs")
    return normalized


def required_acquisition_ids(proof_id: str) -> tuple[str, ...]:
    try:
        return _ACQUISITION_IDS[proof_id]
    except KeyError as exc:
        raise CollectorProvenanceError("collector proof identity is unsupported") from exc


def _validate_acquisitions(
    proof_id: str,
    value: object,
    *,
    started: datetime,
    ended: datetime,
) -> list[dict[str, object]]:
    rows = _sequence(value, "collector acquisitions")
    expected = required_acquisition_ids(proof_id)
    if len(rows) != len(expected):
        raise CollectorProvenanceError("collector acquisition inventory differs")
    normalized: list[dict[str, object]] = []
    previous: datetime | None = None
    for raw, expected_id in zip(rows, expected, strict=True):
        row = _mapping(raw, f"collector acquisition {expected_id}")
        if set(row) != {
            "acquisition_id",
            "transport",
            "request_sha256",
            "response_sha256",
            "observed_at",
        }:
            raise CollectorProvenanceError("collector acquisition schema is not exact")
        if row.get("acquisition_id") != expected_id:
            raise CollectorProvenanceError("collector acquisition inventory differs")
        transport = row.get("transport")
        expected_transport = (
            "docker_restart"
            if expected_id == "service_restart"
            else "docker_inspect"
            if expected_id.startswith("runtime_")
            else "sqlite_backup"
            if expected_id.startswith(("ledger_", "journal_"))
            else "sqlite_row"
            if expected_id.startswith("fulfillment_")
            or expected_id == "facilitator_settle"
            else "casper_rpc"
            if "_rpc_" in expected_id or expected_id.startswith("wcspr_")
            else "https"
        )
        if transport not in _TRANSPORTS or transport != expected_transport:
            raise CollectorProvenanceError("collector transport is unsupported")
        request_sha256 = _hash32(
            row.get("request_sha256"), f"{expected_id} request digest"
        )
        response_sha256 = _hash32(
            row.get("response_sha256"), f"{expected_id} response digest"
        )
        observed_at = row.get("observed_at")
        observed = _timestamp(observed_at, f"{expected_id} observed_at")
        if not started <= observed <= ended:
            raise CollectorProvenanceError("collector acquisition chronology differs")
        if previous is not None and observed < previous:
            raise CollectorProvenanceError("collector acquisitions are not monotonic")
        previous = observed
        normalized.append(
            {
                "acquisition_id": expected_id,
                "transport": transport,
                "request_sha256": request_sha256,
                "response_sha256": response_sha256,
                "observed_at": observed_at,
            }
        )
    return normalized


def _file_binding(
    *,
    path: str,
    raw: bytes,
) -> dict[str, object]:
    return {
        "path": _relative_path(path, "collector output"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }


def build_collector_receipt(
    *,
    proof_id: str,
    started_at: str,
    ended_at: str,
    runner_path: str,
    runner_commit: str,
    runner_sha256: str,
    plan_path: str,
    plan_commit: str,
    plan_sha256: str,
    assembler_commit: str,
    assembler_source_tree_sha256: str,
    host_authority_sha256: str,
    tool_identity: Mapping[str, object],
    command_assets: Sequence[Mapping[str, object]],
    raw_bundle_path: str,
    raw_bundle_bytes: bytes,
    artifact_path: str,
    artifact_bytes: bytes,
    acquisitions: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Build an exact receipt from bound-command results, never status input."""

    started = _timestamp(started_at, "collector started_at")
    ended = _timestamp(ended_at, "collector ended_at")
    if ended < started:
        raise CollectorProvenanceError("collector chronology differs")
    normalized = _validate_acquisitions(
        proof_id, list(acquisitions), started=started, ended=ended
    )
    transcript_sha256 = hashlib.sha256(_canonical(normalized)).hexdigest()
    return {
        "schema_version": COLLECTOR_RECEIPT_SCHEMA_VERSION,
        "collector_id": LIVE_COLLECTOR_IDS[proof_id],
        "proof_id": proof_id,
        "capture_mode": COLLECTOR_CAPTURE_MODE,
        "started_at": started_at,
        "ended_at": ended_at,
        "collector": {
            "runner_path": _relative_path(runner_path, "collector runner"),
            "runner_commit": _git40(runner_commit, "collector runner commit"),
            "runner_sha256": _hash32(
                runner_sha256, "collector runner SHA-256"
            ),
            "tool_identity": _validate_tool_identity(dict(tool_identity)),
            "command_assets": _validate_command_assets(
                [dict(item) for item in command_assets]
            ),
            "exit_code": 0,
        },
        "plan": {
            "path": _relative_path(plan_path, "collector plan"),
            "artifact_commit": _git40(plan_commit, "collector plan commit"),
            "sha256": _hash32(plan_sha256, "collector plan SHA-256"),
        },
        "assembly": {
            "assembler_commit": _git40(
                assembler_commit, "collector assembler commit"
            ),
            "assembler_source_tree_sha256": _hash32(
                assembler_source_tree_sha256,
                "collector assembler source tree SHA-256",
            ),
        },
        "host_authority_sha256": _hash32(
            host_authority_sha256, "collector host authority SHA-256"
        ),
        "raw_bundle": _file_binding(path=raw_bundle_path, raw=raw_bundle_bytes),
        "artifact": _file_binding(path=artifact_path, raw=artifact_bytes),
        "acquisition_transcript_sha256": transcript_sha256,
        "acquisitions": normalized,
    }


def validate_collector_receipt(
    value: object,
    *,
    expected_proof_id: str,
    expected_runner_path: str,
    expected_runner_commit: str,
    expected_runner_sha256: str,
    expected_plan_path: str,
    expected_plan_commit: str,
    expected_plan_sha256: str,
    expected_assembler_commit: str,
    expected_assembler_source_tree_sha256: str,
    expected_host_authority_sha256: str,
    expected_tool_identity: Mapping[str, object],
    expected_command_assets: Sequence[Mapping[str, object]],
    raw_bundle_path: str,
    raw_bundle_bytes: bytes,
    artifact_path: str,
    artifact_bytes: bytes,
) -> dict[str, object]:
    """Validate one collector receipt against independently observed inputs."""

    document = _mapping(value, "collector receipt")
    if set(document) != {
        "schema_version",
        "collector_id",
        "proof_id",
        "capture_mode",
        "started_at",
        "ended_at",
        "collector",
        "plan",
        "assembly",
        "host_authority_sha256",
        "raw_bundle",
        "artifact",
        "acquisition_transcript_sha256",
        "acquisitions",
    }:
        raise CollectorProvenanceError("collector receipt schema is not exact")
    if (
        document.get("schema_version") != COLLECTOR_RECEIPT_SCHEMA_VERSION
        or document.get("collector_id") != LIVE_COLLECTOR_IDS[expected_proof_id]
        or document.get("proof_id") != expected_proof_id
    ):
        raise CollectorProvenanceError("collector receipt identity differs")
    if document.get("capture_mode") != COLLECTOR_CAPTURE_MODE:
        raise CollectorProvenanceError("collector capture mode is not direct")

    started = _timestamp(document.get("started_at"), "collector started_at")
    ended = _timestamp(document.get("ended_at"), "collector ended_at")
    if ended < started:
        raise CollectorProvenanceError("collector chronology differs")

    collector = _mapping(document.get("collector"), "collector identity")
    if set(collector) != {
        "runner_path",
        "runner_commit",
        "runner_sha256",
        "tool_identity",
        "command_assets",
        "exit_code",
    }:
        raise CollectorProvenanceError("collector identity schema is not exact")
    if (
        collector.get("runner_path") != expected_runner_path
        or collector.get("runner_commit") != expected_runner_commit
        or collector.get("runner_sha256") != expected_runner_sha256
        or collector.get("tool_identity") != dict(expected_tool_identity)
        or collector.get("command_assets")
        != [dict(item) for item in expected_command_assets]
        or collector.get("exit_code") != 0
    ):
        raise CollectorProvenanceError("collector runner identity differs")
    _validate_tool_identity(collector.get("tool_identity"))
    _validate_command_assets(collector.get("command_assets"))

    plan = _mapping(document.get("plan"), "collector plan")
    if set(plan) != {"path", "artifact_commit", "sha256"} or plan != {
        "path": expected_plan_path,
        "artifact_commit": expected_plan_commit,
        "sha256": expected_plan_sha256,
    }:
        raise CollectorProvenanceError("collector plan binding differs")
    _relative_path(plan.get("path"), "collector plan")
    _git40(plan.get("artifact_commit"), "collector plan commit")
    _hash32(plan.get("sha256"), "collector plan SHA-256")
    assembly = _mapping(document.get("assembly"), "collector assembly")
    if set(assembly) != {
        "assembler_commit",
        "assembler_source_tree_sha256",
    } or assembly != {
        "assembler_commit": expected_assembler_commit,
        "assembler_source_tree_sha256": expected_assembler_source_tree_sha256,
    }:
        raise CollectorProvenanceError("collector assembly binding differs")
    _git40(assembly.get("assembler_commit"), "collector assembler commit")
    _hash32(
        assembly.get("assembler_source_tree_sha256"),
        "collector assembler source tree SHA-256",
    )
    if document.get("host_authority_sha256") != expected_host_authority_sha256:
        raise CollectorProvenanceError("collector host authority binding differs")
    _hash32(document.get("host_authority_sha256"), "collector host authority SHA-256")

    expected_bundle = _file_binding(path=raw_bundle_path, raw=raw_bundle_bytes)
    bundle = _mapping(document.get("raw_bundle"), "collector raw bundle")
    if set(bundle) != {"path", "sha256", "size"}:
        raise CollectorProvenanceError("collector raw bundle schema is not exact")
    _relative_path(bundle.get("path"), "collector raw bundle")
    if bundle != expected_bundle:
        raise CollectorProvenanceError("collector raw bundle binding differs")
    expected_artifact = _file_binding(path=artifact_path, raw=artifact_bytes)
    artifact = _mapping(document.get("artifact"), "collector artifact")
    if set(artifact) != {"path", "sha256", "size"}:
        raise CollectorProvenanceError("collector artifact schema is not exact")
    _relative_path(artifact.get("path"), "collector artifact")
    if artifact != expected_artifact:
        raise CollectorProvenanceError("collector artifact binding differs")

    acquisitions = _validate_acquisitions(
        expected_proof_id,
        document.get("acquisitions"),
        started=started,
        ended=ended,
    )
    transcript_sha256 = hashlib.sha256(_canonical(acquisitions)).hexdigest()
    if document.get("acquisition_transcript_sha256") != transcript_sha256:
        raise CollectorProvenanceError("collector transcript digest differs")

    return {
        "schema_version": COLLECTOR_RECEIPT_SCHEMA_VERSION,
        "proof_id": expected_proof_id,
        "capture_mode": COLLECTOR_CAPTURE_MODE,
        "started_at": document["started_at"],
        "ended_at": document["ended_at"],
        "raw_bundle_path": raw_bundle_path,
        "raw_bundle_sha256": expected_bundle["sha256"],
        "artifact_path": artifact_path,
        "artifact_sha256": expected_artifact["sha256"],
        "runner_commit": expected_runner_commit,
        "runner_sha256": expected_runner_sha256,
        "plan_path": expected_plan_path,
        "plan_commit": expected_plan_commit,
        "plan_sha256": expected_plan_sha256,
        "assembler_commit": expected_assembler_commit,
        "assembler_source_tree_sha256": expected_assembler_source_tree_sha256,
        "host_authority_sha256": expected_host_authority_sha256,
        "acquisition_transcript_sha256": transcript_sha256,
    }


__all__ = [
    "COLLECTOR_CAPTURE_MODE",
    "COLLECTOR_RECEIPT_SCHEMA_VERSION",
    "COLLECTOR_RUNNER_PATH",
    "CollectorProvenanceError",
    "LIVE_COLLECTOR_ARTIFACT_PATHS",
    "LIVE_COLLECTOR_IDS",
    "LIVE_COLLECTOR_PLAN_PATHS",
    "LIVE_COLLECTOR_RAW_PATHS",
    "LIVE_COLLECTOR_RECEIPT_PATHS",
    "build_collector_receipt",
    "required_acquisition_ids",
    "validate_collector_receipt",
]
