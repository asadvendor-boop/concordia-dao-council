from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import zlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Mapping, Sequence

import pytest

from shared import release_gate_contract, release_manifest
from shared.proof_registry import (
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    validate_release_registry_document,
)
from shared.release_manifest import (
    ARTIFACT_PATHS,
    COMMAND_GATE_ARTIFACT_PATHS,
    COMMAND_GATE_COMMANDS,
    COMMAND_GATE_RECEIPT_PATHS,
    COMMAND_GATE_RUNNER_PATHS,
    G13_RUNNER_PATH,
    G13_SUBMISSION_RECEIPT_PATH,
    NPM_CAPTURE_PATH,
    PROOF_RECEIPT_PATHS,
    RECEIPT_PATHS,
    RELEASE_MANIFEST_PATH,
    ReleaseManifestError,
    assemble_release_manifest_once,
    capture_release_observations_once,
    verify_command_gate_receipts,
    verify_g13_submission_receipt,
)


SOURCE_TIME = "2026-07-23T00:00:00Z"
CAPTURED_AT = "2026-07-23T00:10:00Z"
_TEST_COHOST_HOST = "peer-service.shared.invalid"
_TEST_COHOST_UPSTREAM = "peer-service-gateway:8000"
RECHECKED_AT = "2026-07-23T00:10:25Z"
BUILD_SCRIPT = Path(__file__).parents[1] / "scripts/build_release_manifest.py"
_TEST_IPFS_BODY = b'{"proposal_id":"DAO-PROP-6CB25C","archive":"test"}'


def _certificate_pdf() -> bytes:
    from reportlab.pdfgen.canvas import Canvas

    buffer = io.BytesIO()
    document = Canvas(buffer)
    document.setTitle("Concordia Governance Certificate - DAO-PROP-6CB25C")
    document.setAuthor("Concordia DAO Council")
    document.drawString(72, 720, "Concordia Governance Certificate")
    document.drawString(72, 700, "DAO-PROP-6CB25C")
    document.save()
    return buffer.getvalue()


_TEST_CERTIFICATE_PDF = _certificate_pdf()
_TEST_CARD_DOCUMENT = {
    "card_type": "ProposalCard",
    "previous_card_hash": None,
    "sequence_number": 1,
    "signal_id": "DAO-PROP-6CB25C",
}
_TEST_CARD_JSON = json.dumps(
    _TEST_CARD_DOCUMENT,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)
_TEST_CARD_HASH = hashlib.sha256(_TEST_CARD_JSON.encode()).hexdigest()


def _evidence_png(*, red: int, green: int, blue: int, solid: bool = False) -> bytes:
    """Return a deterministic, valid 800x450 RGB browser-capture fixture."""

    width = 800
    height = 450

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFF_FFFF
        return len(data).to_bytes(4, "big") + kind + data + crc.to_bytes(4, "big")

    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes((8, 2, 0, 0, 0))
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            if solid:
                rows.extend((red, green, blue))
            else:
                rows.extend(
                    (
                        (red + x + y) % 256,
                        (green + 2 * x + y) % 256,
                        (blue + x + 3 * y) % 256,
                    )
                )
    idat = zlib.compress(bytes(rows), level=9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
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


def test_release_command_environment_matches_the_frozen_allowlist() -> None:
    environment = release_manifest._sanitized_command_environment()
    allowed = set(
        release_gate_contract.BOUND_TOOL_POLICY["allowed_environment_keys"]
    )

    assert set(environment) <= allowed
    assert environment["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert environment["NPM_CONFIG_GLOBALCONFIG"] == "/dev/null"
    assert environment["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"


def _test_bound_process_launcher_identity() -> dict[str, object]:
    return {
        "schema_version": "concordia.bound_process_launcher.v1",
        "runtime_tree": {
            "schema_version": "concordia.bound_tool_tree.v1",
            "tree_sha256": "11" * 32,
            "entry_count": 12,
            "file_count": 8,
            "total_file_bytes": 4096,
            "immutable_system": False,
        },
        "active_closure_sha256": "22" * 32,
        "executable_relative_sha256": "33" * 32,
        "shim_sha256": "44" * 32,
        "invocation": ["-I", "-S"],
        "startup_environment": {"LANG": "C", "LC_ALL": "C"},
        "environment_transport": "exact_parent_frame",
        "exec_status": "ready_then_cloexec_eof_or_fixed_failure",
    }


def _git(repository: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "-A")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD").decode().strip()


def _write(repository: Path, relative: str, value: object) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_canonical(value))


def _write_bytes(repository: Path, relative: str, value: bytes) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value)


def _deployment_to_integration_paths() -> set[str]:
    return {
        *ARTIFACT_PATHS.values(),
        "handoff/G11_CLAIM_POLICY.json",
        *release_manifest.COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G11"],
    }


def _new_deployment_history_base(repository: Path) -> str:
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    _write_bytes(
        repository,
        "scripts/build_release_manifest.py",
        b"#!/usr/bin/env python3\nprint('release runner')\n",
    )
    _write_bytes(repository, "gateway/app.py", b"RUNTIME = 'reviewed'\n")
    _write(repository, ARTIFACT_PATHS["safepay_v2"], {"generation": "deployment"})
    return _commit(repository, "reviewed runtime deployment D")


def _write_evidence_integration(repository: Path) -> str:
    for index, relative in enumerate(sorted(_deployment_to_integration_paths())):
        if relative.endswith(".md"):
            _write_bytes(repository, relative, f"# Claim surface {index}\n".encode())
        else:
            _write(
                repository,
                relative,
                {"generation": "integration", "path": relative},
            )
    return _commit(repository, "evidence integration R")


def _write_exact_command_gate_commit(repository: Path) -> str:
    paths: list[str] = []
    for gate_id, receipt_path in COMMAND_GATE_RECEIPT_PATHS.items():
        _write(repository, receipt_path, {"gate_id": gate_id})
        paths.append(receipt_path)
        for command_id, _working_directory, _argv in COMMAND_GATE_COMMANDS[gate_id]:
            for stream in ("stdout", "stderr"):
                relative = _command_log_path(gate_id, command_id, stream)
                _write_bytes(repository, relative, b"")
                paths.append(relative)
    assert len(paths) == 37
    return _commit(repository, "exact command gate receipt commit C")


@pytest.fixture(scope="module")
def real_release_history(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, dict[str, str]]:
    repository = tmp_path_factory.mktemp("real-release-history") / "repository"
    deployment_commit = _new_deployment_history_base(repository)
    integration_commit = _write_evidence_integration(repository)
    command_commit = _write_exact_command_gate_commit(repository)
    candidate = release_manifest.build_host_toolchain_receipt_candidate(
        repository_root=repository,
        source_commit=command_commit,
    )
    _write(
        repository,
        release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        candidate,
    )
    host_commit = _commit(repository, "receipt-only host authority H")
    return repository, {
        "deployment": deployment_commit,
        "integration": integration_commit,
        "command": command_commit,
        "host": host_commit,
    }


def _command_log_path(gate_id: str, command_id: str, stream: str) -> str:
    return f"release/receipts/logs/{gate_id}/{command_id}.{stream}"


def _write_command_gate_receipts(
    repository: Path,
    *,
    frozen_commit: str,
    integration_commit: str,
) -> str:
    freeze_tag_object = (
        _git(
            repository,
            "rev-parse",
            f"refs/tags/{release_manifest.G1_FREEZE_TAG}",
        )
        .decode()
        .strip()
    )

    def executable_chain(tool: str) -> list[dict[str, object]]:
        digest = hashlib.sha256(tool.encode("utf-8")).hexdigest()
        return [
            {
                "role": "entrypoint",
                "invoked_path": f"<USER_LOCAL_BIN>/{tool}",
                "resolved_path": f"<USER_LOCAL_BIN>/{tool}",
                "invoked_device": 1,
                "invoked_inode": 2,
                "resolved_device": 1,
                "resolved_inode": 2,
                "size": 1024,
                "mode": 0o755,
                "owner_uid": 501,
                "mtime_ns": 1,
                "ctime_ns": 1,
                "sha256": digest,
            }
        ]

    for gate_id, commands in COMMAND_GATE_COMMANDS.items():
        command_rows: list[dict[str, object]] = []
        for index, (command_id, working_directory, argv) in enumerate(commands):
            stdout = f"{gate_id} {command_id} passed in <REPOSITORY_ROOT>\n".encode()
            stderr = b""
            stdout_path = _command_log_path(gate_id, command_id, "stdout")
            stderr_path = _command_log_path(gate_id, command_id, "stderr")
            _write_bytes(repository, stdout_path, stdout)
            _write_bytes(repository, stderr_path, stderr)
            command_rows.append(
                {
                    "command_id": command_id,
                    "working_directory": working_directory,
                    "argv": list(argv),
                    "started_at": f"2026-07-23T00:00:{index * 2:02d}Z",
                    "ended_at": f"2026-07-23T00:00:{index * 2 + 1:02d}Z",
                    "exit_code": 0,
                    "stdout": {
                        "path": stdout_path,
                        "sha256": hashlib.sha256(stdout).hexdigest(),
                    },
                    "stderr": {
                        "path": stderr_path,
                        "sha256": hashlib.sha256(stderr).hexdigest(),
                    },
                    "executable_chain": executable_chain(Path(argv[0]).name),
                }
            )
        runner_rows: list[dict[str, str]] = []
        for runner_path in release_manifest.COMMAND_GATE_IDENTITY_PATHS[gate_id]:
            runner_bytes = (repository / runner_path).read_bytes()
            path_commit = (
                _git(
                    repository,
                    "log",
                    "-1",
                    "--format=%H",
                    "--",
                    runner_path,
                )
                .decode()
                .strip()
            )
            runner_rows.append(
                {
                    "path": runner_path,
                    "commit": path_commit,
                    "sha256": hashlib.sha256(runner_bytes).hexdigest(),
                }
            )
        public_build_profile = None
        if gate_id == "G9":
            profile_values = dict(
                release_manifest.COMMAND_GATE_G9_PUBLIC_BUILD_PROFILE
            )
            public_build_profile = {
                "schema_version": (
                    release_manifest
                    .COMMAND_GATE_PUBLIC_BUILD_PROFILE_SCHEMA_VERSION
                ),
                "values": profile_values,
                "sha256": hashlib.sha256(
                    _canonical(profile_values)
                ).hexdigest(),
                "live_test": {
                    "values": dict(
                        release_manifest
                        .COMMAND_GATE_G9_LIVE_TEST_BUILD_PROFILE
                    ),
                    "sha256": hashlib.sha256(
                        _canonical(
                            dict(
                                release_manifest
                                .COMMAND_GATE_G9_LIVE_TEST_BUILD_PROFILE
                            )
                        )
                    ).hexdigest(),
                },
            }

        receipt = {
            "schema_version": release_manifest.COMMAND_GATE_RECEIPT_SCHEMA_VERSION,
            "gate_id": gate_id,
            "frozen_commit": frozen_commit,
            "freeze_tag": {
                "name": release_manifest.G1_FREEZE_TAG,
                "object": freeze_tag_object,
                "peeled_commit": frozen_commit,
            },
            "integration_commit": integration_commit,
            "clean_tree_sha256": hashlib.sha256(b"").hexdigest(),
            "normalization": dict(release_manifest.COMMAND_GATE_NORMALIZATION),
            "executable_chain_schema_version": (
                release_manifest.COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION
            ),
            "runner": runner_rows,
            "bound_process_launcher": _test_bound_process_launcher_identity(),
            "runtime_versions": {
                name: release_manifest.COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS[name]
                for name in release_manifest.COMMAND_GATE_REQUIRED_RUNTIMES[gate_id]
            },
            "runtime_executable_chains": {
                name: executable_chain(name)
                for name in release_manifest.COMMAND_GATE_REQUIRED_RUNTIMES[gate_id]
            },
            "public_build_profile": public_build_profile,
            "started_at": "2026-07-23T00:00:00Z",
            "ended_at": "2026-07-23T00:01:00Z",
            "commands": command_rows,
            "produced_artifacts": [
                {
                    "path": produced_path,
                    "sha256": hashlib.sha256(
                        (repository / produced_path).read_bytes()
                    ).hexdigest(),
                }
                for produced_path in COMMAND_GATE_ARTIFACT_PATHS[gate_id]
            ],
            "input_artifacts": [
                {
                    "path": input_path,
                    "sha256": hashlib.sha256(
                        (repository / input_path).read_bytes()
                    ).hexdigest(),
                }
                for input_path in release_manifest.COMMAND_GATE_INPUT_ARTIFACT_PATHS[
                    gate_id
                ]
            ],
            "fresh_outputs": [
                {"path": path, "state_before": "removed_or_absent"}
                for path in release_manifest.COMMAND_GATE_FRESH_OUTPUT_PATHS[gate_id]
            ],
        }
        _write(repository, COMMAND_GATE_RECEIPT_PATHS[gate_id], receipt)
    return _commit(repository, "immutable command gate receipts")


def _artifact_documents(
    source_commit: str, deployment_commit: str
) -> dict[str, dict[str, object]]:
    historical = {
        "schema_version": "concordia.historical_odra_receipt.v1",
        "proposal_id": "DAO-PROP-6CB25C",
        "generation": "v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "source_url": "https://concordia.47.84.232.193.sslip.io/proof-artifacts/v1/DAO-PROP-6CB25C/historical-odra-receipt",
        "network": "casper-test",
        "lineage_inventory": {"frozen": "inventory"},
        "contract_identity": {"package_hash": "11" * 32},
        "card_chain": {"terminal": _TEST_CARD_HASH},
        "raw_rpc": {"deploy": {"hash": "66" * 32}},
    }
    roots = {
        "schema_version": "concordia.card_chain_roots.v1",
        "roots": {"DAO-PROP-6CB25C": _TEST_CARD_HASH},
    }
    exact = {
        "schema_id": "concordia.v3-proof.v1",
        "deployment": {
            "network": "casper:casper-test",
            "package_hash": "11" * 32,
            "contract_hash": "22" * 32,
            "source_commit": source_commit,
            "deployment_commit": deployment_commit,
        },
        "input": {
            "action": "NativeTransferV1",
            "header": {
                "proposal_id": "DAO-PROP-6CB25C",
                "proposal_hash": "15" * 32,
                "proposal_nonce": "16" * 32,
                "action_version": 1,
                "deployment_domain": "13" * 32,
            },
        },
        "prepared": {"action_id": "33" * 32, "envelope_hash": "44" * 32},
        "run": {
            "steps": [
                {
                    "name": "finalize_exact",
                    "deploy_hash": "17" * 32,
                    "finality_block_evidence": {
                        "block_timestamp": SOURCE_TIME,
                        "finalized_at": SOURCE_TIME,
                        "observed_at": SOURCE_TIME,
                    },
                }
            ]
        },
        "readback": {
            "action_authorized": True,
            "proposal_finalized": True,
        },
    }
    treasury = {
        "schema_version": "concordia.native_treasury_execution.v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "release_identity": {"network": "casper-test"},
        "authorization": {
            "proposal_id": "DAO-PROP-6CB25C",
            "action_id": "33" * 32,
            "envelope_hash": "44" * 32,
        },
        "executor_journal": {"deploy_hash": "77" * 32},
        "finality": {"block_hash": "88" * 32},
        "balance_evidence": {"delta": 50_000_000_000},
        "bounded_transfer_scan": {"matches": 1},
        "artifact_sha256_scope": "canonical_json_without_release_manifest",
    }
    safepay = {
        "schema_version": "safepay-v2",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "capture_identity": {
            "provider_url": "https://x402-provider.example.invalid",
            "provider_deployment_id": "provider-release-1",
            "provider_image_digest": (
                "sha256:" + hashlib.sha256(b"x402-provider").hexdigest()
            ),
            "capture_tool_commit": source_commit,
        },
        "quote": {
            "quote_id": "123e4567-e89b-42d3-a456-426614174000",
            "proposal_id": "DAO-PROP-6CB25C",
            "resource_id": "risk-report:DAO-PROP-6CB25C",
            "network": "casper:casper-test",
            "report_hash": "aa" * 32,
        },
        "issued_quote_rows": {
            "before_restart": {"row_sha256": "90" * 32},
            "after_restart": {"row_sha256": "90" * 32},
        },
        "chain_evidence": {
            "network": "casper:casper-test",
            "payment_hash": "99" * 32,
            "providers": [{"endpoint_id": "node-a"}, {"endpoint_id": "node-b"}],
            "parsed_transfer": {"native_transfer_count": 1},
        },
        "consumption_rows": {
            "before_restart": {"row_sha256": "91" * 32},
            "after_restart": {"row_sha256": "91" * 32},
        },
        "ledger_evidence": {
            "authoritative_database_id": "safepay-provider-ledger",
            "authoritative_schema_id": "concordia.safepay-provider-ledger.sqlite.v1",
            "after_first_consumption": {"sqlite_backup_sha256": "92" * 32},
            "after_exact_retry": {"sqlite_backup_sha256": "93" * 32},
            "after_cross_binding_reuse": {"sqlite_backup_sha256": "94" * 32},
        },
        "redemption_observations": {
            "first_consumption": {"http_status": 200},
            "exact_retry": {"http_status": 200},
            "cross_binding_reuse": {"http_status": 409},
        },
        "protected_report": {
            "proposal_id": "DAO-PROP-6CB25C",
            "report_hash": "aa" * 32,
        },
    }
    official = {
        "schema_version": "concordia.official_x402_settlement.v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "capture_identity": {
            "service_url": "https://x402.example.invalid",
            "service_deployment_id": "x402-release-1",
            "service_image_digest": (
                "sha256:" + hashlib.sha256(b"x402-official").hexdigest()
            ),
            "capture_tool_commit": source_commit,
        },
        "governance_binding": {
            "proposal_id": "DAO-PROP-X402-FINALS-2026",
            "proposal_hash": "18" * 32,
            "proposal_nonce": "19" * 32,
            "action_id": "bb" * 32,
            "action_kind": "OfficialX402SettlementV1",
            "action_version": 1,
            "envelope_hash": "55" * 32,
            "deployment_domain": "13" * 32,
            "network": "casper:casper-test",
            "package_hash": "11" * 32,
            "contract_hash": "22" * 32,
            "finalization_transaction": "20" * 32,
            "finalized_at": CAPTURED_AT,
            "observed_at": CAPTURED_AT,
            "resource_url_hash": "21" * 32,
            "payment_requirements_hash": "14" * 32,
            "signed_payment_payload_hash": "cc" * 32,
            "report_hash": "12" * 32,
            "v3_proof_sha256": "23" * 32,
            "v3_proof_bytes_base64": "e30=",
        },
        "resource_and_payment": {
            "configured_resource_sha256": "21" * 32,
            "accepted_sha256": "14" * 32,
            "payment_requirements_argument_sha256": "14" * 32,
        },
        "authorization": {
            "payment_requirements_hash": "14" * 32,
            "signed_payment_payload_hash": "cc" * 32,
        },
        "facilitator": {
            "supported": {"response_sha256": "24" * 32},
            "verify": {"response_sha256": "25" * 32},
            "settle": {"response_sha256": "26" * 32},
            "parsed_verify": {"isValid": True},
            "parsed_settle": {"success": True},
        },
        "wcspr_readbacks": {
            "pre_verify": {"contract_hash": "27" * 32},
            "pre_settle": {"contract_hash": "27" * 32},
            "post_settle": {"contract_hash": "27" * 32},
        },
        "settlement_chain_evidence": {
            "network": "casper:casper-test",
            "settlement_transaction": "ee" * 32,
            "providers": [{"endpoint_id": "node-a"}, {"endpoint_id": "node-b"}],
            "parsed_settlement": {"execution_error": None},
        },
        "fulfillment": {
            "first_row": {"row_sha256": "28" * 32},
            "post_restart_row": {"row_sha256": "28" * 32},
            "exact_retry": {"response_status": 200},
            "cross_binding_reuse": {"response_status": 409},
        },
        "protected_report": {"report_hash": "12" * 32},
        "release_order": {
            "v3_finalized_at": CAPTURED_AT,
            "settlement_finalized_at": CAPTURED_AT,
            "report_released_at": CAPTURED_AT,
        },
    }

    artifact_by_proof = {
        "historical_odra_receipt_v2": (
            "historical_odra_receipt_v1",
            historical,
            "concordia.historical_odra_receipt.v1",
            "snapshot",
        ),
        "exact_envelope_v3": (
            "exact_envelope_v3",
            exact,
            "concordia.v3-proof.v1",
            "live",
        ),
        "native_treasury_execution_v1": (
            "native_treasury_execution_v1",
            treasury,
            "concordia.native_treasury_execution.v1",
            "live",
        ),
        "safepay_v2": ("safepay_v2", safepay, "safepay-v2", "live"),
        "official_x402_settlement_v1": (
            "official_x402_settlement_v1",
            official,
            "concordia.official_x402_settlement.v1",
            "live",
        ),
    }
    public_items: list[dict[str, object]] = []
    for proof_type, (artifact_id, artifact, schema, mode) in artifact_by_proof.items():
        generation = {
            "historical_odra_receipt_v2": "v1",
            "exact_envelope_v3": "v3",
            "native_treasury_execution_v1": "v3",
            "safepay_v2": "v2",
            "official_x402_settlement_v1": "v3",
        }[proof_type]
        action_id = (
            "33" * 32
            if proof_type in {"exact_envelope_v3", "native_treasury_execution_v1"}
            else "bb" * 32
            if proof_type == "official_x402_settlement_v1"
            else None
        )
        envelope_hash = (
            "44" * 32
            if proof_type in {"exact_envelope_v3", "native_treasury_execution_v1"}
            else "55" * 32
            if proof_type == "official_x402_settlement_v1"
            else None
        )
        executable = proof_type in {
            "exact_envelope_v3",
            "native_treasury_execution_v1",
            "official_x402_settlement_v1",
        }
        official_payment = proof_type == "official_x402_settlement_v1"
        public_items.append(
            {
                "proof_id": proof_type,
                "proof_type": proof_type,
                "generation": generation,
                "lineage": (
                    "canonical"
                    if proof_type == "historical_odra_receipt_v2"
                    else "supplemental"
                ),
                "temporal_scope": (
                    "historical"
                    if proof_type == "historical_odra_receipt_v2"
                    else "current"
                ),
                "execution_outcome": "accepted",
                "claim_scope": f"Verified {proof_type} evidence",
                "enforcement_scope": "Artifact and independent verifier checks",
                "proposal_id": (
                    "DAO-PROP-X402-FINALS-2026"
                    if official_payment
                    else "DAO-PROP-6CB25C"
                ),
                "action_id": action_id,
                "envelope_hash": envelope_hash,
                "schema_version": schema,
                "captured_at": CAPTURED_AT,
                "source_commit": source_commit,
                "deployment_commit": deployment_commit,
                "artifact_path": ARTIFACT_PATHS[artifact_id],
                "artifact_sha256": hashlib.sha256(_canonical(artifact)).hexdigest(),
                "verification_status": "verified",
                "observation_mode": mode,
                "network": "casper:casper-test",
                "package_hash": "11" * 32 if executable else None,
                "contract_hash": "22" * 32 if executable else None,
                "deployment_domain": "13" * 32 if executable else None,
                "payment_requirements_hash": (
                    "14" * 32 if official_payment else None
                ),
                "signed_payment_payload_hash": (
                    "cc" * 32 if official_payment else None
                ),
                "report_hash": (
                    "12" * 32
                    if official_payment
                    else "aa" * 32
                    if proof_type == "safepay_v2"
                    else None
                ),
                "settlement_transaction": (
                    "ee" * 32
                    if official_payment
                    else "99" * 32
                    if proof_type == "safepay_v2"
                    else None
                ),
                "checks": [
                    {
                        "name": name,
                        "required": True,
                        "passed": True,
                        "source": ARTIFACT_PATHS[artifact_id],
                        "observed_at": CAPTURED_AT,
                    }
                    for name in REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]
                ],
                "links": [
                    {
                        "rel": "artifact",
                        "label": proof_type,
                        "href": f"/{ARTIFACT_PATHS[artifact_id]}",
                        "kind": "artifact",
                    }
                ],
            }
        )
    exact_checks = [
        {
            "name": name,
            "required": True,
            "passed": True,
            "source": ARTIFACT_PATHS["exact_envelope_v3"],
            "observed_at": CAPTURED_AT,
        }
        for name in REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]
    ]
    internal_records = [
        {
            "schema_version": 1,
            "proposal_id": "DAO-PROP-6CB25C",
            "proposal_hash": "15" * 32,
            "proposal_nonce": "16" * 32,
            "action_id": "33" * 32,
            "action_kind": "NativeTransferV1",
            "action_version": 1,
            "envelope_hash": "44" * 32,
            "deployment_domain": "13" * 32,
            "network": "casper:casper-test",
            "package_hash": "11" * 32,
            "contract_hash": "22" * 32,
            "v3_finalized_exact": True,
            "finalization_transaction": "17" * 32,
            "finalized_at": SOURCE_TIME,
            "resource_url_hash": None,
            "report_hash": None,
            "payment_requirements_hash": None,
            "signed_payment_payload_hash": None,
            "verification_status": "verified",
            "observed_at": CAPTURED_AT,
            "checks": exact_checks,
        },
        {
            "schema_version": 1,
            "proposal_id": "DAO-PROP-X402-FINALS-2026",
            "proposal_hash": "18" * 32,
            "proposal_nonce": "19" * 32,
            "action_id": "bb" * 32,
            "action_kind": "OfficialX402SettlementV1",
            "action_version": 1,
            "envelope_hash": "55" * 32,
            "deployment_domain": "13" * 32,
            "network": "casper:casper-test",
            "package_hash": "11" * 32,
            "contract_hash": "22" * 32,
            "v3_finalized_exact": True,
            "finalization_transaction": "20" * 32,
            "finalized_at": CAPTURED_AT,
            "resource_url_hash": "21" * 32,
            "report_hash": "12" * 32,
            "payment_requirements_hash": "14" * 32,
            "signed_payment_payload_hash": "cc" * 32,
            "verification_status": "verified",
            "observed_at": CAPTURED_AT,
            "checks": [
                {
                    "name": name,
                    "required": True,
                    "passed": True,
                    "source": ARTIFACT_PATHS["official_x402_settlement_v1"],
                    "observed_at": CAPTURED_AT,
                }
                for name in REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]
            ],
        },
    ]
    registry = {
        "schema_version": 1,
        "public_items": public_items,
        "internal_records": internal_records,
        "card_chain_roots": {
            "artifact_path": ARTIFACT_PATHS["card_chain_roots_v1"],
            "artifact_sha256": hashlib.sha256(_canonical(roots)).hexdigest(),
        },
    }
    return {
        "historical_odra_receipt_v1": historical,
        "card_chain_roots_v1": roots,
        "exact_envelope_v3": exact,
        "native_treasury_execution_v1": treasury,
        "official_x402_settlement_v1": official,
        "proof_registry_v1": registry,
        "safepay_v2": safepay,
    }


def _adapter_check(check: Mapping[str, object]) -> dict[str, object]:
    return {
        "name": check["name"],
        "passed": True,
        "source": check["source"],
        "observed_at": check["observed_at"],
        "evidence_paths": ["/independently/recomputed/evidence"],
        "evidence_sha256": "31" * 32,
    }


def _adapter_results(
    documents: Mapping[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    registry = documents["proof_registry_v1"]
    public_items = {
        str(item["proof_type"]): item
        for item in registry["public_items"]
        if type(item) is dict
    }
    internal_records = {
        str(item["action_kind"]): item
        for item in registry["internal_records"]
        if type(item) is dict
    }
    safepay_item = public_items["safepay_v2"]
    safepay = documents["safepay_v2"]
    safepay_quote = safepay["quote"]
    safepay_chain = safepay["chain_evidence"]
    official_item = public_items["official_x402_settlement_v1"]
    official = documents["official_x402_settlement_v1"]
    official_governance = official["governance_binding"]
    official_settlement = official["settlement_chain_evidence"]
    return {
        "safepay_v2": {
            "schema_version": "concordia.safepay_v2_adapter_result.v1",
            "proof_type": "safepay_v2",
            "artifact_sha256": hashlib.sha256(_canonical(safepay)).hexdigest(),
            "derived_facts": {
                "proposal_id": safepay_quote["proposal_id"],
                "resource_id": safepay_quote["resource_id"],
                "network": safepay_quote["network"],
                "quote_id": safepay_quote["quote_id"],
                "quote_hash": "32" * 32,
                "correlation_id": "1234",
                "payment_hash": safepay_chain["payment_hash"],
                "report_hash": safepay_item["report_hash"],
                "first_fulfillment_hash": "33" * 32,
                "retry_fulfillment_hash": "33" * 32,
                "consumption_count": 1,
                "source_commit": safepay["source_commit"],
                "deployment_commit": safepay["deployment_commit"],
                "captured_at": safepay["captured_at"],
            },
            "checks": [
                _adapter_check(check) for check in safepay_item["checks"]
            ],
        },
        "official_x402_settlement_v1": {
            "schema_version": "concordia.official_x402_adapter_result.v1",
            "proof_type": "official_x402_settlement_v1",
            "artifact_sha256": hashlib.sha256(_canonical(official)).hexdigest(),
            "derived_facts": {
                "proposal_id": official_governance["proposal_id"],
                "proposal_hash": official_governance["proposal_hash"],
                "proposal_nonce": official_governance["proposal_nonce"],
                "action_id": official_governance["action_id"],
                "action_kind": official_governance["action_kind"],
                "action_version": official_governance["action_version"],
                "envelope_hash": official_governance["envelope_hash"],
                "deployment_domain": official_governance["deployment_domain"],
                "network": official_governance["network"],
                "package_hash": official_governance["package_hash"],
                "contract_hash": official_governance["contract_hash"],
                "v3_finalized_exact": True,
                "finalization_transaction": official_governance[
                    "finalization_transaction"
                ],
                "finalized_at": official_governance["finalized_at"],
                "observed_at": official_governance["observed_at"],
                "resource_url_hash": official_governance["resource_url_hash"],
                "payment_requirements_hash": official_governance[
                    "payment_requirements_hash"
                ],
                "signed_payment_payload_hash": official_governance[
                    "signed_payment_payload_hash"
                ],
                "report_hash": official_governance["report_hash"],
                "settlement_transaction": official_settlement[
                    "settlement_transaction"
                ],
                "source_commit": official["source_commit"],
                "deployment_commit": official["deployment_commit"],
                "captured_at": official["captured_at"],
            },
            "internal_record": internal_records["OfficialX402SettlementV1"],
            "checks": [
                _adapter_check(check) for check in official_item["checks"]
            ],
        },
    }


def _parity_artifacts(
    documents: Mapping[str, dict[str, object]],
    *,
    adapter_results: Mapping[str, dict[str, object]] | None = None,
) -> dict[str, release_manifest._Artifact]:
    results: dict[str, release_manifest._Artifact] = {}
    for artifact_id in (
        "historical_odra_receipt_v1",
        "card_chain_roots_v1",
        "exact_envelope_v3",
        "native_treasury_execution_v1",
        "official_x402_settlement_v1",
        "proof_registry_v1",
        "safepay_v2",
    ):
        document = documents[artifact_id]
        raw = _canonical(document)
        metadata = release_manifest._artifact_metadata(
            artifact_id,
            document,
            historical=results.get("historical_odra_receipt_v1"),
            artifact_commit="fe" * 20,
        )
        results[artifact_id] = release_manifest._Artifact(
            artifact_id=artifact_id,
            bound=release_manifest._BoundFile(
                path=ARTIFACT_PATHS[artifact_id],
                raw=raw,
                sha256=hashlib.sha256(raw).hexdigest(),
                artifact_commit="fe" * 20,
                fingerprint=(1, 1, len(raw), 1),
            ),
            document=document,
            canonical=raw,
            schema_version=metadata[0],
            captured_at=metadata[1],
            source_commit=metadata[2],
            deployment_commit=metadata[3],
            observation_mode=metadata[4],
            adapter_result=(
                None
                if adapter_results is None
                else adapter_results.get(artifact_id)
            ),
        )
    return results


def test_fixed_proof_evidence_inventory_matches_pinned_live_schemas() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    root = Path(__file__).parents[1]
    expected = {
        "safepay_v2": (
            "capture_identity",
            "quote",
            "issued_quote_rows",
            "chain_evidence",
            "consumption_rows",
            "ledger_evidence",
            "redemption_observations",
            "protected_report",
        ),
        "official_x402_settlement_v1": (
            "capture_identity",
            "governance_binding",
            "resource_and_payment",
            "authorization",
            "facilitator",
            "wcspr_readbacks",
            "settlement_chain_evidence",
            "fulfillment",
            "protected_report",
            "release_order",
        ),
    }
    schema_paths = {
        "safepay_v2": "handoff/schemas/safepay-v2-live-artifact.schema.json",
        "official_x402_settlement_v1": (
            "handoff/schemas/official-x402-live-artifact.schema.json"
        ),
    }
    for artifact_id, evidence_fields in expected.items():
        assert release_manifest._REQUIRED_EVIDENCE_FIELDS[artifact_id] == (
            evidence_fields
        )
        schema = json.loads((root / schema_paths[artifact_id]).read_bytes())
        assert tuple(schema["required"][4:]) == evidence_fields
        assert set(documents[artifact_id]) == set(schema["required"])
        release_manifest._require_nonempty_proof(
            artifact_id, documents[artifact_id]
        )


def test_fixed_proof_registry_parity_uses_only_independent_adapter_results() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    adapter_results = _adapter_results(documents)
    artifacts = _parity_artifacts(
        documents,
        adapter_results=adapter_results,
    )

    release_manifest._validate_registry_parity(artifacts)

    forged = json.loads(json.dumps(documents))
    forged["safepay_v2"]["verification"] = {
        "verified": True,
        "report_hash": "aa" * 32,
    }
    forged["official_x402_settlement_v1"]["governance_binding"][
        "v3_finalized_exact"
    ] = True
    forged["official_x402_settlement_v1"]["governance_binding"]["checks"] = [
        {"name": "producer_claim", "passed": True}
    ]
    for proof_type, artifact_id in (
        ("safepay_v2", "safepay_v2"),
        ("official_x402_settlement_v1", "official_x402_settlement_v1"),
    ):
        item = next(
            row
            for row in forged["proof_registry_v1"]["public_items"]
            if row["proof_type"] == proof_type
        )
        item["artifact_sha256"] = hashlib.sha256(
            _canonical(forged[artifact_id])
        ).hexdigest()
    with pytest.raises(
        ReleaseManifestError,
        match="independent adapter result",
    ):
        release_manifest._validate_registry_parity(
            _parity_artifacts(forged, adapter_results={})
        )


def test_fixed_proof_registry_parity_rejects_adapter_fact_or_check_drift() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    adapter_results = _adapter_results(documents)
    bad_report = json.loads(json.dumps(adapter_results))
    bad_report["safepay_v2"]["derived_facts"]["report_hash"] = "ab" * 32
    with pytest.raises(ReleaseManifestError, match="SafePay.*adapter"):
        release_manifest._validate_registry_parity(
            _parity_artifacts(documents, adapter_results=bad_report)
        )

    bad_check = json.loads(json.dumps(adapter_results))
    bad_check["official_x402_settlement_v1"]["checks"][0]["name"] = (
        "producer_claim"
    )
    with pytest.raises(ReleaseManifestError, match="official-x402.*adapter"):
        release_manifest._validate_registry_parity(
            _parity_artifacts(documents, adapter_results=bad_check)
        )


def test_fixed_proof_registry_parity_binds_safepay_payment_hash() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    adapter_results = _adapter_results(documents)
    safepay_item = next(
        item
        for item in documents["proof_registry_v1"]["public_items"]
        if item["proof_type"] == "safepay_v2"
    )
    safepay_item["settlement_transaction"] = "98" * 32

    with pytest.raises(ReleaseManifestError, match="SafePay.*adapter"):
        release_manifest._validate_registry_parity(
            _parity_artifacts(documents, adapter_results=adapter_results)
        )


def test_payment_artifact_image_digests_bind_to_observed_runtime() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    artifacts = _parity_artifacts(
        documents,
        adapter_results=_adapter_results(documents),
    )
    compose = _compose_raw()
    runtime = {
        "deployment_commit": "2" * 40,
        "containers": _runtime_raw(compose, "2" * 40),
    }

    release_manifest._validate_payment_artifact_runtime_binding(
        artifacts,
        runtime,
    )

    documents["official_x402_settlement_v1"]["capture_identity"][
        "service_image_digest"
    ] = "sha256:" + "00" * 32
    with pytest.raises(ReleaseManifestError, match="official-x402.*image"):
        release_manifest._validate_payment_artifact_runtime_binding(
            _parity_artifacts(
                documents,
                adapter_results=_adapter_results(documents),
            ),
            runtime,
        )


def test_payment_artifact_deployment_must_match_runtime_D() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    artifacts = _parity_artifacts(
        documents,
        adapter_results=_adapter_results(documents),
    )
    artifacts["safepay_v2"] = replace(
        artifacts["safepay_v2"],
        deployment_commit="3" * 40,
    )
    runtime = {
        "deployment_commit": "2" * 40,
        "containers": _runtime_raw(_compose_raw(), "2" * 40),
    }

    with pytest.raises(ReleaseManifestError, match="deployment commit"):
        release_manifest._validate_payment_artifact_runtime_binding(
            artifacts,
            runtime,
        )


def test_official_x402_adapter_capture_cannot_be_future_dated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    official = documents["official_x402_settlement_v1"]
    future = (
        (datetime.now(UTC) + timedelta(minutes=1))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    official["captured_at"] = future
    raw = _canonical(official)
    result = _adapter_results(documents)["official_x402_settlement_v1"]
    result["artifact_sha256"] = hashlib.sha256(raw).hexdigest()
    result["derived_facts"]["captured_at"] = future
    monkeypatch.setattr(
        release_manifest.release_proof_adapters,
        "verify_official_x402_artifact",
        lambda document, artifact_bytes: result,
    )

    with pytest.raises(
        ReleaseManifestError,
        match="official_x402_settlement_v1 independent adapter release identity differs",
    ):
        release_manifest._run_release_adapter(
            artifact_id="official_x402_settlement_v1",
            document=official,
            raw=raw,
            metadata=(
                "concordia.official_x402_settlement.v1",
                future,
                "1" * 40,
                "2" * 40,
                "live",
            ),
        )


def test_release_adapter_check_cannot_be_future_dated() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    result = _adapter_results(documents)["official_x402_settlement_v1"]
    result["checks"][0]["observed_at"] = (
        (datetime.now(UTC) + timedelta(minutes=1))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    with pytest.raises(
        ReleaseManifestError,
        match="official_x402_settlement_v1 independent adapter check is future-dated",
    ):
        release_manifest._adapter_registry_checks(
            result,
            "official_x402_settlement_v1",
        )


def test_release_registry_parity_rejects_future_dated_artifact() -> None:
    documents = _artifact_documents("1" * 40, "2" * 40)
    documents["official_x402_settlement_v1"]["captured_at"] = (
        (datetime.now(UTC) + timedelta(minutes=1))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    with pytest.raises(
        ReleaseManifestError,
        match="registry artifact is future-dated: official_x402_settlement_v1",
    ):
        release_manifest._validate_registry_parity(_parity_artifacts(documents))


def test_release_registry_requires_all_five_proofs_green_and_card_roots() -> None:
    registry = _artifact_documents("1" * 40, "2" * 40)["proof_registry_v1"]
    assert validate_release_registry_document(registry) == registry

    pending = json.loads(json.dumps(registry))
    safepay = next(
        item
        for item in pending["public_items"]
        if item["proof_type"] == "safepay_v2"
    )
    safepay["verification_status"] = "pending"
    with pytest.raises(ValueError, match="not independently green: safepay_v2"):
        validate_release_registry_document(pending)

    missing_roots = json.loads(json.dumps(registry))
    missing_roots.pop("card_chain_roots")
    with pytest.raises(ValueError, match="card-chain root binding"):
        validate_release_registry_document(missing_roots)


def test_release_registry_requires_distinct_official_proposal_on_same_v3_deployment() -> None:
    registry = _artifact_documents("1" * 40, "2" * 40)["proof_registry_v1"]
    by_type = {
        item["proof_type"]: item for item in registry["public_items"]
    }
    official_record = next(
        record
        for record in registry["internal_records"]
        if record["action_kind"] == "OfficialX402SettlementV1"
    )

    main_proposal = by_type["historical_odra_receipt_v2"]["proposal_id"]
    assert by_type["exact_envelope_v3"]["proposal_id"] == main_proposal
    assert by_type["native_treasury_execution_v1"]["proposal_id"] == main_proposal
    assert by_type["safepay_v2"]["proposal_id"] == main_proposal
    assert by_type["official_x402_settlement_v1"]["proposal_id"] != (
        by_type["exact_envelope_v3"]["proposal_id"]
    )
    assert validate_release_registry_document(registry) == registry

    same_proposal = json.loads(json.dumps(registry))
    same_official = next(
        item
        for item in same_proposal["public_items"]
        if item["proof_type"] == "official_x402_settlement_v1"
    )
    same_record = next(
        record
        for record in same_proposal["internal_records"]
        if record["action_kind"] == "OfficialX402SettlementV1"
    )
    same_official["proposal_id"] = by_type["exact_envelope_v3"]["proposal_id"]
    same_record["proposal_id"] = by_type["exact_envelope_v3"]["proposal_id"]
    with pytest.raises(ValueError, match="official x402 proposal must be distinct"):
        validate_release_registry_document(same_proposal)

    different_deployment = json.loads(json.dumps(registry))
    different_official = next(
        item
        for item in different_deployment["public_items"]
        if item["proof_type"] == "official_x402_settlement_v1"
    )
    different_record = next(
        record
        for record in different_deployment["internal_records"]
        if record["action_kind"] == "OfficialX402SettlementV1"
    )
    different_official["contract_hash"] = "fe" * 32
    different_record["contract_hash"] = "fe" * 32
    with pytest.raises(ValueError, match="same v3 deployment"):
        validate_release_registry_document(different_deployment)

    reused_action = json.loads(json.dumps(registry))
    exact_item = next(
        item
        for item in reused_action["public_items"]
        if item["proof_type"] == "exact_envelope_v3"
    )
    reused_official = next(
        item
        for item in reused_action["public_items"]
        if item["proof_type"] == "official_x402_settlement_v1"
    )
    reused_official["action_id"] = exact_item["action_id"]
    with pytest.raises(
        ValueError,
        match=(
            "public proof lacks an exact internal action binding"
            "|public/internal proof binding differs"
            "|action IDs must differ"
        ),
    ):
        validate_release_registry_document(reused_action)

    assert official_record["proposal_id"] == "DAO-PROP-X402-FINALS-2026"


def _compose_raw() -> dict[str, object]:
    names = (
        "gateway",
        "x402-provider",
        "simulator",
        "dashboard",
        "rowan",
        "mercer",
        "verity",
        "alden",
        "locke",
        "wells",
        "recorder-heartbeat",
        "ipfs",
        "otel-collector",
        "jaeger",
        "x402-official",
    )
    mount_allowlist = {
        "gateway": [
            {
                "type": "volume",
                "source": "concordia-data",
                "target": "/data",
                "volume": {},
            },
            {
                "type": "bind",
                "source": "artifacts",
                "target": "/app/artifacts",
                "read_only": True,
                "bind": {"create_host_path": False},
            },
            {
                "type": "bind",
                "source": "artifacts/live/proof-registry",
                "target": "/run/config/proof-registry",
                "read_only": True,
                "bind": {"create_host_path": False},
            },
        ],
        "ipfs": [
            {
                "type": "volume",
                "source": "concordia-ipfs-data",
                "target": "/data/ipfs",
            }
        ],
        "otel-collector": [
            {
                "type": "bind",
                "source": "deploy/shared-host/otel-collector-config.yml",
                "target": "/etc/otelcol/config.yml",
                "read_only": True,
                "bind": {},
            }
        ],
        "x402-official": [
            {
                "type": "volume",
                "source": "x402_official_data",
                "target": "/data",
                "volume": {},
            },
            {
                "type": "bind",
                "source": "@release-config/x402-official",
                "target": "/run/config",
                "read_only": True,
                "bind": {"create_host_path": False},
            },
        ],
        "x402-provider": [
            {
                "type": "volume",
                "source": "x402_provider_data",
                "target": "/data",
                "volume": {},
            }
        ],
    }
    third_party_images = {
        name: f"registry.example/{name}@sha256:{hashlib.sha256(name.encode()).hexdigest()}"
        for name in release_manifest._COMPOSE_THIRD_PARTY_SERVICES
    }
    services: dict[str, object] = {}
    for name in names:
        environment: dict[str, str] = {"CASPER_CHAIN_NAME": "casper-test"}
        granted_secrets: list[dict[str, str]] = []
        for key, (
            target,
            allowed_services,
        ) in release_manifest._SECRET_FILE_MATRIX.items():
            if name in allowed_services:
                environment[key] = f"/run/secrets/{target}"
                granted_secrets.append({"source": target, "target": target})
        services[name] = {
            "image": third_party_images.get(name, f"concordia/{name}:finals"),
            "build": (
                {"context": "."}
                if name in {"gateway", "dashboard", "x402-official"}
                else None
            ),
            "command": ["run", name],
            "entrypoint": None,
            "networks": {
                network: {}
                for network in release_manifest._COMPOSE_NETWORK_ALLOWLIST[name]
            },
            "volumes": mount_allowlist.get(name, []),
            "depends_on": {},
            "healthcheck": {
                "test": ["CMD", "true"],
                "interval": "10s",
                "retries": 3,
            },
            "restart": "unless-stopped",
            "logging": {
                "driver": "local",
                "options": {"max-file": "5", "max-size": "20m"},
            },
            "environment": environment,
            "secrets": granted_secrets,
        }
    return {
        "name": "concordia",
        "services": services,
        "networks": {
            "concordia-edge": {
                "name": "concordia-edge",
                "external": True,
            },
            "concordia-internal": {"name": "concordia-internal"},
        },
        "volumes": {
            volume_name: {}
            for volume_name in {
                mount[1]
                for mounts in release_manifest._COMPOSE_VOLUME_ALLOWLIST.values()
                for mount in mounts
                if mount[0] == "volume"
            }
        },
        "secrets": {
            target: {
                "file": (
                    "/opt/apps/concordia/secrets/"
                    + release_manifest._SECRET_HOST_BASENAMES[target]
                )
            }
            for target, _services in release_manifest._SECRET_FILE_MATRIX.values()
        },
        "x-concordia-observed-service-config-hashes": {
            name: hashlib.sha256(("config:" + name).encode()).hexdigest()
            for name in names
        },
    }


def _runtime_raw(
    compose: dict[str, object], integration_commit: str
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for name in sorted(compose["services"]):
        digest = "sha256:" + hashlib.sha256(name.encode()).hexdigest()
        project_image = name in release_manifest._COMPOSE_PROJECT_SERVICES
        result.append(
            {
                "service_id": name,
                "project": "concordia",
                "container_id": hashlib.sha256(
                    ("container:" + name).encode()
                ).hexdigest(),
                "config_image": compose["services"][name]["image"],
                "image_id": digest,
                "image_revision": integration_commit if project_image else None,
                "image_source": (
                    "https://github.com/asadvendor-boop/concordia-dao-council"
                    if project_image
                    else None
                ),
                "image_deployment": integration_commit if project_image else None,
                "state_status": "running",
                "health_status": "healthy",
                "started_at": "2026-07-22T23:00:00Z",
                "restart_count": 0,
                "config_hash": compose["x-concordia-observed-service-config-hashes"][
                    name
                ],
            }
        )
    return result


def _caddy_raw() -> dict[str, object]:
    username = "judge"
    bcrypt_hash = "$2b$12$abcdefghijklmnopqrstuumjShLAz1hg5xNkjnYdEhDjbg3Hc48be"
    proxy_secret = "DO-NOT-PERSIST-PROXY-SECRET-32-BYTES"
    active_config = {
        "apps": {
            "http": {
                "servers": {
                    "shared": {
                        "routes": [
                            {
                                "match": [
                                    {
                                        "host": [
                                            "concordia.47.84.232.193.sslip.io",
                                            "concordiadao.xyz",
                                        ],
                                        "path": ["/approve*"],
                                    }
                                ],
                                "handle": [
                                    {
                                        "handler": "authentication",
                                        "providers": {
                                            "http_basic": {
                                                "hash": {"algorithm": "bcrypt"},
                                                "accounts": [
                                                    {
                                                        "username": username,
                                                        "password": bcrypt_hash,
                                                    }
                                                ],
                                            }
                                        },
                                    },
                                    {
                                        "handler": "headers",
                                        "request": {
                                            "set": {"X-Proxy-Secret": [proxy_secret]}
                                        },
                                    },
                                    {
                                        "handler": "reverse_proxy",
                                        "upstreams": [{"dial": "gateway:8000"}],
                                    },
                                ],
                                "terminal": True,
                            },
                            {
                                "match": [
                                    {
                                        "host": [_TEST_COHOST_HOST],
                                        "path": ["/mcp"],
                                    }
                                ],
                                "handle": [
                                    {
                                        "handler": "reverse_proxy",
                                        "upstreams": [
                                            {"dial": _TEST_COHOST_UPSTREAM}
                                        ],
                                    }
                                ],
                            },
                        ]
                    }
                }
            }
        }
    }
    hosts = ["concordia.47.84.232.193.sslip.io", "concordiadao.xyz"]
    return {
        "active_config": active_config,
        "approval_material": {
            "username_sha256": hashlib.sha256(username.encode()).hexdigest(),
            "bcrypt_value": bcrypt_hash,
            "proxy_secret_sha256": hashlib.sha256(proxy_secret.encode()).hexdigest(),
        },
        "unauthenticated_probes": [
            {
                "host": host,
                "method": method,
                "mode": mode,
                "status": 401,
                "basic_challenge": True,
                "reached_gateway": False,
            }
            for host in hosts
            for method, mode in (
                ("GET", "unauthenticated"),
                ("POST", "unauthenticated"),
                ("GET", "spoofed_proxy_header"),
            )
        ],
        "authenticated_probes": [
            {
                "host": host,
                "method": "GET",
                "status": 200,
                "bcrypt_verified": True,
                "gateway_proxy_verified": True,
            }
            for host in hosts
        ],
    }


def _http_raw(
    observed_at: str,
    registry_items: list[dict[str, object]],
) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for probe_id, spec in release_manifest.HTTP_PROBE_SPECS.items():
        semantic = spec.get("semantic")
        body = spec.get("exact_body")
        if semantic == "evidence":
            body = _canonical(
                {
                    "proposal_id": "DAO-PROP-6CB25C",
                    "state": "RESOLVED",
                    "chain_valid": True,
                    "chain_errors": [],
                    "total_cards": 1,
                    "cards": [
                        {
                            "sequence": 1,
                            "card_type": "ProposalCard",
                            "role": "concordia_core",
                            "agent": {"name": "Concordia Core"},
                            "hash": _TEST_CARD_HASH,
                            "published": True,
                            "data": _TEST_CARD_DOCUMENT,
                        }
                    ],
                }
            )
        elif semantic == "safepay":
            body = _canonical(
                {
                    "schema_version": "safepay-v2",
                    "proposal_id": "DAO-PROP-6CB25C",
                    "status": "verified",
                    "replay_safety": "no_double_consumption",
                    "payment_hash": "99" * 32,
                    "report_hash": "aa" * 32,
                }
            )
        elif semantic == "proof_pack":
            inventory = [
                {
                    "sequence": 1,
                    "card_type": "ProposalCard",
                    "card_hash": _TEST_CARD_HASH,
                }
            ]
            canonical_manifest = {
                "proposal_id": "DAO-PROP-6CB25C",
                "card_count": 1,
                "terminal_card_hash": _TEST_CARD_HASH,
                "card_inventory_sha256": hashlib.sha256(
                    _canonical(inventory)
                ).hexdigest(),
            }
            casper_receipt = {"deploy_hash": "66" * 32, "status": "processed"}
            safepay_lite = {
                "schema_version": "safepay-v2",
                "payment_hash": "99" * 32,
                "report_hash": "aa" * 32,
                "replay_safety": "no_double_consumption",
            }
            ipfs_evidence = {
                "cid": release_manifest.HTTP_PROBE_SPECS["ipfs_archive"]["cid"]
            }
            odra_quorum = {
                "status": "satisfied",
                "proposal_id": "DAO-PROP-6CB25C",
                "action_id": "33" * 32,
                "envelope_hash": "44" * 32,
            }
            body = _canonical(
                {
                    "schema_version": "concordia.proof-pack.v2",
                    "proposal_id": "DAO-PROP-6CB25C",
                    "canonical_manifest": canonical_manifest,
                    "evidence": {
                        "chain_valid": True,
                        "terminal_card_hash": _TEST_CARD_HASH,
                    },
                    "proof_center": {
                        "outcome_gallery": [],
                        "casper_receipt": casper_receipt,
                    },
                    "safepay_lite": safepay_lite,
                    "ipfs_evidence": ipfs_evidence,
                    "odra_quorum_exercise": odra_quorum,
                }
            )
        elif semantic == "proof_registry":
            proposal_id = (
                "DAO-PROP-X402-FINALS-2026"
                if probe_id == "proof_registry_official"
                else "DAO-PROP-6CB25C"
            )
            body = _canonical(
                {
                    "schema_version": 1,
                    "generated_at": observed_at,
                    "proposal_id": proposal_id,
                    "items": [
                        item
                        for item in registry_items
                        if item.get("proposal_id") in {None, proposal_id}
                    ],
                }
            )
        elif semantic == "card_chain":
            body = _canonical(
                {
                    "schema_version": "concordia.card_chain.v1",
                    "proposal_id": "DAO-PROP-6CB25C",
                    "captured_at": observed_at,
                    "source_url": release_manifest.HTTP_PROBE_SPECS["card_chain"][
                        "url"
                    ],
                    "cards": [
                        {
                            "sequence_number": 1,
                            "card_type": "ProposalCard",
                            "card_hash": _TEST_CARD_HASH,
                            "canonical_card_json": _TEST_CARD_JSON,
                            "published_at": "2026-07-22T23:59:00Z",
                        }
                    ],
                }
            )
        elif semantic == "trace":
            inventory = [
                {
                    "sequence": 1,
                    "card_type": "ProposalCard",
                    "card_hash": _TEST_CARD_HASH,
                }
            ]
            body = _canonical(
                {
                    "trace_type": "ConcordiaPublicRunTrace",
                    "proposal_id": "DAO-PROP-6CB25C",
                    "generated_at": observed_at.replace("Z", "+00:00"),
                    "canonical_manifest": {
                        "proposal_id": "DAO-PROP-6CB25C",
                        "card_count": 1,
                        "terminal_card_hash": _TEST_CARD_HASH,
                        "card_inventory_sha256": hashlib.sha256(
                            _canonical(inventory)
                        ).hexdigest(),
                    },
                    "observations": [
                        {
                            "sequence": 1,
                            "card_type": "ProposalCard",
                            "hash": _TEST_CARD_HASH,
                            "issuer": None,
                        }
                    ],
                    "decisions": [],
                    "tool_calls": {
                        "casper_receipt": {
                            "deploy_hash": "66" * 32,
                            "status": "processed",
                        },
                        "safepay_lite": {
                            "schema_version": "safepay-v2",
                            "payment_hash": "99" * 32,
                            "report_hash": "aa" * 32,
                            "replay_safety": "no_double_consumption",
                        },
                        "ipfs_archive": {
                            "cid": release_manifest.HTTP_PROBE_SPECS[
                                "ipfs_archive"
                            ]["cid"]
                        },
                        "odra_quorum": {
                            "status": "satisfied",
                            "proposal_id": "DAO-PROP-6CB25C",
                            "action_id": "33" * 32,
                            "envelope_hash": "44" * 32,
                        },
                    },
                    "jaeger_available": True,
                    "traces_url": "https://concordia.47.84.232.193.sslip.io/traces",
                    "redaction": {
                        "status": "applied",
                        "policy": "hashes IDs and proof links only",
                    },
                }
            )
        elif semantic == "ipfs_cid":
            body = _TEST_IPFS_BODY
        elif semantic == "pdf_certificate":
            body = _TEST_CERTIFICATE_PDF
        elif semantic == "provider_openapi":
            body = _canonical(
                {
                    "openapi": "3.1.0",
                    "info": {
                        "title": "Concordia Risk Oracle Provider",
                        "version": "2.0.0",
                    },
                    "paths": {
                        "/x402/v2/quotes": {
                            "post": {
                                "requestBody": {
                                    "required": True,
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "$ref": "#/components/schemas/SafePayQuoteRequestV2"
                                            }
                                        }
                                    },
                                },
                                "responses": {
                                    "402": {"description": "Payment required"}
                                },
                            }
                        },
                        "/x402/v2/redemptions": {
                            "post": {
                                "requestBody": {
                                    "required": True,
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "$ref": "#/components/schemas/SafePayRedemptionV2"
                                            }
                                        }
                                    },
                                },
                                "responses": {"200": {"description": "Fulfilled"}},
                            }
                        },
                    },
                    "components": {
                        "schemas": {
                            "SafePayQuoteRequestV2": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "schema_version",
                                    "proposal_id",
                                    "resource_id",
                                ],
                                "properties": {
                                    "schema_version": {
                                        "const": "safepay-quote-request-v2"
                                    },
                                    "proposal_id": {
                                        "type": "string",
                                        "pattern": "^[A-Z0-9-]{1,64}$",
                                    },
                                    "resource_id": {
                                        "type": "string",
                                        "minLength": 1,
                                        "maxLength": 200,
                                    },
                                },
                            },
                            "SafePayRedemptionV2": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "schema_version",
                                    "quote",
                                    "payment_hash",
                                ],
                                "properties": {
                                    "schema_version": {
                                        "const": "safepay-redemption-v2"
                                    },
                                    "quote": {
                                        "$ref": "#/components/schemas/SafePayQuoteV2"
                                    },
                                    "payment_hash": {
                                        "type": "string",
                                        "pattern": "^[0-9a-f]{64}$",
                                    },
                                },
                            },
                            "SafePayQuoteV2": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": [
                                    "schema_version",
                                    "quote_id",
                                    "proposal_id",
                                    "resource_id",
                                    "network",
                                    "payee_account_hash",
                                    "amount_motes",
                                    "correlation_id",
                                    "report_version",
                                    "report_hash",
                                    "expires_at",
                                    "quote_nonce",
                                    "quote_hash",
                                ],
                                "properties": {
                                    "schema_version": {"const": "safepay-v2"},
                                    "quote_id": {
                                        "type": "string",
                                        "pattern": (
                                            "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                                            "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                                        ),
                                    },
                                    "proposal_id": {
                                        "type": "string",
                                        "pattern": "^[A-Z0-9-]{1,64}$",
                                    },
                                    "resource_id": {
                                        "type": "string",
                                        "minLength": 1,
                                        "maxLength": 200,
                                    },
                                    "network": {"const": "casper:casper-test"},
                                    "payee_account_hash": {
                                        "type": "string",
                                        "pattern": "^[0-9a-f]{64}$",
                                    },
                                    "amount_motes": {
                                        "type": "string",
                                        "pattern": "^[1-9][0-9]*$",
                                        "maxLength": 155,
                                    },
                                    "correlation_id": {
                                        "type": "string",
                                        "pattern": "^(0|[1-9][0-9]*)$",
                                        "maxLength": 20,
                                    },
                                    "report_version": {"const": "safepay-report-v2"},
                                    "report_hash": {
                                        "type": "string",
                                        "pattern": "^[0-9a-f]{64}$",
                                    },
                                    "expires_at": {
                                        "type": "integer",
                                        "minimum": 1,
                                        "maximum": 18_446_744_073_709_551_615,
                                    },
                                    "quote_nonce": {
                                        "type": "string",
                                        "pattern": "^(?!0{64}$)[0-9a-f]{64}$",
                                    },
                                    "quote_hash": {
                                        "type": "string",
                                        "pattern": "^[0-9a-f]{64}$",
                                    },
                                },
                            },
                        }
                    },
                }
            )
        elif semantic == "official_supported":
            body = _canonical(
                {
                    "kinds": [
                        {
                            "x402Version": 2,
                            "scheme": "exact",
                            "network": "casper:casper-test",
                        }
                    ],
                    "extensions": {},
                    "signers": [],
                }
            )
        elif semantic == "official_health":
            body = _canonical(
                {
                    "status": "ok",
                    "settlement_state": "official_hosted_verified_live",
                    "settlement_transaction_hash": "ee" * 32,
                }
            )
        elif semantic == "governance_archive":
            body = _canonical({"proposal_id": "DAO-PROP-6CB25C"})
        elif semantic == "csv":
            body = (
                str(spec["csv_header"])
                + "\n"
                + "value," * (str(spec["csv_header"]).count(","))
                + "value\n"
            ).encode()
        elif body is None:
            body = (spec.get("prefix") or b"") + (spec.get("marker") or b"Concordia")
        headers = {"Content-Type": spec["content_type"]}
        if semantic == "governance_archive":
            headers["Content-Disposition"] = (
                'attachment; filename="concordia-governance-archive-DAO-PROP-6CB25C.json"'
            )
        if semantic == "pdf_certificate":
            headers["Content-Disposition"] = (
                'attachment; filename="concordia-governance-certificate-DAO-PROP-6CB25C.pdf"'
            )
        host = str(spec["url"]).split("//", 1)[1].split("/", 1)[0]
        dns_expectation = release_manifest._FIXED_DNS_EXPECTATIONS[host]
        addresses = list(dns_expectation["addresses"] or ("203.0.113.10",))
        cnames = list(dns_expectation["cnames"] or ())
        values.append(
            {
                "probe_id": probe_id,
                "requested_url": spec["url"],
                "effective_url": spec["effective_url"],
                "redirect_chain": spec["redirect_chain"],
                "status": spec["status"],
                "headers": headers,
                "body": body,
                "tls": {
                    "certificate_sha256": "ab" * 32,
                    "protocol": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "sans": [host],
                    "not_before": "2026-07-01T00:00:00Z",
                    "not_after": "2026-09-01T00:00:00Z",
                    "issuer_cn": "Test CA",
                    "resolved_ips": addresses,
                    "dns": {
                        "addresses": addresses,
                        "cnames": cnames,
                    },
                    "peer_ip": addresses[0],
                },
            }
        )
    return values


def _npm_raw(release_commit: str) -> dict[str, object]:
    tarball = b"npm-tarball-exact-bytes\x00\x01"
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    return {
        "metadata": {
            "name": "@concordia-dao/verify",
            "version": "0.1.0",
            "gitHead": release_commit,
            "time": "2026-07-23T00:08:00Z",
            "dist": {
                "tarball": "https://registry.npmjs.org/@concordia-dao/verify/-/verify-0.1.0.tgz",
                "integrity": integrity,
            },
        },
        "tarball": tarball,
        "registry_signatures": {"invalid": [], "missing": []},
        "package_projection": {
            "name": "@concordia-dao/verify",
            "version": "0.1.0",
            "sourceCommit": release_commit,
            "files": ["LICENSE", "README.md", "dist/cli.js", "package.json"],
            "consumer_install_sha256": "ce" * 32,
            "self_test_digest": "ef" * 32,
        },
    }


def _rpc_raw(observed_at: str) -> list[dict[str, object]]:
    result = {
        "chain_name": "casper-test",
        "block_hash": "01" * 32,
        "block_height": 8_500_001,
        "state_root_hash": "02" * 32,
        "block_timestamp": "2026-07-23T00:09:30Z",
        "protocol_version": "2.0.0",
    }
    return [
        {
            "provider_id": provider_id,
            "operator_id": expected["operator_id"],
            "endpoint": expected["endpoint"],
            "authentication_mode": expected["authentication"],
            "method": "chain_get_block",
            "observed_at": observed_at,
            "result": result,
        }
        for provider_id, expected in release_manifest.RPC_PROVIDERS.items()
    ]


def _snapshot(
    observed_at: str, release_commit: str, repository: Path
) -> release_manifest.RawObservationSnapshot:
    compose = _compose_raw()
    compose["services"]["otel-collector"]["volumes"][0]["source"] = str(
        repository / "deploy/shared-host/otel-collector-config.yml"
    )
    compose["services"]["gateway"]["volumes"][1]["source"] = str(
        repository / "artifacts"
    )
    compose["services"]["gateway"]["volumes"][2]["source"] = str(
        repository / "artifacts/live/proof-registry"
    )
    compose["services"]["x402-official"]["volumes"][1]["source"] = str(
        repository.parent / "config/x402-official"
    )
    deployment_commit = json.loads(
        (repository / ARTIFACT_PATHS["safepay_v2"]).read_bytes()
    )["deployment_commit"]
    registry = json.loads(
        (repository / ARTIFACT_PATHS["proof_registry_v1"]).read_bytes()
    )
    return release_manifest.RawObservationSnapshot(
        observed_at=observed_at,
        compose=compose,
        runtime=_runtime_raw(compose, deployment_commit),
        caddy=_caddy_raw(),
        public_probes=_http_raw(observed_at, registry["public_items"]),
        pages={
            "repository": "asadvendor-boop/concordia-dao-council",
            "build_type": "workflow",
            "cname": "docs.concordiadao.xyz",
            "html_url": "https://docs.concordiadao.xyz/",
            "https_enforced": True,
            "workflow": {
                "name": "docs-pages",
                "status": "completed",
                "conclusion": "success",
                "head_sha": release_commit,
                "run_id": 1234,
            },
            "deployment": {
                "environment": "github-pages",
                "status": "success",
                "sha": release_commit,
                "deployment_id": 5678,
            },
            "release_identity": {"GITHUB_SHA": release_commit, "run_id": 1234},
        },
        npm=_npm_raw(release_commit),
        rpc=_rpc_raw(observed_at),
    )


class FakeCollector:
    def __init__(self, snapshots: list[release_manifest.RawObservationSnapshot]):
        self.snapshots = snapshots
        self.calls = 0

    def collect(self) -> release_manifest.RawObservationSnapshot:
        if self.calls >= len(self.snapshots):
            raise AssertionError("collector called more often than expected")
        value = self.snapshots[self.calls]
        self.calls += 1
        return value


class FakeVerifier:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def verify(
        self,
        *,
        artifact_id: str,
        artifact_path: str,
        artifact_bytes: bytes,
        artifact_document: dict[str, object],
    ) -> dict[str, object]:
        self.calls.append(artifact_id)
        if not artifact_document or any(
            value == {} for value in artifact_document.values()
        ):
            raise ReleaseManifestError("proof artifact has empty required evidence")
        return {
            "verifier_id": f"concordia.release.{artifact_id}.v1",
            "derived_identity": {
                "artifact_id": artifact_id,
                "identity_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            },
            "derived_facts": {
                "artifact_path": artifact_path,
                "evidence_digest": hashlib.sha256(
                    b"derived\0" + artifact_bytes
                ).hexdigest(),
            },
        }


@pytest.fixture
def release_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, str], FakeCollector, FakeVerifier]:
    repository = tmp_path / "repository"
    repository.mkdir()
    release_config = tmp_path / "config/x402-official"
    release_config.mkdir(parents=True)
    (release_config / "x402-governance-v3.json").write_bytes(
        b'{"schema_version":"fixture.governance.v1"}\n'
    )
    (release_config / "x402-resources.json").write_bytes(
        b'{"resources":[]}\n'
    )
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")

    # The verifier implementation itself must be tracked so its path commit is
    # an immutable receipt identity in the temporary repository.
    module_target = repository / "shared/release_manifest.py"
    module_target.parent.mkdir(parents=True)
    module_target.write_bytes(Path(release_manifest.__file__).read_bytes())
    repository_root = Path(release_manifest.__file__).parents[1]
    test_cohost_route = {
        "hosts": [_TEST_COHOST_HOST],
        "paths": ["/mcp"],
        "matchers": [
            {
                "hosts": [_TEST_COHOST_HOST],
                "paths": ["/mcp"],
                "methods": [],
                "unknown_keys": [],
            }
        ],
        "handlers": [
            {
                "handler": "reverse_proxy",
                "upstreams": [_TEST_COHOST_UPSTREAM],
            }
        ],
    }
    monkeypatch.setattr(
        release_manifest,
        "_SHARED_COHOST_MCP_ROUTE_SHA256",
        hashlib.sha256(
            release_manifest._canonical_json(test_cohost_route)
        ).hexdigest(),
    )
    for relative in (
        "scripts/release_gate_runner.py",
        "shared/release_gate_contract.py",
        "shared/bound_command.py",
        "shared/proof_registry.py",
        "shared/g11_claim_policy_authority.py",
        "shared/secret_variants.py",
    ):
        _write_bytes(repository, relative, (repository_root / relative).read_bytes())
    for relative in (
        release_manifest.ORGANIZER_LINK_REQUEST_PATH,
        release_manifest.ORGANIZER_LINK_CORE_PATH,
        release_manifest.ORGANIZER_LINK_RUNNER_PATH,
        release_manifest.ORGANIZER_LINK_VERIFIER_PATH,
    ):
        _write_bytes(repository, relative, (repository_root / relative).read_bytes())
    for gate_id, runner_path in COMMAND_GATE_RUNNER_PATHS.items():
        _write_bytes(
            repository,
            runner_path,
            (
                "#!/usr/bin/env python3\n"
                f'"""Deterministic {gate_id} command-gate runner."""\n'
            ).encode(),
        )
    _write_bytes(
        repository,
        G13_RUNNER_PATH,
        b'#!/usr/bin/env node\n"use strict";\n',
    )
    _write_bytes(
        repository,
        "scripts/run_locked_odra_build.py",
        b'#!/usr/bin/env python3\n"""Fail-closed locked Odra build verifier."""\n',
    )
    _write(
        repository,
        "handoff/G11_CLAIM_POLICY.json",
        {
            "schema_version": "concordia.g11_claim_policy.v1",
            "claims": [],
        },
    )
    _write_bytes(repository, ".gitignore", b"dashboard/.next/\n")
    _write_bytes(
        repository,
        "deploy/shared-host/otel-collector-config.yml",
        b"receivers: {}\nexporters: {}\nservice: {}\n",
    )
    _write_bytes(
        repository,
        COMMAND_GATE_ARTIFACT_PATHS["G2"][0],
        b"\x00asm\x01\x00\x00\x00test-v3",
    )
    _write(
        repository,
        COMMAND_GATE_ARTIFACT_PATHS["G2"][1],
        {"contract_name": "GovernanceReceiptV3", "schema_version": 3},
    )
    for relative in COMMAND_GATE_ARTIFACT_PATHS["G11"][:-1]:
        _write_bytes(
            repository,
            relative,
            f"# Concordia release claim surface: {relative}\n".encode(),
        )
    _write(
        repository,
        COMMAND_GATE_ARTIFACT_PATHS["G11"][-1],
        {
            "schema_version": "concordia.claim_to_artifact_map.v1",
            "claims": [{"claim_id": "constitutional-firewall", "status": "verified"}],
        },
    )
    g1_authority_files = {
        "handoff/G1_INTERFACE_SPEC.md": b"# G1 interface specification\n",
        "handoff/G1_CROSS_LANE_SCHEMAS.json": _canonical(
            {"schema_version": "test.g1.cross_lane.v1"}
        ),
        "handoff/WCSPR_FACILITATOR_READBACK.json": _canonical(
            {"schema_version": "test.g1.wcspr.v1"}
        ),
        "handoff/HISTORICAL_ODRA_SHA256.txt": b"00  historical\n",
        "handoff/HISTORICAL_LIVE_ARTIFACTS_SHA256.txt": b"11  live\n",
        "scripts/generate_g1_vectors.py": b"#!/usr/bin/env python3\n",
        "handoff/G0R_FALLBACK_EVIDENCE.json": _canonical(
            {"schema_version": "test.g0r.evidence.v1"}
        ),
        "handoff/G0R_RESTORE_RUNBOOK.md": b"# Restore runbook\n",
    }
    for relative, body in g1_authority_files.items():
        _write_bytes(repository, relative, body)
    g1_authority = {
        "normative_spec": "handoff/G1_INTERFACE_SPEC.md",
        "normative_spec_sha256": hashlib.sha256(
            g1_authority_files["handoff/G1_INTERFACE_SPEC.md"]
        ).hexdigest(),
        **{
            f"authority_{index}": {
                "path": relative,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
            for index, (relative, body) in enumerate(
                g1_authority_files.items(), start=1
            )
            if relative != "handoff/G1_INTERFACE_SPEC.md"
        },
    }
    _write(
        repository,
        "handoff/G1_FREEZE_MANIFEST.json",
        {
            "manifest_version": "2.0-A.G1.2",
            "spec_id": "concordia-g1-interface-v3",
            "status": "ready",
            "tag": "concordia-g1-freeze-v2.0-a",
            "authority": g1_authority,
            "branch_protocol": {
                "required_root": "refs/tags/concordia-g1-freeze-v2.0-a^{}",
                "approval": {"annotated_tag_is_commit_authority": True},
            },
        },
    )
    _write(repository, "source.json", {"created_at": SOURCE_TIME})
    source_commit = _commit(repository, "source")
    _git(
        repository,
        "tag",
        "-a",
        "concordia-g1-freeze-v2.0-a",
        "-m",
        "Concordia finals G1 interface freeze v2.0-A",
        source_commit,
    )
    freeze_tag_object = (
        _git(
            repository,
            "rev-parse",
            f"refs/tags/{release_manifest.G1_FREEZE_TAG}",
        )
        .decode()
        .strip()
    )
    monkeypatch.setattr(release_manifest, "G1_FREEZE_COMMIT", source_commit)
    monkeypatch.setattr(
        release_manifest,
        "G1_FREEZE_TAG_OBJECT",
        freeze_tag_object,
    )
    post_freeze_authority = json.loads(
        (
            repository_root
            / release_manifest._G1_POST_FREEZE_CORRECTIONS_PATH
        ).read_bytes()
    )
    post_freeze_authority["authority_commit"] = source_commit
    _write(
        repository,
        release_manifest._G1_POST_FREEZE_CORRECTIONS_PATH,
        post_freeze_authority,
    )
    _write_bytes(
        repository,
        "gateway/app.py",
        (
            b'PATH = "/x402/v2/payment-intent"\n'
            b'FIELD = "quote_capability"\n'
            b'SECRET = "SAFEPAY_QUOTE_TOKEN_SECRET"\n'
            b"verify_safepay_v2_quote_capability = True\n"
        ),
    )
    _write_bytes(
        repository,
        "shared/x402_payments.py",
        (
            b'SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA = "safepay-wallet-intent-request-v2"\n'
            b'SAFEPAY_V2_WALLET_INTENT_SCHEMA = "safepay-wallet-intent-v2"\n'
            b'HEADER = "X-Concordia-SafePay-Quote-Capability"\n'
            b'PREFIX = "sqc1"\n'
        ),
    )
    _write_bytes(
        repository,
        "tests/test_safepay_gateway_v2.py",
        (
            b"def test_wallet_intent_requires_an_issuer_authenticated_quote_capability(): pass\n"
            b"def test_missing_quote_capability_secret_fails_before_provider_io(): pass\n"
        ),
    )
    _write_bytes(
        repository,
        "tests/test_compose_secret_scope.py",
        b"safepay_quote_token_secret = True\n",
    )
    _commit(repository, "accepted post-freeze SafePay correction")
    _write(
        repository,
        release_manifest.COMPOSE_FILE_PATH,
        {
            "name": "concordia",
            "services": sorted(_compose_raw()["services"]),
            "safepay_security": {
                "environment_key": "SAFEPAY_QUOTE_TOKEN_SECRET_FILE",
                "runtime_path": "/run/secrets/safepay_quote_token_secret",
            },
        },
    )
    _write(repository, "deployment.json", {"source_commit": source_commit})
    deployment_commit = _commit(repository, "deployment")
    for artifact_id, relative in ARTIFACT_PATHS.items():
        _write(
            repository,
            relative,
            _artifact_documents(source_commit, deployment_commit)[artifact_id],
        )
    artifacts_commit = _commit(repository, "proof artifacts")
    _write_bytes(repository, COMMAND_GATE_ARTIFACT_PATHS["G9"][0], b"test-build-id\n")
    _write(repository, COMMAND_GATE_ARTIFACT_PATHS["G9"][1], {"pages": {}})
    _write(repository, COMMAND_GATE_ARTIFACT_PATHS["G9"][2], {"routes": []})
    gate_receipts_commit = _write_command_gate_receipts(
        repository,
        frozen_commit=source_commit,
        integration_commit=artifacts_commit,
    )
    _write(
        repository,
        release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        {
            "schema_version": (
                release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION
            ),
            "source_commit": gate_receipts_commit,
            "runner_sha256": hashlib.sha256(module_target.read_bytes()).hexdigest(),
            "host_id": "55" * 32,
            "tools": {},
        },
    )
    host_commit = _commit(repository, "host-toolchain authority")

    test_cid_bytes = (
        bytes.fromhex("01551220") + hashlib.sha256(_TEST_IPFS_BODY).digest()
    )
    test_cid = "b" + base64.b32encode(test_cid_bytes).decode("ascii").lower().rstrip(
        "="
    )
    monkeypatch.setitem(
        release_manifest.HTTP_PROBE_SPECS["ipfs_archive"], "cid", test_cid
    )

    collector = FakeCollector(
        [
            _snapshot(CAPTURED_AT, artifacts_commit, repository),
            _snapshot(RECHECKED_AT, artifacts_commit, repository),
        ]
    )
    verifier = FakeVerifier()
    fixture_adapter_results = _adapter_results(
        _artifact_documents(source_commit, deployment_commit)
    )

    def fake_adapter_result(
        artifact_id: str,
        document: dict[str, object],
        raw: bytes,
    ) -> dict[str, object]:
        result = json.loads(json.dumps(fixture_adapter_results[artifact_id]))
        result["artifact_sha256"] = hashlib.sha256(raw).hexdigest()
        facts = result["derived_facts"]
        facts["captured_at"] = document["captured_at"]
        facts["source_commit"] = document["source_commit"]
        facts["deployment_commit"] = document["deployment_commit"]
        return result

    monkeypatch.setattr(
        release_manifest.release_proof_adapters,
        "verify_safepay_v2_artifact",
        lambda document, raw: fake_adapter_result("safepay_v2", document, raw),
    )
    monkeypatch.setattr(
        release_manifest.release_proof_adapters,
        "verify_official_x402_artifact",
        lambda document, raw: fake_adapter_result(
            "official_x402_settlement_v1", document, raw
        ),
    )
    monkeypatch.setattr(release_manifest, "_collector_factory", lambda root: collector)
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    monkeypatch.setattr(
        release_manifest,
        "_utc_now",
        lambda: datetime(2026, 7, 23, 0, 10, 30, tzinfo=UTC),
    )
    monkeypatch.setattr(release_manifest, "_load_secret_canaries", lambda: ())
    fixture_secret_digests: dict[bytes, str] = {}
    for raw_secret in (
        b"$2b$12$abcdefghijklmnopqrstuumjShLAz1hg5xNkjnYdEhDjbg3Hc48be",
        b"DO-NOT-PERSIST-PROXY-SECRET-32-BYTES",
    ):
        digest = hashlib.sha256(raw_secret).hexdigest()
        for variant in release_manifest.secret_variants(raw_secret):
            fixture_secret_digests[variant] = digest
    monkeypatch.setattr(
        release_manifest,
        "_load_secret_variant_digests",
        lambda: fixture_secret_digests,
    )

    def fake_host_toolchain_binding(root: Path):
        bound = release_manifest._load_bound_file(
            root,
            release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
            release_manifest._CONTROL_LIMIT,
        )
        authority = release_manifest.HostToolchainAuthority(
            repository_root=root,
            source_commit=gate_receipts_commit,
            receipt_raw=bound.raw,
        )
        projection = {
            "schema_version": (
                release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION
            ),
            "path": release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
            "sha256": bound.sha256,
            "artifact_commit": bound.artifact_commit,
            "source_commit": gate_receipts_commit,
            "runner_sha256": hashlib.sha256(module_target.read_bytes()).hexdigest(),
            "host_id": "55" * 32,
            "tools_sha256": hashlib.sha256(_canonical({})).hexdigest(),
        }
        return authority, bound, projection

    monkeypatch.setattr(
        release_manifest,
        "_host_toolchain_binding",
        fake_host_toolchain_binding,
    )
    real_run_bound_command = release_manifest.run_bound_command

    def fast_fixture_bound_command(**kwargs):
        if kwargs["tool_id"] != "git":
            return real_run_bound_command(**kwargs)
        argv = ["/usr/bin/git", *tuple(kwargs["argv"])[1:]]
        completed = subprocess.run(
            argv,
            cwd=kwargs["cwd"],
            env=dict(kwargs["env"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if kwargs["check"] and completed.returncode != 0:
            raise release_manifest.BoundCommandError(
                "fixture Git command returned an error"
            )
        return release_manifest.BoundCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            tool_identity={"tool_id": "git", "fixture": True},
        )

    monkeypatch.setattr(
        release_manifest,
        "run_bound_command",
        fast_fixture_bound_command,
    )

    def replay_fixture_command_gates(
        _root: Path,
        *,
        integration_commit: str,
        expected: Sequence[Mapping[str, object]],
    ) -> list[dict[str, object]]:
        assert integration_commit == artifacts_commit
        return [dict(row) for row in expected]

    def replay_fixture_browser(
        root: Path,
        _request: Mapping[str, object],
    ) -> dict[str, object]:
        return json.loads((root / release_manifest.G13_BROWSER_TRACE_PATH).read_bytes())

    def replay_fixture_links(
        _root: Path,
        links: Mapping[str, Mapping[str, object]],
    ) -> dict[str, dict[str, object]]:
        return {
            link_id: {
                "url": row["url"],
                "effective_url": row["effective_url"],
                "status": row["status"],
                "body_sha256": hashlib.sha256(link_id.encode("utf-8")).hexdigest(),
            }
            for link_id, row in links.items()
        }

    monkeypatch.setattr(
        release_manifest,
        "_command_gate_replayer_factory",
        lambda _root: replay_fixture_command_gates,
    )
    monkeypatch.setattr(
        release_manifest,
        "_g13_browser_runner_factory",
        lambda _root: replay_fixture_browser,
    )
    monkeypatch.setattr(
        release_manifest,
        "_g13_link_reprobe_factory",
        lambda _root: replay_fixture_links,
    )

    def replay_fixture_organizer_audit(
        _root: Path,
        audit: release_manifest._BoundFile,
    ) -> dict[str, object]:
        return {
            "schema_version": release_manifest.ORGANIZER_LINK_AUDIT_SCHEMA_VERSION,
            "verdict": "PASS",
            "release_qualified": True,
            "collection_mode": "live_incognito",
            "audit_sha256": audit.sha256,
        }

    monkeypatch.setattr(
        release_manifest,
        "_organizer_link_audit_verifier_factory",
        lambda _root: replay_fixture_organizer_audit,
    )
    return (
        repository,
        {
            "source": source_commit,
            "deployment": deployment_commit,
            "artifacts": artifacts_commit,
            "integration": artifacts_commit,
            "gate_receipts": gate_receipts_commit,
            "host": host_commit,
        },
        collector,
        verifier,
    )


def _write_organizer_link_audit(
    repository: Path,
    relative: str,
    *,
    captured_at: str,
) -> bytes:
    request = json.loads(
        (repository / release_manifest.ORGANIZER_LINK_REQUEST_PATH).read_bytes()
    )
    request_sha256 = hashlib.sha256(
        _canonical(request).removesuffix(b"\n")
    ).hexdigest()
    captured = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    started_at = (captured - timedelta(seconds=1)).isoformat().replace(
        "+00:00", "Z"
    )
    known_link_ids = [item["link_id"] for item in request["known_links"]]
    document = {
        "schema_version": release_manifest.ORGANIZER_LINK_AUDIT_SCHEMA_VERSION,
        "verdict": "PASS",
        "release_qualified": True,
        "collection_mode": "live_incognito",
        "started_at": started_at,
        "captured_at": captured_at,
        "request_sha256": request_sha256,
        "runtime": {
            "node": "node-test-1.0",
            "playwright": "playwright-test-1.0",
            "chromium": "chromium-test-1.0",
            "chromium_executable_sha256": "31" * 32,
        },
        "inventory": {
            "dashboard_route_ids": list(
                release_manifest._ORGANIZER_DASHBOARD_ROUTE_IDS
            ),
            "proof_tab_ids": list(release_manifest._ORGANIZER_PROOF_TAB_IDS),
            "known_link_ids": known_link_ids,
        },
        "summary": {
            "dashboard_route_states": len(
                release_manifest._ORGANIZER_DASHBOARD_ROUTE_IDS
            ),
            "proof_tabs": len(release_manifest._ORGANIZER_PROOF_TAB_IDS),
            "unique_links": len(known_link_ids),
            "blocked_non_read_requests": 0,
            "console_errors": 0,
            "page_errors": 0,
            "first_party_failures": 0,
            "blocked_websockets": 0,
            "client_downloads": 0,
        },
        "dashboard_routes": [
            {"route_id": route_id}
            for route_id in release_manifest._ORGANIZER_DASHBOARD_ROUTE_IDS
        ],
        "proof_tabs": [
            {"route_id": f"proof_tab_{tab_id}"}
            for tab_id in release_manifest._ORGANIZER_PROOF_TAB_IDS
        ],
        "links": [{"link_id": link_id} for link_id in known_link_ids],
    }
    _write(repository, relative, document)
    invocation_relative = (
        release_manifest.ORGANIZER_G12_INVOCATION_PATH
        if relative == release_manifest.ORGANIZER_G12_AUDIT_PATH
        else release_manifest.ORGANIZER_G13_INVOCATION_PATH
    )
    request_raw = (
        repository / release_manifest.ORGANIZER_LINK_REQUEST_PATH
    ).read_bytes()
    audit_raw = (repository / relative).read_bytes()
    _, host_toolchain_bound, _ = release_manifest._host_toolchain_binding(
        repository
    )
    invocation = {
        "schema_version": (
            release_manifest.ORGANIZER_LINK_INVOCATION_SCHEMA_VERSION
        ),
        "phase": (
            "G12"
            if relative == release_manifest.ORGANIZER_G12_AUDIT_PATH
            else "G13"
        ),
        "status": "passed",
        "collection_mode": "live_incognito",
        "started_at": started_at,
        "ended_at": captured_at,
        "command": {
            "argv": [
                "node",
                release_manifest.ORGANIZER_LINK_RUNNER_PATH,
                "--input",
                release_manifest.ORGANIZER_LINK_REQUEST_PATH,
            ],
            "exit_code": 0,
            "fixture_argument_present": False,
            "stdout_sha256": hashlib.sha256(audit_raw).hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "tool_identity_sha256": "41" * 32,
            "command_assets_sha256": "42" * 32,
        },
        "request": {
            "path": release_manifest.ORGANIZER_LINK_REQUEST_PATH,
            "sha256": hashlib.sha256(request_raw).hexdigest(),
        },
        "source_bindings": [
            {
                "path": source,
                "sha256": hashlib.sha256(
                    (repository / source).read_bytes()
                ).hexdigest(),
            }
            for source in (
                release_manifest.ORGANIZER_LINK_CORE_PATH,
                release_manifest.ORGANIZER_LINK_RUNNER_PATH,
            )
        ],
        "host_toolchain": {
            "path": host_toolchain_bound.path,
            "sha256": host_toolchain_bound.sha256,
            "artifact_commit": host_toolchain_bound.artifact_commit,
        },
        "audit": {
            "path": relative,
            "sha256": hashlib.sha256(audit_raw).hexdigest(),
        },
    }
    _write(repository, invocation_relative, invocation)
    return (repository / relative).read_bytes()


def _capture_and_commit(
    repository: Path,
) -> str:
    capture_release_observations_once(repository)
    _write_organizer_link_audit(
        repository,
        release_manifest.ORGANIZER_G12_AUDIT_PATH,
        captured_at="2026-07-23T00:10:26Z",
    )
    return _commit(repository, "code-collected release observations")


def _write_g13_submission_receipt(
    repository: Path, manifest_commit: str, *, mutation: str | None = None
) -> str:
    manifest_path = repository / RELEASE_MANIFEST_PATH
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    captured_at = "2026-07-23T00:12:00Z"
    description_path = "release/g13/YOUTUBE_DESCRIPTION.txt"
    youtube_capture_path = "release/g13/YOUTUBE_INCOGNITO.png"
    dorahacks_capture_path = "release/g13/DORAHACKS_SUBMISSION.png"
    audit_path = "release/g13/FINAL_LINK_AUDIT.json"
    browser_receipt_path = release_manifest.G13_BROWSER_RECEIPT_PATH
    browser_trace_path = release_manifest.G13_BROWSER_TRACE_PATH
    organizer_audit_path = release_manifest.ORGANIZER_G13_AUDIT_PATH
    description = (
        b"Concordia is the constitutional execution firewall for AI-run DAOs on "
        b"Casper. Verify every final receipt at https://concordiadao.xyz/.\n"
    )
    if mutation == "capture":
        png = b"not-a-png"
    elif mutation == "truncated_png":
        png = b"\x89PNG\r\n\x1a\n" + b"G13-EVIDENCE" * 4
    elif mutation == "solid_png":
        png = _evidence_png(red=21, green=44, blue=74, solid=True)
    else:
        png = _evidence_png(red=21, green=44, blue=74)
    dorahacks_png = _evidence_png(red=30, green=82, blue=68)
    _write_bytes(repository, description_path, description)
    _write_bytes(repository, youtube_capture_path, png)
    _write_bytes(repository, dorahacks_capture_path, dorahacks_png)
    links = [
        {
            "link_id": probe["probe_id"],
            "url": probe["requested_url"],
            "effective_url": probe["effective_url"],
            "status": probe["status"],
            "tls_verified": True,
            "checked_at": captured_at,
        }
        for probe in manifest["deployment_surfaces"]["public_probes"]["probes"]
    ]
    links.extend(
        [
            {
                "link_id": "youtube_new_video",
                "url": "https://www.youtube.com/watch?v=AbCdEfGhI12",
                "effective_url": "https://www.youtube.com/watch?v=AbCdEfGhI12",
                "status": 200,
                "tls_verified": True,
                "checked_at": captured_at,
            },
            {
                "link_id": "dorahacks_buidl_46732",
                "url": "https://dorahacks.io/buidl/46732",
                "effective_url": "https://dorahacks.io/buidl/46732",
                "status": 200,
                "tls_verified": True,
                "checked_at": captured_at,
            },
        ]
    )
    trace_links = [dict(item) for item in links]
    if mutation == "links":
        links.pop()
    receipt_bindings = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
        }
        for item in [
            *manifest["observation_receipts"],
            *manifest["proof_verifier_receipts"],
            manifest["npm_tarball_capture"],
            manifest["organizer_rendered_link_audit"],
        ]
    ]
    receipt_bindings.append(
        {
            "path": RELEASE_MANIFEST_PATH,
            "sha256": (
                "00" * 32
                if mutation == "manifest"
                else hashlib.sha256(manifest_bytes).hexdigest()
            ),
        }
    )
    audit = {
        "schema_version": "concordia.g13_final_link_audit.v1",
        "captured_at": captured_at,
        "links": links,
        "receipt_bindings": sorted(receipt_bindings, key=lambda item: item["path"]),
    }
    _write(repository, audit_path, audit)
    audit_bytes = (repository / audit_path).read_bytes()
    runner_bytes = (repository / G13_RUNNER_PATH).read_bytes()
    runner_commit = (
        _git(repository, "log", "-1", "--format=%H", "--", G13_RUNNER_PATH)
        .decode()
        .strip()
    )
    runner = {
        "path": G13_RUNNER_PATH,
        "commit": runner_commit,
        "sha256": hashlib.sha256(runner_bytes).hexdigest(),
        "clean_tree_sha256": hashlib.sha256(b"").hexdigest(),
        "started_at": "2026-07-23T00:11:00Z",
        "ended_at": captured_at,
        "runtime_versions": {
            "chromium": "chromium-test-1.0",
            "chromium_executable_sha256": "31" * 32,
            "node": "node-test-1.0",
            "playwright": "playwright-test-1.0",
        },
    }
    trace_routes = []

    def safe_trace_url(value: str) -> dict[str, object]:
        return {
            "origin_path": value,
            "query_keys": ["v"] if "youtube.com/watch?v=" in value else [],
            "raw_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        }

    def dom_collection(items: list[object]) -> dict[str, object]:
        return {
            "count": len(items),
            "items": items,
            "items_sha256": hashlib.sha256(
                json.dumps(
                    items,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
            "truncated": False,
        }

    for link_id in (
        "dashboard_judge",
        "dashboard_proof",
        "dashboard_evidence",
        "dashboard_technical_note",
        "youtube_new_video",
        "dorahacks_buidl_46732",
    ):
        link = next(item for item in trace_links if item["link_id"] == link_id)
        network_events = [
            {
                "sequence": 1,
                "event": "request",
                "request_id": 1,
                "method": "GET",
                "resource_type": "document",
                "navigation_request": True,
                "url": safe_trace_url(link["url"]),
            }
        ]
        specialized = None
        if link_id == "youtube_new_video":
            network_events.append(
                {
                    "sequence": 2,
                    "event": "request",
                    "request_id": 2,
                    "method": "GET",
                    "resource_type": "image",
                    "navigation_request": False,
                    "url": safe_trace_url(
                        "https://i.ytimg.com/vi/AbCdEfGhI12/hqdefault.jpg"
                    ),
                }
            )
            specialized = {
                "kind": "youtube",
                "facts": {
                    "expected_video_id": "AbCdEfGhI12",
                    "player_video_id": "AbCdEfGhI12",
                    "current_time_seconds": 1.25,
                    "duration_seconds": 184,
                    "paused": False,
                    "ended": False,
                    "ready_state": 4,
                    "caption_button_aria_pressed": "true",
                    "visible_caption_segments": ["Concordia proof"],
                    "text_tracks": [
                        {
                            "kind": "captions",
                            "label": "English",
                            "language": "en",
                            "mode": "showing",
                            "active_cue_count": 1,
                        }
                    ],
                },
            }
        elif link_id == "dorahacks_buidl_46732":
            matching = [
                {
                    "tag": "iframe",
                    "attribute": "src",
                    "value": safe_trace_url(
                        "https://www.youtube.com/watch?v=AbCdEfGhI12"
                    ),
                }
            ]
            specialized = {
                "kind": "dorahacks",
                "facts": {
                    "video_id": "AbCdEfGhI12",
                    "html_occurrences": 1,
                    "matching_elements": matching,
                    "matching_elements_sha256": hashlib.sha256(
                        json.dumps(
                            matching,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ).encode("utf-8")
                    ).hexdigest(),
                    "canonical_href": safe_trace_url(
                        "https://dorahacks.io/buidl/46732"
                    ),
                },
            }
        marker = {
            "dashboard_judge": "Judge Walkthrough",
            "dashboard_proof": "Proof Center",
            "dashboard_evidence": "Evidence Ledger",
            "dashboard_technical_note": "Technical Jury Note",
        }.get(link_id, "Concordia")
        headings = dom_collection(
            [{"level": "h1", "text": marker, "visible": True}]
        )
        empty_collection = dom_collection([])
        visible_text = b"Concordia proof"
        trace_routes.append(
            {
                "link_id": link_id,
                "requested_url": safe_trace_url(link["url"]),
                "final_url": safe_trace_url(link["effective_url"]),
                "main_response": {
                    "status": 200,
                    "headers": {"content-type": "text/html"},
                    "body_bytes": 128,
                    "body_sha256": hashlib.sha256(
                        f"{link_id}-body".encode("utf-8")
                    ).hexdigest(),
                },
                "dom": {
                    "document_url": safe_trace_url(link["effective_url"]),
                    "title": "Concordia",
                    "language": "en",
                    "html_bytes": 256,
                    "html_sha256": hashlib.sha256(
                        f"{link_id}-html".encode("utf-8")
                    ).hexdigest(),
                    "visible_text_chars": len(visible_text),
                    "visible_text_sha256": hashlib.sha256(visible_text).hexdigest(),
                    "concordia_occurrences": 1,
                    "canonical_proposal_occurrences": 1,
                    "headings": headings,
                    "landmarks": {"main": 1, "navigation": 1, "tablist": 0},
                    "links": empty_collection,
                    "frames": empty_collection,
                    "test_ids": empty_collection,
                    "error_overlays": 0,
                },
                "specialized": specialized,
                "network_events": network_events,
                "network_events_sha256": hashlib.sha256(
                    json.dumps(
                        network_events,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest(),
                "blocked_non_read_requests": [],
                "console_errors": [],
                "page_errors": [],
            }
        )
    browser_trace = {
        "schema_version": "concordia.g13_browser_probe_result.v1",
        "started_at": "2026-07-23T00:11:00Z",
        "captured_at": captured_at,
        "incognito_context": {
            "persistent_profile": False,
            "storage_state_loaded": False,
            "cookies_at_start": 0,
        },
        "mutation_guard": {
            "allowed_http_methods": ["GET", "HEAD", "OPTIONS"],
            "blocked_non_read_request_count": 0,
        },
        "runtime_versions": {
            "chromium": "chromium-test-1.0",
            "chromium_executable_sha256": "31" * 32,
            "node": "node-test-1.0",
            "playwright": "playwright-test-1.0",
        },
        "routes": trace_routes,
    }
    if mutation == "browser_trace":
        browser_trace["routes"][0]["main_response"]["status"] = 500
    _write(repository, browser_trace_path, browser_trace)
    browser_trace_bytes = (repository / browser_trace_path).read_bytes()
    browser_receipt = {
        "schema_version": "concordia.g13_browser_receipt.v1",
        "status": "verified",
        "captured_at": captured_at,
        "runner": runner,
        "trace": {
            "path": browser_trace_path,
            "sha256": hashlib.sha256(browser_trace_bytes).hexdigest(),
        },
        "youtube": {
            "watch_url": "https://www.youtube.com/watch?v=AbCdEfGhI12",
            "video_id": "AbCdEfGhI12",
            "state": "playing_or_ended",
            "duration_seconds": 184,
            "captions_visible": True,
            "capture": {
                "path": youtube_capture_path,
                "sha256": hashlib.sha256(png).hexdigest(),
            },
        },
        "dorahacks": {
            "buidl_url": "https://dorahacks.io/buidl/46732",
            "buidl_id": 46732,
            "edit_state": "saved",
            "edit_access_verified": True,
            "embedded_video_id": "AbCdEfGhI12",
            "capture": {
                "path": dorahacks_capture_path,
                "sha256": hashlib.sha256(dorahacks_png).hexdigest(),
            },
        },
    }
    if mutation == "browser_receipt":
        browser_receipt["youtube"]["captions_visible"] = False
    _write(repository, browser_receipt_path, browser_receipt)
    browser_receipt_bytes = (repository / browser_receipt_path).read_bytes()
    organizer_audit_bytes = _write_organizer_link_audit(
        repository,
        organizer_audit_path,
        captured_at=captured_at,
    )
    if mutation == "organizer_audit":
        organizer_audit = json.loads(organizer_audit_bytes)
        organizer_audit["collection_mode"] = "fixture"
        organizer_audit["verdict"] = "NON_QUALIFYING"
        organizer_audit["release_qualified"] = False
        _write(repository, organizer_audit_path, organizer_audit)
        organizer_audit_bytes = (repository / organizer_audit_path).read_bytes()
    receipt = {
        "schema_version": release_manifest.G13_SUBMISSION_RECEIPT_SCHEMA_VERSION,
        "gate_id": "G13",
        "status": "verified",
        "captured_at": captured_at,
        "g12_manifest": {
            "path": RELEASE_MANIFEST_PATH,
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "manifest_commit": manifest_commit,
            "frozen_commit": manifest["frozen_commit"],
            "integration_commit": manifest["integration_commit"],
        },
        "organizer_rendered_link_audit": {
            "path": organizer_audit_path,
            "sha256": hashlib.sha256(organizer_audit_bytes).hexdigest(),
        },
        "browser_receipt": {
            "path": browser_receipt_path,
            "sha256": hashlib.sha256(browser_receipt_bytes).hexdigest(),
        },
        "youtube": {
            "watch_url": "https://www.youtube.com/watch?v=AbCdEfGhI12",
            "video_id": "AbCdEfGhI12",
            "title": "Concordia Finals Demo",
            "description": {
                "path": description_path,
                "sha256": hashlib.sha256(description).hexdigest(),
            },
            "incognito_playback": {
                "incognito": True,
                "state": "playing_or_ended",
                "duration_seconds": 184,
                "captions_visible": True,
                "capture": {
                    "path": youtube_capture_path,
                    "sha256": hashlib.sha256(png).hexdigest(),
                },
            },
        },
        "dorahacks": {
            "buidl_url": "https://dorahacks.io/buidl/46732",
            "buidl_id": 46732,
            "edit_state": "saved",
            "edit_access_verified": True,
            "embedded_video_id": (
                "ZyXwVuTsR98" if mutation == "video" else "AbCdEfGhI12"
            ),
            "capture": {
                "path": dorahacks_capture_path,
                "sha256": hashlib.sha256(dorahacks_png).hexdigest(),
            },
        },
        "final_link_audit": {
            "path": audit_path,
            "sha256": hashlib.sha256(audit_bytes).hexdigest(),
        },
    }
    _write(repository, G13_SUBMISSION_RECEIPT_PATH, receipt)
    return _commit(repository, "verified post-video G13 submission receipt")


def test_capture_is_code_collected_strict_projected_and_commit_bound(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, collector, verifier = release_repository

    paths = capture_release_observations_once(repository)

    assert collector.calls == 1
    assert set(verifier.calls) == set(ARTIFACT_PATHS)
    assert set(path.relative_to(repository).as_posix() for path in paths) == {
        *RECEIPT_PATHS.values(),
        *PROOF_RECEIPT_PATHS.values(),
        NPM_CAPTURE_PATH,
    }
    assert (repository / NPM_CAPTURE_PATH).read_bytes() == _npm_raw(
        commits["integration"]
    )["tarball"]
    for path in paths:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    compose_receipt = json.loads((repository / RECEIPT_PATHS["compose"]).read_bytes())
    assert len(compose_receipt["projection"]["services"]) == 15
    assert (
        compose_receipt["projection"]["tracked_compose"]["artifact_commit"]
        == commits["deployment"]
    )
    encoded = b"".join(
        (repository / path).read_bytes() for path in RECEIPT_PATHS.values()
    )
    assert b"DO-NOT-PERSIST-PROXY-SECRET" not in encoded
    assert b"SECRET-BCRYPT-MATERIAL" not in encoded
    probe_receipt = json.loads(
        (repository / RECEIPT_PATHS["public_probes"]).read_bytes()
    )
    assert all("body" not in item for item in probe_receipt["projection"]["probes"])


def test_command_gate_receipts_are_required_and_gate_specific(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, collector, _ = release_repository
    (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).unlink()
    _commit(repository, "remove required G2 receipt")

    with pytest.raises(
        ReleaseManifestError, match="G2_COMPONENT_GATES|G2.*receipt|command gate"
    ):
        capture_release_observations_once(repository)
    assert collector.calls == 0


def test_command_gate_contract_uses_frozen_isolated_and_fresh_dependency_trees() -> (
    None
):
    assert COMMAND_GATE_COMMANDS == {
        "G2": (
            (
                "python_components",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "-m",
                    "pytest",
                    "-q",
                ),
            ),
            (
                "v3_rust",
                "contracts/odra-governance-receipt-v3",
                ("cargo", "test", "--locked"),
            ),
            (
                "v3_wasm",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "scripts/run_locked_odra_build.py",
                    "--verify-only",
                ),
            ),
            ("verifier_install", "packages/verify", ("npm", "ci")),
            ("verifier_test", "packages/verify", ("npm", "test")),
            ("verifier_lint", "packages/verify", ("npm", "run", "lint")),
            (
                "verifier_audit",
                "packages/verify",
                ("npm", "audit", "--audit-level=high"),
            ),
            (
                "official_x402_install",
                "services/x402-official",
                ("npm", "ci"),
            ),
            (
                "official_x402_build",
                "services/x402-official",
                ("npm", "run", "build"),
            ),
            (
                "official_x402_typecheck",
                "services/x402-official",
                ("npm", "run", "typecheck"),
            ),
            (
                "official_x402_test",
                "services/x402-official",
                ("npm", "test"),
            ),
            (
                "official_x402_audit",
                "services/x402-official",
                ("npm", "audit", "--audit-level=high"),
            ),
        ),
        "G9": (
            ("dashboard_install", "dashboard", ("npm", "ci")),
            ("dashboard_unit", "dashboard", ("npm", "run", "test:unit")),
            (
                "dashboard_live_build",
                "dashboard",
                ("npm", "run", "build:e2e:live"),
            ),
            (
                "dashboard_live_e2e",
                "dashboard",
                ("npm", "run", "test:e2e:live"),
            ),
            ("dashboard_build", "dashboard", ("npm", "run", "build")),
            (
                "dashboard_reviewer_e2e",
                "dashboard",
                ("npm", "run", "test:e2e:reviewer"),
            ),
            (
                "dashboard_audit",
                "dashboard",
                ("npm", "audit", "--audit-level=high"),
            ),
        ),
        "G11": (
            (
                "claim_audit",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "scripts/run_g11_claim_audit.py",
                    "--verify-only",
                ),
            ),
        ),
    }


def test_command_gate_diagnostic_is_read_only_and_commit_bound(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, collector, _ = release_repository

    result = verify_command_gate_receipts(repository)

    assert result == {
        "gate_ids": ["G2", "G9", "G11"],
        "frozen_commit": commits["source"],
        "integration_commit": commits["integration"],
        "status": "verified",
    }
    assert collector.calls == 0
    assert not (repository / RELEASE_MANIFEST_PATH).exists()


def test_real_release_flow_accepts_runtime_D_evidence_R_gate_C_host_H(
    real_release_history: tuple[Path, dict[str, str]],
) -> None:
    repository, commits = real_release_history

    release_manifest._assert_deployment_to_integration_history(
        repository,
        deployment_commit=commits["deployment"],
        integration_commit=commits["integration"],
    )
    release_manifest._assert_exact_command_gate_commit(
        repository,
        integration_commit=commits["integration"],
        command_commit=commits["command"],
    )
    release_manifest._assert_release_only_history(
        repository,
        integration_commit=commits["integration"],
        descendant_commit=commits["host"],
    )
    _authority, host_bound, projection = release_manifest._host_toolchain_binding(
        repository
    )
    release_manifest._assert_host_toolchain_follows_command_commit(
        command_commit=commits["command"],
        host_toolchain_projection=projection,
    )

    assert host_bound.artifact_commit == commits["host"]
    assert projection["source_commit"] == commits["command"]


def test_release_history_accepts_host_authority_after_gate_receipts(
    real_release_history: tuple[Path, dict[str, str]],
) -> None:
    repository, commits = real_release_history
    changed = _git(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        commits["command"],
    ).decode().splitlines()

    assert len(changed) == 37
    release_manifest._assert_release_only_history(
        repository,
        integration_commit=commits["integration"],
        descendant_commit=commits["host"],
    )
    release_manifest._host_toolchain_binding(repository)


def test_command_gate_commit_rejects_staggered_receipt_groups(
    real_release_history: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, commits = real_release_history
    repository = tmp_path / "staggered-command-gates"
    _git(tmp_path, "clone", "--quiet", source.as_posix(), repository.as_posix())
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    _git(repository, "checkout", "--detach", "--quiet", commits["integration"])
    paths = sorted(release_manifest._COMMAND_GATE_FIRST_ADD_PATHS)
    midpoint = len(paths) // 2
    for relative in paths[:midpoint]:
        _write_bytes(repository, relative, b"first command-gate group\n")
    _commit(repository, "first command-gate receipt group")
    for relative in paths[midpoint:]:
        _write_bytes(repository, relative, b"second command-gate group\n")
    staggered_commit = _commit(repository, "second command-gate receipt group")

    with pytest.raises(ReleaseManifestError, match="direct child|exact 37"):
        release_manifest._assert_exact_command_gate_commit(
            repository,
            integration_commit=commits["integration"],
            command_commit=staggered_commit,
        )


def test_host_authority_rejects_non_direct_child_and_post_authority_source_change(
    real_release_history: tuple[Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    source, commits = real_release_history
    receipt_raw = (
        source / release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH
    ).read_bytes()

    non_direct = tmp_path / "non-direct"
    _git(tmp_path, "clone", "--quiet", source.as_posix(), non_direct.as_posix())
    _git(non_direct, "config", "user.name", "Release Test")
    _git(non_direct, "config", "user.email", "release@example.invalid")
    _git(non_direct, "checkout", "--detach", "--quiet", commits["command"])
    _write_bytes(non_direct, NPM_CAPTURE_PATH, b"release-only intermediary\n")
    _commit(non_direct, "intermediary release output")
    _write_bytes(
        non_direct,
        release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        receipt_raw,
    )
    _commit(non_direct, "non-direct host authority")
    with pytest.raises(ReleaseManifestError, match="authority|lineage"):
        release_manifest._host_toolchain_binding(non_direct)

    later_source = tmp_path / "later-source"
    _git(tmp_path, "clone", "--quiet", source.as_posix(), later_source.as_posix())
    _git(later_source, "config", "user.name", "Release Test")
    _git(later_source, "config", "user.email", "release@example.invalid")
    _git(later_source, "checkout", "--detach", "--quiet", commits["command"])
    _write_bytes(later_source, NPM_CAPTURE_PATH, b"release-only intermediary\n")
    intermediary_commit = _commit(later_source, "release-only intermediary")
    candidate = release_manifest.build_host_toolchain_receipt_candidate(
        repository_root=later_source,
        source_commit=intermediary_commit,
    )
    _write(
        later_source,
        release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        candidate,
    )
    _commit(later_source, "valid host authority after intermediary")
    _, _, later_projection = release_manifest._host_toolchain_binding(later_source)
    with pytest.raises(ReleaseManifestError, match="follow command gates"):
        release_manifest._assert_host_toolchain_follows_command_commit(
            command_commit=commits["command"],
            host_toolchain_projection=later_projection,
        )

    post_source = tmp_path / "post-source"
    _git(tmp_path, "clone", "--quiet", source.as_posix(), post_source.as_posix())
    _git(post_source, "config", "user.name", "Release Test")
    _git(post_source, "config", "user.email", "release@example.invalid")
    _write_bytes(post_source, "shared/post_authority_change.py", b"CHANGED = True\n")
    _commit(post_source, "post-authority source change")
    with pytest.raises(ReleaseManifestError, match="source code|authority"):
        release_manifest._host_toolchain_binding(post_source)


@pytest.mark.parametrize(
    "relative",
    [
        "gateway/changed.py",
        ".github/workflows/changed.yml",
        "dashboard/package-lock.json",
        release_manifest.COMPOSE_FILE_PATH,
        "unlisted-release-note.txt",
    ],
)
def test_D_to_R_rejects_runtime_source_changes(
    tmp_path: Path,
    relative: str,
) -> None:
    repository = tmp_path / "repository"
    deployment_commit = _new_deployment_history_base(repository)
    _write_bytes(repository, relative, b"forbidden between D and R\n")
    integration_commit = _commit(repository, f"forbidden D-R change {relative}")

    with pytest.raises(ReleaseManifestError, match="deployment.*integration|allowlist"):
        release_manifest._assert_deployment_to_integration_history(
            repository,
            deployment_commit=deployment_commit,
            integration_commit=integration_commit,
        )


@pytest.mark.parametrize("mutation", ["symlink", "deletion", "rename", "merge"])
def test_D_to_R_rejects_symlink_merge_deletion_and_rename(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository = tmp_path / mutation
    deployment_commit = _new_deployment_history_base(repository)
    safepay_path = repository / ARTIFACT_PATHS["safepay_v2"]

    if mutation == "symlink":
        relative = ARTIFACT_PATHS["exact_envelope_v3"]
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(safepay_path)
        integration_commit = _commit(repository, "symlink evidence")
    elif mutation == "deletion":
        safepay_path.unlink()
        integration_commit = _commit(repository, "deleted evidence")
    elif mutation == "rename":
        target = repository / ARTIFACT_PATHS["exact_envelope_v3"]
        target.parent.mkdir(parents=True, exist_ok=True)
        safepay_path.rename(target)
        integration_commit = _commit(repository, "renamed evidence")
    else:
        _git(repository, "checkout", "-b", "left")
        _write(repository, ARTIFACT_PATHS["exact_envelope_v3"], {"branch": "left"})
        _commit(repository, "left evidence")
        _git(repository, "checkout", "-b", "right", deployment_commit)
        _write(
            repository,
            ARTIFACT_PATHS["native_treasury_execution_v1"],
            {"branch": "right"},
        )
        _commit(repository, "right evidence")
        _git(repository, "merge", "--no-ff", "-m", "merge evidence", "left")
        integration_commit = _git(repository, "rev-parse", "HEAD").decode().strip()

    with pytest.raises(
        ReleaseManifestError,
        match="regular|linear|append|delet|rename|history",
    ):
        release_manifest._assert_deployment_to_integration_history(
            repository,
            deployment_commit=deployment_commit,
            integration_commit=integration_commit,
        )


def test_command_gate_history_rejects_source_change_even_when_later_reverted(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    _write_bytes(repository, "shared/temporary_backdoor.py", b"ENABLED = True\n")
    _commit(repository, "add post-gate source change")
    (repository / "shared/temporary_backdoor.py").unlink()
    _commit(repository, "revert post-gate source change")

    with pytest.raises(
        ReleaseManifestError,
        match="current release code differs from the command-gated integration commit",
    ):
        verify_command_gate_receipts(repository)


def test_g1_authority_binds_exact_annotated_tag_and_tagged_files(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    tag_object = (
        _git(repository, "rev-parse", "refs/tags/concordia-g1-freeze-v2.0-a")
        .decode()
        .strip()
    )

    projection = release_manifest._validate_g1_freeze_authority(
        repository,
        expected_tag="concordia-g1-freeze-v2.0-a",
        expected_tag_object=tag_object,
        expected_commit=commits["source"],
    )

    assert projection["tag_object"] == tag_object
    assert projection["peeled_commit"] == commits["source"]
    assert projection["manifest_path"] == "handoff/G1_FREEZE_MANIFEST.json"
    assert len(projection["authority_files"]) == 8


def test_g1_authority_rejects_lightweight_or_retargeted_tag(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    _git(repository, "tag", "-d", "concordia-g1-freeze-v2.0-a")
    _git(
        repository,
        "tag",
        "concordia-g1-freeze-v2.0-a",
        commits["source"],
    )

    with pytest.raises(ReleaseManifestError, match="annotated tag"):
        release_manifest._validate_g1_freeze_authority(
            repository,
            expected_tag="concordia-g1-freeze-v2.0-a",
            expected_tag_object=release_manifest.G1_FREEZE_TAG_OBJECT,
            expected_commit=commits["source"],
        )


def test_g1_authority_recomputes_every_tagged_file_digest(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _, _ = release_repository
    _git(repository, "tag", "-d", "concordia-g1-freeze-v2.0-a")
    (repository / "handoff/G1_INTERFACE_SPEC.md").write_text("# tampered interface\n")
    tampered_commit = _commit(repository, "tamper tagged authority")
    _git(
        repository,
        "tag",
        "-a",
        "concordia-g1-freeze-v2.0-a",
        "-m",
        "Concordia finals G1 interface freeze v2.0-A",
        tampered_commit,
    )
    tag_object = (
        _git(repository, "rev-parse", "refs/tags/concordia-g1-freeze-v2.0-a")
        .decode()
        .strip()
    )
    monkeypatch.setattr(release_manifest, "G1_FREEZE_TAG_OBJECT", tag_object)
    monkeypatch.setattr(release_manifest, "G1_FREEZE_COMMIT", tampered_commit)

    with pytest.raises(ReleaseManifestError, match="authority digest"):
        release_manifest._validate_g1_freeze_authority(
            repository,
            expected_tag="concordia-g1-freeze-v2.0-a",
            expected_tag_object=tag_object,
            expected_commit=tampered_commit,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_outer",
        "extra_outer",
        "launcher_schema",
        "runtime_not_mapping",
        "runtime_extra",
        "runtime_schema",
        "tree_hash",
        "entry_count_zero",
        "entry_count_boolean",
        "file_count_over_entry_count",
        "total_file_bytes_negative",
        "immutable_system_not_boolean",
        "outer_hash",
        "invocation",
        "startup_environment",
        "environment_transport",
        "exec_status",
    ],
)
def test_bound_process_launcher_identity_is_exact_and_fail_closed(
    mutation: str,
) -> None:
    identity = json.loads(json.dumps(_test_bound_process_launcher_identity()))
    if mutation == "missing_outer":
        identity.pop("shim_sha256")
    elif mutation == "extra_outer":
        identity["unexpected"] = True
    elif mutation == "launcher_schema":
        identity["schema_version"] = "concordia.bound_process_launcher.v0"
    elif mutation == "runtime_not_mapping":
        identity["runtime_tree"] = []
    elif mutation == "runtime_extra":
        identity["runtime_tree"]["unexpected"] = True
    elif mutation == "runtime_schema":
        identity["runtime_tree"]["schema_version"] = "forged"
    elif mutation == "tree_hash":
        identity["runtime_tree"]["tree_sha256"] = "not-a-hash"
    elif mutation == "entry_count_zero":
        identity["runtime_tree"]["entry_count"] = 0
    elif mutation == "entry_count_boolean":
        identity["runtime_tree"]["entry_count"] = True
    elif mutation == "file_count_over_entry_count":
        identity["runtime_tree"]["file_count"] = (
            identity["runtime_tree"]["entry_count"] + 1
        )
    elif mutation == "total_file_bytes_negative":
        identity["runtime_tree"]["total_file_bytes"] = -1
    elif mutation == "immutable_system_not_boolean":
        identity["runtime_tree"]["immutable_system"] = 0
    elif mutation == "outer_hash":
        identity["active_closure_sha256"] = "00"
    elif mutation == "invocation":
        identity["invocation"] = ["-I"]
    elif mutation == "startup_environment":
        identity["startup_environment"]["LANG"] = "caller-controlled"
    elif mutation == "environment_transport":
        identity["environment_transport"] = "ambient"
    else:
        identity["exec_status"] = "unobserved"

    with pytest.raises(ReleaseManifestError, match="launcher"):
        release_manifest._validate_bound_process_launcher_identity(
            identity,
            label="test launcher",
        )


def test_command_gate_replay_contract_binds_launcher_runtime_identity() -> None:
    public_build_values = {
        "NEXT_PUBLIC_GATEWAY_URL": "",
        "NEXT_PUBLIC_CONCORDIA_MODE": "reviewer",
        "NEXT_PUBLIC_CSPR_CLICK_APP_ID": "0f892487-0a8c-45b5-8cea-bbe95c64",
    }
    document = {
        "gate_id": "G2",
        "integration_commit": "11" * 20,
        "commands": [
            {
                "command_id": "example",
                "working_directory": ".",
                "argv": ["example"],
                "exit_code": 0,
            }
        ],
        "produced_artifacts": [{"path": "artifact", "sha256": "22" * 32}],
        "input_artifacts": [],
        "fresh_outputs": [],
        "bound_process_launcher": _test_bound_process_launcher_identity(),
        "public_build_profile": {
            "schema_version": (
                release_manifest.COMMAND_GATE_PUBLIC_BUILD_PROFILE_SCHEMA_VERSION
            ),
            "values": public_build_values,
            "sha256": hashlib.sha256(_canonical(public_build_values)).hexdigest(),
            "live_test": {
                "values": {
                    **public_build_values,
                    "NEXT_PUBLIC_CONCORDIA_MODE": "live",
                },
                "sha256": hashlib.sha256(
                    _canonical(
                        {
                            **public_build_values,
                            "NEXT_PUBLIC_CONCORDIA_MODE": "live",
                        }
                    )
                ).hexdigest(),
            },
        },
    }
    original = release_manifest._command_gate_replay_projection(document)
    changed = json.loads(json.dumps(document))
    changed["bound_process_launcher"]["shim_sha256"] = "55" * 32

    assert release_manifest._command_gate_replay_projection(changed) != original

    changed_profile = json.loads(json.dumps(document))
    changed_profile["public_build_profile"]["values"][
        "NEXT_PUBLIC_CSPR_CLICK_APP_ID"
    ] = "0f892487-0a8c-45b5-8cea-bbe95c65"
    assert (
        release_manifest._command_gate_replay_projection(changed_profile)
        != original
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("argv", "immutable first-add"),
        ("exit", "immutable first-add"),
        ("runtime", "immutable first-add"),
        ("chronology", "immutable first-add"),
        ("receipt_commit", "immutable first-add"),
    ],
)
def test_command_gate_receipts_reject_forged_execution_claims(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    mutation: str,
    message: str,
) -> None:
    repository, _, _, _ = release_repository
    path = repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
    receipt = json.loads(path.read_bytes())
    if mutation == "argv":
        receipt["commands"][0]["argv"] = ["bash", "-c", "true"]
    elif mutation == "exit":
        receipt["commands"][0]["exit_code"] = 1
    elif mutation == "runtime":
        receipt["runtime_versions"].pop("python")
    elif mutation == "chronology":
        receipt["commands"][0]["ended_at"] = "2026-07-22T23:59:59Z"
    else:
        log_path = repository / receipt["commands"][0]["stdout"]["path"]
        payload = log_path.read_bytes() + b"separate-log-commit\n"
        log_path.write_bytes(payload)
        _commit(repository, "forge G2 log separately")
        receipt["commands"][0]["stdout"]["sha256"] = hashlib.sha256(payload).hexdigest()
    _write(repository, COMMAND_GATE_RECEIPT_PATHS["G2"], receipt)
    _commit(repository, f"forge G2 {mutation}")

    with pytest.raises(ReleaseManifestError, match=message):
        _capture_and_commit(repository)
        assemble_release_manifest_once(repository)


@pytest.mark.parametrize(
    ("gate_id", "mutation", "message"),
    [
        ("G2", "freeze_tag", "immutable first-add"),
        ("G2", "runner", "immutable first-add"),
        ("G2", "command_chain", "immutable first-add"),
        ("G2", "runtime_chain", "immutable first-add"),
        ("G2", "input", "immutable first-add"),
        ("G9", "fresh", "immutable first-add"),
        ("G2", "normalization", "immutable first-add"),
        ("G2", "launcher_missing", "immutable first-add"),
        ("G2", "launcher_invalid", "immutable first-add"),
    ],
)
def test_command_gate_receipts_require_the_complete_frozen_schema(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    gate_id: str,
    mutation: str,
    message: str,
) -> None:
    repository, _, _, _ = release_repository
    receipt_path = repository / COMMAND_GATE_RECEIPT_PATHS[gate_id]
    receipt = json.loads(receipt_path.read_bytes())
    if mutation == "freeze_tag":
        receipt["freeze_tag"]["object"] = "00" * 20
    elif mutation == "runner":
        receipt["runner"].pop()
    elif mutation == "command_chain":
        receipt["commands"][0]["executable_chain"][0]["resolved_path"] = (
            f"{Path.home()}/forged-runtime"
        )
    elif mutation == "runtime_chain":
        receipt["runtime_executable_chains"].pop(
            next(iter(receipt["runtime_executable_chains"]))
        )
    elif mutation == "input":
        receipt["input_artifacts"] = [{"path": "source.json", "sha256": "00" * 32}]
    elif mutation == "fresh":
        receipt["fresh_outputs"][0]["state_before"] = "present"
    elif mutation == "launcher_missing":
        receipt.pop("bound_process_launcher")
    elif mutation == "launcher_invalid":
        receipt["bound_process_launcher"]["shim_sha256"] = "00"
    else:
        receipt["normalization"].pop("encoding_errors")

    # Keep the receipt and its normalized logs in one forged commit so the
    # field-specific validator, not the same-commit invariant, rejects it.
    for command in receipt["commands"]:
        for stream in ("stdout", "stderr"):
            log_path = repository / command[stream]["path"]
            payload = log_path.read_bytes() + b"schema-forgery-test\n"
            log_path.write_bytes(payload)
            command[stream]["sha256"] = hashlib.sha256(payload).hexdigest()
    _write(repository, COMMAND_GATE_RECEIPT_PATHS[gate_id], receipt)
    _commit(repository, f"forge {gate_id} {mutation}")

    with pytest.raises(ReleaseManifestError, match=message):
        verify_command_gate_receipts(repository)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("secret", "immutable first-add"),
        ("absolute_repo", "immutable first-add"),
        ("home_cache", "immutable first-add"),
        ("non_utf8", "immutable first-add"),
        ("symlink", "immutable first-add"),
        ("unexpected", "immutable first-add|unexpected.*log|filename"),
    ],
)
def test_command_gate_logs_are_normalized_secret_scanned_and_exact(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    mutation: str,
    message: str,
) -> None:
    repository, _, _, _ = release_repository
    receipt_path = repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
    receipt = json.loads(receipt_path.read_bytes())
    stdout_row = receipt["commands"][0]["stdout"]
    log_path = repository / stdout_row["path"]
    if mutation == "secret":
        payload = b"Authorization: super-secret-token-value\n"
        log_path.write_bytes(payload)
        stdout_row["sha256"] = hashlib.sha256(payload).hexdigest()
        _write(repository, COMMAND_GATE_RECEIPT_PATHS["G2"], receipt)
    elif mutation == "absolute_repo":
        payload = f"built in {repository}\n".encode()
        log_path.write_bytes(payload)
        stdout_row["sha256"] = hashlib.sha256(payload).hexdigest()
        _write(repository, COMMAND_GATE_RECEIPT_PATHS["G2"], receipt)
    elif mutation == "home_cache":
        payload = f"Compiling from {Path.home()}/.rustup/toolchains/nightly\n".encode()
        log_path.write_bytes(payload)
        stdout_row["sha256"] = hashlib.sha256(payload).hexdigest()
        _write(repository, COMMAND_GATE_RECEIPT_PATHS["G2"], receipt)
    elif mutation == "non_utf8":
        payload = b"\xff\xfe"
        log_path.write_bytes(payload)
        stdout_row["sha256"] = hashlib.sha256(payload).hexdigest()
        _write(repository, COMMAND_GATE_RECEIPT_PATHS["G2"], receipt)
    elif mutation == "symlink":
        log_path.unlink()
        log_path.symlink_to(repository / "source.json")
    else:
        _write_bytes(
            repository,
            "release/receipts/logs/G2/unexpected.stdout",
            b"not in the receipt\n",
        )
    _commit(repository, f"forge G2 log {mutation}")

    with pytest.raises(ReleaseManifestError, match=message):
        _capture_and_commit(repository)
        assemble_release_manifest_once(repository)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("unrelated", "immutable first-add"),
        ("ignored_drift", "artifact digest"),
        ("ignored_symlink", "read safely|regular|symlink"),
    ],
)
def test_command_gate_artifacts_are_exact_and_ignored_build_outputs_are_safe(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    mutation: str,
    message: str,
) -> None:
    repository, _, collector, _ = release_repository
    if mutation == "unrelated":
        receipt_path = repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
        receipt = json.loads(receipt_path.read_bytes())
        for command in receipt["commands"]:
            for stream in ("stdout", "stderr"):
                log_path = repository / command[stream]["path"]
                payload = log_path.read_bytes() + b"allowlist-test-revision\n"
                log_path.write_bytes(payload)
                command[stream]["sha256"] = hashlib.sha256(payload).hexdigest()
        receipt["produced_artifacts"][0] = {
            "path": "source.json",
            "sha256": hashlib.sha256(
                (repository / "source.json").read_bytes()
            ).hexdigest(),
        }
        _write(repository, COMMAND_GATE_RECEIPT_PATHS["G2"], receipt)
        _commit(repository, "replace G2 produced artifact")
    else:
        build_id = repository / COMMAND_GATE_ARTIFACT_PATHS["G9"][0]
        if mutation == "ignored_drift":
            build_id.write_bytes(b"different ignored build\n")
        else:
            build_id.unlink()
            build_id.symlink_to(repository / "source.json")

    with pytest.raises(ReleaseManifestError, match=message):
        capture_release_observations_once(repository)
    assert collector.calls == 0


def test_manifest_has_one_to_one_g2_through_g12_evidence_and_external_g13(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    _capture_and_commit(repository)
    assemble_release_manifest_once(repository)

    manifest = json.loads((repository / RELEASE_MANIFEST_PATH).read_bytes())
    assert manifest["status"] == "g12_ready"
    assert manifest["overall_status"] == "pending_external"
    assert manifest["deployment_commit"] == commits["deployment"]
    assert manifest["integration_commit"] == commits["integration"]
    correction_authority = manifest["post_freeze_corrections"]["authority"]
    assert correction_authority["path"] == "handoff/G1_POST_FREEZE_CORRECTIONS.json"
    assert correction_authority["schema_id"] == (
        "concordia.g1-post-freeze-corrections.v1"
    )
    assert correction_authority["status"] == "required"
    assert correction_authority["authority_tag"] == (
        release_manifest.G1_FREEZE_TAG
    )
    assert correction_authority["authority_commit"] == (
        release_manifest.G1_FREEZE_COMMIT
    )
    assert correction_authority["correction_ids"] == [
        f"G1-C{number}-{suffix}"
        for number, suffix in (
            (6, "v3-temporal-order"),
            (7, "proof-registry-deployment-domain"),
            (8, "v3-canonical-block-order"),
            (9, "treasury-authorization-block-hash"),
            (10, "independent-card-chain-artifact"),
            (11, "proof-type-provenance-binding"),
            (12, "proof-observation-chronology"),
            (13, "independent-historical-odra-artifact"),
            (14, "official-x402-separate-proposal-and-governance-identity"),
        )
    ]
    correction = manifest["post_freeze_corrections"]["corrections"][0]
    assert correction["correction_id"] == (
        "safepay_gateway_wallet_intent_capability_v1"
    )
    assert correction["client_interface_version"] == (
        "safepay-gateway-wallet-intent-capability-v1"
    )
    assert correction["request_capability_field"] == "quote_capability"
    assert correction["deployment_prerequisite"] == {
        "environment_key": "SAFEPAY_QUOTE_TOKEN_SECRET_FILE",
        "runtime_path": "/run/secrets/safepay_quote_token_secret",
        "consumer": "gateway",
        "minimum_bytes": 32,
    }
    assert [row["path"] for row in correction["implementation_bindings"]] == list(
        release_manifest._SAFEPAY_GATEWAY_CORRECTION_PATHS
    )
    forged = json.loads(json.dumps(manifest))
    forged["post_freeze_corrections"]["corrections"][0]["client_interface_version"] = (
        "forged-wallet-intent-interface"
    )
    with pytest.raises(ReleaseManifestError, match="post-freeze corrections differ"):
        release_manifest._validate_g12_manifest_offline(
            repository,
            forged,
            canaries=(),
        )
    forged = json.loads(json.dumps(manifest))
    forged["post_freeze_corrections"]["authority"]["correction_ids"].pop()
    with pytest.raises(ReleaseManifestError, match="post-freeze corrections differ"):
        release_manifest._validate_g12_manifest_offline(
            repository,
            forged,
            canaries=(),
        )
    forged = json.loads(json.dumps(manifest))
    forged["deployment_commit"] = commits["integration"]
    with pytest.raises(ReleaseManifestError, match="deployment identity"):
        release_manifest._validate_g12_manifest_offline(
            repository,
            forged,
            canaries=(),
        )
    gates = {item["gate_id"]: item for item in manifest["gate_evidence"]}
    assert list(gates) == [
        "G2",
        "G3",
        "G4",
        "G5",
        "G6",
        "G7a",
        "G7b",
        "G8",
        "G9",
        "G9n",
        "G9d",
        "G10",
        "G11",
        "G12",
        "G13",
    ]
    for gate_id in list(gates)[:-1]:
        assert gates[gate_id]["status"] == "verified"
        assert gates[gate_id]["evidence_refs"]
    assert any(
        reference["path"] == COMMAND_GATE_RECEIPT_PATHS["G2"]
        for reference in gates["G2"]["evidence_refs"]
    )
    assert any(
        reference["path"] == COMMAND_GATE_RECEIPT_PATHS["G9"]
        for reference in gates["G9"]["evidence_refs"]
    )
    assert any(
        reference["path"] == COMMAND_GATE_RECEIPT_PATHS["G11"]
        for reference in gates["G11"]["evidence_refs"]
    )
    assert manifest["organizer_rendered_link_audit"]["path"] == (
        release_manifest.ORGANIZER_G12_AUDIT_PATH
    )
    assert any(
        reference == {
            "kind": "browser_audit",
            "evidence_id": "organizer_rendered_links",
            "path": release_manifest.ORGANIZER_G12_AUDIT_PATH,
            "sha256": manifest["organizer_rendered_link_audit"]["sha256"],
            "artifact_commit": (
                manifest["organizer_rendered_link_audit"]["artifact_commit"]
            ),
        }
        for reference in gates["G12"]["evidence_refs"]
    )
    assert gates["G13"] == {
        "gate_id": "G13",
        "required_receipt_path": G13_SUBMISSION_RECEIPT_PATH,
        "required_rendered_link_audit_path": (
            release_manifest.ORGANIZER_G13_AUDIT_PATH
        ),
        "status": "pending_external",
    }


def test_g13_receipt_is_separate_strict_and_completes_without_mutating_g12(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, collector, _ = release_repository
    _capture_and_commit(repository)
    assemble_release_manifest_once(repository)
    manifest_before = (repository / RELEASE_MANIFEST_PATH).read_bytes()
    manifest_commit = _commit(repository, "immutable G12 release manifest")
    _write_g13_submission_receipt(repository, manifest_commit)

    result = verify_g13_submission_receipt(repository)

    assert result == {
        "gate_id": "G13",
        "g12_manifest_sha256": hashlib.sha256(manifest_before).hexdigest(),
        "overall_status": "complete",
        "status": "verified",
    }
    assert (repository / RELEASE_MANIFEST_PATH).read_bytes() == manifest_before
    manifest = json.loads(manifest_before)
    assert manifest["overall_status"] == "pending_external"
    assert collector.calls == 2


def test_g13_replays_full_g12_semantics_without_live_collection(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, collector, _ = release_repository
    _capture_and_commit(repository)
    assemble_release_manifest_once(repository)
    manifest = json.loads((repository / RELEASE_MANIFEST_PATH).read_bytes())
    manifest["services"] = manifest["services"][:-1]
    _write(repository, RELEASE_MANIFEST_PATH, manifest)
    forged_manifest_commit = _commit(repository, "forge shallow G12 service list")
    _write_g13_submission_receipt(repository, forged_manifest_commit)

    with pytest.raises(ReleaseManifestError, match="runtime service projection"):
        verify_g13_submission_receipt(repository)
    assert collector.calls == 2


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("video", "video|embed"),
        ("manifest", "manifest.*digest|G12"),
        ("links", "link.*audit|exact.*link"),
        ("capture", "PNG|capture|digest"),
        ("truncated_png", "PNG|capture|chunk|CRC"),
        ("solid_png", "blank|visual"),
        ("browser_trace", "browser trace"),
        ("browser_receipt", "browser YouTube"),
        ("organizer_audit", "live-incognito|qualifying"),
    ],
)
def test_g13_verifier_rejects_unbound_or_incomplete_submission_evidence(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    mutation: str,
    message: str,
) -> None:
    repository, _, _, _ = release_repository
    _capture_and_commit(repository)
    assemble_release_manifest_once(repository)
    manifest_commit = _commit(repository, "immutable G12 release manifest")
    _write_g13_submission_receipt(repository, manifest_commit, mutation=mutation)

    with pytest.raises(ReleaseManifestError, match=message):
        verify_g13_submission_receipt(repository)


def test_g13_verifier_rejects_unbound_support_file(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    _capture_and_commit(repository)
    assemble_release_manifest_once(repository)
    manifest_commit = _commit(repository, "immutable G12 release manifest")
    _write_g13_submission_receipt(repository, manifest_commit)
    _write_bytes(repository, "release/g13/UNBOUND_EVIDENCE.txt", b"not bound\n")
    _commit(repository, "add unbound G13 support file")

    with pytest.raises(
        ReleaseManifestError,
        match=(
            "current release code differs|outside the exact release allowlist|"
            "support-file inventory"
        ),
    ):
        verify_g13_submission_receipt(repository)


def test_handwritten_status_json_is_rejected_from_release_history(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, collector, _ = release_repository
    _write(
        repository,
        "release/STAGED_RELEASE_INPUTS.json",
        {"status": "ready", "public_urls": [{"status": "available"}]},
    )
    _commit(repository, "operator-authored status claim")

    capture_release_observations_once(repository)
    _commit(repository, "real observations")
    with pytest.raises(
        ReleaseManifestError,
        match="outside the exact (?:release )?allowlist",
    ):
        assemble_release_manifest_once(repository)
    assert collector.calls == 1


def test_capture_rejects_missing_approval_auth_or_broken_provider_tls(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    bad_caddy = _caddy_raw()
    routes = bad_caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"]
    routes[0]["handle"] = [routes[0]["handle"][-1]]
    bad = replace(bad, caddy=bad_caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    with pytest.raises(ReleaseManifestError, match="approval.*authentication|X-Proxy"):
        capture_release_observations_once(repository)

    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probes = [dict(item) for item in bad.public_probes]
    provider = next(
        item for item in probes if item["probe_id"] == "sslip_provider_root"
    )
    provider["tls"] = None
    bad = replace(bad, public_probes=probes)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    with pytest.raises(ReleaseManifestError, match="TLS"):
        capture_release_observations_once(repository)


def test_unexpected_compose_service_is_rejected_before_runtime_projection(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    compose = _compose_raw()
    compose["services"]["future-observer"] = {
        "image": "concordia/future-observer:finals",
        "build": None,
        "command": ["run"],
        "entrypoint": None,
        "networks": {"shared": {}},
        "volumes": [],
        "depends_on": {},
        "healthcheck": {"interval": "10s", "retries": 3},
        "restart": "unless-stopped",
        "environment": {"CASPER_CHAIN_NAME": "casper-test"},
        "secrets": [],
    }
    compose["x-concordia-observed-service-config-hashes"]["future-observer"] = (
        hashlib.sha256(b"config:future-observer").hexdigest()
    )
    runtime = _runtime_raw(compose, commits["integration"])
    runtime[0]["Env"] = ["TOKEN=must-never-persist"]
    runtime[0]["Mounts"] = [{"Source": "/run/secrets"}]
    snapshot = replace(snapshot, compose=compose, runtime=runtime)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="service allowlist differs"):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    ("service", "key"),
    [
        ("gateway", "CSPR_CLOUD_ACCESS_TOKEN_FILE"),
        ("x402-provider", "X402_PROVIDER_TOKEN"),
        ("mercer", "X402_FACILITATOR_TOKEN"),
        ("dashboard", "SAFEPAY_PROXY_SECRET_FILE"),
    ],
)
def test_compose_rejects_unexpected_or_legacy_payment_secret_targets(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    service: str,
    key: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    snapshot.compose["services"][service]["environment"][key] = "/run/secrets/bad"
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    with pytest.raises(ReleaseManifestError, match="secret target|legacy"):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    "mutation",
    [
        "artifact_auto_create",
        "registry_auto_create",
        "missing_registry_override",
        "external_artifact_source",
        "unscoped_x402_config",
    ],
)
def test_compose_rejects_mutable_or_unscoped_release_directory_binds(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    gateway_volumes = snapshot.compose["services"]["gateway"]["volumes"]
    official_volumes = snapshot.compose["services"]["x402-official"]["volumes"]
    if mutation == "artifact_auto_create":
        gateway_volumes[1]["bind"]["create_host_path"] = True
    elif mutation == "registry_auto_create":
        gateway_volumes[2]["bind"]["create_host_path"] = True
    elif mutation == "missing_registry_override":
        gateway_volumes.pop(2)
    elif mutation == "external_artifact_source":
        gateway_volumes[1]["source"] = str(repository.parent / "config")
    else:
        other = repository.parent / "unscoped-x402"
        other.mkdir()
        (other / "x402-resources.json").write_text(
            '{"resources":[]}\n',
            encoding="ascii",
        )
        official_volumes[1]["source"] = str(other)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(
        ReleaseManifestError,
        match="mount allowlist|host path|outside|release scope|may not create",
    ):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    "mutation",
    [
        "direct_secret",
        "wrong_file_target",
        "secret_bind_mount",
        "ungranted_secret",
        "unknown_file_key",
        "surplus_grant",
        "duplicate_grant",
        "source_target_mismatch",
    ],
)
def test_compose_rejects_direct_or_misdirected_secret_material(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    if mutation == "direct_secret":
        bad.compose["services"]["dashboard"]["environment"][
            "CSPR_CLOUD_ACCESS_TOKEN"
        ] = "LEAKME"
    elif mutation == "wrong_file_target":
        bad.compose["services"]["mercer"]["environment"][
            "CSPR_CLOUD_ACCESS_TOKEN_FILE"
        ] = "/etc/passwd"
    elif mutation == "secret_bind_mount":
        bad.compose["services"]["dashboard"]["volumes"].append(
            {
                "type": "bind",
                "source": "/run/secrets/cspr_cloud_access_token",
                "target": "/run/secrets/cspr_cloud_access_token",
            }
        )
    elif mutation == "ungranted_secret":
        bad.compose["services"]["mercer"]["secrets"] = []
    elif mutation == "unknown_file_key":
        bad.compose["services"]["dashboard"]["environment"][
            "UNREVIEWED_SESSION_TOKEN_FILE"
        ] = "/run/secrets/unreviewed_session_token"
        bad.compose["services"]["dashboard"]["secrets"].append(
            {
                "source": "unreviewed_session_token",
                "target": "unreviewed_session_token",
            }
        )
    elif mutation == "surplus_grant":
        bad.compose["services"]["dashboard"]["secrets"].append(
            {"source": "llm_api_key", "target": "llm_api_key"}
        )
    elif mutation == "duplicate_grant":
        bad.compose["services"]["dashboard"]["secrets"].append(
            dict(bad.compose["services"]["dashboard"]["secrets"][0])
        )
    else:
        bad.compose["services"]["dashboard"]["secrets"][0]["source"] = "attacker_secret"
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="secret|credential"):
        capture_release_observations_once(repository)


def test_secret_canary_paths_are_complete_and_derived_from_one_matrix() -> None:
    targets = {target for target, _ in release_manifest._SECRET_FILE_MATRIX.values()}
    run_paths = {Path("/run/secrets") / target for target in targets}
    host_paths = {
        Path("/opt/apps/concordia/secrets")
        / release_manifest._SECRET_HOST_BASENAMES[target]
        for target in targets
    }
    assert set(release_manifest._SECRET_CANARY_PATHS) == run_paths | host_paths
    assert Path("/run/secrets/x402_official_gateway_token") in run_paths
    assert Path("/run/secrets/x402_official_signer") in run_paths
    assert Path("/run/secrets/safepay_proxy_secret") in run_paths
    assert Path("/run/secrets/safepay_quote_token_secret") in run_paths
    assert Path("/run/secrets/safepay_client_key_hmac_secret") in run_paths


def test_compose_command_is_digest_only_and_runtime_is_bound_to_image_and_config(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    snapshot.compose["services"]["dashboard"]["command"] = [
        "run",
        "--api-key=LEAKME",
    ]
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    capture_release_observations_once(repository)
    receipt = (repository / RECEIPT_PATHS["compose"]).read_text()
    assert "LEAKME" not in receipt
    assert "command_sha256" in receipt

    for field, value in (
        ("config_image", "attacker/image:latest"),
        ("config_hash", "ef" * 32),
    ):
        bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
        dashboard = next(
            item for item in bad.runtime if item["service_id"] == "dashboard"
        )
        dashboard[field] = value
        with pytest.raises(
            ReleaseManifestError, match="runtime.*Compose|config hash|image"
        ):
            release_manifest._runtime_projection(
                repository,
                bad.runtime,
                release_manifest._compose_projection(repository, bad.compose, ()),
                (),
                integration_commit=commits["integration"],
            )


def test_runtime_health_must_match_compose_healthcheck_presence(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    compose_projection = release_manifest._compose_projection(
        repository, snapshot.compose, ()
    )
    with_health = json.loads(json.dumps(snapshot.runtime))
    with_health[0]["health_status"] = "none"
    with pytest.raises(ReleaseManifestError, match="healthcheck|healthy"):
        release_manifest._runtime_projection(
            repository,
            with_health,
            compose_projection,
            (),
            integration_commit=commits["integration"],
        )

    service_id = with_health[0]["service_id"]
    no_health_compose = json.loads(json.dumps(snapshot.compose))
    no_health_compose["services"][service_id]["healthcheck"] = None
    no_health_projection = release_manifest._compose_projection(
        repository, no_health_compose, ()
    )
    healthy_without_healthcheck = json.loads(json.dumps(snapshot.runtime))
    with pytest.raises(ReleaseManifestError, match="healthcheck|none"):
        release_manifest._runtime_projection(
            repository,
            healthy_without_healthcheck,
            no_health_projection,
            (),
            integration_commit=commits["integration"],
        )


def test_runtime_projection_derives_one_reviewed_deployment_commit_D(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)

    projected = release_manifest._runtime_projection(
        repository,
        snapshot.runtime,
        release_manifest._compose_projection(repository, snapshot.compose, ()),
        (),
        integration_commit=commits["integration"],
    )

    assert projected["deployment_commit"] == commits["deployment"]


def test_pages_and_npm_must_bind_integration_R_not_runtime_D(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["deployment"], repository)

    with pytest.raises(
        ReleaseManifestError,
        match="command-gated integration commit",
    ):
        release_manifest._project_snapshot(
            repository,
            snapshot,
            now=datetime(2026, 7, 23, 0, 10, 30, tzinfo=UTC),
            canaries=(),
            integration_commit=commits["integration"],
        )


def test_runtime_commit_must_be_ancestor_of_integration(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    empty_tree = _git(repository, "mktree", input_bytes=b"").decode().strip()
    unrelated = _git(
        repository,
        "commit-tree",
        empty_tree,
        "-m",
        "unrelated deployment",
    ).decode().strip()
    for container in snapshot.runtime:
        if container["service_id"] in release_manifest._COMPOSE_PROJECT_SERVICES:
            container["image_revision"] = unrelated
            container["image_deployment"] = unrelated

    with pytest.raises(ReleaseManifestError, match="ancestor|deployment.*integration"):
        release_manifest._runtime_projection(
            repository,
            snapshot.runtime,
            release_manifest._compose_projection(repository, snapshot.compose, ()),
            (),
            integration_commit=commits["integration"],
        )


def test_runtime_images_must_share_exact_reviewed_D(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    snapshot.runtime[0]["image_revision"] = commits["integration"]
    snapshot.runtime[0]["image_deployment"] = commits["integration"]

    with pytest.raises(ReleaseManifestError, match="one deployment commit|OCI identity"):
        release_manifest._runtime_projection(
            repository,
            snapshot.runtime,
            release_manifest._compose_projection(repository, snapshot.compose, ()),
            (),
            integration_commit=commits["integration"],
        )


def test_digest_pinned_project_service_cannot_bypass_oci_D(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    digest_ref = "registry.example/concordia-dashboard@sha256:" + "ab" * 32
    snapshot.compose["services"]["dashboard"]["image"] = digest_ref
    dashboard = next(
        item for item in snapshot.runtime if item["service_id"] == "dashboard"
    )
    dashboard["config_image"] = digest_ref
    dashboard["image_revision"] = None
    dashboard["image_source"] = None
    dashboard["image_deployment"] = None

    with pytest.raises(
        ReleaseManifestError,
        match="project image policy|project runtime image|OCI identity|runtime image revision",
    ):
        release_manifest._runtime_projection(
            repository,
            snapshot.runtime,
            release_manifest._compose_projection(repository, snapshot.compose, ()),
            (),
            integration_commit=commits["integration"],
        )


@pytest.mark.parametrize("mutation", ["project_image", "project_labels"])
def test_third_party_service_remains_digest_pinned_without_project_labels(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    mutation: str,
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    ipfs = next(item for item in snapshot.runtime if item["service_id"] == "ipfs")
    if mutation == "project_image":
        snapshot.compose["services"]["ipfs"]["image"] = "concordia/ipfs:finals"
        ipfs["config_image"] = "concordia/ipfs:finals"
    else:
        ipfs["image_revision"] = commits["deployment"]
        ipfs["image_source"] = (
            "https://github.com/asadvendor-boop/concordia-dao-council"
        )
        ipfs["image_deployment"] = commits["deployment"]

    with pytest.raises(ReleaseManifestError, match="third-party"):
        release_manifest._runtime_projection(
            repository,
            snapshot.runtime,
            release_manifest._compose_projection(repository, snapshot.compose, ()),
            (),
            integration_commit=commits["integration"],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image_revision", "00" * 20),
        ("image_deployment", None),
        ("image_source", "https://attacker.example/repository"),
    ],
)
def test_runtime_image_oci_identity_binds_exact_reviewed_deployment_commit(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    field: str,
    value: object,
) -> None:
    repository, commits, _, _ = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    snapshot.runtime[0][field] = value
    with pytest.raises(
        ReleaseManifestError,
        match="OCI identity|deployment commit|runtime image deployment",
    ):
        release_manifest._runtime_projection(
            repository,
            snapshot.runtime,
            release_manifest._compose_projection(repository, snapshot.compose, ()),
            (),
            integration_commit=commits["integration"],
        )


def test_known_secret_reflection_and_broad_sensitive_keys_fail_without_echo(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    canary = b"EXACT-CSPR-CLOUD-CANARY-DO-NOT-ECHO"
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    snapshot.public_probes[0]["body"] += canary
    monkeypatch.setattr(release_manifest, "_load_secret_canaries", lambda: (canary,))
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError) as caught:
        capture_release_observations_once(repository)
    assert canary.decode() not in str(caught.value)
    assert "secret" in str(caught.value).lower()

    for key in ("secret", "client_secret", "signing_secret", canary.decode()):
        with pytest.raises(ReleaseManifestError) as key_error:
            release_manifest._assert_safe_projection(
                {"nested": {key: "redacted"}}, (canary,), "projection"
            )
        assert key not in str(key_error.value)


def test_npm_sha256_and_sha512_are_from_same_bounded_tarball_and_must_match_registry(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    capture_release_observations_once(repository)
    receipt = json.loads((repository / RECEIPT_PATHS["npm"]).read_bytes())
    raw = (repository / NPM_CAPTURE_PATH).read_bytes()
    assert receipt["projection"]["tarball_sha256"] == hashlib.sha256(raw).hexdigest()
    assert (
        receipt["projection"]["integrity"]
        == "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
    )
    assert receipt["projection"]["publication_policy"] == (
        "registry_signed_exact_source_reproduction"
    )
    assert receipt["projection"]["source_commit"] == commits["integration"]
    assert receipt["projection"]["publication_commit"] == commits["integration"]
    assert "prepublish_receipt" not in receipt["projection"]

    repository2 = repository.parent / "bad-npm"
    subprocess.run(["cp", "-R", str(repository), str(repository2)], check=True)
    # Remove the first capture in the clone and reset to the pre-capture commit.
    _git(repository2, "reset", "--hard", "HEAD")
    for path in [
        *RECEIPT_PATHS.values(),
        *PROOF_RECEIPT_PATHS.values(),
        NPM_CAPTURE_PATH,
    ]:
        (repository2 / path).unlink(missing_ok=True)
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository2)
    bad.npm["metadata"]["dist"]["integrity"] = (
        "sha512-" + base64.b64encode(b"x" * 64).decode()
    )
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    with pytest.raises(ReleaseManifestError, match="integrity"):
        capture_release_observations_once(repository2)


def test_npm_first_public_release_requires_registry_visible_provenance(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    bad.npm["registry_signatures"]["missing"] = [
        {"keyid": "npm:missing-registry-signature"}
    ]
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="registry signatures"):
        capture_release_observations_once(repository)


def test_rpc_receipt_is_exact_two_operator_projection_and_requires_same_finalized_block(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    capture_release_observations_once(repository)
    receipt = json.loads((repository / RECEIPT_PATHS["rpc"]).read_bytes())
    assert {item["provider_id"] for item in receipt["projection"]["providers"]} == set(
        release_manifest.RPC_PROVIDERS
    )
    assert "headers" not in json.dumps(receipt).lower()
    assert "body" not in json.dumps(receipt).lower()

    repository2 = repository.parent / "bad-rpc"
    subprocess.run(["cp", "-R", str(repository), str(repository2)], check=True)
    for path in [
        *RECEIPT_PATHS.values(),
        *PROOF_RECEIPT_PATHS.values(),
        NPM_CAPTURE_PATH,
    ]:
        (repository2 / path).unlink(missing_ok=True)
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository2)
    bad.rpc[1]["result"] = {**bad.rpc[1]["result"], "block_hash": "ff" * 32}
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    with pytest.raises(ReleaseManifestError, match="same finalized block"):
        capture_release_observations_once(repository2)


def test_public_probe_markers_cannot_replace_structured_proof_predicates(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(
        item for item in bad.public_probes if item["probe_id"] == "proof_registry"
    )
    probe["body"] = b"DAO-PROP-6CB25C verified safepay_v2 exact_envelope_v3"
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="strict JSON|proof registry"):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    ("probe_id", "mutation", "message"),
    [
        ("card_chain", "preimage", "card.*hash|preimage"),
        ("evidence", "inventory", "evidence.*inventory|validated card chain"),
        ("proof_registry", "extra", "registry.*committed"),
        ("trace", "inventory", "trace.*card chain"),
        ("trace", "secret", "sensitive|trace shape"),
    ],
)
def test_public_evidence_registry_and_trace_form_one_recomputed_graph(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    probe_id: str,
    mutation: str,
    message: str,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(item for item in bad.public_probes if item["probe_id"] == probe_id)
    document = json.loads(probe["body"])
    if probe_id == "card_chain":
        preimage = json.loads(document["cards"][0]["canonical_card_json"])
        preimage["signal_id"] = "DAO-PROP-ATTACKER"
        document["cards"][0]["canonical_card_json"] = json.dumps(
            preimage, sort_keys=True, separators=(",", ":")
        )
    elif probe_id == "evidence":
        document["cards"][0]["hash"] = "ff" * 32
    elif probe_id == "proof_registry":
        document["items"].append(dict(document["items"][0]))
    elif mutation == "inventory":
        document["observations"][0]["hash"] = "ff" * 32
    else:
        document["session_token"] = "opaque-attacker-value"
    probe["body"] = _canonical(document)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match=message):
        capture_release_observations_once(repository)


def test_dynamic_public_timestamps_are_narrowly_normalized_but_content_is_stable(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    captured = _snapshot(CAPTURED_AT, commits["integration"], repository)
    rechecked = _snapshot(RECHECKED_AT, commits["integration"], repository)
    collector = FakeCollector([captured, rechecked])
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: collector,
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )
    _capture_and_commit(repository)
    assemble_release_manifest_once(repository)

    receipt = json.loads((repository / RECEIPT_PATHS["public_probes"]).read_bytes())
    by_id = {item["probe_id"]: item for item in receipt["projection"]["probes"]}
    for probe_id, timestamp_field in {
        "card_chain": "captured_at",
        "proof_registry": "generated_at",
        "trace": "generated_at",
    }.items():
        assert by_id[probe_id]["dynamic_timestamps"] == {timestamp_field: CAPTURED_AT}
        assert by_id[probe_id]["body_sha256"] != by_id[probe_id]["stable_body_sha256"]

    repository2 = repository.parent / "dynamic-content-drift"
    subprocess.run(["cp", "-R", str(repository), str(repository2)], check=True)
    (repository2 / RELEASE_MANIFEST_PATH).unlink(missing_ok=True)
    bad_recheck = _snapshot(RECHECKED_AT, commits["integration"], repository2)
    trace = next(
        item for item in bad_recheck.public_probes if item["probe_id"] == "trace"
    )
    document = json.loads(trace["body"])
    document["jaeger_available"] = False
    trace["body"] = _canonical(document)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad_recheck]),
    )
    with pytest.raises(
        ReleaseManifestError,
        match="public trace is not bound to the sanitized card chain",
    ):
        assemble_release_manifest_once(repository2)


@pytest.mark.parametrize("probe_id", ["evidence", "proof_pack", "safepay"])
def test_judge_critical_json_routes_require_artifact_bound_structure(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    probe_id: str,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(item for item in bad.public_probes if item["probe_id"] == probe_id)
    probe["body"] = (
        b'{"proposal_id":"DAO-PROP-6CB25C",'
        b'"status":"verified","no_double_consumption":true}'
    )
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(
        ReleaseManifestError, match=r"evidence|proof[- ]pack|SafePay|artifact"
    ):
        capture_release_observations_once(repository)


def test_official_x402_health_receipt_binds_verified_settlement_artifact(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    capture_release_observations_once(repository)
    receipt = json.loads((repository / RECEIPT_PATHS["public_probes"]).read_bytes())
    health = next(
        item
        for item in receipt["projection"]["probes"]
        if item["probe_id"] == "custom_x402_health"
    )
    expected = ARTIFACT_PATHS["official_x402_settlement_v1"]
    assert health["artifact_bindings"] == [
        {
            "artifact_path": expected,
            "artifact_sha256": hashlib.sha256(
                (repository / expected).read_bytes()
            ).hexdigest(),
        }
    ]


def test_dns_and_tls_projection_rejects_wrong_docs_cname(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(
        item for item in bad.public_probes if item["probe_id"] == "custom_docs_root"
    )
    probe["tls"]["dns"]["cnames"] = ["parkingpage.namecheap.com."]
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="docs CNAME"):
        capture_release_observations_once(repository)


def test_dns_projection_rejects_wrong_fixed_vm_address(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(
        item for item in bad.public_probes if item["probe_id"] == "custom_apex_root"
    )
    probe["tls"]["resolved_ips"] = ["203.0.113.77"]
    probe["tls"]["dns"]["addresses"] = ["203.0.113.77"]
    probe["tls"]["peer_ip"] = "203.0.113.77"
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="fixed deployment target"):
        capture_release_observations_once(repository)


def test_pdf_probe_requires_parseable_certificate_metadata(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(
        item for item in bad.public_probes if item["probe_id"] == "certificate_pdf"
    )
    probe["body"] = (
        b"%PDF-1.7\n"
        b"/Title (Concordia Governance Certificate - DAO-PROP-6CB25C)\n"
        b"Concordia DAO-PROP-6CB25C\n%%EOF\n"
    )
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="PDF.*xref|parseable"):
        capture_release_observations_once(repository)


def test_pdf_string_spoof_cannot_replace_real_parser() -> None:
    prefix = (
        b"%PDF-1.7\n"
        b"/Title (Concordia Governance Certificate - DAO-PROP-6CB25C)\n"
        b"/Author (Concordia DAO Council)\n"
        b"/Count 1\n" + b"X" * 1_100
    )
    offset = len(prefix)
    spoof = (
        prefix
        + b"xref\ntrailer\n<< /Root 1 0 R >>\nstartxref\n"
        + str(offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    headers = {
        "Content-Disposition": (
            'attachment; filename="concordia-governance-certificate-'
            'DAO-PROP-6CB25C.pdf"'
        )
    }

    with pytest.raises(ReleaseManifestError, match="PDF.*parse|parser"):
        release_manifest._pdf_certificate_checks(spoof, headers)


def test_pdf_parser_version_is_exactly_security_reviewed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pypdf

    monkeypatch.setattr(pypdf, "__version__", "6.13.3")
    headers = {
        "Content-Disposition": (
            'attachment; filename="concordia-governance-certificate-'
            'DAO-PROP-6CB25C.pdf"'
        )
    }
    with pytest.raises(ReleaseManifestError, match="parser version"):
        release_manifest._pdf_certificate_checks(_TEST_CERTIFICATE_PDF, headers)


def test_pdf_rejects_nested_annotation_actions() -> None:
    import pypdf
    from pypdf.annotations import Link

    reader = pypdf.PdfReader(io.BytesIO(_TEST_CERTIFICATE_PDF), strict=True)
    writer = pypdf.PdfWriter()
    writer.append_pages_from_reader(reader)
    writer.add_metadata(
        {
            "/Title": "Concordia Governance Certificate - DAO-PROP-6CB25C",
            "/Author": "Concordia DAO Council",
        }
    )
    writer.add_annotation(
        page_number=0,
        annotation=Link(
            rect=(72, 650, 260, 680),
            url="https://attacker.example/collect",
        ),
    )
    active = io.BytesIO()
    writer.write(active)
    headers = {
        "Content-Disposition": (
            'attachment; filename="concordia-governance-certificate-'
            'DAO-PROP-6CB25C.pdf"'
        )
    }

    with pytest.raises(ReleaseManifestError, match="active content"):
        release_manifest._pdf_certificate_checks(active.getvalue(), headers)


def test_png_evidence_is_fully_decoded_and_rejects_blank_images() -> None:
    release_manifest._assert_png_evidence(
        _evidence_png(red=21, green=44, blue=74), "patterned screenshot"
    )
    with pytest.raises(ReleaseManifestError, match="blank|visual"):
        release_manifest._assert_png_evidence(
            _evidence_png(red=21, green=44, blue=74, solid=True),
            "solid screenshot",
        )


def test_png_evidence_rejects_bounded_decompression_overrun_and_trailing_stream() -> (
    None
):
    valid = _evidence_png(red=21, green=44, blue=74)
    ihdr_chunk = valid[8:33]
    idat_length = int.from_bytes(valid[33:37], "big")
    idat = valid[41 : 41 + idat_length]

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFF_FFFF
        return len(data).to_bytes(4, "big") + kind + data + crc.to_bytes(4, "big")

    decoded = zlib.decompress(idat)
    oversized = (
        b"\x89PNG\r\n\x1a\n"
        + ihdr_chunk
        + chunk(b"IDAT", zlib.compress(decoded + b"X" * 2_000_000, level=9))
        + chunk(b"IEND", b"")
    )
    with pytest.raises(ReleaseManifestError, match="decoded length"):
        release_manifest._assert_png_evidence(oversized, "oversized screenshot")

    trailing = (
        b"\x89PNG\r\n\x1a\n"
        + ihdr_chunk
        + chunk(b"IDAT", idat + zlib.compress(b"trailing-stream"))
        + chunk(b"IEND", b"")
    )
    with pytest.raises(ReleaseManifestError, match="decoded length"):
        release_manifest._assert_png_evidence(trailing, "trailing screenshot")


def test_png_evidence_rejects_unmodelled_palette_transparency() -> None:
    valid = _evidence_png(red=21, green=44, blue=74)

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFF_FFFF
        return len(data).to_bytes(4, "big") + kind + data + crc.to_bytes(4, "big")

    with_transparency = valid[:33] + chunk(b"tRNS", b"\x00") + valid[33:]
    with pytest.raises(ReleaseManifestError, match="transparency"):
        release_manifest._assert_png_evidence(
            with_transparency, "transparent screenshot"
        )


def test_provider_openapi_probe_requires_post_only_v2_contract(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(
        item for item in bad.public_probes if item["probe_id"] == "provider_openapi"
    )
    document = json.loads(probe["body"])
    operation = document["paths"]["/x402/v2/redemptions"].pop("post")
    document["paths"]["/x402/v2/redemptions"]["get"] = operation
    probe["body"] = _canonical(document)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="OpenAPI.*POST-only"):
        capture_release_observations_once(repository)


def test_provider_openapi_markers_must_be_bound_to_resolved_request_schemas() -> None:
    spoof = {
        "openapi": "3.1.0",
        "info": {"title": "Concordia Risk Oracle Provider", "version": "2.0.0"},
        "paths": {
            "/x402/v2/quotes": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"type": "string"}}},
                    },
                    "responses": {"402": {"description": "Payment required"}},
                }
            },
            "/x402/v2/redemptions": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"type": "string"}}},
                    },
                    "responses": {"200": {"description": "Fulfilled"}},
                }
            },
        },
        "unrelated_markers": [
            "safepay-quote-request-v2",
            "safepay-redemption-v2",
            "proposal_id",
            "resource_id",
            "payment_hash",
        ],
    }

    with pytest.raises(ReleaseManifestError, match="OpenAPI.*schema"):
        release_manifest._provider_openapi_checks(_canonical(spoof))


def test_official_x402_public_health_requires_live_hosted_settlement_state(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    bad = _snapshot(CAPTURED_AT, commits["integration"], repository)
    probe = next(
        item for item in bad.public_probes if item["probe_id"] == "custom_x402_health"
    )
    probe["body"] = _canonical(
        {"status": "ok", "settlement_state": "blocked_fail_closed"}
    )
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([bad]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="official x402 health"):
        capture_release_observations_once(repository)


def test_caddy_nested_subroutes_preserve_host_path_and_enforcement(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    routes = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"]
    approval = routes[0]
    approval["match"][0].pop("path")
    approval["handle"] = [
        {
            "handler": "subroute",
            "routes": [
                {
                    "match": [{"path": ["/approve*"]}],
                    "handle": _caddy_raw()["active_config"]["apps"]["http"]["servers"][
                        "shared"
                    ]["routes"][0]["handle"],
                }
            ],
        }
    ]
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    capture_release_observations_once(repository)
    receipt = json.loads((repository / RECEIPT_PATHS["caddy"]).read_bytes())
    nested = next(
        route
        for route in receipt["projection"]["routes"]
        if "/approve*" in route["paths"]
    )
    assert nested["hosts"] == [
        "concordia.47.84.232.193.sslip.io",
        "concordiadao.xyz",
    ]
    assert {handler["handler"] for handler in nested["handlers"]} == {
        "authentication",
        "headers",
        "reverse_proxy",
    }


def test_caddy_accepts_two_exact_protected_approval_hosts(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    routes = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"]
    combined = routes[0]
    sslip = json.loads(json.dumps(combined))
    sslip["match"][0]["host"] = ["concordia.47.84.232.193.sslip.io"]
    apex = json.loads(json.dumps(combined))
    apex["match"][0]["host"] = ["concordiadao.xyz"]
    routes[0:1] = [sslip, apex]
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    capture_release_observations_once(repository)
    receipt = json.loads((repository / RECEIPT_PATHS["caddy"]).read_bytes())
    approvals = [
        route
        for route in receipt["projection"]["routes"]
        if route["paths"] == ["/approve*"]
    ]
    assert len(approvals) == 2
    assert {tuple(route["hosts"]) for route in approvals} == {
        ("concordia.47.84.232.193.sslip.io",),
        ("concordiadao.xyz",),
    }


def test_caddy_does_not_flatten_unsafe_match_alternatives(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    approval = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"][0]
    approval["match"] = [
        {"host": ["concordia.47.84.232.193.sslip.io"]},
        {"host": ["concordiadao.xyz"], "path": ["/approve*"]},
    ]
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="matcher"):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("unexpected_host", "unexpected host|coverage"),
        ("wrong_upstream", "gateway proxy"),
        ("proxy_first", "handler order|authentication"),
        ("extra_provider", "http_basic|provider"),
    ],
)
def test_caddy_rejects_unapproved_approval_topology(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    approval = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"][0]
    if mutation == "unexpected_host":
        approval["match"][0]["host"].append("evil.example")
    elif mutation == "wrong_upstream":
        approval["handle"][2]["upstreams"] = [{"dial": "attacker:8000"}]
    elif mutation == "proxy_first":
        approval["handle"] = [
            approval["handle"][2],
            approval["handle"][0],
            approval["handle"][1],
        ]
    else:
        approval["handle"][0]["providers"]["bearer"] = {"token": "ignored"}
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match=message):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("username", "authentication"),
        ("password", "authentication"),
        ("proxy", "X-Proxy"),
    ],
)
def test_caddy_rejects_active_material_that_differs_from_secret_files(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    message: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    approval = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"][0]
    secret_value = "MUTATED-MATERIAL-MUST-NEVER-APPEAR"
    if field in {"username", "password"}:
        approval["handle"][0]["providers"]["http_basic"]["accounts"][0][field] = (
            secret_value
        )
    else:
        approval["handle"][1]["request"]["set"]["X-Proxy-Secret"] = [secret_value]
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match=message) as caught:
        capture_release_observations_once(repository)
    assert secret_value not in str(caught.value)


def test_caddy_password_is_bound_without_fast_hashing_active_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caddy = _caddy_raw()
    test_cohost_route = {
        "hosts": [_TEST_COHOST_HOST],
        "paths": ["/mcp"],
        "matchers": [
            {
                "hosts": [_TEST_COHOST_HOST],
                "paths": ["/mcp"],
                "methods": [],
                "unknown_keys": [],
            }
        ],
        "handlers": [
            {
                "handler": "reverse_proxy",
                "upstreams": [_TEST_COHOST_UPSTREAM],
            }
        ],
    }
    monkeypatch.setattr(
        release_manifest,
        "_SHARED_COHOST_MCP_ROUTE_SHA256",
        hashlib.sha256(
            release_manifest._canonical_json(test_cohost_route)
        ).hexdigest(),
    )
    original = release_manifest._observation_text_sha256
    labels: list[str] = []

    def recording_hash(value, label, *, required=True):
        labels.append(label)
        return original(value, label, required=required)

    monkeypatch.setattr(
        release_manifest,
        "_observation_text_sha256",
        recording_hash,
    )

    projection = release_manifest._caddy_projection(caddy, ())

    assert projection["approval_material"]["bcrypt_secret_file_match"] is True
    assert "bcrypt_sha256" not in projection["approval_material"]
    assert "Caddy basic-auth hash" not in labels


@pytest.mark.parametrize("mutation", ["method", "unknown", "nonterminal"])
def test_caddy_rejects_matcher_drift_and_nonterminal_approval(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    approval = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"][0]
    if mutation == "method":
        approval["match"][0]["method"] = ["GET"]
    elif mutation == "unknown":
        approval["match"][0]["header"] = {"X-Unsafe": ["yes"]}
    else:
        approval["terminal"] = False
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="matcher|terminal"):
        capture_release_observations_once(repository)


def test_caddy_rejects_preceding_route_that_can_bypass_approval(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    routes = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"]
    routes.insert(
        0,
        {
            "match": [{"host": ["concordiadao.xyz"]}],
            "handle": [
                {
                    "handler": "reverse_proxy",
                    "upstreams": [{"dial": "gateway:8000"}],
                }
            ],
        },
    )
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="earlier.*bypass"):
        capture_release_observations_once(repository)


@pytest.mark.parametrize(
    ("probe_group", "mutation"),
    [
        ("unauthenticated_probes", "missing"),
        ("unauthenticated_probes", "status"),
        ("authenticated_probes", "missing"),
        ("authenticated_probes", "status"),
    ],
)
def test_caddy_rejects_missing_or_failed_live_auth_probe(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    probe_group: str,
    mutation: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    if mutation == "missing":
        caddy[probe_group].pop()
    else:
        caddy[probe_group][0]["status"] = 403
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="Caddy.*probes differ"):
        capture_release_observations_once(repository)


@pytest.mark.parametrize("mutation", ["path", "host", "upstream"])
def test_caddy_requires_exact_cohost_mcp_binding(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, commits, _, verifier = release_repository
    snapshot = _snapshot(CAPTURED_AT, commits["integration"], repository)
    caddy = _caddy_raw()
    route = caddy["active_config"]["apps"]["http"]["servers"]["shared"]["routes"][1]
    if mutation == "path":
        route["match"][0]["path"] = ["/mcpevil"]
    elif mutation == "host":
        route["match"][0]["host"] = ["attacker.example"]
    else:
        route["handle"][0]["upstreams"] = [{"dial": "attacker:8000"}]
    snapshot = replace(snapshot, caddy=caddy)
    monkeypatch.setattr(
        release_manifest,
        "_collector_factory",
        lambda root: FakeCollector([snapshot]),
    )
    monkeypatch.setattr(
        release_manifest, "_proof_verifier_factory", lambda root: verifier
    )

    with pytest.raises(ReleaseManifestError, match="cohost|mcp"):
        capture_release_observations_once(repository)


def test_caddy_file_placeholders_require_restricted_byte_exact_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = tuple(tmp_path / name for name in ("user", "bcrypt", "proxy"))
    values = (
        b"judge",
        b"$2b$12$abcdefghijklmnopqrstuumjShLAz1hg5xNkjnYdEhDjbg3Hc48be",
        b"exact-proxy-value-at-least-thirty-two-bytes",
    )
    for path, value in zip(paths, values, strict=True):
        path.write_bytes(value)
        path.chmod(0o600)
    monkeypatch.setattr(release_manifest, "_APPROVAL_CADDY_SECRET_PATHS", paths)
    release_manifest._validate_approval_caddy_secret_files()

    paths[0].write_bytes(b"judge\n")
    with pytest.raises(ReleaseManifestError, match="byte-exact"):
        release_manifest._validate_approval_caddy_secret_files()
    paths[0].write_bytes(values[0])
    paths[1].chmod(0o644)
    with pytest.raises(ReleaseManifestError, match="restricted"):
        release_manifest._validate_approval_caddy_secret_files()


def test_caddy_probe_password_is_one_use_restricted_and_no_follow(
    tmp_path: Path,
) -> None:
    path = tmp_path / "approval-password"
    path.write_bytes(b"correct-horse-battery-staple")
    path.chmod(0o600)

    assert release_manifest._consume_approval_probe_password(path) == (
        b"correct-horse-battery-staple"
    )
    assert not path.exists()

    target = tmp_path / "target"
    target.write_bytes(b"must-not-be-read")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(ReleaseManifestError, match="unavailable or unsafe"):
        release_manifest._consume_approval_probe_password(path)


def test_caddy_live_probe_uses_human_password_without_persisting_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = b"correct-horse-battery-staple"
    bcrypt_hash = b"$2b$12$abcdefghijklmnopqrstuumjShLAz1hg5xNkjnYdEhDjbg3Hc48be"
    calls: list[dict[str, object]] = []

    def fake_request(**kwargs):
        calls.append(kwargs)
        headers = kwargs.get("headers") or {}
        if "Authorization" in headers:
            assert headers["Authorization"].startswith("Basic ")
            assert headers["X-Proxy-Secret"] == ("CONCORDIA-RELEASE-PROBE-INVALID")
            return 200, {}, b"authenticated approval page"
        return 401, {"WWW-Authenticate": 'Basic realm="Concordia"'}, b""

    monkeypatch.setattr(release_manifest, "_fixed_https_json", fake_request)
    unauthenticated, authenticated = release_manifest._collect_approval_caddy_probes(
        username=b"judge",
        password=password,
        bcrypt_hash=bcrypt_hash,
    )

    assert unauthenticated == _caddy_raw()["unauthenticated_probes"]
    assert authenticated == _caddy_raw()["authenticated_probes"]
    serialized = json.dumps(
        {
            "unauthenticated": unauthenticated,
            "authenticated": authenticated,
        },
        sort_keys=True,
    )
    assert password.decode() not in serialized
    assert bcrypt_hash.decode() not in serialized
    assert len(calls) == 8


def test_caddy_live_probe_rejects_wrong_human_password_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        release_manifest,
        "_fixed_https_json",
        lambda **kwargs: pytest.fail("network must not be reached"),
    )
    with pytest.raises(ReleaseManifestError, match="credential verification failed"):
        release_manifest._collect_approval_caddy_probes(
            username=b"judge",
            password=b"wrong-password",
            bcrypt_hash=(
                b"$2b$12$abcdefghijklmnopqrstuumjShLAz1hg5xNkjnYdEhDjbg3Hc48be"
            ),
        )


def test_caddy_collector_combines_admin_config_material_and_live_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = _caddy_raw()

    class Response:
        status = 200

        def read(self, limit: int) -> bytes:
            return json.dumps(expected["active_config"]).encode()

    class Connection:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def request(self, method: str, path: str) -> None:
            assert (method, path) == ("GET", "/config/")

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            pass

    username = b"judge"
    bcrypt_hash = b"$2b$12$abcdefghijklmnopqrstuumjShLAz1hg5xNkjnYdEhDjbg3Hc48be"
    proxy = b"DO-NOT-PERSIST-PROXY-SECRET-32-BYTES"
    monkeypatch.setattr(release_manifest.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(
        release_manifest,
        "_validate_approval_caddy_secret_files",
        lambda: (username, bcrypt_hash, proxy),
    )
    monkeypatch.setattr(
        release_manifest,
        "_consume_approval_probe_password",
        lambda path: b"correct-horse-battery-staple",
    )
    monkeypatch.setattr(
        release_manifest,
        "_collect_approval_caddy_probes",
        lambda **kwargs: (
            expected["unauthenticated_probes"],
            expected["authenticated_probes"],
        ),
    )

    result = release_manifest._DefaultCollector(tmp_path)._caddy()

    assert result == expected


def test_default_collector_consumes_one_use_caddy_password_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = release_manifest._DefaultCollector(tmp_path)
    calls: list[str] = []

    def observed(name: str, value):
        def collect(*args):
            calls.append(name)
            return value

        return collect

    monkeypatch.setattr(collector, "_compose", observed("compose", {}))
    monkeypatch.setattr(collector, "_runtime", observed("runtime", []))
    monkeypatch.setattr(collector, "_public_probes", observed("public", []))
    monkeypatch.setattr(collector, "_pages", observed("pages", {}))
    monkeypatch.setattr(collector, "_npm", observed("npm", {}))
    monkeypatch.setattr(
        collector,
        "_rpc",
        observed("rpc", [{"provider_id": "test-provider"}]),
    )
    monkeypatch.setattr(collector, "_caddy", observed("caddy", {}))
    monkeypatch.setattr(
        release_manifest,
        "_utc_now",
        observed(
            "clock",
            datetime(2026, 7, 23, 0, 10, 30, tzinfo=UTC),
        ),
    )

    snapshot = collector.collect()

    assert calls == [
        "compose",
        "runtime",
        "public",
        "pages",
        "npm",
        "rpc",
        "caddy",
        "clock",
    ]
    assert snapshot.observed_at == "2026-07-23T00:10:30Z"
    assert snapshot.rpc == [
        {
            "provider_id": "test-provider",
            "observed_at": snapshot.observed_at,
        }
    ]


def test_cspr_cloud_rpc_uses_raw_authorization_and_never_reflects_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = b"CSPR-CLOUD-EXACT-TOKEN-NEVER-ECHO"
    captured_headers: dict[str, str] = {}

    def reflected_failure(**kwargs):
        captured_headers.update(kwargs["headers"])
        return 401, {}, b'{"error":"' + token + b'"}'

    monkeypatch.setattr(release_manifest, "_fixed_https_json", reflected_failure)
    with pytest.raises(ReleaseManifestError) as caught:
        release_manifest._rpc_call(
            "https://node.testnet.cspr.cloud/rpc",
            b'{"jsonrpc":"2.0"}',
            authorization=token,
        )
    assert captured_headers["Authorization"] == token.decode("ascii")
    assert not captured_headers["Authorization"].startswith("Bearer ")
    assert token.decode("ascii") not in str(caught.value)


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1}},
        {"jsonrpc": "2.0", "id": 2, "result": {}},
        {"jsonrpc": "1.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 1, "result": {}, "extra": True},
    ],
)
def test_rpc_call_requires_exact_success_envelope(
    monkeypatch: pytest.MonkeyPatch, response: dict[str, object]
) -> None:
    monkeypatch.setattr(
        release_manifest,
        "_fixed_https_json",
        lambda **kwargs: (200, {}, _canonical(response)),
    )

    with pytest.raises(ReleaseManifestError, match="RPC.*envelope"):
        release_manifest._rpc_call(
            "https://node.testnet.casper.network/rpc",
            b'{"jsonrpc":"2.0","id":1}',
            authorization=None,
        )


def test_npm_collector_rejects_nonregistry_tarball_before_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def fake_request(**kwargs):
        calls.append(kwargs["url"])
        return (
            200,
            {},
            _canonical(
                {
                    "name": "@concordia-dao/verify",
                    "version": "0.1.0",
                    "gitHead": "ab" * 20,
                    "dist": {
                        "tarball": "https://attacker.invalid/steal.tgz",
                        "integrity": "sha512-invalid",
                    },
                }
            ),
        )

    monkeypatch.setattr(release_manifest, "_fixed_https_json", fake_request)
    collector = release_manifest._DefaultCollector(tmp_path)
    with pytest.raises(ReleaseManifestError, match="outside the fixed registry"):
        collector._npm()
    assert calls == ["https://registry.npmjs.org/@concordia-dao%2Fverify/latest"]


@pytest.mark.parametrize("extra_installed_file", [False, True])
def test_npm_tarball_is_installed_and_executed_from_an_exact_clean_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_installed_file: bool,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    package_document = {
        "name": "@concordia-dao/verify",
        "version": "0.1.0",
        "type": "module",
        "bin": {"concordia-verify": "dist/cli.js"},
        "scripts": {
            "build": "node build.mjs",
            "clean": "node clean.mjs",
            "prepack": "npm run clean && npm run build",
        },
    }
    package_files = {
        "package.json": _canonical(package_document),
        "dist/cli.js": b'#!/usr/bin/env node\nconsole.log("verified")\n',
        "README.md": b"# verifier\n",
        "LICENSE": b"MIT\n",
    }
    for relative, body in {
        **package_files,
        "package-lock.json": b"{}\n",
        "build.mjs": b"",
        "clean.mjs": b"",
    }.items():
        _write_bytes(repository, f"packages/verify/{relative}", body)
    release_commit = _commit(repository, "verifier package source")

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for relative, body in package_files.items():
            member = tarfile.TarInfo(f"package/{relative}")
            member.size = len(body)
            member.mode = 0o755 if relative == "dist/cli.js" else 0o644
            archive.addfile(member, io.BytesIO(body))
    calls: list[tuple[Path, list[str]]] = []
    proof_data = tmp_path / "proof-data"
    proof_data.mkdir()
    replay_registry = proof_data / "registry.json"
    replay_registry.write_bytes(
        _canonical(
            {
                "schema_version": 1,
                "generated_at": CAPTURED_AT,
                "proposal_id": "DAO-PROP-6CB25C",
                "items": [],
            }
        )
    )

    class FakeBundle:
        registry_path = replay_registry

        def revalidate(self) -> None:
            assert replay_registry.is_file()

        def cleanup(self) -> None:
            pass

    monkeypatch.setattr(
        release_manifest,
        "_materialize_local_verifier_bundle",
        lambda repository_root, *, generated_at: FakeBundle(),
    )

    def fake_run(root: Path, arguments, **kwargs):
        arguments = list(arguments)
        if arguments[0] == "git":
            return subprocess.run(
                arguments,
                cwd=root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        calls.append((root, arguments))
        if arguments[:2] == ["npm", "pack"]:
            filename = "concordia-dao-verify-0.1.0.tgz"
            (root / filename).write_bytes(buffer.getvalue())
            stdout = _canonical([{"filename": filename}])
        elif arguments[0] == "npm" and root.name == "consumer":
            consumer = json.loads((root / "package.json").read_bytes())
            assert consumer["dependencies"] == {
                "@concordia-dao/verify": "file:../concordia-dao-verify.tgz"
            }
            installed = root / "node_modules" / "@concordia-dao" / "verify"
            shutil.copytree(root.parent / "package", installed)
            if extra_installed_file:
                (installed / "UNBOUND.js").write_text("export default false;\n")
            stdout = b""
        elif arguments[0] == "npm":
            assert root.name == "verify"
            stdout = b""
        else:
            assert arguments[0] == "node"
            assert Path(arguments[1]).is_relative_to(root / "node_modules")
            assert arguments[2] == "local"
            stdout = _canonical(
                {
                    "tool": "@concordia-dao/verify",
                    "status": "verified",
                    "valid": True,
                    "exitCode": 0,
                }
            )
        return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(release_manifest, "_run", fake_run)
    monkeypatch.setattr(
        release_manifest,
        "_utc_now",
        lambda: datetime(2026, 7, 23, 0, 10, 30, tzinfo=UTC),
    )
    if extra_installed_file:
        with pytest.raises(ReleaseManifestError, match="inventory"):
            release_manifest._inspect_npm_tarball(
                buffer.getvalue(),
                repository,
                source_commit=release_commit,
            )
        return

    projection = release_manifest._inspect_npm_tarball(
        buffer.getvalue(),
        repository,
        source_commit=release_commit,
    )

    assert projection["name"] == "@concordia-dao/verify"
    assert projection["sourceCommit"] == release_commit
    assert len(projection["consumer_install_sha256"]) == 64
    assert [call[1][0] for call in calls] == [
        "npm",
        "npm",
        "npm",
        "npm",
        "npm",
        "node",
    ]
    assert all(call[0].name == "verify" for call in calls[:4])
    assert calls[4][0] == calls[5][0]
    assert calls[4][0].name == "consumer"


def test_pages_collector_derives_success_from_deployment_status_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    sha = "ab" * 20

    def fake_github(root: Path, endpoint: str):
        assert root == tmp_path
        seen.append(endpoint)
        if endpoint.endswith("/pages"):
            value: object = {
                "build_type": "workflow",
                "cname": "docs.concordiadao.xyz",
                "html_url": "https://docs.concordiadao.xyz/",
                "https_enforced": True,
            }
        elif "workflows/docs-pages.yml/runs" in endpoint:
            value = {
                "workflow_runs": [
                    {
                        "id": 77,
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": sha,
                    }
                ]
            }
        elif endpoint.endswith("deployments?environment=github-pages&per_page=1"):
            value = [{"id": 88, "environment": "github-pages", "sha": sha}]
        elif endpoint.endswith("/deployments/88/statuses?per_page=1"):
            value = [{"state": "success"}]
        else:  # pragma: no cover - makes an unexpected endpoint loud
            raise AssertionError(endpoint)
        return value

    def fake_request(**kwargs):
        assert kwargs["url"] == "https://docs.concordiadao.xyz/release-identity.json"
        return 200, {}, _canonical({"GITHUB_SHA": sha, "run_id": 77})

    monkeypatch.setattr(release_manifest, "_fixed_github_api", fake_github)
    monkeypatch.setattr(release_manifest, "_fixed_https_json", fake_request)
    result = release_manifest._DefaultCollector(tmp_path)._pages()
    assert result["deployment"]["status"] == "success"
    assert any("/deployments/88/statuses" in endpoint for endpoint in seen)


def test_github_api_collector_delegates_auth_to_gh_without_token_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(root: Path, arguments, **kwargs):
        assert root == tmp_path
        calls.append(list(arguments))
        return subprocess.CompletedProcess(
            list(arguments), 0, stdout=b'{"build_type":"workflow"}', stderr=b""
        )

    monkeypatch.setattr(release_manifest, "_run", fake_run)
    result = release_manifest._fixed_github_api(
        tmp_path, "/repos/asadvendor-boop/concordia-dao-council/pages"
    )

    assert result == {"build_type": "workflow"}
    assert calls == [
        [
            "gh",
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "/repos/asadvendor-boop/concordia-dao-council/pages",
        ]
    ]
    assert all(
        not any(
            secret_word in argument.lower()
            for secret_word in ("token", "authorization")
        )
        for argument in calls[0]
    )


def test_external_commands_use_bound_tools_and_sanitized_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv("CONCORDIA_TEST_SECRET_SHOULD_NOT_INHERIT", "LEAKME")
    authority = release_manifest.HostToolchainAuthority(
        repository_root=tmp_path,
        source_commit="ab" * 20,
        receipt_raw=b"{}\n",
    )
    monkeypatch.setattr(
        release_manifest,
        "_host_toolchain_binding",
        lambda root: (authority, object(), {}),
    )

    def fake_bound_command(**kwargs):
        observed.update(kwargs)
        return release_manifest.BoundCommandResult(
            returncode=0,
            stdout=b"",
            stderr=b"",
            tool_identity={"tool_id": kwargs["tool_id"]},
        )

    monkeypatch.setattr(release_manifest, "run_bound_command", fake_bound_command)
    release_manifest._run(tmp_path, ["node", "--version"])

    arguments = observed["argv"]
    environment = observed["env"]
    assert arguments == ("node", "--version")
    assert observed["tool_id"] == "node"
    assert observed["accepted_authority"] is authority
    assert "CONCORDIA_TEST_SECRET_SHOULD_NOT_INHERIT" not in environment
    assert "LEAKME" not in json.dumps(environment)


def test_npm_commands_ignore_caller_home_and_hostile_npmrc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile_home = tmp_path / "hostile-home"
    hostile_home.mkdir()
    hostile_npmrc = hostile_home / ".npmrc"
    hostile_npmrc.write_text(
        "registry=https://attacker.invalid/\n"
        "script-shell=/tmp/attacker-shell\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", hostile_home.as_posix())
    monkeypatch.setenv("NPM_CONFIG_USERCONFIG", hostile_npmrc.as_posix())
    monkeypatch.setenv("DOCKER_CONFIG", hostile_home.as_posix())
    authority = release_manifest.HostToolchainAuthority(
        repository_root=tmp_path,
        source_commit="ab" * 20,
        receipt_raw=b"{}\n",
    )
    monkeypatch.setattr(
        release_manifest,
        "_host_toolchain_binding",
        lambda root: (authority, object(), {}),
    )
    observed: dict[str, str] = {}

    def fake_bound_command(**kwargs):
        environment = dict(kwargs["env"])
        observed.update(environment)
        npmrc = Path(environment["NPM_CONFIG_USERCONFIG"])
        assert npmrc.read_text(encoding="utf-8") == (
            "registry=https://registry.npmjs.org/\n"
            "ignore-scripts=true\n"
            "audit=false\n"
            "fund=false\n"
            "update-notifier=false\n"
        )
        assert Path(environment["HOME"]).parent == npmrc.parent
        assert Path(environment["NPM_CONFIG_CACHE"]).parent == npmrc.parent
        return release_manifest.BoundCommandResult(
            returncode=0,
            stdout=b"11.0.0\n",
            stderr=b"",
            tool_identity={"tool_id": "npm"},
        )

    monkeypatch.setattr(release_manifest, "run_bound_command", fake_bound_command)
    release_manifest._run(tmp_path, ["npm", "--version"])

    assert observed["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"
    assert hostile_home.as_posix() not in json.dumps(observed)
    assert "DOCKER_CONFIG" not in observed
    assert not Path(observed["NPM_CONFIG_USERCONFIG"]).exists()


def test_host_toolchain_candidate_is_canonical_one_time_and_untrusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    _write_bytes(
        repository,
        "scripts/build_release_manifest.py",
        b"#!/usr/bin/env python3\n",
    )
    source_commit = _commit(repository, "release runner source")

    def fast_bound_command(**kwargs):
        assert kwargs["tool_id"] == "git"
        completed = subprocess.run(
            ["/usr/bin/git", *tuple(kwargs["argv"])[1:]],
            cwd=kwargs["cwd"],
            env=dict(kwargs["env"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if kwargs["check"] and completed.returncode:
            raise release_manifest.BoundCommandError("fixture Git failed")
        return release_manifest.BoundCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            tool_identity={"tool_id": "git"},
        )

    monkeypatch.setattr(release_manifest, "run_bound_command", fast_bound_command)
    monkeypatch.setattr(release_manifest, "_load_secret_canaries", lambda: ())
    monkeypatch.setattr(
        release_manifest,
        "build_host_toolchain_receipt_candidate",
        lambda *, repository_root, source_commit: {
            "schema_version": (
                release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION
            ),
            "source_commit": source_commit,
            "runner_sha256": "11" * 32,
            "host_id": "22" * 32,
            "tools": {},
        },
    )

    path = release_manifest.prepare_host_toolchain_receipt_once(repository)
    document = json.loads(path.read_bytes())

    assert path.relative_to(repository).as_posix() == (
        release_manifest.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH
    )
    assert path.read_bytes() == _canonical(document)
    assert document["source_commit"] == source_commit
    assert _git(repository, "status", "--porcelain").strip()
    with pytest.raises(ReleaseManifestError):
        release_manifest.prepare_host_toolchain_receipt_once(repository)


def test_assemble_reobserves_mutable_surfaces_and_rejects_runtime_drift_or_stale_capture(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, collector, _ = release_repository
    _capture_and_commit(repository)
    collector.snapshots[1].runtime[0]["restart_count"] = 1

    with pytest.raises(ReleaseManifestError, match="restart|runtime.*drift"):
        assemble_release_manifest_once(repository)

    collector.calls = 1
    collector.snapshots[1].runtime[0]["restart_count"] = 0
    release_manifest._utc_now = lambda: datetime(2026, 7, 23, 1, 0, tzinfo=UTC)
    with pytest.raises(ReleaseManifestError, match="stale|15 minutes"):
        assemble_release_manifest_once(repository)


def test_assemble_reruns_every_static_verifier_and_rejects_forged_receipt_or_empty_evidence(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, collector, verifier = release_repository
    capture_release_observations_once(repository)
    assert len(verifier.calls) == len(ARTIFACT_PATHS)

    target = repository / PROOF_RECEIPT_PATHS["safepay_v2"]
    document = json.loads(target.read_bytes())
    document["projection"]["derived_identity"]["identity_sha256"] = "00" * 32
    _write(repository, PROOF_RECEIPT_PATHS["safepay_v2"], document)
    _commit(repository, "commit forged proof receipt as first-add release data")
    with pytest.raises(ReleaseManifestError, match="verifier receipt|derived"):
        assemble_release_manifest_once(repository)
    assert len(verifier.calls) > len(ARTIFACT_PATHS)

    # A post-gate artifact rewrite must fail before a forged artifact boolean or
    # a stale proof receipt can influence assembly.  Capture-time tests exercise
    # the direct verifier; assembly additionally closes the integration tree.
    collector.calls = 1
    empty = json.loads((repository / ARTIFACT_PATHS["safepay_v2"]).read_bytes())
    empty["quote"] = {}
    _write(repository, ARTIFACT_PATHS["safepay_v2"], empty)
    _commit(repository, "empty proof evidence")
    with pytest.raises(
        ReleaseManifestError,
        match="current release code differs from the command-gated integration commit",
    ):
        assemble_release_manifest_once(repository)


def test_proof_receipt_time_must_equal_fresh_observation_capture(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    capture_release_observations_once(repository)
    path = repository / PROOF_RECEIPT_PATHS["safepay_v2"]
    document = json.loads(path.read_bytes())
    document["observed_at"] = "2026-07-22T00:00:00Z"
    document["projection_sha256"] = hashlib.sha256(
        _canonical(document["projection"])
    ).hexdigest()
    path.write_bytes(_canonical(document))
    _commit(repository, "commit stale proof time as first-add release data")

    with pytest.raises(ReleaseManifestError, match="proof.*observation|observed_at"):
        assemble_release_manifest_once(repository)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("captured_at", "2026-07-23T00:09:59Z"),
        ("source_commit", "ab" * 20),
        ("deployment_commit", "cd" * 20),
        ("observation_mode", "snapshot"),
    ],
)
def test_registry_item_metadata_and_mode_must_exactly_match_verified_artifact(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    field: str,
    value: str,
) -> None:
    repository, commits, collector, _ = release_repository
    registry_path = repository / ARTIFACT_PATHS["proof_registry_v1"]
    registry = json.loads(registry_path.read_bytes())
    safepay = next(
        item for item in registry["public_items"] if item["proof_type"] == "safepay_v2"
    )
    safepay[field] = value
    _write(repository, ARTIFACT_PATHS["proof_registry_v1"], registry)
    _commit(repository, "drift registry metadata")
    collector.snapshots = [
        _snapshot(CAPTURED_AT, commits["artifacts"], repository),
    ]

    with pytest.raises(
        ReleaseManifestError,
        match="registry.*metadata|observation mode|input artifacts.*digest",
    ):
        capture_release_observations_once(repository)


def test_ordered_commit_ancestry_is_source_to_deployment_to_artifact_to_release_head(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, commits, collector, _ = release_repository
    safepay_path = repository / ARTIFACT_PATHS["safepay_v2"]
    safepay = json.loads(safepay_path.read_bytes())
    safepay["source_commit"], safepay["deployment_commit"] = (
        safepay["deployment_commit"],
        safepay["source_commit"],
    )
    _write(repository, ARTIFACT_PATHS["safepay_v2"], safepay)
    registry_path = repository / ARTIFACT_PATHS["proof_registry_v1"]
    registry = json.loads(registry_path.read_bytes())
    item = next(
        item for item in registry["public_items"] if item["proof_type"] == "safepay_v2"
    )
    item["source_commit"] = safepay["source_commit"]
    item["deployment_commit"] = safepay["deployment_commit"]
    item["artifact_sha256"] = hashlib.sha256(_canonical(safepay)).hexdigest()
    _write(repository, ARTIFACT_PATHS["proof_registry_v1"], registry)
    _commit(repository, "reverse source deployment chain")
    collector.snapshots = [
        _snapshot(CAPTURED_AT, commits["artifacts"], repository),
    ]

    with pytest.raises(
        ReleaseManifestError,
        match="source.*deployment.*ancestor|input artifacts.*digest",
    ):
        capture_release_observations_once(repository)


def test_historical_snapshot_has_narrow_explicit_lineage_exception_only(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _, _ = release_repository
    calls: list[str] = []
    original = release_manifest._require_ordered_ancestry

    def recording(
        root: Path,
        *,
        source_commit: str,
        deployment_commit: str,
        artifact_commit: str,
        historical_exception: bool,
    ) -> None:
        if historical_exception:
            calls.append("historical")
        original(
            root,
            source_commit=source_commit,
            deployment_commit=deployment_commit,
            artifact_commit=artifact_commit,
            historical_exception=historical_exception,
        )

    monkeypatch.setattr(release_manifest, "_require_ordered_ancestry", recording)
    capture_release_observations_once(repository)
    assert calls == ["historical"]


def test_arbitrary_payload_writer_is_not_public_and_assemble_write_is_create_once_atomic(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _, _ = release_repository
    _capture_and_commit(repository)
    assert not hasattr(release_manifest, "write_release_manifest_once")
    assert not hasattr(release_manifest, "build_release_manifest")

    fsynced_directory = False
    original_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        nonlocal fsynced_directory
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            fsynced_directory = True
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    target = assemble_release_manifest_once(repository)
    assert target == repository / RELEASE_MANIFEST_PATH
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert fsynced_directory is True
    with pytest.raises(ReleaseManifestError, match="already exists"):
        assemble_release_manifest_once(repository)


def test_secure_repository_input_opens_use_nonblock_and_cloexec(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _, _ = release_repository
    flags_seen: list[int] = []
    original_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        flags_seen.append(flags)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    release_manifest._read_bounded_repository_file(
        repository, ARTIFACT_PATHS["safepay_v2"], 2 * 1024 * 1024
    )
    assert flags_seen
    assert all(flags & os.O_NONBLOCK for flags in flags_seen)
    assert all(flags & os.O_CLOEXEC for flags in flags_seen)


def test_release_output_never_follows_ancestor_symlink(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    (repository / "release").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReleaseManifestError, match="unsafe|symlink|already exists"):
        release_manifest._atomic_create_once(
            repository, "release/receipts/probe.json", b"{}\n"
        )
    assert not (outside / "receipts/probe.json").exists()


def test_capture_batch_failure_publishes_no_partial_fixed_receipts(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _, _ = release_repository
    original_write = os.write
    writes = 0

    def fail_after_first_file(descriptor: int, value) -> int:
        nonlocal writes
        writes += 1
        if writes > 1:
            raise OSError("injected batch write failure")
        return original_write(descriptor, value)

    monkeypatch.setattr(os, "write", fail_after_first_file)
    with pytest.raises((ReleaseManifestError, OSError)):
        capture_release_observations_once(repository)
    assert not any((repository / path).exists() for path in RECEIPT_PATHS.values())
    assert not any(
        (repository / path).exists() for path in PROOF_RECEIPT_PATHS.values()
    )
    assert not (repository / NPM_CAPTURE_PATH).exists()
    assert not (repository / release_manifest.CAPTURE_JOURNAL_PATH).exists()


def _journal_payloads() -> dict[str, bytes]:
    return {
        relative: f"captured:{relative}\n".encode()
        for relative in (
            *RECEIPT_PATHS.values(),
            *PROOF_RECEIPT_PATHS.values(),
            NPM_CAPTURE_PATH,
        )
    }


def _write_capture_tree(root: Path, payloads: dict[str, bytes]) -> None:
    for relative, payload in payloads.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def test_capture_journal_recovers_previous_tree_before_clean_gate(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    payloads = _journal_payloads()
    transaction_id = "a1" * 16
    journal = release_manifest._capture_journal_document(
        transaction_id=transaction_id,
        release_existed=True,
        payloads=payloads,
        phase="previous_moved",
    )
    release_manifest._write_capture_journal(repository, journal, allow_existing=False)
    original_marker = (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).read_bytes()
    previous = repository / journal["previous_name"]
    staging = repository / journal["staging_name"]
    (repository / "release").rename(previous)
    staging.mkdir()
    _write_capture_tree(
        staging,
        {path.removeprefix("release/"): body for path, body in payloads.items()},
    )

    result = release_manifest._recover_capture_publication(repository)

    assert result == "rolled_back"
    assert (
        repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
    ).read_bytes() == original_marker
    assert not previous.exists()
    assert not staging.exists()
    assert not (repository / release_manifest.CAPTURE_JOURNAL_PATH).exists()


def test_capture_journal_finishes_only_digest_exact_published_tree(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    payloads = _journal_payloads()
    transaction_id = "b2" * 16
    journal = release_manifest._capture_journal_document(
        transaction_id=transaction_id,
        release_existed=True,
        payloads=payloads,
        phase="published",
    )
    release_manifest._write_capture_journal(repository, journal, allow_existing=False)
    previous = repository / journal["previous_name"]
    (repository / "release").rename(previous)
    _write_capture_tree(repository, payloads)

    assert release_manifest._recover_capture_publication(repository) == "published"
    assert not previous.exists()
    assert not (repository / release_manifest.CAPTURE_JOURNAL_PATH).exists()
    for relative, payload in payloads.items():
        assert (repository / relative).read_bytes() == payload


def test_capture_journal_recovers_after_previous_tree_cleanup(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    payloads = _journal_payloads()
    transaction_id = "b3" * 16
    journal = release_manifest._capture_journal_document(
        transaction_id=transaction_id,
        release_existed=True,
        payloads=payloads,
        phase="published",
    )
    release_manifest._write_capture_journal(repository, journal, allow_existing=False)
    previous = repository / journal["previous_name"]
    (repository / "release").rename(previous)
    _write_capture_tree(repository, payloads)
    shutil.rmtree(previous)

    assert release_manifest._recover_capture_publication(repository) == "published"
    assert not (repository / release_manifest.CAPTURE_JOURNAL_PATH).exists()
    for relative, payload in payloads.items():
        assert (repository / relative).read_bytes() == payload


def test_capture_journal_refuses_tampered_published_tree_and_keeps_fallback(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    payloads = _journal_payloads()
    transaction_id = "c3" * 16
    journal = release_manifest._capture_journal_document(
        transaction_id=transaction_id,
        release_existed=True,
        payloads=payloads,
        phase="published",
    )
    release_manifest._write_capture_journal(repository, journal, allow_existing=False)
    previous = repository / journal["previous_name"]
    (repository / "release").rename(previous)
    _write_capture_tree(repository, payloads)
    (repository / RECEIPT_PATHS["compose"]).write_bytes(b"tampered\n")

    with pytest.raises(ReleaseManifestError, match="payload digest"):
        release_manifest._recover_capture_publication(repository)
    assert previous.is_dir()
    assert (repository / release_manifest.CAPTURE_JOURNAL_PATH).is_file()


def test_verifier_tool_commit_advances_for_every_executable_verifier_source(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    before = release_manifest._verifier_tool_commit(repository)
    for relative in (
        "packages/verify/src/cli.ts",
        "shared/transitive_helper.py",
        "scripts/transitive_helper.py",
    ):
        source = repository / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"# tracked verifier source: {relative}\n")
        after = _commit(repository, f"add tracked verifier source {relative}")

        assert before != after
        assert release_manifest._verifier_tool_commit(repository) == after
        before = after


def test_local_verifier_bundle_uses_public_schema_at_root_and_preserves_paths(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    repository, _, _, _ = release_repository
    bundle = release_manifest._materialize_local_verifier_bundle(
        repository,
        generated_at=CAPTURED_AT,
    )
    try:
        registry = json.loads(bundle.registry_path.read_bytes())
        assert set(registry) == {
            "schema_version",
            "generated_at",
            "proposal_id",
            "items",
        }
        assert registry["generated_at"] == CAPTURED_AT
        assert registry["proposal_id"] == "DAO-PROP-6CB25C"
        assert "public_items" not in registry
        assert bundle.registry_path == bundle.root / "registry.json"
        for item in registry["items"]:
            artifact_path = item["artifact_path"]
            materialized = bundle.root / artifact_path
            assert (
                materialized.read_bytes() == (repository / artifact_path).read_bytes()
            )
        bundle.revalidate()
    finally:
        bundle.cleanup()


@pytest.mark.parametrize("mutation", ["bytes", "extra_file"])
def test_local_verifier_bundle_rejects_post_materialization_mutation(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
    mutation: str,
) -> None:
    repository, _, _, _ = release_repository
    bundle = release_manifest._materialize_local_verifier_bundle(
        repository,
        generated_at=CAPTURED_AT,
    )
    try:
        if mutation == "bytes":
            bundle.registry_path.write_bytes(b'{"tampered":true}\n')
        else:
            (bundle.root / "unexpected.json").write_text("{}\n")
        with pytest.raises(ReleaseManifestError, match="private verifier data"):
            bundle.revalidate()
    finally:
        bundle.cleanup()


def test_committed_python_verifier_uses_bound_positional_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materialized = tmp_path / "committed-tree"
    runner = materialized / "scripts/build_release_manifest.py"
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/usr/bin/env python3\n")
    verifier = release_manifest._DefaultProofVerifier(
        Path(release_manifest.__file__).parents[1]
    )
    monkeypatch.setattr(
        verifier,
        "_materialize_committed_tree",
        lambda: materialized,
    )

    def fake_run(root: Path, arguments, **kwargs):
        assert root == materialized
        assert arguments[:6] == [
            "python",
            str(runner),
            "verify-python-artifact",
            "--verifier",
            "v3",
            "--artifact",
        ]
        assert "-c" not in arguments
        input_path = Path(arguments[6])
        assert input_path.read_bytes() == b'{"schema_version":"test"}\n'
        assert kwargs["command_asset_root"] == materialized
        assert kwargs["bound_data_inputs"] == (input_path,)
        return release_manifest.BoundCommandResult(
            returncode=0,
            stdout=b'{"verified":true}\n',
            stderr=b"",
            tool_identity={"tool_id": "python"},
        )

    monkeypatch.setattr(release_manifest, "_run", fake_run)

    assert verifier._committed_python_verifier(
        "v3",
        b'{"schema_version":"test"}\n',
    ) == {"verified": True}


def test_committed_python_verifier_cli_rejects_non_private_input(
    tmp_path: Path,
) -> None:
    artifact = (tmp_path / "artifact.json").resolve()
    artifact.write_text("{}\n")
    artifact.chmod(0o600)

    with pytest.raises(ReleaseManifestError, match="input is not bound"):
        release_manifest.run_committed_python_artifact_verifier(
            "v3",
            artifact,
        )


@pytest.mark.parametrize(
    ("artifact_id", "adapter_name"),
    (
        ("safepay_v2", "verify_safepay_v2_artifact"),
        (
            "official_x402_settlement_v1",
            "verify_official_x402_artifact",
        ),
    ),
)
def test_default_proof_verifier_uses_raw_payment_adapters(
    monkeypatch: pytest.MonkeyPatch,
    artifact_id: str,
    adapter_name: str,
) -> None:
    repository = Path(release_manifest.__file__).parents[1]
    documents = _artifact_documents("ab" * 20, "cd" * 20)
    document = documents[artifact_id]
    raw = _canonical(document)
    expected = _adapter_results(documents)[artifact_id]
    calls: list[tuple[dict[str, object], bytes]] = []

    def adapter(
        candidate: dict[str, object],
        candidate_raw: bytes,
    ) -> dict[str, object]:
        calls.append((candidate, candidate_raw))
        return expected

    monkeypatch.setattr(
        release_manifest.release_proof_adapters,
        adapter_name,
        adapter,
    )
    verifier = release_manifest._DefaultProofVerifier(repository)
    monkeypatch.setattr(
        verifier,
        "_packaged_registry_items",
        lambda: (_ for _ in ()).throw(
            AssertionError("raw payment proof must not depend on registry booleans")
        ),
    )

    result = verifier.verify(
        artifact_id=artifact_id,
        artifact_path=ARTIFACT_PATHS[artifact_id],
        artifact_bytes=raw,
        artifact_document=document,
    )

    assert calls == [(document, raw)]
    assert result["derived_identity"]["artifact_sha256"] == hashlib.sha256(
        raw
    ).hexdigest()
    assert result["derived_facts"]["adapter_result_sha256"] == hashlib.sha256(
        _canonical(expected)
    ).hexdigest()
    assert result["verifier_id"].endswith(adapter_name)


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("rejected", "raw proof adapter rejected"),
        ("wrong_artifact", "raw proof adapter identity differs"),
        ("failed_check", "raw proof adapter returned a non-green check"),
    ),
)
def test_default_proof_verifier_fails_closed_on_payment_adapter_drift(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    message: str,
) -> None:
    repository = Path(release_manifest.__file__).parents[1]
    documents = _artifact_documents("ab" * 20, "cd" * 20)
    document = documents["safepay_v2"]
    raw = _canonical(document)
    result = _adapter_results(documents)["safepay_v2"]

    def adapter(
        candidate: dict[str, object],
        candidate_raw: bytes,
    ) -> dict[str, object]:
        assert candidate is document
        assert candidate_raw == raw
        if failure == "rejected":
            raise release_manifest.release_proof_adapters.ReleaseProofAdapterError(
                "rejected"
            )
        if failure == "wrong_artifact":
            result["artifact_sha256"] = "00" * 32
        else:
            result["checks"][0]["passed"] = False
        return result

    monkeypatch.setattr(
        release_manifest.release_proof_adapters,
        "verify_safepay_v2_artifact",
        adapter,
    )
    verifier = release_manifest._DefaultProofVerifier(repository)

    with pytest.raises(ReleaseManifestError, match=message):
        verifier.verify(
            artifact_id="safepay_v2",
            artifact_path=ARTIFACT_PATHS["safepay_v2"],
            artifact_bytes=raw,
            artifact_document=document,
        )


@pytest.mark.parametrize("duplicate_proof_id", [False, True])
def test_packaged_verifier_executes_only_fresh_committed_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    duplicate_proof_id: bool,
) -> None:
    repository = Path(release_manifest.__file__).parents[1]
    committed_cli = tmp_path / "committed-sdk/packages/verify/dist/cli.js"
    committed_cli.parent.mkdir(parents=True)
    committed_cli.write_text("// test materialization\n")
    replay_registry = tmp_path / "proof-data/registry.json"
    replay_registry.parent.mkdir()
    replay_registry.write_text("{}\n")
    calls: list[list[str]] = []

    verifier = release_manifest._DefaultProofVerifier(repository)
    monkeypatch.setattr(
        verifier,
        "_materialize_committed_sdk_cli",
        lambda: committed_cli,
        raising=False,
    )

    class FakeBundle:
        registry_path = replay_registry

        def revalidate(self) -> None:
            assert replay_registry.read_bytes() == b"{}\n"

        def cleanup(self) -> None:
            pass

    monkeypatch.setattr(
        release_manifest,
        "_materialize_local_verifier_bundle",
        lambda root, *, generated_at: FakeBundle(),
    )

    def fake_run(root: Path, arguments, **kwargs):
        calls.append([str(item) for item in arguments])
        return subprocess.CompletedProcess(
            list(arguments),
            0,
            stdout=_canonical(
                {
                    "tool": "@concordia-dao/verify",
                    "status": "verified",
                    "valid": True,
                    "exitCode": 0,
                    "items": [
                        {
                            "proofId": "safepay_v2",
                            "status": "verified",
                            "green": True,
                            "ignoredAssertions": [],
                        }
                    ]
                    * (2 if duplicate_proof_id else 1),
                }
            ),
            stderr=b"",
        )

    monkeypatch.setattr(release_manifest, "_run", fake_run)
    if duplicate_proof_id:
        with pytest.raises(ReleaseManifestError, match="duplicate proof"):
            verifier._packaged_registry_items()
    else:
        verifier._packaged_registry_items()

    assert calls
    assert calls[0][1] == str(committed_cli)
    assert calls[0][1] != str(repository / "packages/verify/dist/cli.js")
    assert calls[0][3] == str(replay_registry)


def test_cli_has_fixed_capture_assemble_and_g13_commands_without_operator_status_paths(
    release_repository: tuple[Path, dict[str, str], FakeCollector, FakeVerifier],
) -> None:
    # The subprocess cannot inherit monkeypatches, so this test only proves the
    # command contract and its refusal of arbitrary capture/output selectors.
    repository, _, _, _ = release_repository
    help_result = subprocess.run(
        [sys.executable, str(BUILD_SCRIPT), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert help_result.returncode == 0
    assert b"capture" in help_result.stdout
    assert b"assemble" in help_result.stdout
    assert b"prepare-host-toolchain" in help_result.stdout
    assert b"capture-organizer-g12" in help_result.stdout
    assert b"capture-organizer-g13" in help_result.stdout
    assert b"verify-command-gates" in help_result.stdout
    assert b"verify-g13" in help_result.stdout
    rejected = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "capture",
            "--repository-root",
            str(repository),
            "--status-json",
            "operator.json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert rejected.returncode == 2
    assert b"unrecognized arguments: --status-json" in rejected.stderr

    wrong_root = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "capture",
            "--repository-root",
            str(repository),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert wrong_root.returncode == 1
    assert b"executing repository" in wrong_root.stdout


def test_cli_absolute_path_bootstraps_its_own_repository_without_cwd_or_pythonpath(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "isolated-repository"
    scripts = repository / "scripts"
    shared = repository / "shared"
    scripts.mkdir(parents=True)
    shared.mkdir()
    runner = scripts / "build_release_manifest.py"
    runner.write_bytes(BUILD_SCRIPT.read_bytes())
    (shared / "__init__.py").write_text("", encoding="utf-8")
    (shared / "release_manifest.py").write_text(
        "RELEASE_MANIFEST_PATH = 'release/RELEASE_MANIFEST.json'\n"
        "class ReleaseManifestError(ValueError):\n"
        "    pass\n"
        "def verify_command_gate_receipts(root):\n"
        "    return {'status': 'verified'}\n"
        "def prepare_host_toolchain_receipt_once(root):\n"
        "    raise ReleaseManifestError('not used')\n"
        "def run_committed_python_artifact_verifier(verifier_name, artifact):\n"
        "    raise ReleaseManifestError('not used')\n"
        "def capture_release_observations_once(root):\n"
        "    return ()\n"
        "def capture_organizer_link_audit_once(root, *, phase):\n"
        "    raise ReleaseManifestError('not used')\n"
        "def assemble_release_manifest_once(root):\n"
        "    raise ReleaseManifestError('not used')\n"
        "def verify_g13_submission_receipt(root):\n"
        "    return {'status': 'verified'}\n",
        encoding="utf-8",
    )
    unrelated_cwd = tmp_path / "unrelated-cwd"
    unrelated_cwd.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            runner,
            "verify-command-gates",
            "--repository-root",
            repository,
        ],
        cwd=unrelated_cwd,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert json.loads(result.stdout) == {
        "command": "verify-command-gates",
        "status": "verified",
    }
    assert b"ModuleNotFoundError" not in result.stderr
