"""200-response token canaries at every RPC-backed evidence boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.install_governance_receipt_v3 import (
    InstallValidationError,
    _safe_rpc_payload,
    reconcile_two_node_deploy,
)
from scripts.read_v3_state import capture_v3_state
from scripts.run_treasury_execution import capture_native_treasury_snapshot
from shared.casper_rpc_transport import RpcTransportError
from tests.test_casper_rpc_transport import NODE_A, _Response, _client
from tests.test_clvalue_roundtrip import _readback_fixture
from tests.test_treasury_executor import SOURCE_ACCOUNT


NODE_B = "https://rpc-b.example/rpc"
SECRET = "successful-rpc-reflection-canary-8821"


def _token_file(tmp_path: Path) -> Path:
    path = tmp_path / "rpc-token"
    path.write_text(SECRET + "\n", encoding="ascii")
    path.chmod(0o600)
    return path


def _assert_sanitized(error: BaseException, token_file: Path) -> None:
    assert SECRET not in str(error)
    assert str(token_file) not in str(error)


def test_readback_artifact_boundary_rejects_successful_token_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _transcripts, ids = _readback_fixture()
    token_file = _token_file(tmp_path)
    response = {
        "jsonrpc": "2.0",
        "id": "concordia-v3-readback-0",
        "result": {
            "api_version": SECRET,
            "block_with_signatures": {
                "block": {
                    "Version2": {
                        "hash": ids["block"],
                        "header": {
                            "height": 9_010,
                            "state_root_hash": ids["state_root"],
                        },
                        "body": {"transactions": {}},
                    }
                },
                "proofs": [],
            },
        },
    }
    rpc = _client(
        monkeypatch,
        _Response(json.dumps(response).encode("ascii")),
        authorization_files={NODE_A: token_file},
    )

    with pytest.raises(RpcTransportError) as captured:
        capture_v3_state(
            rpc_transport=rpc,
            rpc_url=NODE_A,
            package_hash=ids["package"],
            contract_hash=ids["contract"],
            proposal_id=ids["proposal"],
            action_id=ids["action"],
            block_hash=ids["block"],
        )
    _assert_sanitized(captured.value, token_file)


def test_install_finality_boundary_rejects_successful_token_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = _token_file(tmp_path)
    deploy_hash = "ab" * 32
    response = {
        "jsonrpc": "2.0",
        "id": "concordia-wp10-finality-0",
        "result": {
            "api_version": SECRET,
            "deploy": {"hash": deploy_hash},
            "execution_info": None,
        },
    }
    rpc = _client(
        monkeypatch,
        _Response(json.dumps(response).encode("ascii")),
        authorization_files={NODE_A: token_file},
    )

    with pytest.raises(InstallValidationError) as captured:
        reconcile_two_node_deploy(rpc, deploy_hash=deploy_hash)
    _assert_sanitized(captured.value, token_file)


def test_live_proof_broadcast_boundary_rejects_successful_token_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = _token_file(tmp_path)
    deploy_hash = "ab" * 32
    request = {
        "jsonrpc": "2.0",
        "id": "live-reflection",
        "method": "account_put_deploy",
        "params": {"deploy": {}},
    }
    response = {
        "jsonrpc": "2.0",
        "id": "live-reflection",
        "result": {"api_version": SECRET, "deploy_hash": deploy_hash},
    }
    rpc = _client(
        monkeypatch,
        _Response(json.dumps(response).encode("ascii")),
        authorization_files={NODE_A: token_file},
    )

    with pytest.raises(InstallValidationError) as captured:
        _safe_rpc_payload(rpc, NODE_A, request)
    _assert_sanitized(captured.value, token_file)


def test_treasury_snapshot_boundary_rejects_successful_token_reflection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_file = _token_file(tmp_path)
    response = {
        "jsonrpc": "2.0",
        "id": "treasury-snapshot-status-0",
        "result": {
            "api_version": SECRET,
            "chainspec_name": "casper-test",
            "last_added_block_info": {"hash": "ab" * 32, "height": 9_100},
        },
    }
    rpc = _client(
        monkeypatch,
        _Response(json.dumps(response).encode("ascii")),
        authorization_files={NODE_A: token_file},
    )

    with pytest.raises(RpcTransportError) as captured:
        capture_native_treasury_snapshot(rpc, SOURCE_ACCOUNT)
    _assert_sanitized(captured.value, token_file)
