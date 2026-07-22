from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.factory.deploys import (
    create_deploy,
    create_deploy_parameters,
    create_standard_payment,
)
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import DeployOfModuleBytes

from scripts.install_governance_receipt_v3 import (
    DurableDeployJournal,
    InstallValidationError,
    build_install_parser,
    build_locked_install_args,
    execute_journaled_submission,
    main as install_main,
    reconcile_two_node_deploy,
    validate_public_rpc_endpoints,
    verify_git_release_identity,
    verify_two_node_deploy_finality,
)
from scripts.run_v3_live_proof import build_live_parser, choose_negative_allocation_bps
from shared.casper_rpc_transport import RpcRemoteError


DEPLOY_HASH = "ab" * 32
BLOCK_HASH = "cd" * 32
STATE_ROOT = "ef" * 32
BLOCK_TIMESTAMP = "2026-01-23T12:34:56.789Z"


def _signed_journal_deploy() -> dict[str, object]:
    private = parse_private_key_bytes(bytes([7]) * 32, KeyAlgorithm.ED25519)
    deploy = create_deploy(
        create_deploy_parameters(private, "casper-test", ttl="30m"),
        create_standard_payment(1_000_000_000),
        DeployOfModuleBytes(module_bytes=b"\x00asm", args={}),
    )
    deploy.approve(private)
    return serializer.to_json(deploy)


def _resolver(host: str) -> tuple[str, ...]:
    return {
        "rpc-a.example": ("8.8.8.8",),
        "rpc-b.example": ("1.1.1.1",),
        "same-ip.example": ("8.8.8.8",),
        "private.example": ("10.0.0.7",),
    }[host]


@pytest.mark.parametrize(
    "url",
    [
        "http://rpc-a.example/rpc",
        "https://user:pass@rpc-a.example/rpc",
        "https://rpc-a.example/rpc?token=secret",
        "https://rpc-a.example/rpc#secret",
        "https://127.0.0.1/rpc",
        "https://private.example/rpc",
    ],
)
def test_rpc_policy_rejects_unsafe_endpoints(url: str) -> None:
    with pytest.raises(InstallValidationError, match="public credential-free HTTPS"):
        validate_public_rpc_endpoints(
            [url, "https://rpc-b.example/rpc"], resolver=_resolver
        )


def test_rpc_policy_requires_two_distinct_hosts_and_addresses() -> None:
    with pytest.raises(InstallValidationError, match="distinct"):
        validate_public_rpc_endpoints(
            ["https://rpc-a.example/rpc", "https://rpc-a.example/other"],
            resolver=_resolver,
        )
    with pytest.raises(InstallValidationError, match="distinct"):
        validate_public_rpc_endpoints(
            ["https://rpc-a.example/rpc", "https://same-ip.example/rpc"],
            resolver=_resolver,
        )


def test_journal_is_durable_before_broadcast_and_timeout_resumes_by_hash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "deploy.journal.json"
    deploy = _signed_journal_deploy()
    deploy_hash = str(deploy["hash"]).lower()
    journal = DurableDeployJournal.create(
        path,
        intent={"kind": "install", "nonce": "11" * 32},
        signed_deploy=deploy,
        deploy_hash=deploy_hash,
    )
    observed_states: list[str] = []

    def lost_response(_deploy: dict[str, object], deploy_hash: str) -> object:
        observed_states.append(DurableDeployJournal.open(path).state)
        assert deploy_hash == str(deploy["hash"]).lower()
        raise TimeoutError("response lost")

    first = execute_journaled_submission(
        journal,
        broadcast=lost_response,
        reconcile=lambda _hash: {"status": "pending"},
    )
    assert observed_states == ["broadcast_inflight"]
    assert first.state == "broadcast_ambiguous"
    assert first.deploy_hash == deploy_hash

    second = execute_journaled_submission(
        DurableDeployJournal.open(path),
        broadcast=lambda *_: pytest.fail("ambiguous resume must not rebroadcast"),
        reconcile=lambda deploy_hash: {
            "status": "pending",
            "deploy_hash": deploy_hash,
        },
    )
    assert second.state == "broadcast_ambiguous"
    assert second.deploy_hash == deploy_hash


def test_duplicate_submit_of_finalized_journal_never_calls_network(tmp_path: Path) -> None:
    path = tmp_path / "deploy.journal.json"
    deploy = _signed_journal_deploy()
    deploy_hash = str(deploy["hash"]).lower()
    journal = DurableDeployJournal.create(
        path,
        intent={"kind": "contract_step", "step": "propose_exact"},
        signed_deploy=deploy,
        deploy_hash=deploy_hash,
    )
    journal.transition("prepared", "finalized", evidence={"deploy_hash": deploy_hash})
    result = execute_journaled_submission(
        DurableDeployJournal.open(path),
        broadcast=lambda *_: pytest.fail("finalized journal must not broadcast"),
        reconcile=lambda *_: pytest.fail("finalized journal must not reconcile"),
    )
    assert result.state == "finalized"


def test_expired_deploy_becomes_terminal_only_after_two_exact_absence_codes() -> None:
    class AbsentTransport:
        endpoints = (
            "https://rpc-a.example/rpc",
            "https://rpc-b.example/rpc",
        )

        def call(self, *args: object, **kwargs: object) -> object:
            raise RpcRemoteError(-32001)

    result = reconcile_two_node_deploy(
        AbsentTransport(),
        deploy_hash=DEPLOY_HASH,
        deploy_expires_at=0.0,
    )
    assert result["status"] == "terminal_rejected"
    assert result["detail_code"] == "ttl_expired_and_two_nodes_report_absent"
    assert len(result["absence_observations"]) == 2

    pending = reconcile_two_node_deploy(
        AbsentTransport(),
        deploy_hash=DEPLOY_HASH,
        deploy_expires_at=9_999_999_999.0,
    )
    assert pending == {"status": "pending", "deploy_hash": DEPLOY_HASH}


def test_journal_rejects_resealed_semantic_deploy_tampering(tmp_path: Path) -> None:
    path = tmp_path / "deploy.journal.json"
    deploy = _signed_journal_deploy()
    DurableDeployJournal.create(
        path,
        intent={"kind": "install", "nonce": "11" * 32},
        signed_deploy=deploy,
        deploy_hash=str(deploy["hash"]),
    )
    value = json.loads(path.read_text(encoding="ascii"))
    value["signed_deploy"]["header"]["chain_name"] = "forged-chain"
    canonical_deploy = json.dumps(
        value["signed_deploy"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    value["signed_deploy_json_bytes_hex"] = canonical_deploy.hex()
    value["signed_deploy_sha256"] = __import__("hashlib").sha256(canonical_deploy).hexdigest()
    unsigned = {key: item for key, item in value.items() if key != "journal_sha256"}
    value["journal_sha256"] = __import__("hashlib").sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    path.write_text(json.dumps(value), encoding="ascii")
    with pytest.raises(InstallValidationError, match="canonical Casper"):
        DurableDeployJournal.open(path)


def _deploy_response(*, block_hash: str = BLOCK_HASH, height: int = 42) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": "finality",
        "result": {
            "api_version": "2.0.0",
            "deploy": {"hash": DEPLOY_HASH},
            "execution_info": {
                "block_hash": block_hash,
                "block_height": height,
                "execution_result": {"Version2": {"error_message": None}},
            },
        },
    }


def _block_response(
    *, block_hash: str = BLOCK_HASH, height: int = 42, included: bool = True
) -> dict[str, object]:
    transactions = [{"Deploy": DEPLOY_HASH}] if included else []
    return {
        "jsonrpc": "2.0",
        "id": "block",
        "result": {
            "api_version": "2.0.0",
            "block_with_signatures": {
                "block": {
                    "Version2": {
                        "hash": block_hash,
                        "header": {
                            "height": height,
                            "state_root_hash": STATE_ROOT,
                            "timestamp": BLOCK_TIMESTAMP,
                        },
                        "body": {"transactions": {"0": transactions}},
                    }
                },
                "proofs": [],
            },
        },
    }


def _node_observation(host: str) -> dict[str, object]:
    deploy_request = {
        "jsonrpc": "2.0",
        "id": "finality",
        "method": "info_get_deploy",
        "params": {"deploy_hash": DEPLOY_HASH},
    }
    block_request = {
        "jsonrpc": "2.0",
        "id": "block",
        "method": "chain_get_block",
        "params": {"block_identifier": {"Hash": BLOCK_HASH}},
    }
    return {
        "node_id": host,
        "node_url": f"https://{host}/rpc",
        "deploy_request": deploy_request,
        "deploy_response": _deploy_response(),
        "block_request": block_request,
        "block_response": _block_response(),
    }


def test_two_node_finality_requires_block_inclusion_and_agreement() -> None:
    proof = verify_two_node_deploy_finality(
        [_node_observation("rpc-a.example"), _node_observation("rpc-b.example")],
        deploy_hash=DEPLOY_HASH,
    )
    assert proof["block_hash"] == BLOCK_HASH
    assert proof["block_height"] == 42
    assert proof["state_root_hash"] == STATE_ROOT
    assert proof["block_timestamp"] == BLOCK_TIMESTAMP
    assert proof["finalized_at"] == BLOCK_TIMESTAMP
    assert "observed_at" not in proof
    assert proof["corroboration_count"] == 2

    absent = _node_observation("rpc-b.example")
    absent["block_response"] = _block_response(included=False)
    with pytest.raises(InstallValidationError, match="absent from canonical block"):
        verify_two_node_deploy_finality(
            [_node_observation("rpc-a.example"), absent], deploy_hash=DEPLOY_HASH
        )

    request_tamper = _node_observation("rpc-b.example")
    request_tamper["block_request"] = copy.deepcopy(request_tamper["block_request"])
    request_tamper["block_request"]["params"]["block_identifier"]["Hash"] = "34" * 32
    with pytest.raises(InstallValidationError, match="request"):
        verify_two_node_deploy_finality(
            [_node_observation("rpc-a.example"), request_tamper],
            deploy_hash=DEPLOY_HASH,
        )

    timestamp_disagreement = _node_observation("rpc-b.example")
    timestamp_disagreement["block_response"] = copy.deepcopy(
        timestamp_disagreement["block_response"]
    )
    timestamp_disagreement["block_response"]["result"]["block_with_signatures"][
        "block"
    ]["Version2"]["header"]["timestamp"] = "2026-01-23T12:34:57.000Z"
    with pytest.raises(InstallValidationError, match="disagree"):
        verify_two_node_deploy_finality(
            [_node_observation("rpc-a.example"), timestamp_disagreement],
            deploy_hash=DEPLOY_HASH,
        )

    disagreement = _node_observation("rpc-b.example")
    disagreement["deploy_response"] = _deploy_response(block_hash="12" * 32)
    disagreement["block_response"] = _block_response(block_hash="12" * 32)
    disagreement["block_request"] = copy.deepcopy(disagreement["block_request"])
    disagreement["block_request"]["params"]["block_identifier"]["Hash"] = "12" * 32
    with pytest.raises(InstallValidationError, match="disagree"):
        verify_two_node_deploy_finality(
            [_node_observation("rpc-a.example"), disagreement],
            deploy_hash=DEPLOY_HASH,
        )


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def test_release_identity_rejects_dirty_tree_and_forged_commits(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "WP10 test"], cwd=repo, check=True)
    source = repo / "release.txt"
    source.write_text("release\n", encoding="utf-8")
    subprocess.run(["git", "add", "release.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "release"], cwd=repo, check=True)
    head = _git(repo, "rev-parse", "HEAD")

    identity = verify_git_release_identity(
        repo,
        source_commit=head,
        deployment_commit=head,
        release_paths=("release.txt",),
    )
    assert identity == {"source_commit": head, "deployment_commit": head}

    with pytest.raises(InstallValidationError, match="deployment_commit.*HEAD"):
        verify_git_release_identity(
            repo,
            source_commit=head,
            deployment_commit="00" * 20,
            release_paths=("release.txt",),
        )

    source.write_text("dirty\n", encoding="utf-8")
    with pytest.raises(InstallValidationError, match="clean"):
        verify_git_release_identity(
            repo,
            source_commit=head,
            deployment_commit=head,
            release_paths=("release.txt",),
        )


@pytest.mark.parametrize("approved", [0, 1, 2999, 3000, 10_000])
def test_negative_allocation_is_always_valid_and_different(approved: int) -> None:
    negative = choose_negative_allocation_bps(approved)
    assert 0 <= negative <= 10_000
    assert negative != approved
    assert negative == (2999 if approved == 3000 else 3000)


def test_live_and_install_cli_are_prepare_only_by_default() -> None:
    install = build_install_parser().parse_args(
        [
            "--secret-key", "key",
            "--roles", "roles.json",
            "--installation-nonce", "11" * 32,
            "--wasm", "contract.wasm",
            "--schema", "schema.json",
            "--source-commit", "22" * 20,
            "--deployment-commit", "22" * 20,
            "--journal", "install.journal.json",
            "--manifest-out", "manifest.json",
        ]
    )
    assert install.submit is False
    live = build_live_parser().parse_args(
        [
            "input.json",
            "--roles", "roles.json",
            "--package-hash", "33" * 32,
            "--contract-hash", "44" * 32,
            "--journal", "run.journal.json",
            "--out", "run.json",
        ]
    )
    assert live.submit is False


def test_install_prepare_persists_exact_deploy_without_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    roles = tmp_path / "roles.json"
    roles.write_text("{}", encoding="utf-8")
    journal = tmp_path / "install.journal.json"
    manifest_out = tmp_path / "manifest.json"
    deploy = _signed_journal_deploy()
    manifest = {"install_deploy_hash": deploy["hash"], "status": "prepared"}
    monkeypatch.setattr(
        "scripts.install_governance_receipt_v3.verify_git_release_identity",
        lambda *args, **kwargs: {
            "source_commit": "22" * 20,
            "deployment_commit": "22" * 20,
        },
    )
    monkeypatch.setattr(
        "scripts.install_governance_receipt_v3.build_signed_install_payload",
        lambda **kwargs: (
            {"params": {"deploy": deploy}},
            manifest,
        ),
    )
    monkeypatch.setattr(
        "scripts.install_governance_receipt_v3.validate_finalized_install_deploy",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "scripts.install_governance_receipt_v3.build_public_rpc_transport",
        lambda *args, **kwargs: pytest.fail("prepare must not access network"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "install_governance_receipt_v3.py",
            "--secret-key", str(tmp_path / "unused-key"),
            "--roles", str(roles),
            "--installation-nonce", "11" * 32,
            "--wasm", str(tmp_path / "contract.wasm"),
            "--schema", str(tmp_path / "schema.json"),
            "--source-commit", "22" * 20,
            "--deployment-commit", "22" * 20,
            "--journal", str(journal),
            "--manifest-out", str(manifest_out),
        ],
    )
    assert install_main() == 0
    persisted = DurableDeployJournal.open(journal)
    assert persisted.state == "prepared"
    assert persisted.signed_deploy == json.loads(json.dumps(deploy))
    assert not manifest_out.exists()


def test_frozen_seven_step_release_rejects_threshold_three() -> None:
    roles = {
        name: {"kind": "Account", "account_hash": f"{index:02x}" * 32}
        for index, name in enumerate(
            ("proposer", "finalizer", "signer_a", "signer_b", "signer_c"),
            start=1,
        )
    }
    with pytest.raises(InstallValidationError, match="threshold.*exactly 2"):
        build_locked_install_args(
            installer_account_hash="ff" * 32,
            roles=roles,
            threshold=3,
            casper_chain_name="casper-test",
            installation_nonce="11" * 32,
        )
