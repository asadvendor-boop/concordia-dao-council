"""Offline acceptance tests for the production native-treasury operator."""

from __future__ import annotations

import copy
import hashlib
import json
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pycspr.factory.accounts import parse_private_key
from pycspr.types.crypto import KeyAlgorithm

import shared.secure_secret_file as secure_file

from scripts.run_treasury_execution import (
    EXACT_APPROVED_BPS,
    EXACT_TRANSFER_MOTES,
    EXACT_TREASURY_BASELINE_MOTES,
    OperatorError,
    TreasuryExecutionOperator,
    atomic_write_once,
    build_posthoc_release_manifest,
    capture_native_treasury_snapshot,
    load_signer_from_file,
    main,
    require_durable_journal_path,
    verify_native_authorization_artifacts,
)
from shared.casper_rpc_transport import (
    RpcEndpointPolicyError,
    RpcRemoteError,
    validate_public_rpc_endpoints,
)
from shared.treasury_executor import ExecutionState, JournalConflict, TreasuryExecutor
from tests.test_treasury_executor import (
    DEPLOYMENT_COMMIT,
    RECIPIENT_ACCOUNT,
    SOURCE_ACCOUNT,
    SOURCE_KEY,
    TIMESTAMP_SECONDS,
    _verified,
)
from tests.v3_treasury_fixtures import treasury_v3_proof


NODE_A = "https://rpc-a.example/rpc"
NODE_B = "https://rpc-b.example/rpc"
GAS_MOTES = 123_456_789
PRE_RECIPIENT_BALANCE = 7_000_000_000


def _snapshot_artifact(proof: dict[str, object]) -> dict[str, object]:
    body = proof["input"]["body"]  # type: ignore[index]
    block_hash = str(body["snapshot_block_hash"])
    block_height = int(str(body["snapshot_block_height"]))
    state_root = "98" * 32
    source = str(body["source_account"])
    balance = str(body["treasury_snapshot_balance_motes"])
    status_request = {
        "jsonrpc": "2.0",
        "id": "snapshot-status",
        "method": "info_get_status",
        "params": {},
    }
    status_response = {
        "jsonrpc": "2.0",
        "id": "snapshot-status",
        "result": {"chainspec_name": "casper-test"},
    }
    block_request = {
        "jsonrpc": "2.0",
        "id": "snapshot-block",
        "method": "chain_get_block",
        "params": {"block_identifier": {"Hash": block_hash}},
    }
    block_response = {
        "jsonrpc": "2.0",
        "id": "snapshot-block",
        "result": {
            "block": {
                "hash": block_hash,
                "header": {
                    "height": block_height,
                    "state_root_hash": state_root,
                },
                "body": {},
            }
        },
    }
    balance_request = {
        "jsonrpc": "2.0",
        "id": "snapshot-balance",
        "method": "query_balance_details",
        "params": {
            "state_identifier": {"StateRootHash": state_root},
            "purse_identifier": {
                "main_purse_under_account_hash": f"account-hash-{source}"
            },
        },
    }
    balance_response = {
        "jsonrpc": "2.0",
        "id": "snapshot-balance",
        "result": {
            "name": "query_balance_details_result",
            "value": {
                "api_version": "2.0.0",
                "total_balance": balance,
                "available_balance": balance,
                "total_balance_proof": "01" + ("ab" * 96),
                "holds": [],
            },
        },
    }

    def observation(node_url: str, captured_at: str) -> dict[str, object]:
        return {
            "node_url": node_url,
            "captured_at": captured_at,
            "status_request": copy.deepcopy(status_request),
            "status_response": copy.deepcopy(status_response),
            "block_request": copy.deepcopy(block_request),
            "block_response": copy.deepcopy(block_response),
            "balance_request": copy.deepcopy(balance_request),
            "balance_response": copy.deepcopy(balance_response),
        }

    return {
        "schema_id": "concordia.native-treasury-snapshot.v1",
        "network": "casper-test",
        "source_account_hash": source,
        "expected_balance_motes": balance,
        "observations": [
            observation(NODE_A, "2026-07-23T01:00:00Z"),
            observation(NODE_B, "2026-07-23T01:00:01Z"),
        ],
    }


def _temporally_valid_v3_proof() -> dict[str, object]:
    """Return a complete proof whose snapshot precedes exact finalization."""

    return treasury_v3_proof(
        source_account=SOURCE_ACCOUNT,
        recipient_account=RECIPIENT_ACCOUNT,
    )


class FakeTreasuryRpc:
    """Exact JSON-RPC fake; it never handles or exposes credentials."""

    endpoints = (NODE_A, NODE_B)

    def __init__(
        self,
        authorization,
        *,
        lost_broadcast: bool = False,
        pending: bool = False,
        absent: bool = False,
        disagree: bool = False,
        duplicate: bool = False,
        fail_if_broadcast: bool = False,
    ) -> None:
        self.authorization = authorization
        self.lost_broadcast = lost_broadcast
        self.pending = pending
        self.absent = absent
        self.disagree = disagree
        self.duplicate = duplicate
        self.fail_if_broadcast = fail_if_broadcast
        self.broadcast_calls = 0
        self.calls: list[tuple[str, str, object]] = []
        self.deploy_hash: str | None = None
        start = authorization.finalization_block_height
        self.finality_height = start + 100
        self.finality_hash = "cd" * 32
        self.finality_root = "ce" * 32
        tip = self.finality_height + 1
        self.tip_height = tip
        self.block_hashes = {
            height: hashlib.sha256(f"treasury-block-{height}".encode()).hexdigest()
            for height in range(start, tip + 1)
        }
        self.block_hashes[start] = authorization.finalization_block_hash.hex()
        self.block_hashes[self.finality_height] = self.finality_hash

    @staticmethod
    def _result(request_id: object, value: object) -> dict[str, object]:
        return {"jsonrpc": "2.0", "id": request_id, "result": value}

    def call(
        self,
        endpoint: str,
        method: str,
        params: dict[str, object],
        request_id: object,
        *,
        allow_submit: bool = False,
    ) -> dict[str, object]:
        self.calls.append((endpoint, method, copy.deepcopy(params)))
        if method == "account_put_deploy":
            if not allow_submit or self.fail_if_broadcast:
                raise AssertionError("broadcast must not be called")
            self.broadcast_calls += 1
            deploy = params["deploy"]
            self.deploy_hash = str(deploy["hash"])  # type: ignore[index]
            response = self._result(
                request_id,
                {"api_version": "2.0.0", "deploy_hash": self.deploy_hash},
            )
            if self.lost_broadcast:
                raise TimeoutError("lost response after node acceptance")
            return response

        if method == "info_get_status":
            return self._result(
                request_id,
                {
                    "name": "info_get_status_result",
                    "value": {
                        "api_version": "2.0.0",
                        "chainspec_name": "casper-test",
                        "last_added_block_info": {
                            "hash": self.block_hashes[self.tip_height],
                            "height": self.tip_height,
                        },
                    },
                },
            )

        if method == "info_get_deploy":
            if self.absent:
                raise RpcRemoteError(-32001)
            deploy_hash = str(params["deploy_hash"])
            self.deploy_hash = self.deploy_hash or deploy_hash
            if self.pending:
                return self._result(
                    request_id,
                    {"deploy": {"hash": deploy_hash}, "execution_results": []},
                )
            block_hash = (
                "ef" * 32
                if self.disagree and endpoint == NODE_B
                else self.finality_hash
            )
            return self._result(
                request_id,
                {
                    "deploy": {"hash": deploy_hash},
                    "execution_results": [
                        {
                            "block_hash": block_hash,
                            "result": {
                                "Success": {
                                    "cost": str(GAS_MOTES),
                                    "transfers": [],
                                }
                            },
                        }
                    ],
                },
            )

        if method == "chain_get_block":
            identifier = params["block_identifier"]
            if "Hash" in identifier:  # type: ignore[operator]
                requested_hash = str(identifier["Hash"])  # type: ignore[index]
                if requested_hash == self.authorization.snapshot_block_hash.hex():
                    height = self.authorization.snapshot_block_height
                    block_hash = requested_hash
                    root = self.authorization.snapshot_state_root_hash.hex()
                else:
                    height = self.finality_height
                    block_hash = requested_hash
                    root = self.finality_root
            else:
                height = int(identifier["Height"])  # type: ignore[index]
                block_hash = self.block_hashes[height]
                root = (
                    self.finality_root if height == self.finality_height else "dd" * 32
                )
            parent = (
                "aa" * 32
                if height == self.authorization.finalization_block_height
                else self.block_hashes.get(height - 1, "aa" * 32)
            )
            body = {"deploy_hashes": [], "transfer_hashes": []}
            if height == self.finality_height and self.deploy_hash is not None:
                body["transfer_hashes"] = [self.deploy_hash]
            return self._result(
                request_id,
                {
                    "block": {
                        "hash": block_hash,
                        "header": {
                            "height": height,
                            "parent_hash": parent,
                            "state_root_hash": root,
                        },
                        "body": body,
                    }
                },
            )

        if method == "query_balance_details":
            purse = params["purse_identifier"]  # type: ignore[index]
            account = str(purse["main_purse_under_account_hash"]).removeprefix(  # type: ignore[index]
                "account-hash-"
            )
            root = str(params["state_identifier"]["StateRootHash"])  # type: ignore[index]
            if root == self.authorization.snapshot_state_root_hash.hex():
                balance = (
                    self.authorization.treasury_snapshot_balance_motes
                    if account == SOURCE_ACCOUNT.hex()
                    else PRE_RECIPIENT_BALANCE
                )
            else:
                balance = (
                    self.authorization.treasury_snapshot_balance_motes
                    - self.authorization.amount_motes
                    - GAS_MOTES
                    if account == SOURCE_ACCOUNT.hex()
                    else PRE_RECIPIENT_BALANCE + self.authorization.amount_motes
                )
            return self._result(
                request_id,
                {
                    "name": "query_balance_details_result",
                    "value": {
                        "api_version": "2.0.0",
                        "total_balance": str(balance),
                        "available_balance": str(balance),
                        "total_balance_proof": "01" + ("ab" * 96),
                        "holds": [],
                    },
                },
            )

        if method == "chain_get_block_transfers":
            block_hash = str(params["block_identifier"]["Hash"])  # type: ignore[index]
            height = next(
                height
                for height, value in self.block_hashes.items()
                if value == block_hash
            )
            transfers: list[dict[str, object]] = []
            if height == self.finality_height:
                transfers.append(
                    {
                        "Version1": {
                            "deploy_hash": self.deploy_hash,
                            "from": f"account-hash-{SOURCE_ACCOUNT.hex()}",
                            "to": f"account-hash-{RECIPIENT_ACCOUNT.hex()}",
                            "source": "uref-" + ("11" * 32) + "-007",
                            "target": "uref-" + ("12" * 32) + "-000",
                            "amount": str(self.authorization.amount_motes),
                            "gas": str(GAS_MOTES),
                            "id": self.authorization.transfer_id,
                        }
                    }
                )
            if self.duplicate and height == self.tip_height:
                duplicate = copy.deepcopy(
                    transfers[0]
                    if transfers
                    else {
                        "Version1": {
                            "deploy_hash": "ef" * 32,
                            "from": f"account-hash-{SOURCE_ACCOUNT.hex()}",
                            "to": f"account-hash-{RECIPIENT_ACCOUNT.hex()}",
                            "source": "uref-" + ("11" * 32) + "-007",
                            "target": "uref-" + ("12" * 32) + "-000",
                            "amount": str(self.authorization.amount_motes),
                            "gas": str(GAS_MOTES),
                            "id": self.authorization.transfer_id,
                        }
                    }
                )
                transfers.append(duplicate)
            return self._result(
                request_id,
                {"block_hash": block_hash, "transfers": transfers},
            )
        raise AssertionError(f"unexpected RPC method {method}")


class FakeSnapshotRpc:
    endpoints = (NODE_A, NODE_B)

    def __init__(self, *, mutation: str | None = None) -> None:
        self.mutation = mutation
        self.calls: list[tuple[str, str, bool]] = []
        self.block_hash = "31" * 32
        self.block_height = 8_590_000
        self.state_root = "32" * 32

    def call(
        self,
        endpoint: str,
        method: str,
        params: dict[str, object],
        request_id: object,
        *,
        allow_submit: bool = False,
    ) -> dict[str, object]:
        self.calls.append((endpoint, method, allow_submit))
        if allow_submit or method == "account_put_deploy":
            raise AssertionError("snapshot capture must be read-only")
        if method == "info_get_status":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "chainspec_name": "casper-test",
                    "last_added_block_info": {
                        "hash": self.block_hash,
                        "height": self.block_height,
                    },
                },
            }
        if method == "chain_get_block":
            block_hash = self.block_hash
            block_height = self.block_height
            state_root = self.state_root
            if endpoint == NODE_B:
                if self.mutation == "block_hash":
                    block_hash = "41" * 32
                elif self.mutation == "block_height":
                    block_height += 1
                elif self.mutation == "state_root":
                    state_root = "42" * 32
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "block": {
                        "hash": block_hash,
                        "header": {
                            "height": block_height,
                            "state_root_hash": state_root,
                        },
                        "body": {},
                    }
                },
            }
        if method == "query_balance_details":
            balance = EXACT_TREASURY_BASELINE_MOTES
            if endpoint == NODE_B and self.mutation == "balance":
                balance -= 1
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "name": "query_balance_details_result",
                    "value": {
                        "api_version": "2.0.0",
                        "total_balance": str(balance),
                        "available_balance": str(balance),
                        "total_balance_proof": "01" + ("ab" * 96),
                        "holds": [],
                    },
                },
            }
        raise AssertionError(f"unexpected snapshot RPC method {method}")


def _resolver(host: str) -> tuple[str, ...]:
    return {
        "rpc-a.example": ("8.8.8.8",),
        "rpc-b.example": ("1.1.1.1",),
        "same.example": ("8.8.8.8",),
        "private.example": ("10.0.0.1",),
    }[host]


def _operator(
    tmp_path: Path,
    rpc: FakeTreasuryRpc,
    *,
    clock=lambda: 100.0,
    source_commit: str = "a" * 40,
):
    authorization = rpc.authorization
    executor = TreasuryExecutor(
        tmp_path / "treasury.sqlite3",
        inflight_lease_seconds=1,
        clock=clock,
    )
    return TreasuryExecutionOperator(
        executor=executor,
        authorization=authorization,
        rpc=rpc,
        signer_loader=lambda: SOURCE_KEY,
        timestamp_seconds=TIMESTAMP_SECONDS,
        source_commit=source_commit,
        deployment_commit=DEPLOYMENT_COMMIT,
    )


def test_prepare_only_recomputes_exact_v3_and_raw_snapshot_without_rpc() -> None:
    proof = _temporally_valid_v3_proof()
    authorization = verify_native_authorization_artifacts(
        proof,
        _snapshot_artifact(proof),
    )
    assert authorization.proposal_id == proof["input"]["header"]["proposal_id"]  # type: ignore[index]
    assert authorization.amount_motes == EXACT_TRANSFER_MOTES
    assert (
        authorization.treasury_snapshot_balance_motes == EXACT_TREASURY_BASELINE_MOTES
    )
    assert authorization.approved_allocation_bps == EXACT_APPROVED_BPS


def test_snapshot_capture_binds_two_nodes_to_same_exact_625_cspr_state() -> None:
    rpc = FakeSnapshotRpc()
    artifact_bytes = capture_native_treasury_snapshot(rpc, SOURCE_ACCOUNT)
    artifact = json.loads(artifact_bytes)

    assert artifact["schema_id"] == "concordia.native-treasury-snapshot.v1"
    assert artifact["network"] == "casper-test"
    assert artifact["source_account_hash"] == SOURCE_ACCOUNT.hex()
    assert artifact["expected_balance_motes"] == str(EXACT_TREASURY_BASELINE_MOTES)
    assert len(artifact["observations"]) == 2
    assert "verified" not in artifact and "passed" not in artifact
    assert all(allow_submit is False for _, _, allow_submit in rpc.calls)
    assert all(method != "account_put_deploy" for _, method, _ in rpc.calls)


@pytest.mark.parametrize(
    "mutation",
    ("block_hash", "block_height", "state_root", "balance"),
)
def test_snapshot_capture_rejects_any_two_node_state_disagreement(
    mutation: str,
) -> None:
    rpc = FakeSnapshotRpc(mutation=mutation)
    with pytest.raises(OperatorError, match="snapshot|625|agree"):
        capture_native_treasury_snapshot(rpc, SOURCE_ACCOUNT)
    assert all(allow_submit is False for _, _, allow_submit in rpc.calls)


def test_unactivated_recipient_fails_before_signing_or_broadcast(
    tmp_path: Path,
) -> None:
    authorization = _verified()

    class MissingRecipientRpc(FakeTreasuryRpc):
        def call(
            self,
            endpoint: str,
            method: str,
            params: dict[str, object],
            request_id: object,
            *,
            allow_submit: bool = False,
        ) -> dict[str, object]:
            if method == "query_balance_details":
                purse = params["purse_identifier"]  # type: ignore[index]
                account = str(
                    purse["main_purse_under_account_hash"]  # type: ignore[index]
                )
                root = str(params["state_identifier"]["StateRootHash"])  # type: ignore[index]
                if (
                    account == f"account-hash-{RECIPIENT_ACCOUNT.hex()}"
                    and root == authorization.snapshot_state_root_hash.hex()
                ):
                    raise RpcRemoteError(-32001)
            return super().call(
                endpoint,
                method,
                params,
                request_id,
                allow_submit=allow_submit,
            )

    rpc = MissingRecipientRpc(authorization)
    signer_calls = 0

    def signer_loader() -> object:
        nonlocal signer_calls
        signer_calls += 1
        return SOURCE_KEY

    executor = TreasuryExecutor(tmp_path / "treasury.sqlite3")
    operator = TreasuryExecutionOperator(
        executor=executor,
        authorization=authorization,
        rpc=rpc,
        signer_loader=signer_loader,
        timestamp_seconds=TIMESTAMP_SECONDS,
        source_commit="a" * 40,
        deployment_commit=DEPLOYMENT_COMMIT,
    )

    with pytest.raises(OperatorError, match="recipient.*snapshot"):
        operator.advance(submit=True)

    assert signer_calls == 0
    assert rpc.broadcast_calls == 0
    assert executor.count() == 1


def test_cli_defaults_to_verification_only_without_signer_journal_or_rpc(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_path = tmp_path / "v3-proof.json"
    snapshot_path = tmp_path / "snapshot.json"
    proof_path.write_text("{}", encoding="utf-8")
    snapshot_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "scripts.run_treasury_execution.verify_native_authorization_artifacts",
        lambda *_: _verified(),
    )

    assert (
        main(
            [
                "--v3-proof",
                str(proof_path),
                "--treasury-snapshot",
                str(snapshot_path),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "verification-only"
    assert output["network_mutation_performed"] is False
    assert output["local_file_written"] is False
    assert list(tmp_path.glob("*.sqlite*")) == []


def test_cli_snapshot_capture_never_loads_signer_or_accepts_submit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rpc = FakeSnapshotRpc()
    monkeypatch.setattr(
        "scripts.run_treasury_execution.PinnedHttpsJsonRpc",
        lambda _urls, **_kwargs: rpc,
    )
    monkeypatch.setattr(
        "scripts.run_treasury_execution.load_signer_from_file",
        lambda *_: pytest.fail("read-only snapshot capture must not load a signer"),
    )
    output_path = tmp_path / "snapshot.json"

    assert (
        main(
            [
                "--capture-snapshot",
                "--source-account",
                SOURCE_ACCOUNT.hex(),
                "--rpc",
                NODE_A,
                "--rpc",
                NODE_B,
                "--snapshot-out",
                str(output_path),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "mode": "read-only-snapshot-capture",
        "network_mutation_performed": False,
        "local_file_written": True,
        "snapshot_written": True,
    }
    assert output_path.is_file()

    assert (
        main(
            [
                "--capture-snapshot",
                "--submit",
                "--source-account",
                SOURCE_ACCOUNT.hex(),
                "--rpc",
                NODE_A,
                "--rpc",
                NODE_B,
                "--snapshot-out",
                str(tmp_path / "forbidden.json"),
            ]
        )
        == 1
    )
    assert not (tmp_path / "forbidden.json").exists()


@pytest.mark.parametrize(
    "authorization",
    [
        replace(_verified(), treasury_snapshot_balance_motes=625_000_000_001),
        replace(_verified(), amount_motes=49_999_999_999),
        replace(_verified(), approved_allocation_bps=799),
    ],
)
def test_finals_story_rejects_wrong_baseline_amount_or_bps_before_signing(
    tmp_path: Path,
    authorization,
) -> None:
    rpc = FakeTreasuryRpc(authorization, fail_if_broadcast=True)
    with pytest.raises(OperatorError, match="625|50|800"):
        _operator(tmp_path, rpc)
    assert rpc.calls == []


def test_lost_broadcast_response_restarts_by_hash_without_second_send(
    tmp_path: Path,
) -> None:
    authorization = _verified()
    now = [100.0]
    first_rpc = FakeTreasuryRpc(authorization, lost_broadcast=True)
    first = _operator(tmp_path, first_rpc, clock=lambda: now[0])
    result = first.advance(submit=True)
    assert result.entry.state is ExecutionState.AMBIGUOUS_SUBMITTED
    assert result.artifact_bytes is None
    assert first_rpc.broadcast_calls == 1

    now[0] = 102.0
    resumed_rpc = FakeTreasuryRpc(authorization, fail_if_broadcast=True)
    resumed_rpc.deploy_hash = result.entry.deploy_hash
    resumed = _operator(tmp_path, resumed_rpc, clock=lambda: now[0])
    completed = resumed.advance(submit=True)
    assert resumed_rpc.broadcast_calls == 0
    assert completed.entry.state is ExecutionState.PROVEN
    assert completed.artifact_bytes is not None
    artifact = json.loads(completed.artifact_bytes)
    assert artifact["executor_journal"]["broadcast_attempts"] == 1
    assert artifact["authorization"]["typed_body"]["amount_motes"] == str(
        EXACT_TRANSFER_MOTES
    )


def test_restart_cannot_relabel_persisted_execution_with_new_source_commit(
    tmp_path: Path,
) -> None:
    authorization = _verified()
    now = [100.0]
    first_rpc = FakeTreasuryRpc(authorization, lost_broadcast=True)
    first = _operator(
        tmp_path,
        first_rpc,
        clock=lambda: now[0],
        source_commit="a" * 40,
    )
    assert first.advance(submit=True).entry.state is ExecutionState.AMBIGUOUS_SUBMITTED

    now[0] = 102.0
    resumed_rpc = FakeTreasuryRpc(authorization, fail_if_broadcast=True)
    resumed = _operator(
        tmp_path,
        resumed_rpc,
        clock=lambda: now[0],
        source_commit="c" * 40,
    )
    with pytest.raises(JournalConflict, match="immutable execution data"):
        resumed.advance(submit=True)
    assert resumed_rpc.broadcast_calls == 0


def test_endpoint_disagreement_pending_and_duplicate_transfer_never_emit_artifact(
    tmp_path: Path,
) -> None:
    for index, options in enumerate(
        (
            {"disagree": True},
            {"pending": True},
            {"absent": True},
            {"duplicate": True},
        ),
    ):
        authorization = _verified(action_nonce=bytes([index + 20]) * 32)
        rpc = FakeTreasuryRpc(authorization, **options)
        operator = _operator(tmp_path / str(index), rpc)
        result = operator.advance(submit=True)
        assert result.entry.state is not ExecutionState.PROVEN
        assert result.artifact_bytes is None
        assert rpc.broadcast_calls == 1
        resumed = operator.advance(submit=True)
        assert resumed.entry.state is not ExecutionState.PROVEN
        assert resumed.artifact_bytes is None
        assert rpc.broadcast_calls == 1


def test_rpc_policy_journal_and_signer_fail_closed_without_secret_echo(
    tmp_path: Path,
) -> None:
    assert (
        validate_public_rpc_endpoints([NODE_A, NODE_B], resolver=_resolver)[0].url
        == NODE_A
    )
    for urls in (
        ["http://rpc-a.example/rpc", NODE_B],
        ["https://token@rpc-a.example/rpc", NODE_B],
        ["https://rpc-a.example/rpc?token=secret", NODE_B],
        ["https://private.example/rpc", NODE_B],
        [NODE_A, "https://same.example/rpc"],
    ):
        with pytest.raises(RpcEndpointPolicyError):
            validate_public_rpc_endpoints(urls, resolver=_resolver)

    with pytest.raises(OperatorError, match="absolute durable SQLite"):
        require_durable_journal_path(Path("relative.db"))

    secret = "super-secret-key-material"
    key_path = tmp_path / "signer.pem"
    key_path.write_text(secret, encoding="utf-8")
    key_path.chmod(0o600)
    with pytest.raises(OperatorError) as error:
        load_signer_from_file(key_path, "ED25519", SOURCE_ACCOUNT)
    assert secret not in str(error.value)
    assert str(key_path) not in str(error.value)
    assert error.value.__cause__ is None


def test_signer_file_must_derive_the_exact_treasury_source(tmp_path: Path) -> None:
    key_path = tmp_path / "valid-signer.pem"
    key_path.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    parsed = parse_private_key(key_path, KeyAlgorithm.ED25519)
    expected = parsed.to_public_key().to_account_hash()

    loaded = load_signer_from_file(key_path, "ED25519", expected)
    assert loaded.to_public_key().to_account_hash() == expected
    with pytest.raises(OperatorError, match="does not match"):
        load_signer_from_file(key_path, "ED25519", bytes.fromhex("ff" * 32))


def test_signer_file_rejects_world_readable_and_symlink_ancestor(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    key_path = real / "signer.pem"
    key_path.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    parsed = parse_private_key(key_path, KeyAlgorithm.ED25519)
    expected = parsed.to_public_key().to_account_hash()
    key_path.chmod(0o644)
    with pytest.raises(OperatorError):
        load_signer_from_file(key_path, "ED25519", expected)

    key_path.chmod(0o600)
    ancestor = tmp_path / "ancestor"
    ancestor.symlink_to(real, target_is_directory=True)
    with pytest.raises(OperatorError) as captured:
        load_signer_from_file(ancestor / "signer.pem", "ED25519", expected)
    assert str(key_path) not in str(captured.value)
    assert str(ancestor) not in str(captured.value)
    assert captured.value.__cause__ is None


def test_signer_file_rejects_metadata_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = tmp_path / "signer.pem"
    key_path.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    parsed = parse_private_key(key_path, KeyAlgorithm.ED25519)
    expected = parsed.to_public_key().to_account_hash()
    real_fstat = secure_file.os.fstat
    regular_calls = 0

    def raced_fstat(descriptor: int) -> object:
        nonlocal regular_calls
        metadata = real_fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return metadata
        regular_calls += 1
        if regular_calls == 1:
            return metadata
        fields = {
            name: getattr(metadata, name)
            for name in (
                "st_mode",
                "st_uid",
                "st_size",
                "st_dev",
                "st_ino",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        fields["st_ctime_ns"] += 1
        return SimpleNamespace(**fields)

    monkeypatch.setattr(secure_file.os, "fstat", raced_fstat)
    with pytest.raises(OperatorError):
        load_signer_from_file(key_path, "ED25519", expected)


@pytest.mark.parametrize(
    "extra",
    (
        ("--journal", "/tmp/release.sqlite"),
        ("--signer-key-file", "/tmp/signer.pem"),
        ("--key-algorithm", "ED25519"),
        ("--artifact-out", "/tmp/artifact.json"),
        ("--source-account", "11" * 32),
        ("--snapshot-out", "/tmp/snapshot.json"),
    ),
)
def test_posthoc_mode_rejects_every_unrelated_argument(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, str],
) -> None:
    result = main(
        [
            "--finalize-release-manifest",
            str(tmp_path / "artifact.json"),
            "--artifact-commit",
            "ab" * 20,
            "--release-manifest-out",
            str(tmp_path / "release.json"),
            *extra,
        ]
    )
    assert result == 1
    assert "post-hoc finalization requires only" in capsys.readouterr().out


@pytest.mark.parametrize(
    "extra",
    (
        ("--source-account", "11" * 32),
        ("--snapshot-out", "/tmp/snapshot.json"),
        ("--artifact-commit", "ab" * 20),
        ("--release-manifest-out", "/tmp/release.json"),
    ),
)
def test_submit_mode_rejects_every_non_submit_argument(
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, str],
) -> None:
    result = main(["--submit", *extra])
    assert result == 1
    assert "submit mode accepts only" in capsys.readouterr().out


def test_atomic_artifact_write_is_idempotent_but_never_overwrites(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "artifact.json"
    atomic_write_once(destination, b'{"a":1}')
    atomic_write_once(destination, b'{"a":1}')
    with pytest.raises(OperatorError, match="different bytes"):
        atomic_write_once(destination, b'{"a":2}')


def test_posthoc_release_manifest_verifies_exact_committed_artifact_bytes(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "release-repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "release@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Release Test"],
        cwd=repository,
        check=True,
    )
    marker = repository / "source.txt"
    marker.write_text("source\n", encoding="utf-8")
    subprocess.run(["git", "add", "source.txt"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "source"], cwd=repository, check=True)
    source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    artifact = repository / "artifact.json"
    payload = json.dumps(
        {
            "schema_version": "concordia.native_treasury_execution.v1",
            "source_commit": source_commit,
            "deployment_commit": source_commit,
            "authorization": {
                "exact_v3_proof": {"deployment": {"deployment_commit": source_commit}}
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    artifact.write_bytes(payload)
    subprocess.run(["git", "add", "artifact.json"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "artifact"], cwd=repository, check=True)
    artifact_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    manifest = json.loads(
        build_posthoc_release_manifest(
            artifact_path=artifact,
            artifact_commit=artifact_commit,
            repository_root=repository,
        )
    )
    assert manifest["status"] == "artifact_commit_verified"
    assert manifest["artifact_commit"] == artifact_commit
    assert manifest["source_commit"] == source_commit
    assert manifest["artifact_sha256"] == hashlib.sha256(payload).hexdigest()

    artifact.write_bytes(payload + b" ")
    with pytest.raises(OperatorError, match="differs"):
        build_posthoc_release_manifest(
            artifact_path=artifact,
            artifact_commit=artifact_commit,
            repository_root=repository,
        )
