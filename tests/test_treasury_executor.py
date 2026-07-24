"""TX-01..TX-14 acceptance tests for the durable v3 treasury executor."""

from __future__ import annotations

import copy
import json
import multiprocessing
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm

from shared.casper_state_proof import verify_account_balance_at_block
from shared.treasury_snapshot import verify_treasury_snapshot_artifact
from shared.native_transfer_deploy import (
    DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    build_signed_native_transfer_deploy,
)
from shared.treasury_executor import (
    AuthorizationMismatch,
    BroadcastResult,
    ExecutionKey,
    ExecutionState,
    FinalityEvidence,
    InvalidTransition,
    JournalConflict,
    ReconciliationResult,
    TreasuryExecutor,
)
from shared.v3_authorization import (
    V3DeploymentIdentity,
    VerifiedNativeAuthorization,
    verify_exact_v3_finalization,
    verify_native_authorization,
)
from scripts.read_v3_state import verify_and_seal_readback_artifact
from tests.v3_treasury_fixtures import treasury_v3_proof


SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
SOURCE_ACCOUNT = SOURCE_KEY.to_public_key().to_account_hash()
RECIPIENT_ACCOUNT = bytes.fromhex("42" * 32)
TIMESTAMP_SECONDS = 1_753_228_800.0
from tests.test_clvalue_roundtrip import _HISTORICAL_SOURCE_COMMIT

# The authorization/proof source commit must equal the deployment's declared
# build commit (the split-API historical verifier binds both to the frozen
# manifest pins at that exact commit).
SOURCE_COMMIT = _HISTORICAL_SOURCE_COMMIT
DEPLOYMENT_COMMIT = _HISTORICAL_SOURCE_COMMIT


def _verified(
    *,
    proposal_id: str = "DAO-PROP-V3-TREASURY",
    action_nonce: bytes = bytes.fromhex("44" * 32),
    recipient_account: bytes = RECIPIENT_ACCOUNT,
) -> VerifiedNativeAuthorization:
    proof = treasury_v3_proof(
        source_account=SOURCE_ACCOUNT,
        recipient_account=recipient_account,
        proposal_id=proposal_id,
        action_nonce=action_nonce,
    )
    header = proof["input"]["header"]
    body = proof["input"]["body"]
    deployment_raw = proof["deployment"]
    build = deployment_raw["build"]
    source = deployment_raw["source"]

    deployment = V3DeploymentIdentity(
        network="casper-test",
        package_hash=bytes.fromhex(str(deployment_raw["package_hash"])),
        contract_hash=bytes.fromhex(str(deployment_raw["contract_hash"])),
        schema_version=3,
        deployment_domain=bytes.fromhex(str(header["deployment_domain"])),
        casper_chain_name="casper-test",
        source_sha256=bytes.fromhex(str(source["lib_rs_sha256"])),
        wasm_sha256=bytes.fromhex(str(build["wasm_sha256"])),
        schema_sha256=bytes.fromhex(str(build["schema_sha256"])),
    )
    readback = verify_and_seal_readback_artifact(proof["readback"])
    snapshot_block_hash = str(body["snapshot_block_hash"])
    snapshot_block_height = int(str(body["snapshot_block_height"]))
    snapshot_state_root = "98" * 32
    snapshot_balance = int(str(body["treasury_snapshot_balance_motes"]))
    primary_snapshot = verify_account_balance_at_block(
        chain_status_request={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "info_get_status",
            "params": {},
        },
        chain_status_payload={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"chainspec_name": "casper-test"},
        },
        canonical_block_request={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "chain_get_block",
            "params": {"block_identifier": {"Hash": snapshot_block_hash}},
        },
        canonical_block_payload={
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "block": {
                    "hash": snapshot_block_hash,
                    "header": {
                        "height": snapshot_block_height,
                        "state_root_hash": snapshot_state_root,
                    },
                    "body": {},
                }
            },
        },
        balance_request={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "query_balance_details",
            "params": {
                "state_identifier": {"StateRootHash": snapshot_state_root},
                "purse_identifier": {
                    "main_purse_under_account_hash": f"account-hash-{SOURCE_ACCOUNT.hex()}"
                },
            },
        },
        balance_response={
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "name": "query_balance_details_result",
                "value": {
                    "api_version": "2.0.0",
                    "total_balance": str(snapshot_balance),
                    "available_balance": str(snapshot_balance),
                    "total_balance_proof": "01" + ("ab" * 96),
                    "holds": [],
                },
            },
        },
        expected_account_hash=SOURCE_ACCOUNT,
        expected_block_hash=bytes.fromhex(snapshot_block_hash),
        expected_block_height=snapshot_block_height,
        expected_state_root_hash=bytes.fromhex(snapshot_state_root),
        expected_balance_motes=snapshot_balance,
    )
    observations = []
    for index, node in enumerate(("rpc-a.example", "rpc-b.example"), start=1):
        observation = {
            "node_url": f"https://{node}/rpc",
            "captured_at": f"2026-07-23T00:00:0{index}Z",
            "status_request": json.loads(primary_snapshot.status_request_json),
            "status_response": json.loads(primary_snapshot.status_json),
            "block_request": json.loads(primary_snapshot.block_request_json),
            "block_response": json.loads(primary_snapshot.block_json),
            "balance_request": json.loads(primary_snapshot.balance_request_json),
            "balance_response": json.loads(primary_snapshot.balance_response_json),
        }
        for field in (
            "status_request",
            "status_response",
            "block_request",
            "block_response",
            "balance_request",
            "balance_response",
        ):
            observation[field]["id"] = index
        observations.append(observation)
    snapshot = verify_treasury_snapshot_artifact(
        {
            "schema_id": "concordia.native-treasury-snapshot.v1",
            "network": "casper-test",
            "source_account_hash": SOURCE_ACCOUNT.hex(),
            "expected_balance_motes": str(snapshot_balance),
            "observations": observations,
        },
        expected_account_hash=SOURCE_ACCOUNT,
        expected_block_hash=bytes.fromhex(snapshot_block_hash),
        expected_block_height=snapshot_block_height,
        expected_balance_motes=snapshot_balance,
    )
    return verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=readback,
        snapshot=snapshot,
        finalization=verify_exact_v3_finalization(proof),
    )


def _key(authorization: VerifiedNativeAuthorization) -> ExecutionKey:
    return ExecutionKey(
        authorization.network,
        authorization.action_id,
        authorization.envelope_hash,
    )


def _signed(authorization: VerifiedNativeAuthorization) -> bytes:
    return build_signed_native_transfer_deploy(
        source_private_key=SOURCE_KEY,
        recipient_account_hash=authorization.recipient_account,
        amount_motes=authorization.amount_motes,
        transfer_id=authorization.transfer_id,
        timestamp_seconds=TIMESTAMP_SECONDS,
    )


def _evidence(
    deploy_hash: str,
    *,
    gas_motes: int = 123_456_789,
    block_height: int = 8_600_100,
    mutate_rpc: object = None,
    mutate_block: object = None,
) -> FinalityEvidence:
    rpc: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "deploy": {"hash": deploy_hash},
            "execution_results": [
                {
                    "block_hash": "cd" * 32,
                    "result": {"Success": {"cost": str(gas_motes), "transfers": []}},
                }
            ],
        },
    }
    block: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "block": {
                "hash": "cd" * 32,
                "header": {
                    "height": block_height,
                    "state_root_hash": "ce" * 32,
                },
                "body": {"deploy_hashes": [], "transfer_hashes": [deploy_hash]},
            }
        },
    }
    if callable(mutate_rpc):
        mutate_rpc(rpc)
    if callable(mutate_block):
        mutate_block(block)

    def observation(node_url: str, captured_at: str) -> dict[str, object]:
        return {
            "node_url": node_url,
            "captured_at": captured_at,
            "status_request": {
                "jsonrpc": "2.0",
                "id": 90,
                "method": "info_get_status",
                "params": {},
            },
            "status_response": {
                "jsonrpc": "2.0",
                "id": 90,
                "result": {
                    "name": "info_get_status_result",
                    "value": {
                        "api_version": "2.0.0",
                        "chainspec_name": "casper-test",
                    },
                },
            },
            "transaction_request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "info_get_deploy",
                "params": {
                    "deploy_hash": deploy_hash,
                    "finalized_approvals": True,
                },
            },
            "transaction_response": copy.deepcopy(rpc),
            "canonical_block_request": {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "chain_get_block",
                "params": {"block_identifier": {"Hash": "cd" * 32}},
            },
            "canonical_block_response": copy.deepcopy(block),
        }

    return FinalityEvidence(
        (
            observation(
                "https://node.testnet.casper.network/rpc",
                "2026-07-23T00:01:02Z",
            ),
            observation(
                "https://rpc.testnet.casperlabs.io/rpc",
                "2026-07-23T00:01:04Z",
            ),
        )
    )


def _authorized_executor(
    database_path: Path,
    authorization: VerifiedNativeAuthorization | None = None,
    **executor_options: object,
) -> tuple[TreasuryExecutor, VerifiedNativeAuthorization]:
    authorization = authorization or _verified()
    executor = TreasuryExecutor(database_path, **executor_options)
    executor.authorize(
        authorization,
        source_commit=SOURCE_COMMIT,
        deployment_commit=DEPLOYMENT_COMMIT,
    )
    return executor, authorization


def _fail_if_called(*_args: object, **_kwargs: object) -> object:
    raise AssertionError("callback must not be called")


def _process_prepare(database_path: str, key: ExecutionKey, marker_path: str) -> None:
    executor = TreasuryExecutor(database_path)

    def build(authorization: VerifiedNativeAuthorization) -> bytes:
        with open(marker_path, "ab", buffering=0) as marker:
            marker.write(b"prepared\n")
        time.sleep(0.1)
        return _signed(authorization)

    executor.prepare(key, build)


def test_tx01_accepts_only_factory_verified_exact_envelope_authorization(
    tmp_path: Path,
) -> None:
    executor = TreasuryExecutor(tmp_path / "executor.db")
    authorization = _verified()

    with pytest.raises(AuthorizationMismatch, match="factory-verified"):
        executor.authorize(
            object(),  # type: ignore[arg-type]
            source_commit=SOURCE_COMMIT,
            deployment_commit=DEPLOYMENT_COMMIT,
        )
    with pytest.raises(AuthorizationMismatch, match="recomputed typed envelope"):
        executor.authorize(
            replace(authorization, amount_motes=1),
            source_commit=SOURCE_COMMIT,
            deployment_commit=DEPLOYMENT_COMMIT,
        )
    with pytest.raises(AuthorizationMismatch, match="deployment commit"):
        executor.authorize(
            authorization,
            source_commit=SOURCE_COMMIT,
            deployment_commit="ee" * 20,
        )

    entry = executor.authorize(
        authorization,
        source_commit=SOURCE_COMMIT,
        deployment_commit=DEPLOYMENT_COMMIT,
    )
    assert entry.authorization == authorization
    assert entry.state is ExecutionState.AUTHORIZED
    assert executor.count() == 1


def test_tx01_restart_revalidates_every_persisted_authorization_field(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)

    with sqlite3.connect(database_path) as db:
        db.execute(
            "UPDATE treasury_execution_journal SET approved_allocation_bps=801 "
            "WHERE network=? AND action_id=? AND envelope_hash=?",
            (
                _key(authorization).network,
                _key(authorization).action_id,
                _key(authorization).envelope_hash,
            ),
        )

    with pytest.raises(AuthorizationMismatch, match="recomputed typed envelope"):
        TreasuryExecutor(database_path).get(_key(authorization))
    assert executor.count() == 1


def test_tx01_restart_reparses_persisted_raw_snapshot_transcript(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    _executor, authorization = _authorized_executor(database_path)
    with sqlite3.connect(database_path) as db:
        transcript = db.execute(
            "SELECT snapshot_balance_response_json FROM treasury_execution_journal"
        ).fetchone()[0]
        db.execute(
            "UPDATE treasury_execution_journal SET snapshot_balance_response_json=?",
            (str(transcript).replace("625000000000", "625000000001"),),
        )

    with pytest.raises(AuthorizationMismatch, match="authorization transcript"):
        TreasuryExecutor(database_path).get(_key(authorization))


@pytest.mark.parametrize("mutation", ("drop", "swap", "mutate_second"))
def test_tx01_restart_reparses_exact_two_observer_snapshot_artifact(
    tmp_path: Path,
    mutation: str,
) -> None:
    database_path = tmp_path / "executor.db"
    _executor, authorization = _authorized_executor(database_path)
    with sqlite3.connect(database_path) as db:
        raw = db.execute(
            "SELECT treasury_snapshot_artifact_json FROM treasury_execution_journal"
        ).fetchone()[0]
        artifact = json.loads(raw)
        if mutation == "drop":
            artifact["observations"] = artifact["observations"][:1]
        elif mutation == "swap":
            artifact["observations"] = list(reversed(artifact["observations"]))
        else:
            value = artifact["observations"][1]["balance_response"]["result"]["value"]
            value["total_balance"] = "625000000001"
            value["available_balance"] = "625000000001"
        db.execute(
            "UPDATE treasury_execution_journal SET treasury_snapshot_artifact_json=?",
            (json.dumps(artifact, sort_keys=True, separators=(",", ":")),),
        )

    with pytest.raises(AuthorizationMismatch, match="snapshot|authorization"):
        TreasuryExecutor(database_path).get(_key(authorization))


def test_tx01_restart_reparses_persisted_exact_finalization_proof(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    _executor, authorization = _authorized_executor(database_path)
    with sqlite3.connect(database_path) as db:
        artifact = db.execute(
            "SELECT v3_proof_artifact_json FROM treasury_execution_journal"
        ).fetchone()[0]
        db.execute(
            "UPDATE treasury_execution_journal SET v3_proof_artifact_json=?",
            (
                str(artifact).replace(
                    authorization.finalization_state_root_hash.hex(),
                    "ff" * 32,
                    1,
                ),
            ),
        )

    with pytest.raises(AuthorizationMismatch, match="authorization transcript"):
        TreasuryExecutor(database_path).get(_key(authorization))


def test_tx02_persists_canonical_signed_bytes_and_derived_hash_before_broadcast(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    raw = _signed(authorization)
    prepared = executor.prepare(_key(authorization), lambda _: raw)

    assert prepared.state is ExecutionState.PREPARED
    assert prepared.signed_bytes == raw
    assert prepared.signed_bytes_sha256 is not None
    assert prepared.deploy_hash is not None

    observed: list[ExecutionState] = []

    def broadcast(signed_bytes: bytes, deploy_hash: str) -> BroadcastResult:
        persisted = TreasuryExecutor(database_path).get(_key(authorization))
        observed.append(persisted.state)
        assert persisted.signed_bytes == signed_bytes == raw
        assert persisted.deploy_hash == deploy_hash == prepared.deploy_hash
        return BroadcastResult("accepted", deploy_hash)

    submitted = executor.broadcast(_key(authorization), broadcast)
    assert observed == [ExecutionState.AMBIGUOUS_SUBMITTED]
    assert submitted.state is ExecutionState.SUBMITTED
    assert submitted.broadcast_attempts == 1


@pytest.mark.parametrize("raw", [b"not-a-deploy", b""])
def test_tx02_invalid_signed_bytes_never_enter_the_journal(
    tmp_path: Path,
    raw: bytes,
) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    expected = ValueError if not raw else AuthorizationMismatch
    with pytest.raises(expected):
        executor.prepare(_key(authorization), lambda _: raw)
    entry = executor.get(_key(authorization))
    assert entry.state is ExecutionState.AUTHORIZED
    assert entry.signed_bytes is None
    assert entry.deploy_hash is None


def test_tx03_concurrent_prepare_has_exactly_one_signer_invocation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls = 0

    def invoke() -> object:
        nonlocal calls
        barrier.wait()

        def sign(_: VerifiedNativeAuthorization) -> bytes:
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.05)
            return _signed(authorization)

        return TreasuryExecutor(database_path).prepare(_key(authorization), sign)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(), range(2)))

    assert calls == 1
    assert {result.state for result in results} == {ExecutionState.PREPARED}
    assert executor.count() == 1


def test_tx03_two_processes_cannot_claim_the_same_action(tmp_path: Path) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    marker_path = tmp_path / "prepare-calls.log"
    context = multiprocessing.get_context("spawn")
    workers = [
        context.Process(
            target=_process_prepare,
            args=(str(database_path), _key(authorization), str(marker_path)),
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert [worker.exitcode for worker in workers] == [0, 0]
    assert marker_path.read_bytes().splitlines() == [b"prepared"]
    assert executor.get(_key(authorization)).state is ExecutionState.PREPARED


def test_tx04_duplicate_prepare_is_idempotent_and_never_resigns(tmp_path: Path) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    first = executor.prepare(_key(authorization), lambda _: _signed(authorization))
    second = executor.prepare(_key(authorization), _fail_if_called)
    assert second == first


def test_tx05_concurrent_broadcast_has_exactly_one_network_invocation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls = 0

    def invoke() -> object:
        nonlocal calls
        barrier.wait()

        def submit(_: bytes, deploy_hash: str) -> BroadcastResult:
            nonlocal calls
            with lock:
                calls += 1
            time.sleep(0.05)
            return BroadcastResult("accepted", deploy_hash)

        return TreasuryExecutor(database_path).broadcast(_key(authorization), submit)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(), range(2)))

    assert calls == 1
    assert {result.state for result in results} <= {
        ExecutionState.AMBIGUOUS_SUBMITTED,
        ExecutionState.SUBMITTED,
    }
    assert executor.get(_key(authorization)).state is ExecutionState.SUBMITTED
    assert executor.get(_key(authorization)).broadcast_attempts == 1


def test_tx05_submitted_and_finalized_replays_never_broadcast_again(
    tmp_path: Path,
) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    submitted = executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    assert executor.broadcast(_key(authorization), _fail_if_called) == submitted
    final = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(
            "finalized", deploy_hash, _evidence(deploy_hash)
        ),
    )
    assert executor.broadcast(_key(authorization), _fail_if_called) == final
    assert (
        executor.resume(
            _key(authorization),
            prepare=_fail_if_called,
            broadcast=_fail_if_called,
            reconcile=_fail_if_called,
        )
        == final
    )


def test_tx06_crash_or_timeout_after_write_stays_ambiguous(tmp_path: Path) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))

    def crash(_raw: bytes, _deploy_hash: str) -> BroadcastResult:
        raise TimeoutError("connection dropped after network write")

    ambiguous = executor.broadcast(_key(authorization), crash)
    assert ambiguous.state is ExecutionState.AMBIGUOUS_SUBMITTED
    assert ambiguous.last_detail_code == "broadcast_exception_TimeoutError"
    assert ambiguous.broadcast_attempts == 1


def test_tx06_live_broadcast_lease_blocks_racing_reconciliation(tmp_path: Path) -> None:
    now = [100.0]
    executor, authorization = _authorized_executor(
        tmp_path / "executor.db", clock=lambda: now[0], inflight_lease_seconds=30
    )
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    callback_entered = threading.Event()
    callback_release = threading.Event()

    def submit(_raw: bytes, deploy_hash: str) -> BroadcastResult:
        callback_entered.set()
        assert callback_release.wait(timeout=5)
        return BroadcastResult("accepted", deploy_hash)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(executor.broadcast, _key(authorization), submit)
        assert callback_entered.wait(timeout=5)
        calls = 0

        def reconcile(_deploy_hash: str) -> ReconciliationResult:
            nonlocal calls
            calls += 1
            return ReconciliationResult("pending", _deploy_hash)

        raced = executor.reconcile(_key(authorization), reconcile)
        assert raced.state is ExecutionState.AMBIGUOUS_SUBMITTED
        assert calls == 0
        callback_release.set()
        assert future.result(timeout=5).state is ExecutionState.SUBMITTED


def test_tx07_expired_ambiguous_lease_reconciles_only_by_stored_hash(
    tmp_path: Path,
) -> None:
    now = [100.0]
    executor, authorization = _authorized_executor(
        tmp_path / "executor.db", clock=lambda: now[0], inflight_lease_seconds=10
    )
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    ambiguous = executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("ambiguous", deploy_hash, "timeout"),
    )
    now[0] = 111.0
    seen: list[str] = []
    final = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: (
            seen.append(deploy_hash)
            or ReconciliationResult("finalized", deploy_hash, _evidence(deploy_hash))
        ),
    )
    assert seen == [ambiguous.deploy_hash]
    assert final.state is ExecutionState.FINALIZED


def test_tx08_retryable_failure_survives_restart_and_reuses_identical_bytes(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    raw = _signed(authorization)
    executor.prepare(_key(authorization), lambda _: raw)
    retryable = executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult(
            "retryable_failure", deploy_hash, "node_unavailable"
        ),
    )
    assert retryable.state is ExecutionState.RETRYABLE_FAILURE
    attempts: list[tuple[bytes, str]] = []
    submitted = TreasuryExecutor(database_path).resume(
        _key(authorization),
        broadcast=lambda signed, deploy_hash: (
            attempts.append((signed, deploy_hash))
            or BroadcastResult("accepted", deploy_hash)
        ),
    )
    assert attempts == [(raw, retryable.deploy_hash)]
    assert submitted.state is ExecutionState.SUBMITTED
    assert submitted.broadcast_attempts == 2


def test_tx09_corrupted_persisted_bytes_fail_terminal_before_network(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    with sqlite3.connect(database_path) as db:
        db.execute(
            "UPDATE treasury_execution_journal SET signed_bytes=? "
            "WHERE network=? AND action_id=? AND envelope_hash=?",
            (
                b"corrupt",
                _key(authorization).network,
                _key(authorization).action_id,
                _key(authorization).envelope_hash,
            ),
        )
    failed = TreasuryExecutor(database_path).broadcast(
        _key(authorization), _fail_if_called
    )
    assert failed.state is ExecutionState.TERMINAL_FAILURE
    assert failed.last_detail_code == "signed_bytes_digest_mismatch"
    assert failed.broadcast_attempts == 0


def test_tx09_rehashed_but_semantically_corrupt_bytes_fail_full_validation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    corrupt = b"not-a-canonical-casper-deploy"
    import hashlib

    with sqlite3.connect(database_path) as db:
        db.execute(
            "UPDATE treasury_execution_journal SET signed_bytes=?, signed_bytes_sha256=? "
            "WHERE network=? AND action_id=? AND envelope_hash=?",
            (
                corrupt,
                hashlib.sha256(corrupt).hexdigest(),
                _key(authorization).network,
                _key(authorization).action_id,
                _key(authorization).envelope_hash,
            ),
        )
    failed = TreasuryExecutor(database_path).broadcast(
        _key(authorization), _fail_if_called
    )
    assert failed.state is ExecutionState.TERMINAL_FAILURE
    assert failed.last_detail_code == "signed_deploy_validation_failed"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("pending", ExecutionState.SUBMITTED),
        ("retryable_absent", ExecutionState.RETRYABLE_FAILURE),
        ("terminal_failure", ExecutionState.SUBMITTED),
        ("invented", ExecutionState.SUBMITTED),
    ],
)
def test_tx10_reconciliation_statuses_are_fail_closed(
    tmp_path: Path,
    status: str,
    expected: ExecutionState,
) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    result = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(status, deploy_hash),
    )
    assert result.state is expected


@pytest.mark.parametrize(
    ("mutate_rpc", "mutate_block"),
    [
        (
            lambda rpc: rpc["result"]["deploy"].update(hash="aa" * 32),
            None,
        ),
        (
            lambda rpc: rpc["result"]["execution_results"].clear(),
            None,
        ),
        (
            lambda rpc: rpc["result"]["execution_results"][0].update(
                result={"Failure": {"cost": "1", "error_message": "revert"}}
            ),
            None,
        ),
        (
            None,
            lambda block: block["result"]["block"].update(hash="aa" * 32),
        ),
        (
            None,
            lambda block: block["result"]["block"]["body"]["transfer_hashes"].clear(),
        ),
    ],
    ids=("wrong-hash", "unprocessed", "failed", "noncanonical-block", "not-included"),
)
def test_tx11_finalized_status_is_untrusted_without_strict_node_evidence(
    tmp_path: Path,
    mutate_rpc: object,
    mutate_block: object,
) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    submitted = executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    failed = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(
            "finalized",
            deploy_hash,
            _evidence(
                deploy_hash,
                mutate_rpc=mutate_rpc,
                mutate_block=mutate_block,
            ),
        ),
    )
    assert failed.state is ExecutionState.SUBMITTED
    assert failed.last_detail_code == "finality_evidence_invalid"
    assert submitted.deploy_hash == failed.deploy_hash


def test_tx11_finalized_status_without_evidence_is_terminal(tmp_path: Path) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    failed = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult("finalized", deploy_hash),
    )
    assert failed.state is ExecutionState.SUBMITTED
    assert failed.last_detail_code == "finality_evidence_missing"


def test_tx11_artifact_booleans_cannot_substitute_for_node_evidence(
    tmp_path: Path,
) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    booleans = FinalityEvidence(
        ({"processed": True, "finalized": True, "success": True},)
    )
    failed = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult("finalized", deploy_hash, booleans),
    )
    assert failed.state is ExecutionState.SUBMITTED
    assert failed.last_detail_code == "finality_evidence_invalid"


def test_callback_declared_terminal_failure_is_quarantined_until_proven(
    tmp_path: Path,
) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    ambiguous = executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult(
            "terminal_failure", deploy_hash, "caller_claimed_revert"
        ),
    )
    assert ambiguous.state is ExecutionState.AMBIGUOUS_SUBMITTED
    assert ambiguous.last_detail_code == "unverified_broadcast_terminal_failure"
    unresolved = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(
            "terminal_failure", deploy_hash, detail_code="caller_claimed_revert"
        ),
    )
    assert unresolved.state is ExecutionState.AMBIGUOUS_SUBMITTED
    assert unresolved.last_detail_code == "unverified_reconcile_terminal_failure"


def test_local_integrity_terminal_failure_is_never_retried(tmp_path: Path) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    with sqlite3.connect(database_path) as db:
        db.execute("UPDATE treasury_execution_journal SET signed_bytes=X'01'")
    failed = executor.broadcast(_key(authorization), _fail_if_called)
    assert failed.state is ExecutionState.TERMINAL_FAILURE
    assert (
        TreasuryExecutor(database_path).resume(
            _key(authorization),
            prepare=_fail_if_called,
            broadcast=_fail_if_called,
            reconcile=_fail_if_called,
        )
        == failed
    )


def test_tx12_global_action_id_binding_blocks_reauthorization_under_new_proposal(
    tmp_path: Path,
) -> None:
    executor, first = _authorized_executor(tmp_path / "executor.db")
    assert (
        executor.authorize(
            first,
            source_commit=SOURCE_COMMIT,
            deployment_commit=DEPLOYMENT_COMMIT,
        ).state
        is ExecutionState.AUTHORIZED
    )
    second = _verified(proposal_id="DAO-PROP-V3-OTHER")
    assert second.action_id == first.action_id
    assert second.envelope_hash != first.envelope_hash
    with pytest.raises(JournalConflict, match="action_id"):
        executor.authorize(
            second,
            source_commit=SOURCE_COMMIT,
            deployment_commit=DEPLOYMENT_COMMIT,
        )
    assert executor.count() == 1


def test_tx13_new_action_nonce_creates_a_distinct_legitimate_action(
    tmp_path: Path,
) -> None:
    executor, first = _authorized_executor(tmp_path / "executor.db")
    second = _verified(action_nonce=bytes.fromhex("45" * 32))
    assert second.action_id != first.action_id
    assert (
        executor.authorize(
            second,
            source_commit=SOURCE_COMMIT,
            deployment_commit=DEPLOYMENT_COMMIT,
        ).state
        is ExecutionState.AUTHORIZED
    )
    assert executor.count() == 2


def test_tx14_finalized_proof_fields_and_gas_survive_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    submitted = executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    final = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(
            "finalized",
            deploy_hash,
            _evidence(deploy_hash, gas_motes=987_654_321),
        ),
    )
    restarted = TreasuryExecutor(database_path).get(_key(authorization))
    assert final == restarted
    assert restarted.state is ExecutionState.FINALIZED
    assert restarted.deploy_hash == submitted.deploy_hash
    assert restarted.block_hash == "cd" * 32
    assert restarted.block_height == 8_600_100
    assert restarted.state_root_hash == "ce" * 32
    assert restarted.gas_motes == 987_654_321
    assert restarted.finality_rpc_method == "info_get_deploy"
    assert restarted.execution_result_kind == "Success"
    assert restarted.block_inclusion_path == "transfer_hashes"
    assert restarted.finality_checks
    assert restarted.corroboration_count == 1
    assert restarted.amount_motes == 50_000_000_000
    assert restarted.amount_motes != restarted.gas_motes
    assert executor.integrity_check() == "ok"


@pytest.mark.parametrize("tamper", ["evidence", "derived-field"])
def test_tx14_restart_revalidates_persisted_finality_evidence(
    tmp_path: Path,
    tamper: str,
) -> None:
    database_path = tmp_path / "executor.db"
    executor, authorization = _authorized_executor(database_path)
    executor.prepare(_key(authorization), lambda _: _signed(authorization))
    executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(
            "finalized", deploy_hash, _evidence(deploy_hash)
        ),
    )
    with sqlite3.connect(database_path) as db:
        if tamper == "evidence":
            observations_json = db.execute(
                "SELECT finality_node_observations_json FROM treasury_execution_journal"
            ).fetchone()[0]
            db.execute(
                "UPDATE treasury_execution_journal "
                "SET finality_node_observations_json=?",
                (str(observations_json).replace("ce" * 32, "aa" * 32),),
            )
        else:
            db.execute("UPDATE treasury_execution_journal SET gas_motes='1'")

    with pytest.raises(JournalConflict, match="persisted finality"):
        TreasuryExecutor(database_path).get(_key(authorization))


def test_reconcile_before_submission_is_rejected(tmp_path: Path) -> None:
    executor, authorization = _authorized_executor(tmp_path / "executor.db")
    with pytest.raises(InvalidTransition, match="AUTHORIZED"):
        executor.reconcile(_key(authorization), _fail_if_called)


def test_constructor_requires_durable_file_and_bounded_payment(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="durable"):
        TreasuryExecutor(":memory:")
    with pytest.raises(ValueError, match="non-zero"):
        TreasuryExecutor(tmp_path / "zero.db", payment_amount_motes=0)
    executor = TreasuryExecutor(
        tmp_path / "payment.db",
        payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    )
    assert executor.integrity_check() == "ok"
