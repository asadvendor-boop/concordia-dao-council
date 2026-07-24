"""Durable composition gate for finalized treasury execution evidence."""

from __future__ import annotations

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from shared.casper_state_proof import verify_account_balance_at_block
from shared.native_transfer_finality import verify_finalized_native_transfer
from shared.native_transfer_scan import verify_no_duplicate_native_transfer
from shared.treasury_executor import (
    BroadcastResult,
    ExecutionState,
    InvalidTransition,
    JournalConflict,
    ReconciliationResult,
    TreasuryExecutor,
)
from tests.test_treasury_executor import (
    DEPLOYMENT_COMMIT,
    RECIPIENT_ACCOUNT,
    SOURCE_COMMIT,
    SOURCE_ACCOUNT,
    _evidence,
    _key,
    _signed,
    _verified,
)


GAS = 123_456_789
# The synthetic v3 proof finalizes at height 9,007 and is read back at 9,010.
# Model the governed native transfer as a later deploy so the duplicate scan
# begins at the exact authorization block without manufacturing millions of
# unrelated synthetic blocks.
FINALITY_HEIGHT = 9_012
FINALITY_HASH = bytes.fromhex("cd" * 32)
FINALITY_ROOT = bytes.fromhex("ce" * 32)


def _balance(
    *,
    account: bytes,
    block_hash: bytes,
    block_height: int,
    state_root: bytes,
    balance: int,
    request_base: int,
):
    return verify_account_balance_at_block(
        chain_status_request={
            "jsonrpc": "2.0",
            "id": request_base,
            "method": "info_get_status",
            "params": {},
        },
        chain_status_payload={
            "jsonrpc": "2.0",
            "id": request_base,
            "result": {"chainspec_name": "casper-test"},
        },
        canonical_block_request={
            "jsonrpc": "2.0",
            "id": request_base + 1,
            "method": "chain_get_block",
            "params": {"block_identifier": {"Hash": block_hash.hex()}},
        },
        canonical_block_payload={
            "jsonrpc": "2.0",
            "id": request_base + 1,
            "result": {
                "block": {
                    "hash": block_hash.hex(),
                    "header": {
                        "height": block_height,
                        "state_root_hash": state_root.hex(),
                    },
                    "body": {},
                }
            },
        },
        balance_request={
            "jsonrpc": "2.0",
            "id": request_base + 2,
            "method": "query_balance_details",
            "params": {
                "state_identifier": {"StateRootHash": state_root.hex()},
                "purse_identifier": {
                    "main_purse_under_account_hash": f"account-hash-{account.hex()}"
                },
            },
        },
        balance_response={
            "jsonrpc": "2.0",
            "id": request_base + 2,
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
        },
        expected_account_hash=account,
        expected_block_hash=block_hash,
        expected_block_height=block_height,
        expected_state_root_hash=state_root,
        expected_balance_motes=balance,
    )


def _finalized(tmp_path: Path):
    authorization = _verified()
    executor = TreasuryExecutor(tmp_path / "executor.db")
    executor.authorize(
        authorization,
        source_commit=SOURCE_COMMIT,
        deployment_commit=DEPLOYMENT_COMMIT,
    )
    prepared = executor.prepare(_key(authorization), lambda _: _signed(authorization))
    executor.broadcast(
        _key(authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )
    final = executor.reconcile(
        _key(authorization),
        lambda deploy_hash: ReconciliationResult(
            "finalized",
            deploy_hash,
            _evidence(
                deploy_hash,
                gas_motes=GAS,
                block_height=FINALITY_HEIGHT,
            ),
        ),
    )
    evidence = _evidence(
        prepared.deploy_hash or "",
        gas_motes=GAS,
        block_height=FINALITY_HEIGHT,
    )
    finality = verify_finalized_native_transfer(
        requested_deploy_hash=prepared.deploy_hash or "",
        node_observations=evidence.node_observations,
        signed_deploy_bytes=prepared.signed_bytes or b"",
        expected_source_account_hash=authorization.source_account,
        expected_recipient_account_hash=authorization.recipient_account,
        expected_amount_motes=authorization.amount_motes,
        expected_transfer_id=authorization.transfer_id,
        expected_payment_amount_motes=prepared.payment_amount_motes,
        max_payment_amount_motes=prepared.payment_amount_motes,
    )
    assert final.state is ExecutionState.FINALIZED
    return executor, authorization, finality


def _proof_inputs(
    tmp_path: Path,
    *,
    scan_authorization_block_hash: bytes | None = None,
    alternate_pre_source: bool = False,
):
    executor, authorization, finality = _finalized(tmp_path)
    pre_source = authorization.treasury_snapshot_balance_motes
    pre_recipient = 7_000_000_000
    if alternate_pre_source:
        pre_source_proof = _balance(
            account=SOURCE_ACCOUNT,
            block_hash=authorization.snapshot_block_hash,
            block_height=authorization.snapshot_block_height,
            state_root=authorization.snapshot_state_root_hash,
            balance=pre_source,
            request_base=100,
        )
    else:
        snapshot = json.loads(authorization.treasury_snapshot_artifact_json)
        observation = snapshot["observations"][0]
        pre_source_proof = verify_account_balance_at_block(
            chain_status_request=observation["status_request"],
            chain_status_payload=observation["status_response"],
            canonical_block_request=observation["block_request"],
            canonical_block_payload=observation["block_response"],
            balance_request=observation["balance_request"],
            balance_response=observation["balance_response"],
            expected_account_hash=authorization.source_account,
            expected_block_hash=authorization.snapshot_block_hash,
            expected_block_height=authorization.snapshot_block_height,
            expected_state_root_hash=authorization.snapshot_state_root_hash,
            expected_balance_motes=pre_source,
        )
    pre_recipient_proof = _balance(
        account=RECIPIENT_ACCOUNT,
        block_hash=authorization.snapshot_block_hash,
        block_height=authorization.snapshot_block_height,
        state_root=authorization.snapshot_state_root_hash,
        balance=pre_recipient,
        request_base=200,
    )
    post_source_proof = _balance(
        account=SOURCE_ACCOUNT,
        block_hash=FINALITY_HASH,
        block_height=FINALITY_HEIGHT,
        state_root=FINALITY_ROOT,
        balance=pre_source - authorization.amount_motes - GAS,
        request_base=300,
    )
    post_recipient_proof = _balance(
        account=RECIPIENT_ACCOUNT,
        block_hash=FINALITY_HASH,
        block_height=FINALITY_HEIGHT,
        state_root=FINALITY_ROOT,
        balance=pre_recipient + authorization.amount_motes,
        request_base=400,
    )

    start = authorization.finalization_block_height
    observed = FINALITY_HEIGHT + 1
    block_hashes = {
        height: f"{height - start + 1:064x}" for height in range(start, observed + 1)
    }
    block_hashes[start] = (
        scan_authorization_block_hash or authorization.finalization_block_hash
    ).hex()
    block_hashes[FINALITY_HEIGHT] = FINALITY_HASH.hex()
    observations = []
    for height in range(start, observed + 1):
        block_hash = block_hashes[height]
        parent_hash = "aa" * 32 if height == start else block_hashes[height - 1]
        transfers: list[dict[str, object]] = []
        if height == FINALITY_HEIGHT:
            transfers = [
                {
                    "Version1": {
                        "deploy_hash": finality.deploy_hash,
                        "from": f"account-hash-{SOURCE_ACCOUNT.hex()}",
                        "to": f"account-hash-{RECIPIENT_ACCOUNT.hex()}",
                        "source": "uref-" + "11" * 32 + "-007",
                        "target": "uref-" + "12" * 32 + "-000",
                        "amount": str(authorization.amount_motes),
                        "gas": str(GAS),
                        "id": authorization.transfer_id,
                    }
                }
            ]
        observations.append(
            {
                "block_request": {
                    "jsonrpc": "2.0",
                    "id": f"b-{height}",
                    "method": "chain_get_block",
                    "params": {"block_identifier": {"Height": height}},
                },
                "block_response": {
                    "jsonrpc": "2.0",
                    "id": f"b-{height}",
                    "result": {
                        "block": {
                            "hash": block_hash,
                            "header": {
                                "height": height,
                                "parent_hash": parent_hash,
                                "state_root_hash": "dd" * 32,
                            },
                            "body": {},
                        }
                    },
                },
                "transfers_request": {
                    "jsonrpc": "2.0",
                    "id": f"t-{height}",
                    "method": "chain_get_block_transfers",
                    "params": {"block_identifier": {"Hash": block_hash}},
                },
                "transfers_response": {
                    "jsonrpc": "2.0",
                    "id": f"t-{height}",
                    "result": {"block_hash": block_hash, "transfers": transfers},
                },
            }
        )
    no_duplicate = verify_no_duplicate_native_transfer(
        chain_status_request={
            "jsonrpc": "2.0",
            "id": "tip",
            "method": "info_get_status",
            "params": {},
        },
        chain_status_response={
            "jsonrpc": "2.0",
            "id": "tip",
            "result": {
                "chainspec_name": "casper-test",
                "last_added_block_info": {
                    "hash": block_hashes[observed],
                    "height": observed,
                },
            },
        },
        block_observations=observations,
        authorization_block_height=start,
        finality_proof=finality,
    )
    return (
        executor,
        authorization,
        {
            "pre_source_balance": pre_source_proof,
            "pre_recipient_balance": pre_recipient_proof,
            "post_source_balance": post_source_proof,
            "post_recipient_balance": post_recipient_proof,
            "no_duplicate_proof": no_duplicate,
        },
    )


def test_proof_gate_persists_and_reparses_all_raw_evidence(tmp_path: Path) -> None:
    executor, authorization, proofs = _proof_inputs(tmp_path)
    proven = executor.prove_execution(_key(authorization), **proofs)
    assert proven.state is ExecutionState.PROVEN
    assert proven.post_transfer_proof is not None
    assert proven.no_duplicate_proof is not None
    assert proven.execution_proof_sha256 is not None

    restarted = TreasuryExecutor(tmp_path / "executor.db").get(_key(authorization))
    assert restarted == proven
    assert restarted.state is ExecutionState.PROVEN


def test_proof_gate_is_idempotent_and_resume_never_reexecutes(tmp_path: Path) -> None:
    executor, authorization, proofs = _proof_inputs(tmp_path)
    first = executor.prove_execution(_key(authorization), **proofs)
    second = executor.prove_execution(_key(authorization), **proofs)
    assert second == first
    assert executor.resume(_key(authorization)) == first


@pytest.mark.parametrize("stale_result", ["pending", "finalized", "exception"])
def test_stale_reconcile_callback_cannot_demote_proven_execution(
    tmp_path: Path,
    stale_result: str,
) -> None:
    proof_dir = tmp_path / "proof-fixture"
    proof_dir.mkdir()
    _proof_executor, expected_authorization, proofs = _proof_inputs(proof_dir)

    database_path = tmp_path / "race.db"
    executor = TreasuryExecutor(database_path)
    executor.authorize(
        expected_authorization,
        source_commit=SOURCE_COMMIT,
        deployment_commit=DEPLOYMENT_COMMIT,
    )
    executor.prepare(
        _key(expected_authorization),
        lambda _: _signed(expected_authorization),
    )
    executor.broadcast(
        _key(expected_authorization),
        lambda _raw, deploy_hash: BroadcastResult("accepted", deploy_hash),
    )

    callback_entered = threading.Event()
    callback_release = threading.Event()

    def stale_callback(deploy_hash: str) -> ReconciliationResult:
        callback_entered.set()
        assert callback_release.wait(timeout=5)
        if stale_result == "exception":
            raise TimeoutError("stale node timeout")
        if stale_result == "finalized":
            return ReconciliationResult(
                "finalized",
                deploy_hash,
                _evidence(
                    deploy_hash,
                    gas_motes=GAS,
                    block_height=FINALITY_HEIGHT,
                ),
            )
        return ReconciliationResult("pending", deploy_hash)

    with ThreadPoolExecutor(max_workers=1) as pool:
        stale_future = pool.submit(
            TreasuryExecutor(database_path).reconcile,
            _key(expected_authorization),
            stale_callback,
        )
        assert callback_entered.wait(timeout=5)

        winning_executor = TreasuryExecutor(database_path)
        winning_executor.reconcile(
            _key(expected_authorization),
            lambda deploy_hash: ReconciliationResult(
                "finalized",
                deploy_hash,
                _evidence(
                    deploy_hash,
                    gas_motes=GAS,
                    block_height=FINALITY_HEIGHT,
                ),
            ),
        )
        proven = winning_executor.prove_execution(
            _key(expected_authorization),
            **proofs,
        )
        with sqlite3.connect(database_path) as db:
            row_before = db.execute(
                "SELECT * FROM treasury_execution_journal"
            ).fetchone()

        callback_release.set()
        assert stale_future.result(timeout=5) == proven

    with sqlite3.connect(database_path) as db:
        row_after = db.execute("SELECT * FROM treasury_execution_journal").fetchone()
    assert row_after == row_before
    assert TreasuryExecutor(database_path).get(_key(expected_authorization)) == proven


def test_proof_gate_rejects_nonfinalized_execution(tmp_path: Path) -> None:
    authorization = _verified()
    executor = TreasuryExecutor(tmp_path / "executor.db")
    executor.authorize(
        authorization,
        source_commit=SOURCE_COMMIT,
        deployment_commit=DEPLOYMENT_COMMIT,
    )
    with pytest.raises(InvalidTransition, match="AUTHORIZED"):
        executor.prove_execution(_key(authorization), **{})  # type: ignore[arg-type]


def test_proof_gate_requires_authorization_snapshot_as_pre_source(
    tmp_path: Path,
) -> None:
    executor, authorization, proofs = _proof_inputs(tmp_path)
    proofs["pre_source_balance"] = _balance(
        account=SOURCE_ACCOUNT,
        block_hash=bytes.fromhex("ab" * 32),
        block_height=authorization.snapshot_block_height - 1,
        state_root=bytes.fromhex("ac" * 32),
        balance=authorization.treasury_snapshot_balance_motes,
        request_base=500,
    )
    with pytest.raises(JournalConflict, match="authorization snapshot"):
        executor.prove_execution(_key(authorization), **proofs)


def test_proof_gate_rejects_competing_block_at_v3_authorization_height(
    tmp_path: Path,
) -> None:
    executor, authorization, proofs = _proof_inputs(
        tmp_path,
        scan_authorization_block_hash=bytes.fromhex("fe" * 32),
    )

    with pytest.raises(JournalConflict, match="authorization block hash"):
        executor.prove_execution(_key(authorization), **proofs)


@pytest.mark.parametrize(
    "column", ["post_balance_evidence_json", "no_duplicate_scan_json"]
)
def test_restart_rejects_tampered_persisted_execution_proof(
    tmp_path: Path, column: str
) -> None:
    executor, authorization, proofs = _proof_inputs(tmp_path)
    executor.prove_execution(_key(authorization), **proofs)
    database_path = tmp_path / "executor.db"
    with sqlite3.connect(database_path) as db:
        raw = db.execute(f"SELECT {column} FROM treasury_execution_journal").fetchone()[
            0
        ]
        decoded = json.loads(raw)
        if column == "post_balance_evidence_json":
            decoded["post_recipient"]["balance_response"]["result"]["balance"] = "1"
        else:
            decoded["authorization_block_height"] += 1
        db.execute(
            f"UPDATE treasury_execution_journal SET {column}=?",
            (json.dumps(decoded, sort_keys=True, separators=(",", ":")),),
        )
    with pytest.raises(JournalConflict, match="execution proof"):
        TreasuryExecutor(database_path).get(_key(authorization))
