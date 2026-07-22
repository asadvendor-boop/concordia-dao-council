"""Strict post-execution native-transfer balance proof tests."""

from __future__ import annotations

import dataclasses
import hashlib

import pytest
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm

from shared.casper_state_proof import verify_account_balance_at_block
from shared.native_transfer_deploy import build_signed_native_transfer_deploy
from shared.native_transfer_finality import verify_finalized_native_transfer
from shared.post_transfer_proof import (
    PostTransferBalanceProof,
    PostTransferProofError,
    require_verified_post_transfer_balance,
    verify_post_transfer_balance,
)


MAX_U512 = (1 << 512) - 1
SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
SOURCE = SOURCE_KEY.to_public_key().to_account_hash()
RECIPIENT = bytes.fromhex("22" * 32)
AMOUNT = 50_000_000_000
GAS = 100_000_000
PRE_SOURCE = 625_000_000_000
POST_SOURCE = PRE_SOURCE - AMOUNT - GAS
PRE_RECIPIENT = 7_000_000_000
POST_RECIPIENT = PRE_RECIPIENT + AMOUNT
PRE_BLOCK = bytes.fromhex("31" * 32)
PRE_ROOT = bytes.fromhex("32" * 32)
PRE_HEIGHT = 8_400_000
POST_BLOCK = bytes.fromhex("41" * 32)
POST_ROOT = bytes.fromhex("42" * 32)
POST_HEIGHT = 8_400_123
TRANSFER_ID = 0x0102_0304_0506_0708


def _balance(
    *,
    account: bytes,
    block_hash: bytes,
    state_root: bytes,
    height: int,
    balance: int,
    request_id_base: int,
):
    status_id = request_id_base
    block_id = request_id_base + 1
    balance_id = request_id_base + 2
    status_request = {
        "jsonrpc": "2.0",
        "id": status_id,
        "method": "info_get_status",
        "params": {},
    }
    status_payload = {
        "jsonrpc": "2.0",
        "id": status_id,
        "result": {
            "name": "info_get_status_result",
            "value": {"api_version": "2.0.0", "chainspec_name": "casper-test"},
        },
    }
    block_request = {
        "jsonrpc": "2.0",
        "id": block_id,
        "method": "chain_get_block",
        "params": {"block_identifier": {"Hash": block_hash.hex()}},
    }
    block_payload = {
        "jsonrpc": "2.0",
        "id": block_id,
        "result": {
            "name": "chain_get_block_result",
            "value": {
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": block_hash.hex(),
                            "header": {
                                "height": height,
                                "state_root_hash": state_root.hex(),
                            },
                            "body": {"transactions": {}},
                        }
                    },
                    "proofs": [],
                }
            },
        },
    }
    balance_request = {
        "jsonrpc": "2.0",
        "id": balance_id,
        "method": "query_balance_details",
        "params": {
            "state_identifier": {"StateRootHash": state_root.hex()},
            "purse_identifier": {
                "main_purse_under_account_hash": "account-hash-" + account.hex()
            },
        },
    }
    balance_response = {
        "jsonrpc": "2.0",
        "id": balance_id,
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
    return verify_account_balance_at_block(
        chain_status_request=status_request,
        chain_status_payload=status_payload,
        canonical_block_request=block_request,
        canonical_block_payload=block_payload,
        balance_request=balance_request,
        balance_response=balance_response,
        expected_account_hash=account,
        expected_block_hash=block_hash,
        expected_block_height=height,
        expected_state_root_hash=state_root,
        expected_balance_motes=balance,
    )


def _finality(*, amount: int = AMOUNT, gas: int = GAS):
    signed = build_signed_native_transfer_deploy(
        source_private_key=SOURCE_KEY,
        recipient_account_hash=RECIPIENT,
        amount_motes=amount,
        transfer_id=TRANSFER_ID,
        timestamp_seconds=1_753_228_800.0,
    )
    from shared.native_transfer_deploy import validate_signed_native_transfer_deploy

    deploy_hash = validate_signed_native_transfer_deploy(
        signed,
        expected_source_account_hash=SOURCE,
        expected_recipient_account_hash=RECIPIENT,
        expected_amount_motes=amount,
        expected_transfer_id=TRANSFER_ID,
    ).deploy_hash_hex
    rpc_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "name": "info_get_deploy_result",
            "value": {
                "deploy": {"hash": deploy_hash},
                "execution_info": {
                    "block_hash": POST_BLOCK.hex(),
                    "block_height": POST_HEIGHT,
                    "execution_result": {
                        "Version2": {"error_message": None, "cost": str(gas)}
                    },
                },
            },
        },
    }
    block_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "name": "chain_get_block_result",
            "value": {
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": POST_BLOCK.hex(),
                            "header": {
                                "height": POST_HEIGHT,
                                "state_root_hash": POST_ROOT.hex(),
                            },
                            "body": {
                                "transactions": {"0": [{"Deploy": deploy_hash}]}
                            },
                        }
                    },
                    "proofs": [],
                }
            },
        },
    }
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
            "transaction_response": rpc_payload,
            "canonical_block_request": {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "chain_get_block",
                "params": {
                    "block_identifier": {"Hash": POST_BLOCK.hex()}
                },
            },
            "canonical_block_response": block_payload,
        }
    return verify_finalized_native_transfer(
        requested_deploy_hash=deploy_hash,
        node_observations=(
            observation(
                "https://node.testnet.casper.network/rpc",
                "2026-07-23T00:01:02Z",
            ),
            observation(
                "https://rpc.testnet.casperlabs.io/rpc",
                "2026-07-23T00:01:04Z",
            ),
        ),
        signed_deploy_bytes=signed,
        expected_source_account_hash=SOURCE,
        expected_recipient_account_hash=RECIPIENT,
        expected_amount_motes=amount,
        expected_transfer_id=TRANSFER_ID,
    )


def _inputs(
    *,
    amount: int = AMOUNT,
    gas: int = GAS,
    pre_source: int = PRE_SOURCE,
    post_source: int = POST_SOURCE,
    pre_recipient: int = PRE_RECIPIENT,
    post_recipient: int = POST_RECIPIENT,
) -> dict[str, object]:
    return {
        "pre_source_balance": _balance(
            account=SOURCE,
            block_hash=PRE_BLOCK,
            state_root=PRE_ROOT,
            height=PRE_HEIGHT,
            balance=pre_source,
            request_id_base=10,
        ),
        "pre_recipient_balance": _balance(
            account=RECIPIENT,
            block_hash=PRE_BLOCK,
            state_root=PRE_ROOT,
            height=PRE_HEIGHT,
            balance=pre_recipient,
            request_id_base=20,
        ),
        "post_source_balance": _balance(
            account=SOURCE,
            block_hash=POST_BLOCK,
            state_root=POST_ROOT,
            height=POST_HEIGHT,
            balance=post_source,
            request_id_base=30,
        ),
        "post_recipient_balance": _balance(
            account=RECIPIENT,
            block_hash=POST_BLOCK,
            state_root=POST_ROOT,
            height=POST_HEIGHT,
            balance=post_recipient,
            request_id_base=40,
        ),
        "finality_proof": _finality(amount=amount, gas=gas),
        "expected_source_account_hash": SOURCE,
        "expected_recipient_account_hash": RECIPIENT,
        "expected_amount_motes": amount,
    }


def _verify(**overrides: object) -> PostTransferBalanceProof:
    inputs = _inputs()
    inputs.update(overrides)
    return verify_post_transfer_balance(**inputs)


def test_factory_proves_exact_post_transfer_balance_deltas_and_inventory() -> None:
    inputs = _inputs()
    proof = verify_post_transfer_balance(**inputs)

    assert proof.network == "casper-test"
    assert proof.source_account_hash == SOURCE
    assert proof.recipient_account_hash == RECIPIENT
    assert proof.pre_block_hash == PRE_BLOCK
    assert proof.pre_block_height == PRE_HEIGHT
    assert proof.pre_state_root_hash == PRE_ROOT
    assert proof.post_block_hash == POST_BLOCK
    assert proof.post_block_height == POST_HEIGHT
    assert proof.post_state_root_hash == POST_ROOT
    assert proof.source_balance_before_motes == PRE_SOURCE
    assert proof.source_balance_after_motes == POST_SOURCE
    assert proof.recipient_balance_before_motes == PRE_RECIPIENT
    assert proof.recipient_balance_after_motes == POST_RECIPIENT
    assert proof.amount_motes == AMOUNT
    assert proof.gas_motes == GAS
    assert proof.source_delta_motes == AMOUNT + GAS
    assert proof.recipient_delta_motes == AMOUNT
    assert proof.deploy_hash == inputs["finality_proof"].deploy_hash
    assert proof.signed_deploy_sha256 == hashlib.sha256(
        inputs["finality_proof"].signed_deploy.canonical_signed_bytes
    ).hexdigest()
    assert len(proof.transcript_sha256_inventory) == 24
    inventory = dict(proof.transcript_sha256_inventory)
    assert inventory["pre_source.status_request"] == inputs[
        "pre_source_balance"
    ].status_request_sha256
    assert inventory["post_recipient.balance_response"] == inputs[
        "post_recipient_balance"
    ].balance_response_sha256
    assert require_verified_post_transfer_balance(proof) is proof
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.amount_motes = 1  # type: ignore[misc]


def test_constructor_is_hidden_and_fabricated_instances_fail_closed() -> None:
    with pytest.raises(TypeError):
        PostTransferBalanceProof()  # type: ignore[call-arg]
    fabricated = object.__new__(PostTransferBalanceProof)
    with pytest.raises(PostTransferProofError, match="not factory-verified"):
        require_verified_post_transfer_balance(fabricated)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("amount_motes", 1),
        ("source_balance_after_motes", 1),
        ("deploy_hash", "00" * 32),
        ("transcript_sha256_inventory", ()),
    ],
)
def test_output_tampering_fails_process_local_integrity_gate(
    field: str, value: object
) -> None:
    proof = _verify()
    object.__setattr__(proof, field, value)
    with pytest.raises(PostTransferProofError, match="integrity"):
        require_verified_post_transfer_balance(proof)


@pytest.mark.parametrize(
    "role",
    [
        "pre_source_balance",
        "pre_recipient_balance",
        "post_source_balance",
        "post_recipient_balance",
    ],
)
def test_each_input_balance_must_retain_its_parser_integrity(role: str) -> None:
    inputs = _inputs()
    object.__setattr__(inputs[role], "balance_motes", 1)
    with pytest.raises(PostTransferProofError, match="balance proof"):
        verify_post_transfer_balance(**inputs)


def test_finality_input_must_retain_its_parser_integrity() -> None:
    inputs = _inputs()
    object.__setattr__(inputs["finality_proof"], "gas_motes", 1)
    with pytest.raises(PostTransferProofError, match="finality proof"):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("block_hash", bytes.fromhex("55" * 32), "pre-state block"),
        ("block_height", PRE_HEIGHT + 1, "pre-state height"),
        ("state_root_hash", bytes.fromhex("56" * 32), "pre-state root"),
    ],
)
def test_pre_source_and_recipient_must_share_one_canonical_snapshot(
    field: str, replacement: object, error: str
) -> None:
    inputs = _inputs()
    original = inputs["pre_recipient_balance"]
    values = {
        "block_hash": original.block_hash,
        "block_height": original.block_height,
        "state_root": original.state_root_hash,
    }
    values[field if field != "state_root_hash" else "state_root"] = replacement
    inputs["pre_recipient_balance"] = _balance(
        account=RECIPIENT,
        block_hash=values["block_hash"],
        state_root=values["state_root"],
        height=values["block_height"],
        balance=PRE_RECIPIENT,
        request_id_base=20,
    )
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("role", "field", "replacement", "error"),
    [
        ("post_source_balance", "block_hash", bytes.fromhex("61" * 32), "finality block"),
        ("post_recipient_balance", "height", POST_HEIGHT + 1, "finality height"),
        ("post_source_balance", "state_root", bytes.fromhex("62" * 32), "finality state root"),
    ],
)
def test_both_post_balances_must_be_at_the_exact_finality_snapshot(
    role: str, field: str, replacement: object, error: str
) -> None:
    inputs = _inputs()
    is_source = role == "post_source_balance"
    values: dict[str, object] = {
        "block_hash": POST_BLOCK,
        "state_root": POST_ROOT,
        "height": POST_HEIGHT,
    }
    values[field] = replacement
    inputs[role] = _balance(
        account=SOURCE if is_source else RECIPIENT,
        block_hash=values["block_hash"],
        state_root=values["state_root"],
        height=values["height"],
        balance=POST_SOURCE if is_source else POST_RECIPIENT,
        request_id_base=30 if is_source else 40,
    )
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


def test_pre_snapshot_must_strictly_precede_post_snapshot() -> None:
    inputs = _inputs()
    inputs["pre_source_balance"] = _balance(
        account=SOURCE,
        block_hash=PRE_BLOCK,
        state_root=PRE_ROOT,
        height=POST_HEIGHT,
        balance=PRE_SOURCE,
        request_id_base=10,
    )
    inputs["pre_recipient_balance"] = _balance(
        account=RECIPIENT,
        block_hash=PRE_BLOCK,
        state_root=PRE_ROOT,
        height=POST_HEIGHT,
        balance=PRE_RECIPIENT,
        request_id_base=20,
    )
    with pytest.raises(PostTransferProofError, match="strictly precede"):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("role", "account", "error"),
    [
        ("pre_source_balance", RECIPIENT, "pre-source account"),
        ("post_source_balance", RECIPIENT, "post-source account"),
        ("pre_recipient_balance", SOURCE, "pre-recipient account"),
        ("post_recipient_balance", SOURCE, "post-recipient account"),
    ],
)
def test_each_balance_role_is_bound_to_the_exact_expected_account(
    role: str, account: bytes, error: str
) -> None:
    inputs = _inputs()
    post = role.startswith("post")
    source_role = role.endswith("source_balance")
    inputs[role] = _balance(
        account=account,
        block_hash=POST_BLOCK if post else PRE_BLOCK,
        state_root=POST_ROOT if post else PRE_ROOT,
        height=POST_HEIGHT if post else PRE_HEIGHT,
        balance=(POST_SOURCE if post else PRE_SOURCE)
        if source_role
        else (POST_RECIPIENT if post else PRE_RECIPIENT),
        request_id_base={
            "pre_source_balance": 10,
            "pre_recipient_balance": 20,
            "post_source_balance": 30,
            "post_recipient_balance": 40,
        }[role],
    )
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("post_balance", "error"),
    [
        (PRE_RECIPIENT + AMOUNT - 1, "recipient delta"),
        (PRE_RECIPIENT + AMOUNT + 1, "recipient delta"),
        (PRE_RECIPIENT - 1, "recipient balance decreased"),
    ],
)
def test_recipient_delta_must_be_exactly_transfer_amount(
    post_balance: int, error: str
) -> None:
    inputs = _inputs(post_recipient=post_balance)
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("post_balance", "error"),
    [
        (POST_SOURCE - 1, "source delta"),
        (POST_SOURCE + 1, "source delta"),
        (PRE_SOURCE + 1, "source balance increased"),
    ],
)
def test_source_delta_must_be_exactly_amount_plus_finality_gas(
    post_balance: int, error: str
) -> None:
    inputs = _inputs(post_source=post_balance)
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


def test_amount_plus_gas_u512_overflow_fails_before_arithmetic() -> None:
    inputs = _inputs(
        amount=1,
        gas=MAX_U512,
        pre_source=MAX_U512,
        post_source=0,
        pre_recipient=0,
        post_recipient=1,
    )
    with pytest.raises(PostTransferProofError, match="U512 overflow"):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("expected_source_account_hash", b"x", "source account"),
        ("expected_recipient_account_hash", b"x", "recipient account"),
        ("expected_amount_motes", True, "positive U512"),
        ("expected_amount_motes", 0, "positive U512"),
        ("expected_amount_motes", MAX_U512 + 1, "positive U512"),
    ],
)
def test_expected_inputs_are_exact_typed_values(
    field: str, value: object, error: str
) -> None:
    inputs = _inputs()
    inputs[field] = value
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


def test_source_and_recipient_must_be_distinct() -> None:
    inputs = _inputs()
    inputs["expected_recipient_account_hash"] = SOURCE
    with pytest.raises(PostTransferProofError, match="distinct"):
        verify_post_transfer_balance(**inputs)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("expected_source_account_hash", bytes.fromhex("77" * 32), "signed transfer source"),
        ("expected_recipient_account_hash", bytes.fromhex("78" * 32), "signed transfer recipient"),
        ("expected_amount_motes", AMOUNT + 1, "signed transfer amount"),
    ],
)
def test_expected_action_must_match_the_finalized_signed_transfer(
    field: str, value: object, error: str
) -> None:
    inputs = _inputs()
    inputs[field] = value
    with pytest.raises(PostTransferProofError, match=error):
        verify_post_transfer_balance(**inputs)


def test_transcript_inventory_is_canonical_ordered_and_complete() -> None:
    inputs = _inputs()
    proof = verify_post_transfer_balance(**inputs)
    expected_labels = tuple(
        f"{role}.{field}"
        for role in ("pre_source", "pre_recipient", "post_source", "post_recipient")
        for field in (
            "status_request",
            "status",
            "block_request",
            "block",
            "balance_request",
            "balance_response",
        )
    )

    assert tuple(label for label, _sha in proof.transcript_sha256_inventory) == expected_labels
    assert all(len(sha) == 64 and sha == sha.lower() for _label, sha in proof.transcript_sha256_inventory)
