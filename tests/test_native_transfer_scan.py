"""Time-bounded, chain-derived no-second-transfer proof tests."""

from __future__ import annotations

import dataclasses

import pytest
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm

from shared.native_transfer_deploy import (
    DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    build_signed_native_transfer_deploy,
    validate_signed_native_transfer_deploy,
)
from shared.native_transfer_finality import verify_finalized_native_transfer
from shared.native_transfer_scan import (
    NativeTransferScanError,
    VerifiedNoDuplicateNativeTransfer,
    require_verified_no_duplicate_native_transfer,
    verify_no_duplicate_native_transfer,
    verify_no_duplicate_native_transfer_transcript,
)


SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
SOURCE = SOURCE_KEY.to_public_key().to_account_hash()
RECIPIENT = bytes.fromhex("22" * 32)
AMOUNT = 50_000_000_000
TRANSFER_ID = 0x0102_0304_0506_0708
AUTHORIZATION_HEIGHT = 8_400_121
INCLUSION_HEIGHT = 8_400_123
OBSERVED_HEIGHT = 8_400_124
BLOCK_HASHES = {height: f"{height - AUTHORIZATION_HEIGHT + 1:02x}" * 32 for height in range(AUTHORIZATION_HEIGHT, OBSERVED_HEIGHT + 1)}
STATE_ROOT = "cd" * 32

SIGNED = build_signed_native_transfer_deploy(
    source_private_key=SOURCE_KEY,
    recipient_account_hash=RECIPIENT,
    amount_motes=AMOUNT,
    transfer_id=TRANSFER_ID,
    payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    timestamp_seconds=1_753_228_800.0,
    ttl="30m",
)
DEPLOY_HASH = validate_signed_native_transfer_deploy(
    SIGNED,
    expected_source_account_hash=SOURCE,
    expected_recipient_account_hash=RECIPIENT,
    expected_amount_motes=AMOUNT,
    expected_transfer_id=TRANSFER_ID,
).deploy_hash_hex


def _finality():
    rpc = {
        "jsonrpc": "2.0",
        "id": "deploy",
        "result": {
            "deploy": {"hash": DEPLOY_HASH},
            "execution_results": [{
                "block_hash": BLOCK_HASHES[INCLUSION_HEIGHT],
                "result": {"Success": {"cost": "100000000", "transfers": []}},
            }],
        },
    }
    block = _block_response(INCLUSION_HEIGHT, request_id="finality-block")
    block["result"]["block"]["body"] = {  # type: ignore[index]
        "deploy_hashes": [],
        "transfer_hashes": [DEPLOY_HASH],
    }
    def observation(node_url: str, captured_at: str) -> dict[str, object]:
        return {
            "node_url": node_url,
            "captured_at": captured_at,
            "status_request": {
                "jsonrpc": "2.0",
                "id": "status",
                "method": "info_get_status",
                "params": {},
            },
            "status_response": {
                "jsonrpc": "2.0",
                "id": "status",
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
                "id": "deploy",
                "method": "info_get_deploy",
                "params": {
                    "deploy_hash": DEPLOY_HASH,
                    "finalized_approvals": True,
                },
            },
            "transaction_response": rpc,
            "canonical_block_request": {
                "jsonrpc": "2.0",
                "id": "finality-block",
                "method": "chain_get_block",
                "params": {
                    "block_identifier": {
                        "Hash": BLOCK_HASHES[INCLUSION_HEIGHT]
                    }
                },
            },
            "canonical_block_response": block,
        }
    return verify_finalized_native_transfer(
        requested_deploy_hash=DEPLOY_HASH,
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
        signed_deploy_bytes=SIGNED,
        expected_source_account_hash=SOURCE,
        expected_recipient_account_hash=RECIPIENT,
        expected_amount_motes=AMOUNT,
        expected_transfer_id=TRANSFER_ID,
        expected_payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        max_payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    )


def _block_request(height: int, *, request_id: object | None = None) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id if request_id is not None else f"block-{height}",
        "method": "chain_get_block",
        "params": {"block_identifier": {"Height": height}},
    }


def _block_response(height: int, *, request_id: object | None = None) -> dict[str, object]:
    parent_hash = (
        "aa" * 32
        if height == AUTHORIZATION_HEIGHT
        else BLOCK_HASHES[height - 1]
    )
    return {
        "jsonrpc": "2.0",
        "id": request_id if request_id is not None else f"block-{height}",
        "result": {
            "block": {
                "hash": BLOCK_HASHES[height],
                "header": {
                    "height": height,
                    "parent_hash": parent_hash,
                    "state_root_hash": STATE_ROOT,
                },
                "body": {"deploy_hashes": [], "transfer_hashes": []},
            }
        },
    }


def _transfers_request(height: int) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": f"transfers-{height}",
        "method": "chain_get_block_transfers",
        "params": {"block_identifier": {"Hash": BLOCK_HASHES[height]}},
    }


def _transfer(*, deploy_hash: str = DEPLOY_HASH, recipient: bytes = RECIPIENT, amount: int = AMOUNT, transfer_id: int = TRANSFER_ID) -> dict[str, object]:
    return {
        "Version1": {
            "deploy_hash": deploy_hash,
            "from": f"account-hash-{SOURCE.hex()}",
            "to": f"account-hash-{recipient.hex()}",
            "source": "uref-" + "11" * 32 + "-007",
            "target": "uref-" + "12" * 32 + "-000",
            "amount": str(amount),
            "gas": "100000000",
            "id": transfer_id,
        }
    }


def _transfers_response(height: int, transfers: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": f"transfers-{height}",
        "result": {
            "block_hash": BLOCK_HASHES[height],
            "transfers": transfers or [],
        },
    }


def _status_request() -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": "status", "method": "info_get_status", "params": {}}


def _status_response() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": "status",
        "result": {
            "chainspec_name": "casper-test",
            "last_added_block_info": {
                "hash": BLOCK_HASHES[OBSERVED_HEIGHT],
                "height": OBSERVED_HEIGHT,
            },
        },
    }


def _observations() -> list[dict[str, object]]:
    return [
        {
            "block_request": _block_request(height),
            "block_response": _block_response(height),
            "transfers_request": _transfers_request(height),
            "transfers_response": _transfers_response(
                height,
                [_transfer()] if height == INCLUSION_HEIGHT else [],
            ),
        }
        for height in range(AUTHORIZATION_HEIGHT, OBSERVED_HEIGHT + 1)
    ]


def _verify(**overrides: object) -> VerifiedNoDuplicateNativeTransfer:
    values: dict[str, object] = {
        "chain_status_request": _status_request(),
        "chain_status_response": _status_response(),
        "block_observations": _observations(),
        "authorization_block_height": AUTHORIZATION_HEIGHT,
        "finality_proof": _finality(),
    }
    values.update(overrides)
    return verify_no_duplicate_native_transfer(**values)


def test_exact_contiguous_scan_proves_one_transfer_only() -> None:
    proof = _verify()
    assert proof.network == "casper-test"
    assert proof.authorization_block_height == AUTHORIZATION_HEIGHT
    assert proof.authorization_block_hash == BLOCK_HASHES[AUTHORIZATION_HEIGHT]
    assert proof.inclusion_block_height == INCLUSION_HEIGHT
    assert proof.observed_through_block_height == OBSERVED_HEIGHT
    assert proof.matched_transfer_count == 1
    assert proof.deploy_hash == DEPLOY_HASH
    assert len(proof.transcript_sha256) == 64
    assert require_verified_no_duplicate_native_transfer(proof) is proof
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.matched_transfer_count = 2  # type: ignore[misc]


def test_constructor_and_post_factory_tamper_fail_closed() -> None:
    with pytest.raises(TypeError):
        VerifiedNoDuplicateNativeTransfer()  # type: ignore[call-arg]
    proof = _verify()
    object.__setattr__(proof, "matched_transfer_count", 2)
    with pytest.raises(NativeTransferScanError, match="integrity"):
        require_verified_no_duplicate_native_transfer(proof)


@pytest.mark.parametrize("missing_height", [AUTHORIZATION_HEIGHT, INCLUSION_HEIGHT, OBSERVED_HEIGHT])
def test_scan_must_cover_every_height(missing_height: int) -> None:
    observations = [item for item in _observations() if item["block_request"]["params"]["block_identifier"]["Height"] != missing_height]  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="contiguous"):
        _verify(block_observations=observations)


def test_second_transfer_with_same_source_and_transfer_id_fails() -> None:
    observations = _observations()
    observations[-1]["transfers_response"] = _transfers_response(OBSERVED_HEIGHT, [_transfer(deploy_hash="ef" * 32)])
    with pytest.raises(NativeTransferScanError, match="exactly one"):
        _verify(block_observations=observations)


@pytest.mark.parametrize("field", ["recipient", "amount", "deploy_hash"])
def test_only_matching_transfer_must_equal_finalized_action(field: str) -> None:
    kwargs: dict[str, object] = {}
    if field == "recipient":
        kwargs["recipient"] = bytes.fromhex("33" * 32)
    elif field == "amount":
        kwargs["amount"] = AMOUNT + 1
    else:
        kwargs["deploy_hash"] = "ef" * 32
    observations = _observations()
    observations[INCLUSION_HEIGHT - AUTHORIZATION_HEIGHT]["transfers_response"] = _transfers_response(INCLUSION_HEIGHT, [_transfer(**kwargs)])
    with pytest.raises(NativeTransferScanError, match="finalized action"):
        _verify(block_observations=observations)


def test_response_ids_and_block_hashes_are_bound() -> None:
    observations = _observations()
    observations[0]["transfers_response"]["id"] = "wrong"  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="response id"):
        _verify(block_observations=observations)

    observations = _observations()
    observations[0]["transfers_response"]["result"]["block_hash"] = "ff" * 32  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="block hash"):
        _verify(block_observations=observations)


def test_transfer_block_hash_must_equal_finality_block_hash() -> None:
    observations = _observations()
    index = INCLUSION_HEIGHT - AUTHORIZATION_HEIGHT
    wrong_hash = "fe" * 32
    observations[index]["block_response"]["result"]["block"]["hash"] = wrong_hash  # type: ignore[index]
    observations[index]["transfers_request"]["params"]["block_identifier"]["Hash"] = wrong_hash  # type: ignore[index]
    observations[index]["transfers_response"]["result"]["block_hash"] = wrong_hash  # type: ignore[index]
    observations[index + 1]["block_response"]["result"]["block"]["header"]["parent_hash"] = wrong_hash  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="finalized action"):
        _verify(block_observations=observations)


def test_every_adjacent_block_must_bind_parent_hash() -> None:
    observations = _observations()
    observations[2]["block_response"]["result"]["block"]["header"]["parent_hash"] = "ff" * 32  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="parent chain"):
        _verify(block_observations=observations)


def test_latest_status_bounds_scan_and_chain() -> None:
    bad = _status_response()
    bad["result"]["chainspec_name"] = "casper"  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="casper-test"):
        _verify(chain_status_response=bad)

    bad = _status_response()
    bad["result"]["last_added_block_info"]["height"] = OBSERVED_HEIGHT + 1  # type: ignore[index]
    with pytest.raises(NativeTransferScanError, match="contiguous"):
        _verify(chain_status_response=bad)


def test_scan_cannot_begin_after_authorization_or_end_before_inclusion() -> None:
    with pytest.raises(NativeTransferScanError, match="authorization"):
        _verify(authorization_block_height=INCLUSION_HEIGHT + 1)


def test_transcript_round_trip_reparse_detects_serialized_tamper() -> None:
    proof = _verify()
    transcript = proof.transcript_json.replace(DEPLOY_HASH, "ef" * 32)
    with pytest.raises(NativeTransferScanError):
        verify_no_duplicate_native_transfer_transcript(
            transcript,
            finality_proof=_finality(),
        )
