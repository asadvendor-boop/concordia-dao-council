"""Fail-closed canonical block and historical account-balance proof tests."""

from __future__ import annotations

import dataclasses

import pytest

from shared.casper_state_proof import (
    CasperStateProofError,
    VerifiedAccountBalance,
    require_verified_account_balance,
    verify_account_balance_at_block,
)


ACCOUNT = bytes.fromhex("41" * 32)
BLOCK_HASH = "42" * 32
STATE_ROOT = "43" * 32
HEIGHT = 8_600_000
BALANCE = 625_000_000_000
AVAILABLE_BALANCE = 624_000_000_000
HOLD_AMOUNT = BALANCE - AVAILABLE_BALANCE
MERKLE_PROOF = "01" + ("ab" * 96)


def _status() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "name": "info_get_status_result",
            "value": {"api_version": "2.0.0", "chainspec_name": "casper-test"},
        },
    }


def _status_request() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "info_get_status",
        "params": {},
    }


def _block(*, modern: bool = True) -> dict[str, object]:
    value: dict[str, object] = {
        "hash": BLOCK_HASH,
        "header": {"height": HEIGHT, "state_root_hash": STATE_ROOT},
        "body": {"transactions": {}},
    }
    if not modern:
        return {"jsonrpc": "2.0", "id": 2, "result": {"block": value}}
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "name": "chain_get_block_result",
            "value": {
                "block_with_signatures": {
                    "block": {"Version2": value},
                    "proofs": [],
                }
            },
        },
    }


def _block_request() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "chain_get_block",
        "params": {"block_identifier": {"Hash": BLOCK_HASH}},
    }


def _balance_request() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "query_balance_details",
        "params": {
            "state_identifier": {"StateRootHash": STATE_ROOT},
            "purse_identifier": {
                "main_purse_under_account_hash": f"account-hash-{ACCOUNT.hex()}"
            },
        },
    }


def _balance_response(*, modern: bool = True) -> dict[str, object]:
    result: dict[str, object] = {
        "api_version": "2.0.0",
        "total_balance": str(BALANCE),
        "available_balance": str(AVAILABLE_BALANCE),
        "total_balance_proof": MERKLE_PROOF,
        "holds": [
            {
                "time": 1_753_228_800_000,
                "amount": str(HOLD_AMOUNT),
                "proof": "02" + ("cd" * 64),
            }
        ],
    }
    if modern:
        result = {"name": "query_balance_details_result", "value": result}
    return {"jsonrpc": "2.0", "id": 3, "result": result}


def _verify(**overrides: object) -> VerifiedAccountBalance:
    values: dict[str, object] = {
        "chain_status_request": _status_request(),
        "chain_status_payload": _status(),
        "canonical_block_request": _block_request(),
        "canonical_block_payload": _block(),
        "balance_request": _balance_request(),
        "balance_response": _balance_response(),
        "expected_account_hash": ACCOUNT,
        "expected_block_hash": bytes.fromhex(BLOCK_HASH),
        "expected_block_height": HEIGHT,
        "expected_state_root_hash": bytes.fromhex(STATE_ROOT),
        "expected_balance_motes": BALANCE,
    }
    values.update(overrides)
    return verify_account_balance_at_block(**values)


def test_factory_accepts_exact_casper_test_block_and_state_root_balance() -> None:
    proof = _verify(
        canonical_block_payload=_block(),
        balance_response=_balance_response(),
    )

    assert proof.network == "casper-test"
    assert proof.account_hash == ACCOUNT
    assert proof.block_hash == bytes.fromhex(BLOCK_HASH)
    assert proof.block_height == HEIGHT
    assert proof.state_root_hash == bytes.fromhex(STATE_ROOT)
    assert proof.balance_motes == BALANCE
    assert proof.available_balance_motes == AVAILABLE_BALANCE
    assert proof.balance_holds_total_motes == HOLD_AMOUNT
    assert proof.node_provided_merkle_proof == bytes.fromhex(MERKLE_PROOF)
    assert proof.merkle_proof_verification_scope == "node-provided-not-locally-verified"
    assert "cryptographically_verified" not in proof.__slots__
    assert proof.balance_request_method == "query_balance_details"
    assert proof.balance_request_id == 3
    assert require_verified_account_balance(proof) is proof
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.balance_motes = 1  # type: ignore[misc]


def test_balance_details_requires_exact_named_result_wrapper() -> None:
    with pytest.raises(CasperStateProofError, match="named result wrapper"):
        _verify(balance_response=_balance_response(modern=False))


def test_factory_constructor_is_not_public() -> None:
    with pytest.raises(TypeError):
        VerifiedAccountBalance()  # type: ignore[call-arg]
    fabricated = object.__new__(VerifiedAccountBalance)
    with pytest.raises(CasperStateProofError, match="not parser-verified"):
        require_verified_account_balance(fabricated)


def test_post_factory_tampering_fails_integrity_gate() -> None:
    proof = _verify()
    object.__setattr__(proof, "balance_motes", 1)
    with pytest.raises(CasperStateProofError, match="integrity"):
        require_verified_account_balance(proof)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda payload: payload["result"]["value"].update(
                chainspec_name="casper-mainnet"
            ),
            "casper-test",
        ),
        (lambda payload: payload.update(error={"code": -1}), "contains error"),
        (lambda payload: payload["result"].update(value={}), "status result"),
    ],
    ids=("wrong-network", "rpc-error", "empty-status"),
)
def test_status_must_prove_casper_test(mutator: object, error: str) -> None:
    payload = _status()
    assert callable(mutator)
    mutator(payload)
    with pytest.raises(CasperStateProofError, match=error):
        _verify(chain_status_payload=payload)


@pytest.mark.parametrize(
    ("request_name", "mutator", "error"),
    [
        (
            "status",
            lambda request: request.update(method="info_get_peers"),
            "info_get_status",
        ),
        (
            "block",
            lambda request: request["params"]["block_identifier"].update(
                Hash="aa" * 32
            ),
            "block hash",
        ),
        (
            "block",
            lambda request: request["params"].update(extra=True),
            "exactly",
        ),
    ],
)
def test_status_and_block_requests_are_exactly_bound(
    request_name: str,
    mutator: object,
    error: str,
) -> None:
    request = _status_request() if request_name == "status" else _block_request()
    assert callable(mutator)
    mutator(request)
    argument = (
        {"chain_status_request": request}
        if request_name == "status"
        else {"canonical_block_request": request}
    )
    with pytest.raises(CasperStateProofError, match=error):
        _verify(**argument)


@pytest.mark.parametrize(
    ("field", "bad", "error"),
    [
        ("hash", "aa" * 32, "block hash"),
        ("height", HEIGHT + 1, "block height"),
        ("state_root_hash", "aa" * 32, "state root"),
    ],
)
def test_canonical_block_must_match_every_expected_snapshot_field(
    field: str,
    bad: object,
    error: str,
) -> None:
    payload = _block()
    block = payload["result"]["value"]["block_with_signatures"]["block"]["Version2"]
    if field == "hash":
        block[field] = bad
    else:
        block["header"][field] = bad
    with pytest.raises(CasperStateProofError, match=error):
        _verify(canonical_block_payload=payload)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda request: request.update(method="query_global_state"),
            "query_balance_details",
        ),
        (
            lambda request: request["params"]["state_identifier"].update(
                StateRootHash="aa" * 32
            ),
            "state root",
        ),
        (
            lambda request: request["params"]["purse_identifier"].update(
                main_purse_under_account_hash="account-hash-" + "aa" * 32
            ),
            "account hash",
        ),
        (lambda request: request["params"].update(extra=True), "exactly"),
    ],
    ids=("wrong-method", "wrong-root", "wrong-account", "extra-param"),
)
def test_balance_request_binds_exact_method_state_root_and_account(
    mutator: object,
    error: str,
) -> None:
    request = _balance_request()
    assert callable(mutator)
    mutator(request)
    with pytest.raises(CasperStateProofError, match=error):
        _verify(balance_request=request)


@pytest.mark.parametrize(
    ("balance", "error"),
    [
        (True, "canonical"),
        (-1, "canonical"),
        ("0625000000000", "canonical"),
        ("1.0", "canonical"),
        (str(1 << 512), "U512"),
        (None, "canonical"),
    ],
)
def test_balance_response_requires_canonical_u512_decimal(
    balance: object,
    error: str,
) -> None:
    response = _balance_response()
    response["result"]["value"]["total_balance"] = balance
    with pytest.raises(CasperStateProofError, match=error):
        _verify(balance_response=response)


def test_balance_response_id_must_match_request() -> None:
    response = _balance_response()
    response["id"] = 4
    with pytest.raises(CasperStateProofError, match="id"):
        _verify(balance_response=response)


@pytest.mark.parametrize(
    ("response_name", "error"),
    [
        ("query_balance_result", "query_balance_details_result"),
        ("query_balance_details_result_v2", "query_balance_details_result"),
    ],
)
def test_balance_response_name_must_match_proof_bearing_method(
    response_name: str, error: str
) -> None:
    response = _balance_response()
    response["result"]["name"] = response_name
    with pytest.raises(CasperStateProofError, match=error):
        _verify(balance_response=response)


def test_plain_query_balance_is_never_accepted_as_proof() -> None:
    request = _balance_request()
    request["method"] = "query_balance"
    response = {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "name": "query_balance_result",
            "value": {"api_version": "2.0.0", "balance": str(BALANCE)},
        },
    }

    with pytest.raises(CasperStateProofError, match="query_balance_details"):
        _verify(balance_request=request, balance_response=response)


@pytest.mark.parametrize(
    ("field", "bad", "error"),
    [
        ("available_balance", None, "available balance"),
        ("holds", {}, "holds"),
        ("total_balance_proof", "", "Merkle proof"),
        ("total_balance_proof", "AB", "Merkle proof"),
        ("total_balance_proof", "abc", "Merkle proof"),
    ],
)
def test_balance_details_requires_full_proof_bearing_schema(
    field: str, bad: object, error: str
) -> None:
    response = _balance_response()
    response["result"]["value"][field] = bad

    with pytest.raises(CasperStateProofError, match=error):
        _verify(balance_response=response)


def test_balance_details_rejects_unknown_or_missing_result_fields() -> None:
    response = _balance_response()
    response["result"]["value"]["verified"] = True
    with pytest.raises(CasperStateProofError, match="exactly frozen fields"):
        _verify(balance_response=response)

    response = _balance_response()
    response["result"]["value"].pop("holds")
    with pytest.raises(CasperStateProofError, match="exactly frozen fields"):
        _verify(balance_response=response)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (lambda hold: hold.update(amount="01"), "hold amount"),
        (lambda hold: hold.update(time=True), "hold time"),
        (lambda hold: hold.update(proof=""), "hold proof"),
        (lambda hold: hold.update(extra=True), "hold fields"),
    ],
)
def test_holds_are_strict_and_available_balance_matches_total_minus_holds(
    mutator: object, error: str
) -> None:
    response = _balance_response()
    hold = response["result"]["value"]["holds"][0]
    assert callable(mutator)
    mutator(hold)
    with pytest.raises(CasperStateProofError, match=error):
        _verify(balance_response=response)

    response = _balance_response()
    response["result"]["value"]["available_balance"] = str(AVAILABLE_BALANCE + 1)
    with pytest.raises(CasperStateProofError, match="hold arithmetic"):
        _verify(balance_response=response)


def test_wrong_expected_balance_fails_closed() -> None:
    with pytest.raises(CasperStateProofError, match="balance"):
        _verify(expected_balance_motes=BALANCE + 1)


def test_empty_or_explorer_boolean_payloads_never_become_proof() -> None:
    with pytest.raises(CasperStateProofError):
        _verify(canonical_block_payload={"canonical": True, "finalized": True})
    with pytest.raises(CasperStateProofError):
        _verify(balance_response={"verified": True, "balance": str(BALANCE)})
