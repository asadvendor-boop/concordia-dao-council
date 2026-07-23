"""Fail-closed verification: only exact finalized evidence is accepted."""

from __future__ import annotations

import pytest

from mc_support import make_observation
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.verify import (
    evaluate_expected_prequorum_refusal,
    evaluate_expected_success,
    evaluate_native_transfer_readback,
    evaluate_step_observations,
    validate_observation,
)

PACKAGE = "8b" * 32
CONTRACT = "9c" * 32
QUORUM_NOT_MET = "User error: 8"

_SUCCESS_TARGET = {
    "package_hash": PACKAGE,
    "contract_hash": CONTRACT,
    "entry_point": "approve_envelope",
    "typed_args": {"proposal_id": "MAINNET-CANARY-001", "envelope_hash": "ab" * 32},
    "transfer": None,
}


def _success_observation(**overrides: object) -> dict[str, object]:
    target = dict(_SUCCESS_TARGET)
    target_override = overrides.pop("target", None)
    if isinstance(target_override, dict):
        target.update(target_override)
    return make_observation("F-approve-signer-a", target=target, **overrides)


def _evaluate_success(observation: dict[str, object]) -> None:
    evaluate_expected_success(
        validate_observation(observation),
        package_hash=PACKAGE,
        contract_hash=CONTRACT,
        entry_point="approve_envelope",
        typed_args=dict(_SUCCESS_TARGET["typed_args"]),
    )


def test_exact_finalized_success_is_accepted() -> None:
    _evaluate_success(_success_observation())


def test_pending_execution_is_refused() -> None:
    observation = _success_observation(block={"status": "pending"})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.PROOF_PENDING


def test_unsigned_block_proof_is_refused() -> None:
    observation = _success_observation(block={"block_proofs_present": False})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.PROOF_UNSIGNED


def test_non_member_deploy_is_refused() -> None:
    observation = _success_observation(block={"deploy_is_member": False})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.PROOF_NOT_MEMBER


def test_malformed_block_evidence_is_refused() -> None:
    observation = _success_observation(block={"block_hash": "zz"})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED


def test_missing_observation_fields_are_refused() -> None:
    observation = _success_observation()
    del observation["execution"]
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED


def test_testnet_observation_is_refused() -> None:
    observation = _success_observation(chain_name_observed="casper-test")
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.NETWORK_MISMATCH


def test_execution_error_where_success_expected_is_refused() -> None:
    observation = _success_observation(
        execution={"success": False, "error_message": "User error: 16"}
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.EXECUTION_FAILED


def test_wrong_contract_is_refused() -> None:
    observation = _success_observation(target={"contract_hash": "11" * 32})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.WRONG_CONTRACT


def test_wrong_entry_point_is_refused() -> None:
    observation = _success_observation(target={"entry_point": "propose_envelope"})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.WRONG_ENTRY_POINT


def test_wrong_typed_args_post_quorum_envelope_is_refused() -> None:
    tampered_args = {
        "proposal_id": "MAINNET-CANARY-001",
        "envelope_hash": "cd" * 32,
    }
    observation = _success_observation(target={"typed_args": tampered_args})
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_success(observation)
    assert refusal.value.code == RefusalCode.WRONG_TYPED_ARGS


def _prequorum(observation: dict[str, object]) -> None:
    evaluate_expected_prequorum_refusal(
        validate_observation(observation),
        package_hash=PACKAGE,
        contract_hash=CONTRACT,
        entry_point="approve_envelope",
        typed_args=dict(_SUCCESS_TARGET["typed_args"]),
        expected_error_message=QUORUM_NOT_MET,
    )


def test_exact_finalized_quorum_not_met_is_positive_proof() -> None:
    observation = _success_observation(
        execution={"success": False, "error_message": QUORUM_NOT_MET}
    )
    _prequorum(observation)


def test_prequorum_success_is_refused() -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        _prequorum(_success_observation())
    assert refusal.value.code == RefusalCode.PREQUORUM_UNEXPECTED_SUCCESS


def test_prequorum_wrong_error_code_is_refused() -> None:
    observation = _success_observation(
        execution={"success": False, "error_message": "User error: 10"}
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _prequorum(observation)
    assert refusal.value.code == RefusalCode.WRONG_REFUSAL_CODE


def test_prequorum_pending_refusal_is_not_proof() -> None:
    observation = _success_observation(
        block={"status": "pending"},
        execution={"success": False, "error_message": QUORUM_NOT_MET},
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _prequorum(observation)
    assert refusal.value.code == RefusalCode.PROOF_PENDING


_TRANSFER = {
    "source_account": "1a" * 32,
    "recipient_account": "2b" * 32,
    "amount_motes": "50000000000",
    "transfer_id": "9337813909867025738",
}


def _transfer_observation(**transfer_overrides: object) -> dict[str, object]:
    transfer = dict(_TRANSFER)
    transfer.update(transfer_overrides)
    return make_observation(
        "I-executor-native-transfer",
        target={
            "package_hash": None,
            "contract_hash": None,
            "entry_point": None,
            "typed_args": None,
            "transfer": transfer,
        },
    )


def _evaluate_transfer(observation: dict[str, object]) -> None:
    evaluate_native_transfer_readback(
        validate_observation(observation),
        source_account=_TRANSFER["source_account"],
        recipient_account=_TRANSFER["recipient_account"],
        amount_motes=_TRANSFER["amount_motes"],
        transfer_id=_TRANSFER["transfer_id"],
    )


def test_exact_transfer_readback_is_accepted() -> None:
    _evaluate_transfer(_transfer_observation())


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_account", "3c" * 32),
        ("recipient_account", "4d" * 32),
        ("amount_motes", "50000000001"),
        ("transfer_id", "1"),
    ],
)
def test_wrong_transfer_identity_is_refused(field: str, value: str) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        _evaluate_transfer(_transfer_observation(**{field: value}))
    assert refusal.value.code == RefusalCode.TRANSFER_MISMATCH


def test_absent_step_observation_is_refused() -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        evaluate_step_observations([], step_id="B-install-rc-wasm")
    assert refusal.value.code == RefusalCode.OBSERVATION_ABSENT


def test_ambiguous_duplicate_observations_are_refused() -> None:
    duplicated = [
        make_observation("B-install-rc-wasm"),
        make_observation("B-install-rc-wasm"),
    ]
    with pytest.raises(CanaryRefusal) as refusal:
        evaluate_step_observations(duplicated, step_id="B-install-rc-wasm")
    assert refusal.value.code == RefusalCode.AMBIGUOUS_RESULT
