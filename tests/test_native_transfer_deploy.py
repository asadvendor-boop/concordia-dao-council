from __future__ import annotations

import dataclasses
from collections.abc import Callable

import pytest
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.factory.digests import create_digest_of_deploy, create_digest_of_deploy_body
from pycspr.types.cl import (
    CLT_Type_String,
    CLT_Type_U64,
    CLV_Key,
    CLV_KeyType,
    CLV_Option,
    CLV_PublicKey,
    CLV_String,
    CLV_U64,
    CLV_U512,
)
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import Deploy, DeployArgument, DeployOfModuleBytes, DeployOfTransfer

from shared.native_transfer_deploy import (
    DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    NativeTransferDeployError,
    NativeTransferDeployFacts,
    build_signed_native_transfer_deploy,
    validate_signed_native_transfer_deploy,
)


SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
OTHER_KEY = parse_private_key_bytes(bytes(range(33, 65)), KeyAlgorithm.ED25519)
SOURCE_ACCOUNT = SOURCE_KEY.to_public_key().to_account_hash()
RECIPIENT = bytes.fromhex("22" * 32)
OTHER_RECIPIENT = bytes.fromhex("33" * 32)
AMOUNT = 50_000_000_000
TRANSFER_ID = 0x0102_0304_0506_0708
TIMESTAMP_SECONDS = 1_753_228_800.0


def _valid_raw(**overrides: object) -> bytes:
    values: dict[str, object] = {
        "source_private_key": SOURCE_KEY,
        "recipient_account_hash": RECIPIENT,
        "amount_motes": AMOUNT,
        "transfer_id": TRANSFER_ID,
        "payment_amount_motes": DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        "timestamp_seconds": TIMESTAMP_SECONDS,
        "ttl": "30m",
    }
    values.update(overrides)
    return build_signed_native_transfer_deploy(**values)


def _validate(raw: bytes, **overrides: object) -> NativeTransferDeployFacts:
    values: dict[str, object] = {
        "expected_source_account_hash": SOURCE_ACCOUNT,
        "expected_recipient_account_hash": RECIPIENT,
        "expected_amount_motes": AMOUNT,
        "expected_transfer_id": TRANSFER_ID,
        "expected_payment_amount_motes": DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        "max_payment_amount_motes": DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    }
    values.update(overrides)
    return validate_signed_native_transfer_deploy(raw, **values)


def _decoded(raw: bytes) -> Deploy:
    remainder, deploy = serializer.from_bytes(raw, Deploy)
    assert remainder == b""
    return deploy


def _rehash_and_sign(deploy: Deploy, signer=SOURCE_KEY) -> bytes:
    deploy.header.body_hash = create_digest_of_deploy_body(deploy.payment, deploy.session)
    deploy.hash = create_digest_of_deploy(deploy.header)
    deploy.approvals = []
    deploy.approve(signer)
    return serializer.to_bytes(deploy)


def _mutated_valid_deploy(mutator: Callable[[Deploy], None], signer=SOURCE_KEY) -> bytes:
    deploy = _decoded(_valid_raw())
    mutator(deploy)
    return _rehash_and_sign(deploy, signer)


def test_builder_emits_canonical_signed_native_transfer_and_validator_returns_immutable_facts() -> None:
    raw = _valid_raw()

    facts = _validate(raw)

    assert isinstance(facts, NativeTransferDeployFacts)
    assert facts.canonical_signed_bytes == raw
    assert facts.chain_name == "casper-test"
    assert facts.source_account_hash == SOURCE_ACCOUNT
    assert facts.source_public_key == SOURCE_KEY.account_key
    assert facts.recipient_account_hash == RECIPIENT
    assert facts.amount_motes == AMOUNT
    assert facts.transfer_id == TRANSFER_ID
    assert facts.payment_amount_motes == DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES
    assert facts.deploy_hash == _decoded(raw).hash
    assert facts.deploy_hash_hex == facts.deploy_hash.hex()
    assert facts.body_hash == _decoded(raw).header.body_hash
    assert facts.approval_signers == (SOURCE_KEY.account_key,)
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts.amount_motes = 1  # type: ignore[misc]

    deploy = _decoded(raw)
    assert type(deploy.payment) is DeployOfModuleBytes
    assert deploy.payment.module_bytes == b""
    assert [argument.name for argument in deploy.payment.arguments] == ["amount"]
    assert type(deploy.session) is DeployOfTransfer
    assert [argument.name for argument in deploy.session.arguments] == ["target", "amount", "id"]
    target = deploy.session.arguments[0].value
    assert type(target) is CLV_Key
    assert target.key_type is CLV_KeyType.ACCOUNT
    assert target.identifier == RECIPIENT


def test_rejects_empty_or_non_bytes_input() -> None:
    with pytest.raises(NativeTransferDeployError, match="signed deploy bytes must be non-empty bytes"):
        _validate(b"")
    with pytest.raises(NativeTransferDeployError, match="signed deploy bytes must be non-empty bytes"):
        validate_signed_native_transfer_deploy(  # type: ignore[arg-type]
            bytearray(_valid_raw()),
            expected_source_account_hash=SOURCE_ACCOUNT,
            expected_recipient_account_hash=RECIPIENT,
            expected_amount_motes=AMOUNT,
            expected_transfer_id=TRANSFER_ID,
        )


def test_rejects_trailing_bytes() -> None:
    with pytest.raises(NativeTransferDeployError, match="trailing bytes"):
        _validate(_valid_raw() + b"\x00")


def test_rejects_noncanonical_binary_even_when_pycspr_decodes_same_value() -> None:
    raw = _valid_raw()
    canonical_argument = serializer.to_bytes(
        DeployArgument("amount", CLV_U512(DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES))
    )
    assert raw.count(canonical_argument) == 1
    # U512(100_000_000) canonically uses four little-endian magnitude bytes.
    # Prefixing the value with length five and appending a redundant high zero
    # decodes to the same integer, but must be rejected by exact round-trip.
    noncanonical_argument = (
        canonical_argument[:10]
        + (6).to_bytes(4, "little")
        + b"\x05"
        + canonical_argument[15:19]
        + b"\x00"
        + canonical_argument[19:]
    )
    noncanonical = raw.replace(canonical_argument, noncanonical_argument, 1)

    with pytest.raises(NativeTransferDeployError, match="non-canonical"):
        _validate(noncanonical)


def test_rejects_body_hash_mismatch_even_when_deploy_hash_and_signature_match_header() -> None:
    deploy = _decoded(_valid_raw())
    deploy.header.body_hash = bytes([deploy.header.body_hash[0] ^ 1]) + deploy.header.body_hash[1:]
    deploy.hash = create_digest_of_deploy(deploy.header)
    deploy.approvals = []
    deploy.approve(SOURCE_KEY)

    with pytest.raises(NativeTransferDeployError, match="body hash mismatch"):
        _validate(serializer.to_bytes(deploy))


def test_rejects_deploy_hash_mismatch_even_when_signature_matches_supplied_hash() -> None:
    deploy = _decoded(_valid_raw())
    deploy.hash = bytes([deploy.hash[0] ^ 1]) + deploy.hash[1:]
    deploy.approvals = []
    deploy.approve(SOURCE_KEY)

    with pytest.raises(NativeTransferDeployError, match="deploy hash mismatch"):
        _validate(serializer.to_bytes(deploy))


def test_rejects_missing_approval() -> None:
    deploy = _decoded(_valid_raw())
    deploy.approvals = []

    with pytest.raises(NativeTransferDeployError, match="at least one approval"):
        _validate(serializer.to_bytes(deploy))


def test_rejects_invalid_approval_signature() -> None:
    deploy = _decoded(_valid_raw())
    approval = deploy.approvals[0]
    approval.signature = approval.signature[:-1] + bytes([approval.signature[-1] ^ 1])

    with pytest.raises(NativeTransferDeployError, match="invalid approval signature"):
        _validate(serializer.to_bytes(deploy))


def test_rejects_wrong_source_account_even_when_deploy_is_validly_signed() -> None:
    raw = _valid_raw(source_private_key=OTHER_KEY)

    with pytest.raises(NativeTransferDeployError, match="source account hash mismatch"):
        _validate(raw)


def test_rejects_wrong_chain_name() -> None:
    raw = _valid_raw(chain_name="casper-testnet")

    with pytest.raises(NativeTransferDeployError, match="chain must be exactly casper-test"):
        _validate(raw)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda deploy: setattr(deploy, "payment", DeployOfModuleBytes(args=deploy.payment.arguments, module_bytes=b"x")),
            "standard payment module bytes must be empty",
        ),
        (
            lambda deploy: setattr(deploy, "payment", DeployOfTransfer(args=deploy.payment.arguments)),
            "payment must be exactly ModuleBytes",
        ),
        (
            lambda deploy: setattr(deploy.payment, "args", []),
            "payment arguments must be exactly amount",
        ),
        (
            lambda deploy: setattr(
                deploy.payment,
                "args",
                [DeployArgument("amount", CLV_U512(DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES)), DeployArgument("amount", CLV_U512(DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES))],
            ),
            "payment arguments must be exactly amount",
        ),
        (
            lambda deploy: setattr(deploy.payment.arguments[0], "value", CLV_U64(DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES)),
            "payment amount must be U512",
        ),
    ],
    ids=("nonempty-module", "wrong-payment-variant", "missing-arg", "duplicate-arg", "wrong-amount-type"),
)
def test_rejects_nonstandard_payment(mutator: Callable[[Deploy], None], error: str) -> None:
    raw = _mutated_valid_deploy(mutator)

    with pytest.raises(NativeTransferDeployError, match=error):
        _validate(raw)


def test_rejects_payment_amount_that_is_not_exact_expected_value() -> None:
    raw = _valid_raw(payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES - 1)

    with pytest.raises(NativeTransferDeployError, match="payment amount mismatch"):
        _validate(raw)


def test_rejects_payment_amount_above_configured_bound() -> None:
    raw = _valid_raw(payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES + 1)

    with pytest.raises(NativeTransferDeployError, match="payment amount exceeds bound"):
        _validate(
            raw,
            expected_payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES + 1,
            max_payment_amount_motes=DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        )


def test_rejects_session_variant_other_than_native_transfer() -> None:
    raw = _mutated_valid_deploy(
        lambda deploy: setattr(deploy, "session", DeployOfModuleBytes(args=[], module_bytes=b""))
    )

    with pytest.raises(NativeTransferDeployError, match="session must be exactly Transfer"):
        _validate(raw)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda deploy: setattr(deploy.session, "args", list(reversed(deploy.session.arguments))),
            "session arguments must be exactly ordered target, amount, id",
        ),
        (
            lambda deploy: setattr(
                deploy.session,
                "args",
                deploy.session.arguments + [DeployArgument("id", CLV_Option(CLV_U64(TRANSFER_ID), CLT_Type_U64()))],
            ),
            "session arguments must be exactly ordered target, amount, id",
        ),
        (
            lambda deploy: setattr(
                deploy.session.arguments[0],
                "value",
                CLV_PublicKey(SOURCE_KEY.algo, SOURCE_KEY.pbk),
            ),
            "target must be an account-variant Key",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[0], "value", CLV_Key(RECIPIENT, CLV_KeyType.HASH)),
            "target must be an account-variant Key",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[0], "value", CLV_Key(OTHER_RECIPIENT, CLV_KeyType.ACCOUNT)),
            "recipient account hash mismatch",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[1], "value", CLV_U64(AMOUNT)),
            "transfer amount must be U512",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[1], "value", CLV_U512(AMOUNT + 1)),
            "transfer amount mismatch",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[2], "value", CLV_Option(None, CLT_Type_U64())),
            "transfer id must be Some U64",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[2], "value", CLV_Option(CLV_String("x"), CLT_Type_String())),
            "transfer id must be Some U64",
        ),
        (
            lambda deploy: setattr(deploy.session.arguments[2], "value", CLV_Option(CLV_U64(TRANSFER_ID + 1), CLT_Type_U64())),
            "transfer id mismatch",
        ),
    ],
    ids=(
        "arg-order",
        "duplicate-arg",
        "target-public-key",
        "target-hash-key",
        "target-value",
        "amount-type",
        "amount-value",
        "id-none",
        "id-type",
        "id-value",
    ),
)
def test_rejects_non_exact_native_transfer_session(mutator: Callable[[Deploy], None], error: str) -> None:
    raw = _mutated_valid_deploy(mutator)

    with pytest.raises(NativeTransferDeployError, match=error):
        _validate(raw)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("expected_source_account_hash", b"short", "expected source account hash must be 32 bytes"),
        ("expected_recipient_account_hash", b"short", "expected recipient account hash must be 32 bytes"),
        ("expected_amount_motes", 0, "expected transfer amount must be positive U512"),
        ("expected_transfer_id", -1, "expected transfer id must be U64"),
        ("expected_payment_amount_motes", 0, "expected payment amount must be positive U512"),
        ("max_payment_amount_motes", 0, "payment amount bound must be positive U512"),
    ],
)
def test_rejects_invalid_expectations(field: str, value: object, error: str) -> None:
    with pytest.raises(NativeTransferDeployError, match=error):
        _validate(_valid_raw(), **{field: value})
