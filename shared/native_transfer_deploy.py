"""Canonical construction and independent validation of signed Casper transfers.

The treasury executor persists signed deploy bytes before broadcast.  This
module is the boundary that proves those bytes are one exact native transfer;
it deliberately validates the binary deploy again instead of trusting builder
metadata or a JSON rendering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pycspr import crypto, serializer
from pycspr.factory.deploys import create_deploy, create_deploy_parameters
from pycspr.factory.digests import create_digest_of_deploy, create_digest_of_deploy_body
from pycspr.types.cl import (
    CLT_Type_U64,
    CLV_Key,
    CLV_KeyType,
    CLV_Option,
    CLV_U64,
    CLV_U512,
)
from pycspr.types.node.rpc import Deploy, DeployArgument, DeployOfModuleBytes, DeployOfTransfer


CASPER_TEST_CHAIN_NAME = "casper-test"
DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES = 100_000_000
_MAX_U64 = (1 << 64) - 1
_MAX_U512 = (1 << 512) - 1


class NativeTransferDeployError(ValueError):
    """A signed deploy is malformed, non-canonical, or not the expected action."""


@dataclass(frozen=True, slots=True)
class NativeTransferDeployFacts:
    """Immutable facts independently decoded from canonical signed bytes."""

    canonical_signed_bytes: bytes
    deploy_hash: bytes
    deploy_hash_hex: str
    body_hash: bytes
    chain_name: str
    source_public_key: bytes
    source_account_hash: bytes
    recipient_account_hash: bytes
    amount_motes: int
    transfer_id: int
    payment_amount_motes: int
    approval_signers: tuple[bytes, ...]


def _require_bytes32(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise NativeTransferDeployError(f"{label} must be 32 bytes")
    return value


def _require_positive_u512(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_U512:
        raise NativeTransferDeployError(f"{label} must be positive U512")
    return value


def _require_u64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_U64:
        raise NativeTransferDeployError(f"{label} must be U64")
    return value


def _account_key_bytes(signer: object) -> bytes:
    if type(signer) is bytes:
        account_key = signer
    else:
        account_key = getattr(signer, "account_key", None)
    if type(account_key) is not bytes or len(account_key) not in (33, 34):
        raise NativeTransferDeployError("approval signer has invalid public key bytes")
    return account_key


def build_signed_native_transfer_deploy(
    *,
    source_private_key: Any,
    recipient_account_hash: bytes,
    amount_motes: int,
    transfer_id: int,
    payment_amount_motes: int = DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    timestamp_seconds: float | None = None,
    ttl: str = "30m",
    chain_name: str = CASPER_TEST_CHAIN_NAME,
) -> bytes:
    """Build canonical signed bytes using the frozen native-transfer arg order.

    ``pycspr.factory.deploys.create_transfer`` encodes the target as a public
    key and uses a different argument order.  Concordia binds a recipient
    account hash, so the target is constructed explicitly as ``Key::Account``
    and the session order is exactly ``target, amount, id``.
    """

    recipient = _require_bytes32(recipient_account_hash, "recipient account hash")
    amount = _require_positive_u512(amount_motes, "transfer amount")
    identifier = _require_u64(transfer_id, "transfer id")
    payment_amount = _require_positive_u512(payment_amount_motes, "payment amount")
    if not isinstance(chain_name, str) or not chain_name:
        raise NativeTransferDeployError("chain name must be non-empty text")
    if not isinstance(ttl, str) or not ttl:
        raise NativeTransferDeployError("ttl must be non-empty text")

    payment = DeployOfModuleBytes(
        args=[DeployArgument("amount", CLV_U512(payment_amount))],
        module_bytes=b"",
    )
    session = DeployOfTransfer(
        args=[
            DeployArgument("target", CLV_Key(recipient, CLV_KeyType.ACCOUNT)),
            DeployArgument("amount", CLV_U512(amount)),
            DeployArgument("id", CLV_Option(CLV_U64(identifier), CLT_Type_U64())),
        ]
    )
    parameters = create_deploy_parameters(
        source_private_key,
        chain_name,
        timestamp=timestamp_seconds,
        ttl=ttl,
    )
    deploy = create_deploy(parameters, payment, session)
    deploy.approve(source_private_key)
    return serializer.to_bytes(deploy)


def validate_signed_native_transfer_deploy(
    raw: bytes,
    *,
    expected_source_account_hash: bytes,
    expected_recipient_account_hash: bytes,
    expected_amount_motes: int,
    expected_transfer_id: int,
    expected_payment_amount_motes: int = DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    max_payment_amount_motes: int = DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
) -> NativeTransferDeployFacts:
    """Decode and fail closed unless ``raw`` is the one expected transfer.

    Integrity (canonical bytes, hashes, and every approval) and semantics
    (chain, source, payment, session variant, ordered typed args, and values)
    are independently checked.  No caller-provided deploy hash or decoded
    metadata is trusted.
    """

    source_expected = _require_bytes32(
        expected_source_account_hash, "expected source account hash"
    )
    recipient_expected = _require_bytes32(
        expected_recipient_account_hash, "expected recipient account hash"
    )
    amount_expected = _require_positive_u512(
        expected_amount_motes, "expected transfer amount"
    )
    transfer_id_expected = _require_u64(expected_transfer_id, "expected transfer id")
    payment_expected = _require_positive_u512(
        expected_payment_amount_motes, "expected payment amount"
    )
    payment_bound = _require_positive_u512(
        max_payment_amount_motes, "payment amount bound"
    )

    if type(raw) is not bytes or not raw:
        raise NativeTransferDeployError("signed deploy bytes must be non-empty bytes")
    try:
        remainder, deploy = serializer.from_bytes(raw, Deploy)
    except Exception as exc:
        raise NativeTransferDeployError("signed deploy bytes could not be decoded") from exc
    if remainder:
        raise NativeTransferDeployError("signed deploy contains trailing bytes")
    try:
        canonical = serializer.to_bytes(deploy)
    except Exception as exc:
        raise NativeTransferDeployError("decoded deploy could not be re-encoded") from exc
    if canonical != raw:
        # pycspr 1.2.0's one-approval decoder can consume one byte beyond the
        # approval.  Exact round-trip still exposes the appended data; retain
        # the more precise trailing-bytes failure classification.
        if raw.startswith(canonical):
            raise NativeTransferDeployError("signed deploy contains trailing bytes")
        raise NativeTransferDeployError("signed deploy uses non-canonical binary encoding")

    computed_body_hash = create_digest_of_deploy_body(deploy.payment, deploy.session)
    if deploy.header.body_hash != computed_body_hash:
        raise NativeTransferDeployError("body hash mismatch")
    computed_deploy_hash = create_digest_of_deploy(deploy.header)
    if deploy.hash != computed_deploy_hash:
        raise NativeTransferDeployError("deploy hash mismatch")

    if not deploy.approvals:
        raise NativeTransferDeployError("signed deploy requires at least one approval")
    approval_signers: list[bytes] = []
    seen_signers: set[bytes] = set()
    for approval in deploy.approvals:
        signer = _account_key_bytes(approval.signer)
        if signer in seen_signers:
            raise NativeTransferDeployError("duplicate approval signer")
        seen_signers.add(signer)
        try:
            signature_valid = crypto.verify_deploy_approval_signature(
                computed_deploy_hash,
                approval.signature,
                signer,
            )
        except Exception as exc:
            raise NativeTransferDeployError("invalid approval signature") from exc
        if not signature_valid:
            raise NativeTransferDeployError("invalid approval signature")
        approval_signers.append(signer)

    if deploy.header.chain_name != CASPER_TEST_CHAIN_NAME:
        raise NativeTransferDeployError("chain must be exactly casper-test")
    source_public_key = deploy.header.account.account_key
    source_account_hash = deploy.header.account.account_hash
    if source_account_hash != source_expected:
        raise NativeTransferDeployError("source account hash mismatch")

    if type(deploy.payment) is not DeployOfModuleBytes:
        raise NativeTransferDeployError("payment must be exactly ModuleBytes")
    if type(deploy.payment.module_bytes) is not bytes or deploy.payment.module_bytes != b"":
        raise NativeTransferDeployError("standard payment module bytes must be empty")
    payment_arguments = deploy.payment.arguments
    if [argument.name for argument in payment_arguments] != ["amount"]:
        raise NativeTransferDeployError("payment arguments must be exactly amount")
    payment_value = payment_arguments[0].value
    if type(payment_value) is not CLV_U512:
        raise NativeTransferDeployError("payment amount must be U512")
    if payment_value.value > payment_bound:
        raise NativeTransferDeployError("payment amount exceeds bound")
    if payment_value.value != payment_expected:
        raise NativeTransferDeployError("payment amount mismatch")

    if type(deploy.session) is not DeployOfTransfer:
        raise NativeTransferDeployError("session must be exactly Transfer")
    session_arguments = deploy.session.arguments
    if [argument.name for argument in session_arguments] != ["target", "amount", "id"]:
        raise NativeTransferDeployError(
            "session arguments must be exactly ordered target, amount, id"
        )

    target_value = session_arguments[0].value
    if type(target_value) is not CLV_Key or target_value.key_type is not CLV_KeyType.ACCOUNT:
        raise NativeTransferDeployError("target must be an account-variant Key")
    if target_value.identifier != recipient_expected:
        raise NativeTransferDeployError("recipient account hash mismatch")

    amount_value = session_arguments[1].value
    if type(amount_value) is not CLV_U512:
        raise NativeTransferDeployError("transfer amount must be U512")
    if amount_value.value != amount_expected:
        raise NativeTransferDeployError("transfer amount mismatch")

    id_value = session_arguments[2].value
    if (
        type(id_value) is not CLV_Option
        or type(id_value.option_type) is not CLT_Type_U64
        or type(id_value.value) is not CLV_U64
    ):
        raise NativeTransferDeployError("transfer id must be Some U64")
    if id_value.value.value != transfer_id_expected:
        raise NativeTransferDeployError("transfer id mismatch")

    return NativeTransferDeployFacts(
        canonical_signed_bytes=raw,
        deploy_hash=computed_deploy_hash,
        deploy_hash_hex=computed_deploy_hash.hex(),
        body_hash=computed_body_hash,
        chain_name=deploy.header.chain_name,
        source_public_key=source_public_key,
        source_account_hash=source_account_hash,
        recipient_account_hash=target_value.identifier,
        amount_motes=amount_value.value,
        transfer_id=id_value.value.value,
        payment_amount_motes=payment_value.value,
        approval_signers=tuple(approval_signers),
    )


__all__ = [
    "CASPER_TEST_CHAIN_NAME",
    "DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES",
    "NativeTransferDeployError",
    "NativeTransferDeployFacts",
    "build_signed_native_transfer_deploy",
    "validate_signed_native_transfer_deploy",
]
