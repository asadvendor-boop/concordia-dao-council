"""Fail-closed proof that one finalized native transfer moved exact balances.

This module composes four parser-issued historical account-balance proofs with
one parser-issued finalized native-transfer proof.  It never accepts caller
booleans or pre-decoded balance deltas.  Network collection and artifact
serialization intentionally live outside this boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field

from shared.casper_state_proof import (
    CasperStateProofError,
    VerifiedAccountBalance,
    require_verified_account_balance,
)
from shared.native_transfer_finality import (
    FinalizedNativeTransferProof,
    NativeTransferFinalityError,
    require_verified_finalized_native_transfer,
)


_MAX_U512 = (1 << 512) - 1
_LOWER_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_FACTORY_SEAL = object()
_INTEGRITY_KEY = secrets.token_bytes(32)
_TRANSCRIPT_FIELDS = (
    "status_request",
    "status",
    "block_request",
    "block",
    "balance_request",
    "balance_response",
)
_TRANSCRIPT_ROLES = (
    "pre_source",
    "pre_recipient",
    "post_source",
    "post_recipient",
)
_TRANSCRIPT_LABELS = tuple(
    f"{role}.{name}" for role in _TRANSCRIPT_ROLES for name in _TRANSCRIPT_FIELDS
)


class PostTransferProofError(ValueError):
    """The supplied evidence does not prove the exact post-transfer balances."""


@dataclass(frozen=True, slots=True, init=False)
class PostTransferBalanceProof:
    """Immutable exact-balance proof issued only by the strict factory."""

    network: str
    source_account_hash: bytes
    recipient_account_hash: bytes
    pre_block_hash: bytes
    pre_block_height: int
    pre_state_root_hash: bytes
    post_block_hash: bytes
    post_block_height: int
    post_state_root_hash: bytes
    deploy_hash: str
    source_balance_before_motes: int
    source_balance_after_motes: int
    recipient_balance_before_motes: int
    recipient_balance_after_motes: int
    amount_motes: int
    gas_motes: int
    source_delta_motes: int
    recipient_delta_motes: int
    signed_deploy_sha256: str
    transcript_sha256_inventory: tuple[tuple[str, str], ...]
    _factory_seal: object = field(repr=False, compare=False)
    _integrity_tag: bytes = field(repr=False, compare=False)

    def __new__(cls, *_args: object, **_kwargs: object) -> PostTransferBalanceProof:
        raise TypeError(
            "PostTransferBalanceProof is created only by "
            "verify_post_transfer_balance"
        )


def _canonical_integrity_material(proof: PostTransferBalanceProof) -> bytes:
    material = {
        "network": proof.network,
        "source_account_hash": proof.source_account_hash.hex(),
        "recipient_account_hash": proof.recipient_account_hash.hex(),
        "pre_block_hash": proof.pre_block_hash.hex(),
        "pre_block_height": proof.pre_block_height,
        "pre_state_root_hash": proof.pre_state_root_hash.hex(),
        "post_block_hash": proof.post_block_hash.hex(),
        "post_block_height": proof.post_block_height,
        "post_state_root_hash": proof.post_state_root_hash.hex(),
        "deploy_hash": proof.deploy_hash,
        "source_balance_before_motes": str(proof.source_balance_before_motes),
        "source_balance_after_motes": str(proof.source_balance_after_motes),
        "recipient_balance_before_motes": str(
            proof.recipient_balance_before_motes
        ),
        "recipient_balance_after_motes": str(proof.recipient_balance_after_motes),
        "amount_motes": str(proof.amount_motes),
        "gas_motes": str(proof.gas_motes),
        "source_delta_motes": str(proof.source_delta_motes),
        "recipient_delta_motes": str(proof.recipient_delta_motes),
        "signed_deploy_sha256": proof.signed_deploy_sha256,
        "transcript_sha256_inventory": [
            [label, digest] for label, digest in proof.transcript_sha256_inventory
        ],
    }
    return json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _integrity_tag(proof: PostTransferBalanceProof) -> bytes:
    return hmac.new(
        _INTEGRITY_KEY,
        _canonical_integrity_material(proof),
        hashlib.sha256,
    ).digest()


def _make_proof(**values: object) -> PostTransferBalanceProof:
    proof = object.__new__(PostTransferBalanceProof)
    for name, value in values.items():
        object.__setattr__(proof, name, value)
    object.__setattr__(proof, "_factory_seal", _FACTORY_SEAL)
    object.__setattr__(proof, "_integrity_tag", _integrity_tag(proof))
    return proof


def _bytes32(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise PostTransferProofError(f"{label} must be exactly 32 bytes")
    return value


def _positive_u512(value: object, label: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_U512:
        raise PostTransferProofError(f"{label} must be positive U512")
    return value


def _is_u512(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_U512


def _require_balance(
    value: object, label: str
) -> VerifiedAccountBalance:
    try:
        return require_verified_account_balance(value)
    except CasperStateProofError as exc:
        raise PostTransferProofError(f"{label} balance proof is invalid") from exc


def _require_finality(value: object) -> FinalizedNativeTransferProof:
    try:
        return require_verified_finalized_native_transfer(value)
    except NativeTransferFinalityError as exc:
        raise PostTransferProofError("finality proof is invalid") from exc


def _balance_inventory(
    role: str, proof: VerifiedAccountBalance
) -> tuple[tuple[str, str], ...]:
    digests = (
        proof.status_request_sha256,
        proof.status_sha256,
        proof.block_request_sha256,
        proof.block_sha256,
        proof.balance_request_sha256,
        proof.balance_response_sha256,
    )
    return tuple(
        (f"{role}.{name}", digest)
        for name, digest in zip(_TRANSCRIPT_FIELDS, digests, strict=True)
    )


def _validate_issued_proof(proof: PostTransferBalanceProof) -> None:
    if (
        proof.network != "casper-test"
        or type(proof.source_account_hash) is not bytes
        or len(proof.source_account_hash) != 32
        or type(proof.recipient_account_hash) is not bytes
        or len(proof.recipient_account_hash) != 32
        or proof.source_account_hash == proof.recipient_account_hash
        or type(proof.pre_block_hash) is not bytes
        or len(proof.pre_block_hash) != 32
        or type(proof.pre_state_root_hash) is not bytes
        or len(proof.pre_state_root_hash) != 32
        or type(proof.post_block_hash) is not bytes
        or len(proof.post_block_hash) != 32
        or type(proof.post_state_root_hash) is not bytes
        or len(proof.post_state_root_hash) != 32
        or type(proof.pre_block_height) is not int
        or type(proof.post_block_height) is not int
        or not 0 <= proof.pre_block_height < proof.post_block_height
        or _LOWER_HASH_RE.fullmatch(proof.deploy_hash) is None
        or not all(
            _is_u512(value)
            for value in (
                proof.source_balance_before_motes,
                proof.source_balance_after_motes,
                proof.recipient_balance_before_motes,
                proof.recipient_balance_after_motes,
                proof.amount_motes,
                proof.gas_motes,
                proof.source_delta_motes,
                proof.recipient_delta_motes,
            )
        )
        or proof.amount_motes == 0
        or proof.amount_motes > _MAX_U512 - proof.gas_motes
        or proof.source_delta_motes != proof.amount_motes + proof.gas_motes
        or proof.recipient_delta_motes != proof.amount_motes
        or proof.source_balance_before_motes < proof.source_balance_after_motes
        or proof.source_balance_before_motes - proof.source_balance_after_motes
        != proof.source_delta_motes
        or proof.recipient_balance_after_motes
        < proof.recipient_balance_before_motes
        or proof.recipient_balance_after_motes
        - proof.recipient_balance_before_motes
        != proof.recipient_delta_motes
        or _LOWER_HASH_RE.fullmatch(proof.signed_deploy_sha256) is None
        or type(proof.transcript_sha256_inventory) is not tuple
        or len(proof.transcript_sha256_inventory) != len(_TRANSCRIPT_LABELS)
    ):
        raise PostTransferProofError("post-transfer proof integrity check failed")

    for index, item in enumerate(proof.transcript_sha256_inventory):
        if (
            type(item) is not tuple
            or len(item) != 2
            or item[0] != _TRANSCRIPT_LABELS[index]
            or type(item[1]) is not str
            or _LOWER_HASH_RE.fullmatch(item[1]) is None
        ):
            raise PostTransferProofError("post-transfer proof integrity check failed")


def require_verified_post_transfer_balance(
    value: object,
) -> PostTransferBalanceProof:
    """Return only an untampered proof issued by this process's factory."""

    if (
        type(value) is not PostTransferBalanceProof
        or getattr(value, "_factory_seal", None) is not _FACTORY_SEAL
    ):
        raise PostTransferProofError(
            "post-transfer balance proof is not factory-verified"
        )
    tag = getattr(value, "_integrity_tag", None)
    try:
        expected_tag = _integrity_tag(value)
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise PostTransferProofError(
            "post-transfer proof integrity check failed"
        ) from exc
    if type(tag) is not bytes or not hmac.compare_digest(tag, expected_tag):
        raise PostTransferProofError("post-transfer proof integrity check failed")
    _validate_issued_proof(value)
    return value


def verify_post_transfer_balance(
    *,
    pre_source_balance: VerifiedAccountBalance,
    pre_recipient_balance: VerifiedAccountBalance,
    post_source_balance: VerifiedAccountBalance,
    post_recipient_balance: VerifiedAccountBalance,
    finality_proof: FinalizedNativeTransferProof,
    expected_source_account_hash: bytes,
    expected_recipient_account_hash: bytes,
    expected_amount_motes: int,
) -> PostTransferBalanceProof:
    """Prove exact source and recipient deltas around one finalized transfer."""

    source = _bytes32(expected_source_account_hash, "expected source account")
    recipient = _bytes32(
        expected_recipient_account_hash, "expected recipient account"
    )
    amount = _positive_u512(expected_amount_motes, "expected amount")
    if source == recipient:
        raise PostTransferProofError("source and recipient accounts must be distinct")

    pre_source = _require_balance(pre_source_balance, "pre-source")
    pre_recipient = _require_balance(pre_recipient_balance, "pre-recipient")
    post_source = _require_balance(post_source_balance, "post-source")
    post_recipient = _require_balance(post_recipient_balance, "post-recipient")
    finality = _require_finality(finality_proof)

    signed = finality.signed_deploy
    if signed.source_account_hash != source:
        raise PostTransferProofError(
            "expected source does not match signed transfer source"
        )
    if signed.recipient_account_hash != recipient:
        raise PostTransferProofError(
            "expected recipient does not match signed transfer recipient"
        )
    if signed.amount_motes != amount:
        raise PostTransferProofError(
            "expected amount does not match signed transfer amount"
        )

    account_checks = (
        (pre_source.account_hash, source, "pre-source account"),
        (post_source.account_hash, source, "post-source account"),
        (pre_recipient.account_hash, recipient, "pre-recipient account"),
        (post_recipient.account_hash, recipient, "post-recipient account"),
    )
    for actual, expected, label in account_checks:
        if actual != expected:
            raise PostTransferProofError(f"{label} does not match expected account")

    if any(
        proof.network != "casper-test"
        for proof in (pre_source, pre_recipient, post_source, post_recipient)
    ) or signed.chain_name != "casper-test":
        raise PostTransferProofError("all evidence must prove network casper-test")

    if pre_recipient.block_hash != pre_source.block_hash:
        raise PostTransferProofError("pre-state block does not match")
    if pre_recipient.block_height != pre_source.block_height:
        raise PostTransferProofError("pre-state height does not match")
    if pre_recipient.state_root_hash != pre_source.state_root_hash:
        raise PostTransferProofError("pre-state root does not match")

    finality_block = bytes.fromhex(finality.block_hash)
    finality_root = bytes.fromhex(finality.state_root_hash)
    for proof in (post_source, post_recipient):
        if proof.block_hash != finality_block:
            raise PostTransferProofError("post-state does not match finality block")
        if proof.block_height != finality.block_height:
            raise PostTransferProofError("post-state does not match finality height")
        if proof.state_root_hash != finality_root:
            raise PostTransferProofError(
                "post-state does not match finality state root"
            )

    if pre_source.block_height >= finality.block_height:
        raise PostTransferProofError(
            "pre-state snapshot must strictly precede post-state snapshot"
        )

    gas = finality.gas_motes
    if amount > _MAX_U512 - gas:
        raise PostTransferProofError("amount plus gas causes U512 overflow")
    expected_source_delta = amount + gas

    if post_recipient.balance_motes < pre_recipient.balance_motes:
        raise PostTransferProofError("recipient balance decreased")
    recipient_delta = post_recipient.balance_motes - pre_recipient.balance_motes
    if recipient_delta != amount:
        raise PostTransferProofError("recipient delta does not match transfer amount")

    if post_source.balance_motes > pre_source.balance_motes:
        raise PostTransferProofError("source balance increased")
    source_delta = pre_source.balance_motes - post_source.balance_motes
    if source_delta != expected_source_delta:
        raise PostTransferProofError(
            "source delta does not match transfer amount plus gas"
        )

    inventory = tuple(
        item
        for role, proof in (
            ("pre_source", pre_source),
            ("pre_recipient", pre_recipient),
            ("post_source", post_source),
            ("post_recipient", post_recipient),
        )
        for item in _balance_inventory(role, proof)
    )
    signed_deploy_sha256 = hashlib.sha256(
        signed.canonical_signed_bytes
    ).hexdigest()

    proof = _make_proof(
        network="casper-test",
        source_account_hash=source,
        recipient_account_hash=recipient,
        pre_block_hash=pre_source.block_hash,
        pre_block_height=pre_source.block_height,
        pre_state_root_hash=pre_source.state_root_hash,
        post_block_hash=finality_block,
        post_block_height=finality.block_height,
        post_state_root_hash=finality_root,
        deploy_hash=finality.deploy_hash,
        source_balance_before_motes=pre_source.balance_motes,
        source_balance_after_motes=post_source.balance_motes,
        recipient_balance_before_motes=pre_recipient.balance_motes,
        recipient_balance_after_motes=post_recipient.balance_motes,
        amount_motes=amount,
        gas_motes=gas,
        source_delta_motes=source_delta,
        recipient_delta_motes=recipient_delta,
        signed_deploy_sha256=signed_deploy_sha256,
        transcript_sha256_inventory=inventory,
    )
    return require_verified_post_transfer_balance(proof)


__all__ = [
    "PostTransferBalanceProof",
    "PostTransferProofError",
    "require_verified_post_transfer_balance",
    "verify_post_transfer_balance",
]
