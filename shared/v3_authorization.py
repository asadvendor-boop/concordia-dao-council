"""Factory for executor-safe, fully recomputed v3 native authorizations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
from typing import Any

from shared.actions_v3 import derive_native_material
from shared.envelope_v3 import bytes32, canonical_value, length_prefix, uint_value


class V3AuthorizationError(ValueError):
    """Chain, deployment, snapshot, or envelope evidence does not bind exactly."""


@dataclass(frozen=True)
class V3DeploymentIdentity:
    network: str
    package_hash: bytes
    contract_hash: bytes
    schema_version: int
    deployment_domain: bytes
    casper_chain_name: str
    source_sha256: bytes
    wasm_sha256: bytes
    schema_sha256: bytes


@dataclass(frozen=True)
class V3ChainReadback:
    network: str
    package_hash: bytes
    contract_hash: bytes
    schema_version: int
    deployment_domain: bytes
    casper_chain_name: str
    proposal_id: str
    proposed_envelope: bytes
    finalized: bool
    finalized_envelope: bytes
    action_id: bytes
    action_authorized: bool
    observed_block_hash: bytes
    observed_block_height: int
    observed_state_root_hash: bytes


@dataclass(frozen=True)
class CanonicalTreasurySnapshot:
    network: str
    block_hash: bytes
    block_height: int
    state_root_hash: bytes
    source_account: bytes
    source_balance_motes: int


@dataclass(frozen=True)
class VerifiedNativeAuthorization:
    """Execution subset derived only after complete exact-envelope verification."""

    network: str
    proposal_id: str
    action_id: bytes
    envelope_hash: bytes
    source_account: bytes
    recipient_account: bytes
    amount_motes: int
    treasury_snapshot_balance_motes: int
    approved_allocation_bps: int
    transfer_id: int
    snapshot_block_hash: bytes
    snapshot_block_height: int
    snapshot_state_root_hash: bytes
    finalization_block_hash: bytes
    finalization_block_height: int
    finalization_state_root_hash: bytes
    package_hash: bytes
    contract_hash: bytes
    deployment_domain: bytes
    source_sha256: bytes
    wasm_sha256: bytes
    schema_sha256: bytes
    header_bytes: bytes
    body_bytes: bytes
    action_core_bytes: bytes
    verification_seal: bytes


def _authorization_seal(value: VerifiedNativeAuthorization) -> bytes:
    preimage = b"CONCORDIA_VERIFIED_NATIVE_AUTHORIZATION_V1\0"
    preimage += length_prefix(value.network, "network")
    preimage += length_prefix(value.proposal_id, "proposal_id")
    preimage += value.action_id + value.envelope_hash
    preimage += value.source_account + value.recipient_account
    preimage += canonical_value("U512", value.amount_motes, "amount_motes")
    preimage += canonical_value(
        "U512", value.treasury_snapshot_balance_motes, "treasury_snapshot_balance_motes"
    )
    preimage += canonical_value("u32", value.approved_allocation_bps, "approved_allocation_bps")
    preimage += canonical_value("u64", value.transfer_id, "transfer_id")
    preimage += value.snapshot_block_hash
    preimage += canonical_value("u64", value.snapshot_block_height, "snapshot_block_height")
    preimage += value.snapshot_state_root_hash
    preimage += value.finalization_block_hash
    preimage += canonical_value("u64", value.finalization_block_height, "finalization_block_height")
    preimage += value.finalization_state_root_hash
    preimage += value.package_hash + value.contract_hash + value.deployment_domain
    preimage += value.source_sha256 + value.wasm_sha256 + value.schema_sha256
    for encoded in (value.header_bytes, value.body_bytes, value.action_core_bytes):
        preimage += hashlib.sha256(encoded).digest()
    return hashlib.sha256(preimage).digest()


def validate_verified_authorization(value: object) -> VerifiedNativeAuthorization:
    if not isinstance(value, VerifiedNativeAuthorization):
        raise V3AuthorizationError("executor requires a factory-verified native authorization")
    if len(value.verification_seal) != 32 or not hmac.compare_digest(
        value.verification_seal,
        _authorization_seal(value),
    ):
        raise V3AuthorizationError("verified authorization integrity seal mismatch")
    return value


def _require_bytes(name: str, value: object, *, nonzero: bool = True) -> bytes:
    try:
        result = bytes32(value, name)
    except ValueError as exc:
        raise V3AuthorizationError(f"{name}: {exc}") from exc
    if nonzero and result == bytes(32):
        raise V3AuthorizationError(f"{name}: must be non-zero")
    return result


def _require_exact(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise V3AuthorizationError(f"{name}: readback does not match verified envelope")


def _validate_deployment(deployment: V3DeploymentIdentity) -> None:
    _require_exact("network", deployment.network, "casper-test")
    _require_exact("schema_version", deployment.schema_version, 3)
    _require_exact("casper_chain_name", deployment.casper_chain_name, "casper-test")
    for name in (
        "package_hash",
        "contract_hash",
        "deployment_domain",
        "source_sha256",
        "wasm_sha256",
        "schema_sha256",
    ):
        _require_bytes(name, getattr(deployment, name))


def verify_native_authorization(
    *,
    header: Mapping[str, Any],
    body: Mapping[str, Any],
    deployment: V3DeploymentIdentity,
    readback: V3ChainReadback,
    snapshot: CanonicalTreasurySnapshot,
) -> VerifiedNativeAuthorization:
    """Recompute the 19+11-field envelope and bind it to pinned chain state."""

    _validate_deployment(deployment)
    material = derive_native_material(header, body)

    header_domain = _require_bytes("deployment_domain", header["deployment_domain"])
    header_action_id = _require_bytes("action_id", header["action_id"])
    body_source = _require_bytes("source_account", body["source_account"])
    body_recipient = _require_bytes("recipient_account", body["recipient_account"])
    body_snapshot_hash = _require_bytes("snapshot_block_hash", body["snapshot_block_hash"])
    proposal_id = str(header["proposal_id"])
    approved_bps = uint_value(header["approved_allocation_bps"], 32, "approved_allocation_bps")
    amount_motes = uint_value(body["amount_motes"], 512, "amount_motes")
    snapshot_balance = uint_value(
        body["treasury_snapshot_balance_motes"], 512, "treasury_snapshot_balance_motes"
    )
    snapshot_height = uint_value(body["snapshot_block_height"], 64, "snapshot_block_height")
    transfer_id = uint_value(body["transfer_id"], 64, "transfer_id")

    _require_exact("header schema_version", int(header["schema_version"]), deployment.schema_version)
    _require_exact("header deployment_domain", header_domain, deployment.deployment_domain)
    _require_exact("header casper_chain_name", header["casper_chain_name"], deployment.casper_chain_name)

    expected_readback = {
        "network": deployment.network,
        "package_hash": deployment.package_hash,
        "contract_hash": deployment.contract_hash,
        "schema_version": deployment.schema_version,
        "deployment_domain": deployment.deployment_domain,
        "casper_chain_name": deployment.casper_chain_name,
        "proposal_id": proposal_id,
        "proposed_envelope": material.envelope_hash,
        "finalized": True,
        "finalized_envelope": material.envelope_hash,
        "action_id": material.action_id,
        "action_authorized": True,
    }
    for field, expected in expected_readback.items():
        _require_exact(field, getattr(readback, field), expected)
    for name in (
        "package_hash",
        "contract_hash",
        "deployment_domain",
        "proposed_envelope",
        "finalized_envelope",
        "action_id",
        "observed_block_hash",
        "observed_state_root_hash",
    ):
        _require_bytes(f"readback {name}", getattr(readback, name))
    finalization_height = uint_value(
        readback.observed_block_height, 64, "observed_block_height"
    )

    expected_snapshot = {
        "network": deployment.network,
        "block_hash": body_snapshot_hash,
        "block_height": snapshot_height,
        "source_account": body_source,
        "source_balance_motes": snapshot_balance,
    }
    for field, expected in expected_snapshot.items():
        _require_exact(field, getattr(snapshot, field), expected)
    _require_bytes("snapshot block_hash", snapshot.block_hash)
    snapshot_state_root = _require_bytes("snapshot state_root_hash", snapshot.state_root_hash)
    if snapshot.block_height >= finalization_height:
        raise V3AuthorizationError("snapshot must precede v3 finalization readback")

    verified = VerifiedNativeAuthorization(
        network=deployment.network,
        proposal_id=proposal_id,
        action_id=header_action_id,
        envelope_hash=material.envelope_hash,
        source_account=body_source,
        recipient_account=body_recipient,
        amount_motes=amount_motes,
        treasury_snapshot_balance_motes=snapshot_balance,
        approved_allocation_bps=approved_bps,
        transfer_id=transfer_id,
        snapshot_block_hash=body_snapshot_hash,
        snapshot_block_height=snapshot_height,
        snapshot_state_root_hash=snapshot_state_root,
        finalization_block_hash=_require_bytes(
            "readback observed_block_hash", readback.observed_block_hash
        ),
        finalization_block_height=finalization_height,
        finalization_state_root_hash=_require_bytes(
            "readback observed_state_root_hash", readback.observed_state_root_hash
        ),
        package_hash=deployment.package_hash,
        contract_hash=deployment.contract_hash,
        deployment_domain=deployment.deployment_domain,
        source_sha256=deployment.source_sha256,
        wasm_sha256=deployment.wasm_sha256,
        schema_sha256=deployment.schema_sha256,
        header_bytes=material.header_bytes,
        body_bytes=material.body_bytes,
        action_core_bytes=material.action_core_bytes,
        verification_seal=bytes(32),
    )
    return replace(verified, verification_seal=_authorization_seal(verified))
