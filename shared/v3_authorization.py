"""Factory for executor-safe, fully recomputed v3 native authorizations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
from typing import Any

from shared.actions_v3 import derive_native_material
from shared.casper_state_proof import CasperStateProofError
from shared.treasury_snapshot import (
    TreasurySnapshotError,
    VerifiedTreasurySnapshot,
    require_verified_treasury_snapshot,
    verify_treasury_snapshot_artifact,
)
from shared.envelope_v3 import bytes32, canonical_value, length_prefix, uint_value
from scripts.read_v3_state import (
    ReadbackValidationError,
    VerifiedV3Readback,
    validate_verified_readback,
    verify_and_seal_readback_artifact,
)


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


# Backward-compatible import name.  Unlike the former public dataclass, this
# alias is constructor-restricted and can only come from the raw transcript
# parser in scripts.read_v3_state.
V3ChainReadback = VerifiedV3Readback


# Backward-compatible import name; construction remains parser-only.
CanonicalTreasurySnapshot = VerifiedTreasurySnapshot


@dataclass(frozen=True)
class VerifiedV3Finalization:
    """Exact ``finalize_exact`` block facts derived from the complete raw proof."""

    network: str
    package_hash: bytes
    contract_hash: bytes
    deployment_domain: bytes
    proposal_id: str
    action_id: bytes
    envelope_hash: bytes
    block_hash: bytes
    block_height: int
    state_root_hash: bytes
    proof_artifact_json: str
    proof_artifact_sha256: str
    verification_seal: bytes


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
    snapshot_status_request_json: str
    snapshot_status_json: str
    snapshot_block_request_json: str
    snapshot_block_json: str
    snapshot_balance_request_json: str
    snapshot_balance_response_json: str
    snapshot_status_request_sha256: str
    snapshot_status_sha256: str
    snapshot_block_request_sha256: str
    snapshot_block_sha256: str
    snapshot_balance_request_sha256: str
    snapshot_balance_response_sha256: str
    treasury_snapshot_artifact_json: str
    treasury_snapshot_artifact_sha256: str
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
    typed_header_json: str
    typed_body_json: str
    readback_artifact_json: str
    readback_artifact_sha256: str
    v3_proof_artifact_json: str
    v3_proof_artifact_sha256: str
    verification_seal: bytes


def _finalization_seal(value: VerifiedV3Finalization) -> bytes:
    preimage = b"CONCORDIA_VERIFIED_V3_FINALIZATION_V1\0"
    preimage += length_prefix(value.network, "network")
    preimage += value.package_hash + value.contract_hash + value.deployment_domain
    preimage += length_prefix(value.proposal_id, "proposal_id")
    preimage += value.action_id + value.envelope_hash
    preimage += value.block_hash
    preimage += canonical_value("u64", value.block_height, "block_height")
    preimage += value.state_root_hash
    preimage += hashlib.sha256(value.proof_artifact_json.encode("ascii")).digest()
    preimage += bytes.fromhex(value.proof_artifact_sha256)
    return hashlib.sha256(preimage).digest()


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
    preimage += canonical_value(
        "u32", value.approved_allocation_bps, "approved_allocation_bps"
    )
    preimage += canonical_value("u64", value.transfer_id, "transfer_id")
    preimage += value.snapshot_block_hash
    preimage += canonical_value(
        "u64", value.snapshot_block_height, "snapshot_block_height"
    )
    preimage += value.snapshot_state_root_hash
    for transcript in (
        value.snapshot_status_request_json,
        value.snapshot_status_json,
        value.snapshot_block_request_json,
        value.snapshot_block_json,
        value.snapshot_balance_request_json,
        value.snapshot_balance_response_json,
    ):
        preimage += hashlib.sha256(transcript.encode("ascii")).digest()
    preimage += hashlib.sha256(
        value.treasury_snapshot_artifact_json.encode("ascii")
    ).digest()
    preimage += bytes.fromhex(value.treasury_snapshot_artifact_sha256)
    preimage += value.finalization_block_hash
    preimage += canonical_value(
        "u64", value.finalization_block_height, "finalization_block_height"
    )
    preimage += value.finalization_state_root_hash
    preimage += value.package_hash + value.contract_hash + value.deployment_domain
    preimage += value.source_sha256 + value.wasm_sha256 + value.schema_sha256
    for encoded in (value.header_bytes, value.body_bytes, value.action_core_bytes):
        preimage += hashlib.sha256(encoded).digest()
    for transcript in (
        value.typed_header_json,
        value.typed_body_json,
        value.readback_artifact_json,
        value.v3_proof_artifact_json,
    ):
        preimage += hashlib.sha256(transcript.encode("ascii")).digest()
    preimage += bytes.fromhex(value.readback_artifact_sha256)
    preimage += bytes.fromhex(value.v3_proof_artifact_sha256)
    return hashlib.sha256(preimage).digest()


def _json_safe(value: object) -> object:
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is bytes:
        return value.hex()
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise V3AuthorizationError("typed envelope keys must be strings")
        return {str(key): _json_safe(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [_json_safe(item) for item in value]
    raise V3AuthorizationError("typed envelope contains a non-JSON value")


def _canonical_input_json(value: Mapping[str, Any], label: str) -> str:
    try:
        encoded = json.dumps(
            _json_safe(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise V3AuthorizationError(f"{label} is not canonical JSON") from exc
    return encoded


def _canonical_artifact_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise V3AuthorizationError("readback artifact is not canonical JSON") from exc


def verify_exact_v3_finalization(value: object) -> VerifiedV3Finalization:
    """Reparse a complete v3 proof and seal its exact successful finalization."""

    try:
        artifact_json = _canonical_artifact_json(value)
        artifact = json.loads(artifact_json)
        # Keep the CLI verifier out of this module's import graph while still
        # using the one canonical full-proof parser for every persisted proof.
        from scripts.verify_v3_proof import verify_v3_proof_document

        summary = verify_v3_proof_document(artifact)
        exact = summary["contract_step_outcomes"]["finalize_exact"]
        exact_steps = [
            step
            for step in artifact["run"]["steps"]
            if step.get("name") == "finalize_exact"
        ]
        if len(exact_steps) != 1:
            raise ValueError("exact finalization step is not unique")
        block_evidence = exact_steps[0]["finality_block_evidence"]
        header = artifact["input"]["header"]
        if (
            summary.get("valid") is not True
            or exact.get("success") is not True
            or exact.get("user_error") is not None
            or block_evidence.get("status") != "finalized"
            or block_evidence.get("block_hash") != exact.get("block_hash")
            or block_evidence.get("block_height") != exact.get("block_height")
        ):
            raise ValueError("exact finalization is not successful raw evidence")
        finalization = VerifiedV3Finalization(
            network=str(summary["network"]),
            package_hash=bytes.fromhex(str(summary["package_hash"])),
            contract_hash=bytes.fromhex(str(summary["contract_hash"])),
            deployment_domain=bytes32(header["deployment_domain"], "deployment_domain"),
            proposal_id=str(summary["proposal_id"]),
            action_id=bytes32(summary["action_id"], "action_id"),
            envelope_hash=bytes32(summary["envelope_hash"], "envelope_hash"),
            block_hash=bytes32(exact["block_hash"], "block_hash"),
            block_height=uint_value(exact["block_height"], 64, "block_height"),
            state_root_hash=bytes32(
                block_evidence["state_root_hash"], "state_root_hash"
            ),
            proof_artifact_json=artifact_json,
            proof_artifact_sha256=hashlib.sha256(
                artifact_json.encode("ascii")
            ).hexdigest(),
            verification_seal=bytes(32),
        )
    except (
        AttributeError,
        TypeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        raise V3AuthorizationError(
            "exact v3 finalization proof failed verification"
        ) from exc
    return replace(
        finalization,
        verification_seal=_finalization_seal(finalization),
    )


def validate_verified_v3_finalization(value: object) -> VerifiedV3Finalization:
    """Reparse persisted raw proof and compare every sealed finalization fact."""

    if type(value) is not VerifiedV3Finalization:
        raise V3AuthorizationError("exact v3 finalization must be parser-verified")
    try:
        artifact = json.loads(value.proof_artifact_json)
        if _canonical_artifact_json(artifact) != value.proof_artifact_json:
            raise ValueError("v3 proof artifact is not canonical")
        reparsed = verify_exact_v3_finalization(artifact)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise V3AuthorizationError("exact v3 finalization transcript failed") from exc
    if (
        len(value.proof_artifact_sha256) != 64
        or not hmac.compare_digest(
            value.proof_artifact_sha256,
            hashlib.sha256(value.proof_artifact_json.encode("ascii")).hexdigest(),
        )
        or not hmac.compare_digest(value.verification_seal, _finalization_seal(value))
        or reparsed != value
    ):
        raise V3AuthorizationError("exact v3 finalization evidence mismatch")
    return value


def validate_verified_authorization(value: object) -> VerifiedNativeAuthorization:
    if type(value) is not VerifiedNativeAuthorization:
        raise V3AuthorizationError(
            "executor requires a factory-verified native authorization"
        )
    try:
        header = json.loads(value.typed_header_json)
        body = json.loads(value.typed_body_json)
        if type(header) is not dict or type(body) is not dict:
            raise TypeError("typed envelope documents must be objects")
        if _canonical_input_json(header, "typed header") != value.typed_header_json:
            raise ValueError("typed header is not canonical")
        if _canonical_input_json(body, "typed body") != value.typed_body_json:
            raise ValueError("typed body is not canonical")
        material = derive_native_material(header, body)
        snapshot_evidence = verify_treasury_snapshot_artifact(
            json.loads(value.treasury_snapshot_artifact_json),
            expected_account_hash=value.source_account,
            expected_block_hash=value.snapshot_block_hash,
            expected_block_height=value.snapshot_block_height,
            expected_balance_motes=value.treasury_snapshot_balance_motes,
        )
        snapshot = snapshot_evidence.primary
        readback_artifact = json.loads(value.readback_artifact_json)
        if _canonical_artifact_json(readback_artifact) != value.readback_artifact_json:
            raise ValueError("readback artifact is not canonical")
        readback = validate_verified_readback(
            verify_and_seal_readback_artifact(readback_artifact)
        )
        proof_artifact = json.loads(value.v3_proof_artifact_json)
        if _canonical_artifact_json(proof_artifact) != value.v3_proof_artifact_json:
            raise ValueError("v3 proof artifact is not canonical")
        finalization = verify_exact_v3_finalization(proof_artifact)
    except (
        AttributeError,
        TypeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        CasperStateProofError,
        TreasurySnapshotError,
        ReadbackValidationError,
        V3AuthorizationError,
    ) as exc:
        raise V3AuthorizationError(
            "authorization transcript verification failed"
        ) from exc
    expected_snapshot_hashes = (
        value.snapshot_status_request_sha256,
        value.snapshot_status_sha256,
        value.snapshot_block_request_sha256,
        value.snapshot_block_sha256,
        value.snapshot_balance_request_sha256,
        value.snapshot_balance_response_sha256,
    )
    observed_snapshot_hashes = (
        snapshot.status_request_sha256,
        snapshot.status_sha256,
        snapshot.block_request_sha256,
        snapshot.block_sha256,
        snapshot.balance_request_sha256,
        snapshot.balance_response_sha256,
    )
    if expected_snapshot_hashes != observed_snapshot_hashes:
        raise V3AuthorizationError("snapshot transcript hash mismatch")
    if (
        snapshot_evidence.artifact_json != value.treasury_snapshot_artifact_json
        or len(value.treasury_snapshot_artifact_sha256) != 64
        or not hmac.compare_digest(
            snapshot_evidence.artifact_sha256,
            value.treasury_snapshot_artifact_sha256,
        )
    ):
        raise V3AuthorizationError("two-observer snapshot artifact hash mismatch")
    primary_transcripts = (
        snapshot.status_request_json,
        snapshot.status_json,
        snapshot.block_request_json,
        snapshot.block_json,
        snapshot.balance_request_json,
        snapshot.balance_response_json,
    )
    persisted_primary_transcripts = (
        value.snapshot_status_request_json,
        value.snapshot_status_json,
        value.snapshot_block_request_json,
        value.snapshot_block_json,
        value.snapshot_balance_request_json,
        value.snapshot_balance_response_json,
    )
    if primary_transcripts != persisted_primary_transcripts:
        raise V3AuthorizationError(
            "authorization transcript primary snapshot differs from "
            "two-observer artifact"
        )
    artifact_sha256 = hashlib.sha256(
        value.readback_artifact_json.encode("ascii")
    ).hexdigest()
    if len(value.readback_artifact_sha256) != 64 or not hmac.compare_digest(
        value.readback_artifact_sha256, artifact_sha256
    ):
        raise V3AuthorizationError("readback artifact hash mismatch")
    proof_sha256 = hashlib.sha256(
        value.v3_proof_artifact_json.encode("ascii")
    ).hexdigest()
    if (
        len(value.v3_proof_artifact_sha256) != 64
        or not hmac.compare_digest(value.v3_proof_artifact_sha256, proof_sha256)
        or not hmac.compare_digest(
            finalization.proof_artifact_sha256,
            value.v3_proof_artifact_sha256,
        )
    ):
        raise V3AuthorizationError("v3 proof artifact hash mismatch")

    expected_material = {
        "network": "casper-test",
        "proposal_id": str(header["proposal_id"]),
        "action_id": material.action_id,
        "envelope_hash": material.envelope_hash,
        "source_account": bytes32(body["source_account"], "source_account"),
        "recipient_account": bytes32(body["recipient_account"], "recipient_account"),
        "amount_motes": uint_value(body["amount_motes"], 512, "amount_motes"),
        "treasury_snapshot_balance_motes": uint_value(
            body["treasury_snapshot_balance_motes"],
            512,
            "treasury_snapshot_balance_motes",
        ),
        "approved_allocation_bps": uint_value(
            header["approved_allocation_bps"], 32, "approved_allocation_bps"
        ),
        "transfer_id": uint_value(body["transfer_id"], 64, "transfer_id"),
        "snapshot_block_hash": bytes32(
            body["snapshot_block_hash"], "snapshot_block_hash"
        ),
        "snapshot_block_height": uint_value(
            body["snapshot_block_height"], 64, "snapshot_block_height"
        ),
        "header_bytes": material.header_bytes,
        "body_bytes": material.body_bytes,
        "action_core_bytes": material.action_core_bytes,
    }
    for field, expected in expected_material.items():
        if getattr(value, field) != expected:
            raise V3AuthorizationError(
                f"{field} does not match recomputed typed envelope"
            )
    readback_expected = {
        "network": value.network,
        "package_hash": value.package_hash,
        "contract_hash": value.contract_hash,
        "schema_version": 3,
        "deployment_domain": value.deployment_domain,
        "casper_chain_name": "casper-test",
        "proposal_id": value.proposal_id,
        "proposed_envelope": value.envelope_hash,
        "finalized": True,
        "finalized_envelope": value.envelope_hash,
        "action_id": value.action_id,
        "action_authorized": True,
    }
    for field, expected in readback_expected.items():
        if getattr(readback, field) != expected:
            raise V3AuthorizationError(f"readback {field} does not match authorization")
    if readback.approval_count < readback.threshold:
        raise V3AuthorizationError("readback quorum is not satisfied")
    finalization_expected = {
        "network": value.network,
        "package_hash": value.package_hash,
        "contract_hash": value.contract_hash,
        "deployment_domain": value.deployment_domain,
        "proposal_id": value.proposal_id,
        "action_id": value.action_id,
        "envelope_hash": value.envelope_hash,
        "block_hash": value.finalization_block_hash,
        "block_height": value.finalization_block_height,
        "state_root_hash": value.finalization_state_root_hash,
    }
    for field, expected in finalization_expected.items():
        if getattr(finalization, field) != expected:
            raise V3AuthorizationError(
                f"exact finalization {field} does not match authorization"
            )
    proof_readback = proof_artifact.get("readback")
    if _canonical_artifact_json(proof_readback) != value.readback_artifact_json:
        raise V3AuthorizationError(
            "v3 proof readback differs from persisted authorization readback"
        )
    if (
        snapshot.account_hash != value.source_account
        or snapshot.block_hash != value.snapshot_block_hash
        or snapshot.block_height != value.snapshot_block_height
        or snapshot.state_root_hash != value.snapshot_state_root_hash
        or snapshot.balance_motes != value.treasury_snapshot_balance_motes
    ):
        raise V3AuthorizationError("snapshot does not match typed authorization")
    if snapshot.block_height >= value.finalization_block_height:
        raise V3AuthorizationError("snapshot must precede exact v3 finalization")
    if readback.observed_block_height < value.finalization_block_height:
        raise V3AuthorizationError("v3 readback predates exact finalization")
    if readback.observed_block_height == value.finalization_block_height and (
        readback.observed_block_hash != value.finalization_block_hash
        or readback.observed_state_root_hash != value.finalization_state_root_hash
    ):
        raise V3AuthorizationError(
            "v3 readback disagrees with exact finalization block"
        )
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
    readback: VerifiedV3Readback,
    snapshot: VerifiedTreasurySnapshot,
    finalization: VerifiedV3Finalization,
) -> VerifiedNativeAuthorization:
    """Recompute the 19+11-field envelope and bind it to pinned chain state."""

    _validate_deployment(deployment)
    try:
        snapshot = require_verified_treasury_snapshot(snapshot)
    except TreasurySnapshotError as exc:
        raise V3AuthorizationError("snapshot is not parser-verified") from exc
    try:
        readback = validate_verified_readback(readback)
    except ReadbackValidationError as exc:
        raise V3AuthorizationError("readback is not parser-verified") from exc
    finalization = validate_verified_v3_finalization(finalization)
    try:
        proof_artifact = json.loads(finalization.proof_artifact_json)
        proof_deployment = proof_artifact["deployment"]
        proof_build = proof_deployment["build"]
        proof_source = proof_deployment["source"]
        if _canonical_artifact_json(
            readback.persisted_artifact()
        ) != _canonical_artifact_json(proof_artifact["readback"]):
            raise ValueError("readback differs from exact proof")
        proof_release = {
            "source_sha256": bytes32(proof_source["lib_rs_sha256"], "source_sha256"),
            "wasm_sha256": bytes32(proof_build["wasm_sha256"], "wasm_sha256"),
            "schema_sha256": bytes32(proof_build["schema_sha256"], "schema_sha256"),
        }
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise V3AuthorizationError(
            "v3 proof deployment/readback binding is invalid"
        ) from exc
    for field, expected in proof_release.items():
        _require_exact(field, getattr(deployment, field), expected)
    material = derive_native_material(header, body)

    header_domain = _require_bytes("deployment_domain", header["deployment_domain"])
    header_action_id = _require_bytes("action_id", header["action_id"])
    body_source = _require_bytes("source_account", body["source_account"])
    body_recipient = _require_bytes("recipient_account", body["recipient_account"])
    body_snapshot_hash = _require_bytes(
        "snapshot_block_hash", body["snapshot_block_hash"]
    )
    proposal_id = str(header["proposal_id"])
    approved_bps = uint_value(
        header["approved_allocation_bps"], 32, "approved_allocation_bps"
    )
    amount_motes = uint_value(body["amount_motes"], 512, "amount_motes")
    snapshot_balance = uint_value(
        body["treasury_snapshot_balance_motes"], 512, "treasury_snapshot_balance_motes"
    )
    snapshot_height = uint_value(
        body["snapshot_block_height"], 64, "snapshot_block_height"
    )
    transfer_id = uint_value(body["transfer_id"], 64, "transfer_id")

    _require_exact(
        "header schema_version",
        int(header["schema_version"]),
        deployment.schema_version,
    )
    _require_exact(
        "header deployment_domain", header_domain, deployment.deployment_domain
    )
    _require_exact(
        "header casper_chain_name",
        header["casper_chain_name"],
        deployment.casper_chain_name,
    )

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
    expected_finalization = {
        "network": deployment.network,
        "package_hash": deployment.package_hash,
        "contract_hash": deployment.contract_hash,
        "deployment_domain": deployment.deployment_domain,
        "proposal_id": proposal_id,
        "action_id": material.action_id,
        "envelope_hash": material.envelope_hash,
    }
    for field, expected in expected_finalization.items():
        _require_exact(field, getattr(finalization, field), expected)
    finalization_height = uint_value(
        finalization.block_height, 64, "finalization_block_height"
    )

    expected_snapshot = {
        "network": deployment.network,
        "block_hash": body_snapshot_hash,
        "block_height": snapshot_height,
        "account_hash": body_source,
        "balance_motes": snapshot_balance,
    }
    for field, expected in expected_snapshot.items():
        _require_exact(field, getattr(snapshot, field), expected)
    _require_bytes("snapshot block_hash", snapshot.block_hash)
    snapshot_state_root = _require_bytes(
        "snapshot state_root_hash", snapshot.state_root_hash
    )
    if snapshot.block_height >= finalization_height:
        raise V3AuthorizationError("snapshot must precede exact v3 finalization")
    if readback.observed_block_height < finalization_height:
        raise V3AuthorizationError("v3 readback predates exact finalization")
    if readback.observed_block_height == finalization_height and (
        readback.observed_block_hash != finalization.block_hash
        or readback.observed_state_root_hash != finalization.state_root_hash
    ):
        raise V3AuthorizationError(
            "v3 readback disagrees with exact finalization block"
        )

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
        snapshot_status_request_json=snapshot.primary.status_request_json,
        snapshot_status_json=snapshot.primary.status_json,
        snapshot_block_request_json=snapshot.primary.block_request_json,
        snapshot_block_json=snapshot.primary.block_json,
        snapshot_balance_request_json=snapshot.primary.balance_request_json,
        snapshot_balance_response_json=snapshot.primary.balance_response_json,
        snapshot_status_request_sha256=snapshot.primary.status_request_sha256,
        snapshot_status_sha256=snapshot.primary.status_sha256,
        snapshot_block_request_sha256=snapshot.primary.block_request_sha256,
        snapshot_block_sha256=snapshot.primary.block_sha256,
        snapshot_balance_request_sha256=snapshot.primary.balance_request_sha256,
        snapshot_balance_response_sha256=snapshot.primary.balance_response_sha256,
        treasury_snapshot_artifact_json=snapshot.artifact_json,
        treasury_snapshot_artifact_sha256=snapshot.artifact_sha256,
        finalization_block_hash=_require_bytes(
            "exact finalization block_hash", finalization.block_hash
        ),
        finalization_block_height=finalization_height,
        finalization_state_root_hash=_require_bytes(
            "exact finalization state_root_hash", finalization.state_root_hash
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
        typed_header_json=_canonical_input_json(header, "typed header"),
        typed_body_json=_canonical_input_json(body, "typed body"),
        readback_artifact_json=_canonical_artifact_json(readback.persisted_artifact()),
        readback_artifact_sha256="",
        v3_proof_artifact_json=finalization.proof_artifact_json,
        v3_proof_artifact_sha256=finalization.proof_artifact_sha256,
        verification_seal=bytes(32),
    )
    verified = replace(
        verified,
        readback_artifact_sha256=hashlib.sha256(
            verified.readback_artifact_json.encode("ascii")
        ).hexdigest(),
    )
    return replace(verified, verification_seal=_authorization_seal(verified))
