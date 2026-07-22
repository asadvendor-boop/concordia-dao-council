"""Fail-closed construction of executable v3 native authorizations."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from shared.v3_authorization import (
    CanonicalTreasurySnapshot,
    V3AuthorizationError,
    V3ChainReadback,
    V3DeploymentIdentity,
    validate_verified_authorization,
    verify_native_authorization,
)


VECTOR = (
    Path(__file__).parent / "golden/envelope_v3/native_transfer/GV-NT-01.json"
)


def _values(fields: list[dict[str, object]]) -> dict[str, object]:
    return {str(field["name"]): field["value"] for field in fields}


def _inputs() -> tuple[dict[str, object], dict[str, object]]:
    typed_input = json.loads(VECTOR.read_text(encoding="utf-8"))["typed_input"]
    return _values(typed_input["header"]), _values(typed_input["body"])


def _deployment(header: dict[str, object]) -> V3DeploymentIdentity:
    return V3DeploymentIdentity(
        network="casper-test",
        package_hash=bytes.fromhex("91" * 32),
        contract_hash=bytes.fromhex("92" * 32),
        schema_version=3,
        deployment_domain=bytes.fromhex(str(header["deployment_domain"])),
        casper_chain_name="casper-test",
        source_sha256=bytes.fromhex("93" * 32),
        wasm_sha256=bytes.fromhex("94" * 32),
        schema_sha256=bytes.fromhex("95" * 32),
    )


def _readback(
    header: dict[str, object],
    deployment: V3DeploymentIdentity,
) -> V3ChainReadback:
    envelope_hash = bytes.fromhex(
        json.loads(VECTOR.read_text(encoding="utf-8"))["hashes"]["envelope_hash"]
    )
    return V3ChainReadback(
        network="casper-test",
        package_hash=deployment.package_hash,
        contract_hash=deployment.contract_hash,
        schema_version=3,
        deployment_domain=deployment.deployment_domain,
        casper_chain_name="casper-test",
        proposal_id=str(header["proposal_id"]),
        proposed_envelope=envelope_hash,
        finalized=True,
        finalized_envelope=envelope_hash,
        action_id=bytes.fromhex(str(header["action_id"])),
        action_authorized=True,
        observed_block_hash=bytes.fromhex("96" * 32),
        observed_block_height=8_600_000,
        observed_state_root_hash=bytes.fromhex("97" * 32),
    )


def _snapshot(body: dict[str, object]) -> CanonicalTreasurySnapshot:
    return CanonicalTreasurySnapshot(
        network="casper-test",
        block_hash=bytes.fromhex(str(body["snapshot_block_hash"])),
        block_height=int(str(body["snapshot_block_height"])),
        state_root_hash=bytes.fromhex("98" * 32),
        source_account=bytes.fromhex(str(body["source_account"])),
        source_balance_motes=int(str(body["treasury_snapshot_balance_motes"])),
    )


def test_factory_binds_complete_native_envelope_to_chain_and_snapshot() -> None:
    header, body = _inputs()
    deployment = _deployment(header)

    verified = verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=_readback(header, deployment),
        snapshot=_snapshot(body),
    )

    assert verified.proposal_id == header["proposal_id"]
    assert verified.action_id == bytes.fromhex(str(header["action_id"]))
    assert verified.envelope_hash.hex() == "9b3b6c9ec91cbc6ffb657addce26b47172835e2a8337cf209eca78ac664ab646"
    assert verified.amount_motes == 50_000_000_000
    assert verified.treasury_snapshot_balance_motes == 625_000_000_000
    assert verified.approved_allocation_bps == 800
    assert verified.snapshot_state_root_hash == bytes.fromhex("98" * 32)
    assert verified.finalization_state_root_hash == bytes.fromhex("97" * 32)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("network", "casper-testnet"),
        ("package_hash", bytes.fromhex("a1" * 32)),
        ("contract_hash", bytes.fromhex("a2" * 32)),
        ("schema_version", 2),
        ("deployment_domain", bytes.fromhex("a3" * 32)),
        ("casper_chain_name", "casper-mainnet"),
        ("proposal_id", "DAO-PROP-OTHER"),
        ("proposed_envelope", bytes.fromhex("a4" * 32)),
        ("finalized", False),
        ("finalized_envelope", bytes.fromhex("a5" * 32)),
        ("action_id", bytes.fromhex("a6" * 32)),
        ("action_authorized", False),
    ],
)
def test_factory_rejects_every_mismatched_chain_binding(
    field: str,
    bad_value: object,
) -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    readback = replace(_readback(header, deployment), **{field: bad_value})

    with pytest.raises(V3AuthorizationError, match=field):
        verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=readback,
            snapshot=_snapshot(body),
        )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("network", "casper-testnet"),
        ("block_hash", bytes.fromhex("b1" * 32)),
        ("block_height", 8_590_557),
        ("source_account", bytes.fromhex("b2" * 32)),
        ("source_balance_motes", 625_000_000_001),
    ],
)
def test_factory_rejects_every_mismatched_snapshot_binding(
    field: str,
    bad_value: object,
) -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    snapshot = replace(_snapshot(body), **{field: bad_value})

    with pytest.raises(V3AuthorizationError, match=field):
        verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=_readback(header, deployment),
            snapshot=snapshot,
        )


def test_snapshot_must_precede_finalization_readback() -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    readback = replace(_readback(header, deployment), observed_block_height=8_590_556)

    with pytest.raises(V3AuthorizationError, match="precede"):
        verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=readback,
            snapshot=_snapshot(body),
        )


def test_verified_authorization_integrity_seal_rejects_post_factory_mutation() -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    verified = verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=_readback(header, deployment),
        snapshot=_snapshot(body),
    )

    validate_verified_authorization(verified)
    forged = replace(verified, approved_allocation_bps=1_000)

    with pytest.raises(V3AuthorizationError, match="integrity seal"):
        validate_verified_authorization(forged)
