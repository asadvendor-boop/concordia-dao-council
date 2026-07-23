"""Failure-first tests for the public key inventory and secret guard."""

from __future__ import annotations

from pathlib import Path

import pytest

from mc_support import ROLE_PUBLIC_KEYS, make_key_inventory, write_json
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.keys import (
    derive_account_hash,
    load_key_inventory,
    refuse_known_testnet_identity_reuse,
)
from tools.mainnet_canary.secret_guard import (
    refuse_secret_path,
    scan_for_secret_material,
)


def test_absent_inventory_is_a_stable_refusal(tmp_path: Path) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(tmp_path / "missing.json")
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_ABSENT


def test_valid_inventory_loads_and_recomputes_account_hashes(
    tmp_path: Path,
) -> None:
    path = write_json(tmp_path / "inventory.json", make_key_inventory())
    inventory = load_key_inventory(path)
    assert inventory.threshold == 2
    proposer = inventory.roles["proposer"]
    assert proposer.account_hash_hex == derive_account_hash(
        ROLE_PUBLIC_KEYS["proposer"]
    )


def test_account_hash_mismatch_is_refused(tmp_path: Path) -> None:
    document = make_key_inventory()
    document["roles"]["proposer"]["account_hash_hex"] = "9" * 64
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_INVALID


def test_missing_role_is_refused(tmp_path: Path) -> None:
    document = make_key_inventory()
    del document["roles"]["signer_c"]
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.ROLE_SET_INVALID


def test_overlapping_governance_roles_are_refused(tmp_path: Path) -> None:
    document = make_key_inventory()
    document["roles"]["signer_a"] = dict(document["roles"]["proposer"])
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.ROLE_SET_INVALID


def test_source_equals_recipient_is_refused(tmp_path: Path) -> None:
    document = make_key_inventory()
    document["roles"]["recipient"] = dict(document["roles"]["treasury_source"])
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.ROLE_SET_INVALID


def test_testnet_network_inventory_is_refused(tmp_path: Path) -> None:
    document = make_key_inventory(network="casper-test")
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.NETWORK_MISMATCH


def test_invalid_threshold_is_refused(tmp_path: Path) -> None:
    path = write_json(tmp_path / "inventory.json", make_key_inventory(threshold=1))
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_INVALID


def test_key_mount_reference_outside_secret_mount_is_refused(
    tmp_path: Path,
) -> None:
    document = make_key_inventory()
    document["roles"]["proposer"]["key_file_mount_path"] = "/tmp/proposer.pem"
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_INVALID


def test_inventory_with_embedded_private_key_is_refused_without_echo(
    tmp_path: Path,
) -> None:
    document = make_key_inventory()
    marker = "-----BEGIN PRIVATE KEY-----"
    document["roles"]["proposer"]["public_key_hex"] = marker
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_SECRET_MATERIAL
    assert marker not in refusal.value.detail


def test_testnet_identity_reuse_is_refused(tmp_path: Path) -> None:
    path = write_json(tmp_path / "inventory.json", make_key_inventory())
    inventory = load_key_inventory(path)
    reused_hash = inventory.roles["treasury_source"].account_hash_hex
    with pytest.raises(CanaryRefusal) as refusal:
        refuse_known_testnet_identity_reuse(inventory, {reused_hash})
    assert refusal.value.code == RefusalCode.TESTNET_IDENTITY_REUSE


def test_secret_paths_are_never_opened() -> None:
    for candidate in (
        "/run/secrets/mainnet_canary/proposer.pem",
        "/run/secrets/anything",
        "/home/user/keys/treasury.pem",
    ):
        with pytest.raises(CanaryRefusal) as refusal:
            refuse_secret_path(candidate, context="test")
        assert refusal.value.code == RefusalCode.SECRET_PATH_READ_REFUSED


def test_secret_scanner_catches_key_like_material() -> None:
    assert scan_for_secret_material("-----BEGIN EC PRIVATE KEY-----")
    assert scan_for_secret_material("Authorization: token-value")
    assert scan_for_secret_material("secret_key = deadbeef")
    assert not scan_for_secret_material('{"public_key_hex": "01aabb"}')
