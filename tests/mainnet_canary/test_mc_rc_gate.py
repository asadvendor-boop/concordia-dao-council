"""Failure-first tests for the Testnet-RC release-dependency gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from mc_support import (
    TESTNET_WASM_SHA,
    git_commit_all,
    make_rc_declaration,
    write_json,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.rc_gate import validate_rc_gate


def _declare(tmp_path: Path, repo: Path, **overrides: object) -> Path:
    return write_json(
        tmp_path / "rc-declaration.json", make_rc_declaration(repo, **overrides)
    )


def test_absent_rc_declaration_blocks_everything(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, tmp_path / "missing.json")
    assert refusal.value.code == RefusalCode.RC_DECLARATION_ABSENT


def test_valid_declaration_passes_and_returns_rc_facts(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    rc = validate_rc_gate(hermetic_repo, _declare(tmp_path, hermetic_repo))
    assert rc.testnet_wasm_sha256 == TESTNET_WASM_SHA
    assert rc.mainnet_wasm_chain_name == "casper"


def test_unknown_and_missing_fields_are_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    document = make_rc_declaration(hermetic_repo)
    document["extra_field"] = True
    path = write_json(tmp_path / "rc.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_DECLARATION_INVALID


def test_red_gate_is_refused(hermetic_repo: Path, tmp_path: Path) -> None:
    document = make_rc_declaration(hermetic_repo)
    document["gates"]["hosted_gates_green"] = False
    path = write_json(tmp_path / "rc.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_GATES_NOT_GREEN


def test_testnet_chain_name_is_refused_in_mainnet_mode(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    path = _declare(tmp_path, hermetic_repo, mainnet_chain_name="casper-test")
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.CHAIN_NAME_MISMATCH


def test_testnet_endpoint_is_refused_in_mainnet_mode(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    path = _declare(
        tmp_path,
        hermetic_repo,
        mainnet_rpc_url="https://node.testnet.casper.network/rpc",
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.ENDPOINT_NOT_PINNED


def test_wrong_commit_is_refused(hermetic_repo: Path, tmp_path: Path) -> None:
    path = _declare(
        tmp_path, hermetic_repo, peeled_commit_sha="1" * 40
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_COMMIT_MISMATCH


def test_dirty_tracked_tree_is_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    path = _declare(tmp_path, hermetic_repo)
    tracked = (
        hermetic_repo / "contracts" / "odra-governance-receipt" / "legacy-source.txt"
    )
    tracked.write_text("mutated\n", encoding="utf-8")
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.SOURCE_TREE_DIRTY


def test_wrong_wasm_hash_is_refused(hermetic_repo: Path, tmp_path: Path) -> None:
    path = _declare(tmp_path, hermetic_repo, testnet_wasm_sha256="2" * 64)
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_WASM_MISMATCH


def test_missing_mainnet_wasm_attestation_is_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    path = _declare(tmp_path, hermetic_repo, mainnet_wasm_sha256=None)
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_MAINNET_WASM_UNATTESTED


def test_reusing_testnet_wasm_as_mainnet_wasm_is_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    """The Testnet RC Wasm hard-codes chain `casper-test`; byte-identical
    reuse cannot initialise on Mainnet (interface manifest finding B1)."""

    from tools.mainnet_canary.constants import TESTNET_RC_WASM_SHA256_AT_PREP_BASE

    path = _declare(
        tmp_path,
        hermetic_repo,
        mainnet_wasm_sha256=TESTNET_RC_WASM_SHA256_AT_PREP_BASE,
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_MAINNET_WASM_UNATTESTED


def test_mainnet_wasm_with_testnet_chain_constant_is_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    path = _declare(tmp_path, hermetic_repo, mainnet_wasm_chain_name="casper-test")
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.RC_MAINNET_WASM_UNATTESTED


def test_historical_hash_drift_is_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    """A drifted historical artifact fails line-level recomputation even
    when the inventory file itself is untouched."""

    tracked = (
        hermetic_repo / "contracts" / "odra-governance-receipt" / "legacy-source.txt"
    )
    tracked.write_text("silently rewritten history\n", encoding="utf-8")
    git_commit_all(hermetic_repo, "tamper with frozen history")
    path = _declare(tmp_path, hermetic_repo)
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.HISTORICAL_HASH_DRIFT


def test_historical_inventory_file_drift_is_refused(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    path = _declare(
        tmp_path, hermetic_repo, historical_odra_inventory_sha256="3" * 64
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.HISTORICAL_HASH_DRIFT


def test_secret_material_in_declaration_is_refused_without_echo(
    hermetic_repo: Path, tmp_path: Path
) -> None:
    document = make_rc_declaration(hermetic_repo)
    document["rc_tag"] = "-----BEGIN PRIVATE KEY-----"
    path = write_json(tmp_path / "rc.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        validate_rc_gate(hermetic_repo, path)
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_SECRET_MATERIAL
    assert "BEGIN PRIVATE KEY" not in refusal.value.detail
