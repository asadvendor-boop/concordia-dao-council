"""Blocker 1 failure-first suite: executed attestation binding.

A caller-authored summary with plausible counters/hashes must refuse; every
altered repository-recomputable fact (artifact bytes, path, toolchain, tag,
profile) must refuse with a stable code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.attestation import (
    attestation_entry_digest,
    production_build_runner,
    verify_attestation_document,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    return mc_support.build_hermetic_repo(tmp_path)


def _verify(repo: Path, document: dict[str, object]) -> dict[str, object]:
    return verify_attestation_document(
        repo,
        document,
        rc_tag="concordia-testnet-rc-v3.0-test",
        rc_peeled_commit_sha=mc_support.repo_head(repo),
        rc_mainnet_wasm_sha256=mc_support.MAINNET_WASM_SHA,
    )


def _redigested(document: dict[str, object]) -> dict[str, object]:
    document["entry_digests"] = {
        profile: attestation_entry_digest(entry)
        for profile, entry in document["network_artifacts"].items()
    }
    return document


def test_the_executed_document_verifies(repo: Path) -> None:
    _verify(repo, mc_support.make_attestation(repo))


def test_caller_authored_summary_with_plausible_counters_refuses(
    repo: Path,
) -> None:
    """The exact blocker-1 attack: right shape, right-looking counters and
    hashes — but the recorded tag object never existed in the repository."""

    document = mc_support.make_attestation(repo)
    for entry in document["network_artifacts"].values():
        entry["tag_object_sha"] = "9" * 40
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


def test_legacy_v1_shaped_summary_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    del document["entry_digests"]
    del document["schema_id"]
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


def test_altered_artifact_hash_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["testnet"]["wasm_sha256"] = "0" * 64
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.ARTIFACT_HASH_UNBACKED


def test_altered_artifact_path_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["testnet"]["artifact_relpath"] = (
        "somewhere/else.wasm"
    )
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


def test_altered_toolchain_lock_digest_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["mainnet-native"]["toolchain"][
        "cargo_lock_sha256"
    ] = "1" * 64
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.TOOLCHAIN_UNPINNED


def test_altered_tag_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    for entry in document["network_artifacts"].values():
        entry["tag"] = "some-other-tag"
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


def test_altered_profile_delta_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["mainnet-native"]["build_env_delta"] = {
        "CONCORDIA_V3_NETWORK_PROFILE": "mainnet-native",
        "EXTRA_FLAG": "1",
    }
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.SOURCE_DELTA_NOT_ALLOWLISTED


def test_edited_after_build_without_redigest_refuses(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["mainnet-native"]["wasm_size_bytes"] = 8192
    # Deliberately NOT re-digested: the canonical digest catches the edit.
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


def test_byte_identical_profiles_refuse(repo: Path) -> None:
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["mainnet-native"]["wasm_sha256"] = (
        mc_support.TESTNET_WASM_SHA
    )
    _redigested(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify(repo, document)
    # Disjointness or declared-hash backing — either stable code closes it.
    assert refusal.value.code in (
        RefusalCode.RC_MAINNET_WASM_UNATTESTED,
        RefusalCode.ARTIFACT_HASH_UNBACKED,
    )


def test_production_runner_requires_absolute_pinned_cargo() -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        production_build_runner("cargo")
    assert refusal.value.code == RefusalCode.BUILD_COMMAND_INVALID
