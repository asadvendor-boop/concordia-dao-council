"""RC gate v2: reproducible artifact attestation (failing-first suite).

Requirements under test (Sol Mainnet hardening prompt):
- annotated-tag resolution only (tag object + peeled commit; missing,
  lightweight, and moved tags all refuse);
- any tracked/staged/unstaged/untracked drift refuses;
- each network artifact is built TWICE from independently exported clean
  trees and must be byte-identical;
- the recorded hash is recomputed from the ACTUAL built artifact — a
  declared hash is never trusted;
- Mainnet and Testnet artifact hashes must differ;
- the only permitted build-input delta between network artifacts is the
  allowlisted profile environment variable;
- toolchain identity must be pinned or the attestation refuses;
- the RC declaration's expected pre-quorum error must be EXACTLY
  ``User error: 8`` (no prefix matching).
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.attestation import (
    ALLOWED_BUILD_ENV_KEY,
    attest_network_build,
    require_disjoint_network_artifacts,
    resolve_annotated_tag,
    verify_declared_artifact_hash,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.rc_gate import validate_rc_gate


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _toolchain() -> dict[str, str]:
    return {
        "rustc_version": "rustc 1.86.0-nightly (test)",
        "cargo_odra_version": "cargo-odra 0.1.7",
        "cargo_lock_sha256": "ab" * 32,
    }


def _executable() -> dict[str, str]:
    return {
        "path": "/opt/toolchain/bin/cargo",
        "path_sha256": "cd" * 32,
        "version": "cargo-odra 0.1.7",
    }


def _deterministic_runner(tree: Path, env_delta: dict[str, str]) -> Path:
    """Fake accepted release command: output depends only on tree + profile."""

    digest = hashlib.sha256()
    for path in sorted(tree.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(tree)).encode())
            digest.update(path.read_bytes())
    digest.update(env_delta[ALLOWED_BUILD_ENV_KEY].encode())
    out = tree / "wasm" / "GovernanceReceiptV3.wasm"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\x00asm" + digest.digest())
    return out


def _nondeterministic_runner(tree: Path, env_delta: dict[str, str]) -> Path:
    import os

    out = tree / "wasm" / "GovernanceReceiptV3.wasm"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"\x00asm" + os.urandom(16))
    return out


def _attest(repo: Path, tmp_path: Path, *, profile: str = "mainnet-native", runner=None, toolchain=None, tag: str = "rc-tag-v1"):
    return attest_network_build(
        repo,
        tag=tag,
        expected_peeled_commit_sha=mc_support.repo_head(repo),
        profile=profile,
        build_runner=runner or _deterministic_runner,
        # SEC7: the scratch parent must already exist; the attestation owns a
        # uniquely-named child under it and never creates/deletes the root.
        scratch_dir=tmp_path,
        toolchain_probe=toolchain or _toolchain,
        executable_probe=_executable,
    )


@pytest.fixture()
def tagged_repo(hermetic_repo: Path) -> Path:
    _git(hermetic_repo, "tag", "-a", "rc-tag-v1", "-m", "annotated RC tag")
    return hermetic_repo


class TestTagResolution:
    def test_missing_tag_refuses(self, hermetic_repo: Path) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            resolve_annotated_tag(hermetic_repo, "no-such-tag")
        assert refusal.value.code == RefusalCode.TAG_MISSING

    def test_lightweight_tag_refuses(self, hermetic_repo: Path) -> None:
        _git(hermetic_repo, "tag", "light-tag")
        with pytest.raises(CanaryRefusal) as refusal:
            resolve_annotated_tag(hermetic_repo, "light-tag")
        assert refusal.value.code == RefusalCode.TAG_NOT_ANNOTATED

    def test_annotated_tag_resolves_object_and_peeled_commit(self, tagged_repo: Path) -> None:
        resolution = resolve_annotated_tag(tagged_repo, "rc-tag-v1")
        assert resolution.peeled_commit_sha == mc_support.repo_head(tagged_repo)
        assert resolution.tag_object_sha != resolution.peeled_commit_sha
        assert len(resolution.tag_object_sha) == 40

    def test_moved_tag_refuses(self, tagged_repo: Path) -> None:
        original_head = mc_support.repo_head(tagged_repo)
        (tagged_repo / "new-file.txt").write_text("moved\n", encoding="utf-8")
        mc_support.git_commit_all(tagged_repo, "advance")
        _git(tagged_repo, "tag", "-f", "-a", "rc-tag-v1", "-m", "moved tag")
        with pytest.raises(CanaryRefusal) as refusal:
            resolve_annotated_tag(
                tagged_repo, "rc-tag-v1", expected_peeled_commit_sha=original_head
            )
        assert refusal.value.code == RefusalCode.TAG_MOVED


class TestDriftRefusals:
    def test_untracked_file_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        (tagged_repo / "stray-untracked.txt").write_text("drift\n", encoding="utf-8")
        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path)
        assert refusal.value.code == RefusalCode.SOURCE_TREE_DIRTY

    def test_unstaged_modification_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        target = tagged_repo / "handoff" / "HISTORICAL_ODRA_SHA256.txt"
        target.write_text(target.read_text(encoding="utf-8") + "# drift\n", encoding="utf-8")
        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path)
        assert refusal.value.code == RefusalCode.SOURCE_TREE_DIRTY

    def test_staged_modification_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        (tagged_repo / "staged.txt").write_text("staged\n", encoding="utf-8")
        _git(tagged_repo, "add", "staged.txt")
        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path)
        assert refusal.value.code == RefusalCode.SOURCE_TREE_DIRTY


class TestReproducibleBuilds:
    def test_double_build_produces_backed_hash(self, tagged_repo: Path, tmp_path: Path) -> None:
        attestation = _attest(tagged_repo, tmp_path)
        assert attestation["profile"] == "mainnet-native"
        assert attestation["build_env_delta"] == {ALLOWED_BUILD_ENV_KEY: "mainnet-native"}
        assert attestation["builds"] == 2
        assert len(attestation["wasm_sha256"]) == 64
        assert attestation["wasm_size_bytes"] > 0
        assert attestation["toolchain"]["cargo_odra_version"] == "cargo-odra 0.1.7"

    def test_nondeterministic_build_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path, runner=_nondeterministic_runner)
        assert refusal.value.code == RefusalCode.BUILD_NOT_REPRODUCIBLE

    def test_unknown_profile_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path, profile="casper-test")
        assert refusal.value.code == RefusalCode.BUILD_COMMAND_INVALID

    def test_failed_build_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        def broken(tree: Path, env_delta: dict[str, str]) -> Path:
            raise RuntimeError("compiler exploded")

        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path, runner=broken)
        assert refusal.value.code == RefusalCode.BUILD_FAILED

    def test_missing_toolchain_identity_refuses(self, tagged_repo: Path, tmp_path: Path) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            _attest(tagged_repo, tmp_path, toolchain=lambda: {"rustc_version": ""})
        assert refusal.value.code == RefusalCode.TOOLCHAIN_UNPINNED

    def test_network_profiles_must_yield_disjoint_artifacts(self, tagged_repo: Path, tmp_path: Path) -> None:
        testnet = _attest(tagged_repo, tmp_path, profile="testnet")
        mainnet = _attest(tagged_repo, tmp_path, profile="mainnet-native")
        assert testnet["wasm_sha256"] != mainnet["wasm_sha256"]
        require_disjoint_network_artifacts(testnet, mainnet)
        with pytest.raises(CanaryRefusal) as refusal:
            require_disjoint_network_artifacts(testnet, dict(mainnet, wasm_sha256=testnet["wasm_sha256"]))
        assert refusal.value.code == RefusalCode.RC_MAINNET_WASM_UNATTESTED

    def test_declared_hash_must_be_backed_by_actual_artifact(self, tagged_repo: Path, tmp_path: Path) -> None:
        attestation = _attest(tagged_repo, tmp_path)
        verify_declared_artifact_hash(attestation, attestation["wasm_sha256"])
        with pytest.raises(CanaryRefusal) as refusal:
            verify_declared_artifact_hash(attestation, "0" * 64)
        assert refusal.value.code == RefusalCode.ARTIFACT_HASH_UNBACKED


class TestRcGateTightening:
    def test_prequorum_error_prefix_match_is_no_longer_accepted(
        self, hermetic_repo: Path, tmp_path: Path
    ) -> None:
        # `User error: 88` passed the prototype's startswith() check; v2
        # requires the exact QuorumNotMet rendering `User error: 8`.
        declaration = mc_support.make_rc_declaration(
            hermetic_repo, expected_prequorum_error_message="User error: 88"
        )
        path = mc_support.write_json(tmp_path / "rc.json", declaration)
        with pytest.raises(CanaryRefusal) as refusal:
            validate_rc_gate(hermetic_repo, path)
        assert refusal.value.code == RefusalCode.RC_DECLARATION_INVALID

    def test_untracked_file_now_fails_the_clean_tree_check(
        self, hermetic_repo: Path, tmp_path: Path
    ) -> None:
        # The prototype used --untracked-files=no, so untracked drift passed.
        declaration = mc_support.make_rc_declaration(hermetic_repo)
        path = mc_support.write_json(tmp_path / "rc.json", declaration)
        (hermetic_repo / "untracked-drift.txt").write_text("x\n", encoding="utf-8")
        with pytest.raises(CanaryRefusal) as refusal:
            validate_rc_gate(hermetic_repo, path)
        assert refusal.value.code == RefusalCode.SOURCE_TREE_DIRTY
