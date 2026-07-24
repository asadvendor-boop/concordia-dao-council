"""SEC7 failure-first suite: the attestation never rm -rf's a caller root.

A caller-selected scratch root may contain unrelated files.  The attestation
must create and remove only a uniquely-owned child under a validated parent,
and unrelated sentinels must survive BOTH a successful build and a failing
one.  A non-existent, symlinked, or file parent must refuse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.mainnet_canary.attestation import _OwnedScratchChild
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode


def test_owned_child_removes_only_itself_on_success(tmp_path: Path) -> None:
    parent = tmp_path / "scratch-root"
    parent.mkdir()
    sentinel = parent / "operator-keeps-this.txt"
    sentinel.write_text("do not delete me", encoding="utf-8")

    with _OwnedScratchChild(parent) as owned:
        assert owned.parent == parent
        (owned / "build-artifact").write_text("x", encoding="utf-8")
        child = owned

    assert not child.exists()          # our child is gone
    assert sentinel.exists()           # the sentinel survived
    assert parent.exists()             # the caller's root survived


def test_owned_child_removes_only_itself_on_failure(tmp_path: Path) -> None:
    parent = tmp_path / "scratch-root"
    parent.mkdir()
    sentinel = parent / "operator-keeps-this.txt"
    sentinel.write_text("survive the exception too", encoding="utf-8")

    with pytest.raises(RuntimeError):
        with _OwnedScratchChild(parent) as owned:
            (owned / "half-written").write_text("x", encoding="utf-8")
            raise RuntimeError("build blew up mid-flight")

    assert sentinel.exists()
    assert parent.exists()
    # No leftover owned children under the parent.
    assert [p.name for p in parent.iterdir()] == ["operator-keeps-this.txt"]


def test_nonexistent_parent_refuses(tmp_path: Path) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        _OwnedScratchChild(tmp_path / "does-not-exist")
    assert refusal.value.code == RefusalCode.BUILD_COMMAND_INVALID


def test_symlinked_parent_refuses(tmp_path: Path) -> None:
    real = tmp_path / "real-dir"
    real.mkdir()
    link = tmp_path / "link-dir"
    link.symlink_to(real)
    with pytest.raises(CanaryRefusal) as refusal:
        _OwnedScratchChild(link)
    assert refusal.value.code == RefusalCode.BUILD_COMMAND_INVALID


def test_file_parent_refuses(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "a-file"
    not_a_dir.write_text("x", encoding="utf-8")
    with pytest.raises(CanaryRefusal) as refusal:
        _OwnedScratchChild(not_a_dir)
    assert refusal.value.code == RefusalCode.BUILD_COMMAND_INVALID


def test_two_owned_children_are_distinct(tmp_path: Path) -> None:
    parent = tmp_path / "scratch-root"
    parent.mkdir()
    with _OwnedScratchChild(parent) as a, _OwnedScratchChild(parent) as b:
        assert a != b
        assert a.parent == parent and b.parent == parent
