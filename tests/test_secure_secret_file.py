"""Adversarial tests for secret-file custody shared by release operators."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import shared.secure_secret_file as secure_file
from shared.secure_secret_file import SecureSecretFileError, read_secure_secret_file


def _secret(path: Path, value: bytes = b"release-secret\n") -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("mode", (0o400, 0o600))
def test_secure_secret_file_accepts_only_owner_private_regular_file(
    tmp_path: Path,
    mode: int,
) -> None:
    path = _secret(tmp_path / "secret")
    path.chmod(mode)

    assert read_secure_secret_file(path, max_bytes=64) == b"release-secret\n"


@pytest.mark.parametrize("mode", (0o004, 0o040, 0o440, 0o644, 0o660))
def test_secure_secret_file_rejects_group_or_other_access(
    tmp_path: Path,
    mode: int,
) -> None:
    path = _secret(tmp_path / "secret")
    path.chmod(mode)

    with pytest.raises(SecureSecretFileError):
        read_secure_secret_file(path, max_bytes=64)


def test_secure_secret_file_rejects_final_and_ancestor_symlinks(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    secret = _secret(real / "secret")
    final_link = real / "final-link"
    final_link.symlink_to(secret)
    ancestor_link = tmp_path / "ancestor-link"
    ancestor_link.symlink_to(real, target_is_directory=True)

    for path in (final_link, ancestor_link / "secret"):
        with pytest.raises(SecureSecretFileError):
            read_secure_secret_file(path, max_bytes=64)


def test_secure_secret_file_rejects_wrong_owner_without_disclosing_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _secret(tmp_path / "do-not-disclose-this-path")
    real_fstat = secure_file.os.fstat

    def wrong_owner(descriptor: int) -> object:
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            values = {
                name: getattr(metadata, name)
                for name in (
                    "st_mode",
                    "st_size",
                    "st_dev",
                    "st_ino",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            values["st_uid"] = os.geteuid() + 1
            return SimpleNamespace(**values)
        return metadata

    monkeypatch.setattr(secure_file.os, "fstat", wrong_owner)
    with pytest.raises(SecureSecretFileError) as captured:
        read_secure_secret_file(path, max_bytes=64)

    assert str(path) not in str(captured.value)
    assert "release-secret" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_secure_secret_file_rejects_metadata_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _secret(tmp_path / "secret")
    real_fstat = secure_file.os.fstat
    regular_calls = 0

    def raced_fstat(descriptor: int) -> object:
        nonlocal regular_calls
        metadata = real_fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return metadata
        regular_calls += 1
        if regular_calls == 1:
            return metadata
        values = {
            name: getattr(metadata, name)
            for name in (
                "st_mode",
                "st_uid",
                "st_size",
                "st_dev",
                "st_ino",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        values["st_mtime_ns"] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(secure_file.os, "fstat", raced_fstat)
    with pytest.raises(SecureSecretFileError):
        read_secure_secret_file(path, max_bytes=64)


def test_secure_secret_file_uses_nofollow_cloexec_and_nonblock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _secret(tmp_path / "secret")
    real_open = secure_file.os.open
    calls: list[int] = []

    def recording_open(*args: object, **kwargs: object) -> int:
        calls.append(int(args[1]))
        return real_open(*args, **kwargs)

    monkeypatch.setattr(secure_file.os, "open", recording_open)
    assert read_secure_secret_file(path, max_bytes=64) == b"release-secret\n"

    final_flags = calls[-1]
    for flag_name in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
        flag = getattr(os, flag_name, 0)
        if flag:
            assert final_flags & flag
