"""Custody and durable-output boundaries for the v3 release operators."""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import shared.secure_secret_file as secure_file
from scripts.install_governance_receipt_v3 import (
    InstallValidationError,
    build_signed_install_payload,
)
from scripts.run_v3_live_proof import LiveProofError, _role_key
import scripts.read_v3_state as readback_cli
from shared.atomic_private_file import AtomicPrivateFileError, write_private_file_once


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (
    ROOT / "contracts/odra-governance-receipt-v3/resources/casper_contract_schemas/"
    "governance_receiptv3_schema.json"
)
WASM = ROOT / "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm"


def _pem(path: Path, *, mode: int = 0o600) -> Path:
    private = ed25519.Ed25519PrivateKey.generate()
    payload = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def _roles() -> dict[str, object]:
    return {
        name: {"kind": "Account", "account_hash": bytes([offset] * 32).hex()}
        for name, offset in zip(
            ("proposer", "finalizer", "signer_a", "signer_b", "signer_c"),
            (11, 12, 13, 14, 15),
            strict=True,
        )
    }


def _install(path: Path) -> None:
    build_signed_install_payload(
        secret_key_path=path,
        key_algorithm="ED25519",
        roles=_roles(),
        threshold=2,
        installation_nonce="77" * 32,
        wasm_path=WASM,
        schema_path=SCHEMA,
        payment_amount_motes=30_000_000_000,
        ttl="30m",
        source_commit="ab" * 20,
        deployment_commit="cd" * 20,
    )


def test_private_artifact_writer_is_create_once_durable_and_mode_0600(
    tmp_path: Path,
) -> None:
    target = tmp_path / "readback.json"
    write_private_file_once(target, b'{"artifact":"verified"}\n')

    assert target.read_bytes() == b'{"artifact":"verified"}\n'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(AtomicPrivateFileError, match="already exists"):
        write_private_file_once(target, b'{"artifact":"replacement"}\n')


def test_private_artifact_writer_rejects_final_and_ancestor_symlinks(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"untouched")
    final_link = tmp_path / "readback.json"
    final_link.symlink_to(outside)
    with pytest.raises(AtomicPrivateFileError):
        write_private_file_once(final_link, b"replacement")
    assert outside.read_bytes() == b"untouched"

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(AtomicPrivateFileError):
        write_private_file_once(parent_link / "readback.json", b"payload")
    assert not (real_parent / "readback.json").exists()


def test_readback_cli_uses_create_once_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "readback.json"
    artifact = {"facts": {"observed_block_height": 9_010}}
    monkeypatch.setattr(
        readback_cli,
        "PinnedHttpsJsonRpc",
        lambda *_args, **_kwargs: SimpleNamespace(
            endpoints=("https://rpc-a.example/rpc", "https://rpc-b.example/rpc")
        ),
    )
    monkeypatch.setattr(readback_cli, "capture_v3_state", lambda **_kwargs: artifact)
    monkeypatch.setattr(
        readback_cli, "verify_and_seal_readback_artifact", lambda value: value
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "read_v3_state.py",
            "--rpc-url",
            "https://rpc-a.example/rpc",
            "--rpc-url",
            "https://rpc-b.example/rpc",
            "--package-hash",
            "11" * 32,
            "--contract-hash",
            "22" * 32,
            "--proposal-id",
            "DAO-PROP-V3",
            "--action-id",
            "33" * 32,
            "--out",
            str(target),
        ],
    )

    assert readback_cli.main() == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(SystemExit):
        readback_cli.main()


def test_install_and_live_load_owner_private_signer_bytes(tmp_path: Path) -> None:
    key = _pem(tmp_path / "installer.pem")
    _install(key)

    public, private, custody = _role_key(
        {
            "custody": "server",
            "secret_key_path": str(key),
            "key_algorithm": "ED25519",
        }
    )
    assert public is private
    assert custody == "server"


@pytest.mark.parametrize("entrypoint", ("install", "live"))
@pytest.mark.parametrize("mode", (0o644, 0o660))
def test_install_and_live_reject_non_private_signer_mode_without_disclosure(
    tmp_path: Path,
    entrypoint: str,
    mode: int,
) -> None:
    key = _pem(tmp_path / "do-not-disclose.pem", mode=mode)
    with pytest.raises((InstallValidationError, LiveProofError)) as captured:
        if entrypoint == "install":
            _install(key)
        else:
            _role_key(
                {
                    "custody": "server",
                    "secret_key_path": str(key),
                    "key_algorithm": "ED25519",
                }
            )
    assert str(key) not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize("entrypoint", ("install", "live"))
def test_install_and_live_reject_ancestor_symlink_without_disclosure(
    tmp_path: Path,
    entrypoint: str,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    key = _pem(real / "do-not-disclose.pem")
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    candidate = linked / key.name

    with pytest.raises((InstallValidationError, LiveProofError)) as captured:
        if entrypoint == "install":
            _install(candidate)
        else:
            _role_key(
                {
                    "custody": "server",
                    "secret_key_path": str(candidate),
                    "key_algorithm": "ED25519",
                }
            )
    assert str(candidate) not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize("entrypoint", ("install", "live"))
def test_install_and_live_reject_signer_metadata_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    key = _pem(tmp_path / "raced.pem")
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
        values["st_ctime_ns"] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(secure_file.os, "fstat", raced_fstat)
    with pytest.raises((InstallValidationError, LiveProofError)):
        if entrypoint == "install":
            _install(key)
        else:
            _role_key(
                {
                    "custody": "server",
                    "secret_key_path": str(key),
                    "key_algorithm": "ED25519",
                }
            )


def test_signer_error_never_discloses_secret_contents(tmp_path: Path) -> None:
    secret = "release-private-key-canary-1fb4"
    key = tmp_path / "invalid.pem"
    key.write_text(secret, encoding="ascii")
    key.chmod(0o600)

    with pytest.raises(InstallValidationError) as install_error:
        _install(key)
    with pytest.raises(LiveProofError) as live_error:
        _role_key(
            {
                "custody": "server",
                "secret_key_path": str(key),
                "key_algorithm": "ED25519",
            }
        )
    for error in (install_error.value, live_error.value):
        assert secret not in str(error)
        assert str(key) not in str(error)
        assert error.__cause__ is None
