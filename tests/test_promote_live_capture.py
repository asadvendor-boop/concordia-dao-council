from __future__ import annotations

import hashlib
import fcntl
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import promote_live_capture as promotion
from shared.bound_command import _run_bound_git as actual_bound_git


def _git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments], cwd=root, text=True
    ).strip()


def _commit(root: Path, message: str) -> str:
    _git(root, "add", ".")
    _git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii") + b"\n"


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init")
    (root / "README").write_text("fixture\n", encoding="ascii")
    _commit(root, "initial")

    def fake_admission(*, repository_root: Path, proof_id: str, artifact, receipt_path, raw_bundle_path, release: bool):
        assert release is True
        assert receipt_path == repository_root / promotion.CAPTURE_PATHS[proof_id]["receipt"]
        assert raw_bundle_path == repository_root / promotion.CAPTURE_PATHS[proof_id]["raw"]
        expected = _canonical({"proof": proof_id})
        if artifact.raw != expected:
            raise promotion.PromotionError("collector proof identity differs")
        return {"artifact_sha256": hashlib.sha256(artifact.raw).hexdigest()}

    monkeypatch.setattr(promotion, "_verify_live_collector_admission", fake_admission)

    # Most tests exercise promotion's fixed bound-Git call shape without paying
    # the host-toolchain staging cost. The poisoned-PATH test below restores
    # the real helper for an end-to-end trust-boundary assertion.
    def fast_bound_git(
        repository_root: Path,
        arguments: tuple[str, ...],
        *,
        check: bool = True,
        stdout_limit: int = 4 * 1024 * 1024,
    ) -> SimpleNamespace:
        result = subprocess.run(
            ["/usr/bin/git", "--no-replace-objects", *arguments],
            cwd=repository_root,
            capture_output=True,
            check=False,
        )
        if check and result.returncode:
            raise RuntimeError("fixture bound Git failed")
        if len(result.stdout) > stdout_limit:
            raise RuntimeError("fixture bound Git output exceeds limit")
        return SimpleNamespace(stdout=result.stdout, returncode=result.returncode)

    monkeypatch.setattr(promotion, "_run_bound_git", fast_bound_git)
    return root


def _source_batch(root: Path, proof_id: str, *, candidate: bytes | None = None) -> bytes:
    paths = promotion.CAPTURE_PATHS[proof_id]
    candidate = candidate if candidate is not None else _canonical({"proof": proof_id})
    for key, raw in {
        "receipt": _canonical({"receipt": proof_id}),
        "raw": _canonical({"raw": proof_id}),
        "candidate": candidate,
    }.items():
        path = root / paths[key]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    _commit(root, f"capture {proof_id}")
    return candidate


def _seal_committed_promotion(root: Path, proof_id: str) -> tuple[bytes, str]:
    candidate = _source_batch(root, proof_id)
    promotion.prepare(root, proof_id)
    destination = root / promotion.PROMOTION_PATHS[proof_id]["destination"]
    destination_commit = _commit(root, f"promote {proof_id}")
    promotion.seal(root, proof_id)
    _commit(root, f"seal {proof_id}")
    return candidate, destination_commit


def test_prepare_creates_only_the_fixed_byte_exact_destination(repository: Path) -> None:
    candidate = _source_batch(repository, "safepay_v2")

    result = promotion.prepare(repository, "safepay_v2")

    destination = repository / promotion.PROMOTION_PATHS["safepay_v2"]["destination"]
    assert destination.read_bytes() == candidate
    assert result["source_candidate_sha256"] == hashlib.sha256(candidate).hexdigest()
    assert not (repository / promotion.PROMOTION_PATHS["safepay_v2"]["receipt"]).exists()


def test_prepare_uses_bound_git_when_path_is_poisoned(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source_batch(repository, "safepay_v2")
    monkeypatch.setattr(promotion, "_run_bound_git", actual_bound_git)
    marker = tmp_path / "fake-git-invoked"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    fake_git.write_text(
        f"#!/bin/sh\nprintf poisoned > {marker}\nexit 99\n", encoding="ascii"
    )
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", fake_bin.as_posix())

    result = promotion.prepare(repository, "safepay_v2")

    assert result["destination_path"] == promotion.PROMOTION_PATHS["safepay_v2"]["destination"]
    assert not marker.exists()


def test_seal_and_verify_bind_destination_first_add_commit_in_canonical_receipt(repository: Path) -> None:
    candidate, destination_commit = _seal_committed_promotion(repository, "safepay_v2")

    result = promotion.verify(repository, "safepay_v2")

    receipt = repository / promotion.PROMOTION_PATHS["safepay_v2"]["receipt"]
    raw = receipt.read_bytes()
    document = json.loads(raw)
    assert raw == _canonical(document)
    assert document["destination"]["first_add_commit"] == destination_commit
    assert document["source"]["candidate_sha256"] == hashlib.sha256(candidate).hexdigest()
    assert result["destination_first_add_commit"] == destination_commit


def test_prepare_refuses_a_preexisting_destination(repository: Path) -> None:
    _source_batch(repository, "safepay_v2")
    destination = repository / promotion.PROMOTION_PATHS["safepay_v2"]["destination"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"{}\n")
    _commit(repository, "preexisting destination")

    with pytest.raises(
        promotion.PromotionError, match="destination already exists|prior history"
    ):
        promotion.prepare(repository, "safepay_v2")


def test_prepare_refuses_rewritten_candidate_history(repository: Path) -> None:
    _source_batch(repository, "safepay_v2")
    path = repository / promotion.CAPTURE_PATHS["safepay_v2"]["candidate"]
    path.write_bytes(_canonical({"proof": "safepay_v2", "rewrite": True}))
    _commit(repository, "rewrite candidate")

    with pytest.raises(promotion.PromotionError, match="immutable first-add"):
        promotion.prepare(repository, "safepay_v2")


def test_prepare_refuses_candidate_receipt_raw_not_added_together(repository: Path) -> None:
    paths = promotion.CAPTURE_PATHS["safepay_v2"]
    for key, raw in {
        "receipt": _canonical({"receipt": "safepay_v2"}),
        "raw": _canonical({"raw": "safepay_v2"}),
    }.items():
        path = repository / paths[key]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    _commit(repository, "receipt and raw")
    path = repository / paths["candidate"]
    path.write_bytes(_canonical({"proof": "safepay_v2"}))
    _commit(repository, "candidate separately")

    with pytest.raises(promotion.PromotionError, match="one immutable commit"):
        promotion.prepare(repository, "safepay_v2")


def test_prepare_refuses_cross_proof_candidate_swap(repository: Path) -> None:
    _source_batch(
        repository,
        "official_x402_settlement_v1",
        candidate=_canonical({"proof": "safepay_v2"}),
    )

    with pytest.raises(promotion.PromotionError, match="collector proof identity differs"):
        promotion.prepare(repository, "official_x402_settlement_v1")


def test_prepare_refuses_noncanonical_candidate_bytes(repository: Path) -> None:
    _source_batch(repository, "safepay_v2", candidate=b'{"proof":"safepay_v2"}')

    with pytest.raises(promotion.PromotionError, match="not canonical JSON"):
        promotion.prepare(repository, "safepay_v2")


def test_prepare_refuses_missing_receipt(repository: Path) -> None:
    _source_batch(repository, "safepay_v2")
    (repository / promotion.CAPTURE_PATHS["safepay_v2"]["receipt"]).unlink()
    _commit(repository, "remove receipt")

    with pytest.raises(promotion.PromotionError, match="collector receipt is unavailable"):
        promotion.prepare(repository, "safepay_v2")


@pytest.mark.parametrize("field", ("receipt", "raw"))
def test_prepare_refuses_noncanonical_collector_batch_member(
    repository: Path, field: str
) -> None:
    _source_batch(repository, "safepay_v2")
    path = repository / promotion.CAPTURE_PATHS["safepay_v2"][field]
    path.write_bytes(b"{}")
    _commit(repository, f"rewrite {field} noncanonically")

    with pytest.raises(promotion.PromotionError, match="not canonical JSON"):
        promotion.prepare(repository, "safepay_v2")


def test_prepare_refuses_an_inconsistent_collector_receipt(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source_batch(repository, "safepay_v2")

    def reject(**_kwargs: object) -> dict[str, object]:
        raise ValueError("receipt artifact binding differs")

    monkeypatch.setattr(promotion, "_verify_live_collector_admission", reject)

    with pytest.raises(promotion.PromotionError, match="collector provenance is inconsistent"):
        promotion.prepare(repository, "safepay_v2")


def test_seal_refuses_a_destination_with_nonmatching_bytes(repository: Path) -> None:
    _source_batch(repository, "safepay_v2")
    promotion.prepare(repository, "safepay_v2")
    destination = repository / promotion.PROMOTION_PATHS["safepay_v2"]["destination"]
    destination.write_bytes(_canonical({"proof": "other"}))
    _commit(repository, "wrong destination")

    with pytest.raises(promotion.PromotionError, match="destination bytes differ"):
        promotion.seal(repository, "safepay_v2")


def test_verify_refuses_a_rewritten_promotion_receipt(repository: Path) -> None:
    _seal_committed_promotion(repository, "safepay_v2")
    receipt = repository / promotion.PROMOTION_PATHS["safepay_v2"]["receipt"]
    document = json.loads(receipt.read_bytes())
    document["source"]["candidate_sha256"] = "0" * 64
    receipt.write_bytes(_canonical(document))
    _commit(repository, "rewrite receipt")

    with pytest.raises(promotion.PromotionError, match="immutable first-add"):
        promotion.verify(repository, "safepay_v2")


@pytest.mark.parametrize("kind", ("tracked", "untracked"))
def test_prepare_refuses_dirty_worktree_before_destination_creation(
    repository: Path,
    kind: str,
) -> None:
    _source_batch(repository, "safepay_v2")
    if kind == "tracked":
        (repository / "README").write_text("dirty\n", encoding="ascii")
    else:
        (repository / "untracked.txt").write_text("dirty\n", encoding="ascii")
    destination = repository / promotion.PROMOTION_PATHS["safepay_v2"]["destination"]

    with pytest.raises(promotion.PromotionError, match="worktree is not clean"):
        promotion.prepare(repository, "safepay_v2")

    assert not destination.exists()


def test_prepare_refuses_active_release_lock_before_destination_creation(
    repository: Path,
) -> None:
    _source_batch(repository, "safepay_v2")
    lock = repository / ".git" / "concordia-release-manifest.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    destination = repository / promotion.PROMOTION_PATHS["safepay_v2"]["destination"]
    try:
        with pytest.raises(
            promotion.PromotionError, match="another release operation"
        ):
            promotion.prepare(repository, "safepay_v2")
    finally:
        os.close(descriptor)

    assert not destination.exists()


def test_prepare_refuses_after_recovery_before_destination_creation(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _source_batch(repository, "safepay_v2")
    import shared.release_manifest as release_manifest

    monkeypatch.setattr(
        release_manifest, "_recover_capture_publication", lambda _root: "published"
    )
    destination = repository / promotion.PROMOTION_PATHS["safepay_v2"]["destination"]

    with pytest.raises(promotion.PromotionError, match="recovery completed"):
        promotion.prepare(repository, "safepay_v2")

    assert not destination.exists()


@pytest.mark.parametrize("kind", ("tracked", "untracked"))
def test_seal_refuses_dirty_worktree_before_receipt_creation(
    repository: Path,
    kind: str,
) -> None:
    _source_batch(repository, "safepay_v2")
    promotion.prepare(repository, "safepay_v2")
    _commit(repository, "promote destination")
    if kind == "tracked":
        (repository / "README").write_text("dirty\n", encoding="ascii")
    else:
        (repository / "untracked.txt").write_text("dirty\n", encoding="ascii")
    receipt = repository / promotion.PROMOTION_PATHS["safepay_v2"]["receipt"]

    with pytest.raises(promotion.PromotionError, match="worktree is not clean"):
        promotion.seal(repository, "safepay_v2")

    assert not receipt.exists()
