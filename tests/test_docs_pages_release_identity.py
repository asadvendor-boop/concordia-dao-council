from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "write_docs_release_identity.py"
WORKFLOW = ROOT / ".github" / "workflows" / "docs-pages.yml"
SHA = "0123456789abcdef0123456789abcdef01234567"


def _run_writer(output: Path, *, sha: str = SHA, run_id: str = "42") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GITHUB_SHA"] = sha
    env["GITHUB_RUN_ID"] = run_id
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(output)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_writer_emits_exact_canonical_release_identity(tmp_path: Path) -> None:
    output = tmp_path / "release-identity.json"

    completed = _run_writer(output)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""
    assert output.read_bytes() == (
        b'{"GITHUB_SHA":"0123456789abcdef0123456789abcdef01234567","run_id":42}\n'
    )


@pytest.mark.parametrize(
    ("sha", "run_id"),
    [
        ("A" * 40, "42"),
        ("0" * 39, "42"),
        ("0" * 41, "42"),
        ("g" * 40, "42"),
        (SHA, "0"),
        (SHA, "-1"),
        (SHA, "1.0"),
        (SHA, "+1"),
        (SHA, ""),
    ],
)
def test_writer_rejects_invalid_sha_or_run_id(
    tmp_path: Path, sha: str, run_id: str
) -> None:
    output = tmp_path / "release-identity.json"

    completed = _run_writer(output, sha=sha, run_id=run_id)

    assert completed.returncode != 0
    assert not output.exists()


def test_writer_refuses_existing_output_without_replacing_it(tmp_path: Path) -> None:
    output = tmp_path / "release-identity.json"
    output.write_bytes(b"keep-me\n")

    completed = _run_writer(output)

    assert completed.returncode != 0
    assert output.read_bytes() == b"keep-me\n"


def test_writer_refuses_symlink_output_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes(b"keep-me\n")
    output = tmp_path / "release-identity.json"
    output.symlink_to(target)

    completed = _run_writer(output)

    assert completed.returncode != 0
    assert output.is_symlink()
    assert target.read_bytes() == b"keep-me\n"


def test_writer_refuses_symlink_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-site"
    real_parent.mkdir()
    linked_parent = tmp_path / "site"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    output = linked_parent / "release-identity.json"

    completed = _run_writer(output)

    assert completed.returncode != 0
    assert not (real_parent / "release-identity.json").exists()


def test_docs_pages_generates_identity_after_build_before_upload() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    steps = workflow["jobs"]["build"]["steps"]
    names = [step["name"] for step in steps]

    build_index = names.index("Build site (strict — warnings are errors)")
    identity_index = names.index("Bind deployed docs to this workflow run")
    upload_index = names.index("Upload Pages artifact")

    assert build_index < identity_index < upload_index
    assert (
        steps[identity_index]["run"]
        == "python scripts/write_docs_release_identity.py --output site/release-identity.json"
    )
    assert '      - "scripts/write_docs_release_identity.py"' in raw
