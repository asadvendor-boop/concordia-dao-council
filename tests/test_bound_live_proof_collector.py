from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import runpy
import socket
import subprocess
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bound_live_proof_collector as collector


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _minimal_plan(proof_id: str = "safepay_v2") -> dict[str, object]:
    requests = {
        acquisition_id: {
            "method": "POST",
            "body_base64": base64.b64encode(b"{}").decode("ascii"),
            "headers": {"content-type": "application/json"},
        }
        for acquisition_id in collector._required_ids(proof_id)
        if collector._requires_plan_request(acquisition_id)
    }
    return {
        "schema_version": collector.PLAN_SCHEMA_VERSION,
        "proof_id": proof_id,
        "source_commit": "11" * 20,
        "deployment_commit": "22" * 20,
        "bundle_skeleton": {},
        "requests": requests,
    }


def _init_preflight_repository(tmp_path: Path) -> None:
    subprocess.run(("/usr/bin/git", "init", "-q"), cwd=tmp_path, check=True)
    subprocess.run(
        ("/usr/bin/git", "config", "user.email", "collector@example.test"),
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ("/usr/bin/git", "config", "user.name", "Collector Test"),
        cwd=tmp_path,
        check=True,
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("clean\n", encoding="utf-8")
    subprocess.run(("/usr/bin/git", "add", "."), cwd=tmp_path, check=True)
    subprocess.run(
        ("/usr/bin/git", "commit", "-qm", "initial"),
        cwd=tmp_path,
        check=True,
    )


def _patch_release_git(
    monkeypatch: pytest.MonkeyPatch,
    release_manifest: object,
) -> None:
    def local_git(
        root: Path,
        arguments: object,
        *,
        check: bool = True,
        limit: int = 16 * 1024 * 1024,
    ) -> SimpleNamespace:
        command = ("/usr/bin/git", *tuple(arguments))
        completed = subprocess.run(
            command,
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if check and completed.returncode != 0:
            raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
        if len(completed.stdout) > limit:
            raise AssertionError("test Git output exceeded bound")
        return SimpleNamespace(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    monkeypatch.setattr(release_manifest, "_git", local_git)


def test_collect_requires_explicit_mode_before_reading_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    touched = {"read": 0, "bound": 0}

    def forbidden_read(*_args: object, **_kwargs: object) -> bytes:
        touched["read"] += 1
        raise AssertionError("plan read before mutation acknowledgement")

    monkeypatch.setattr(collector, "_read_regular", forbidden_read)

    result = collector.main(
        [
            "collect",
            "--repository-root",
            str(tmp_path),
            "--proof-id",
            "safepay_v2",
        ]
    )

    assert result == 2
    assert touched == {"read": 0, "bound": 0}
    assert "EXPLICIT_MODE_REQUIRED" in capsys.readouterr().err


@pytest.mark.parametrize("dirty_kind", ("tracked", "untracked"))
def test_submit_refuses_dirty_tree_before_bound_worker_or_live_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dirty_kind: str,
) -> None:
    from shared import bound_command, release_manifest

    _init_preflight_repository(tmp_path)
    _patch_release_git(monkeypatch, release_manifest)
    if dirty_kind == "tracked":
        (tmp_path / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    else:
        (tmp_path / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    touched: list[str] = []
    monkeypatch.setattr(
        bound_command,
        "run_bound_command",
        lambda *_args, **_kwargs: touched.append("worker"),
    )
    monkeypatch.setattr(
        collector,
        "_http_request",
        lambda *_args, **_kwargs: touched.append("http"),
    )
    monkeypatch.setattr(
        collector,
        "_docker_request",
        lambda *_args, **_kwargs: touched.append("docker"),
    )
    monkeypatch.setattr(
        collector,
        "_sqlite_online_backup",
        lambda *_args, **_kwargs: touched.append("sqlite"),
    )

    result = collector.main(
        [
            "collect",
            "--repository-root",
            str(tmp_path),
            "--proof-id",
            "safepay_v2",
            "--submit",
        ]
    )

    assert result == 2
    assert touched == []
    lock_path = (
        tmp_path
        / ".git"
        / "concordia-release-manifest.lock"
    )
    assert lock_path.exists()
    assert release_manifest._recover_capture_publication(tmp_path) == "none"


def test_submit_recovers_but_refuses_active_capture_journal_before_live_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shared import bound_command, release_manifest

    _init_preflight_repository(tmp_path)
    _patch_release_git(monkeypatch, release_manifest)
    touched: list[str] = []
    monkeypatch.setattr(
        release_manifest,
        "_recover_capture_publication",
        lambda _root: touched.append("recover") or "rolled_back",
    )
    monkeypatch.setattr(
        release_manifest,
        "_require_clean_worktree",
        lambda _root: touched.append("clean"),
    )
    monkeypatch.setattr(
        bound_command,
        "run_bound_command",
        lambda *_args, **_kwargs: touched.append("worker"),
    )

    result = collector.main(
        [
            "collect",
            "--repository-root",
            str(tmp_path),
            "--proof-id",
            "safepay_v2",
            "--submit",
        ]
    )

    assert result == 2
    assert touched == ["recover"]


def test_submit_refuses_when_another_release_operation_holds_the_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shared import bound_command, release_manifest

    _init_preflight_repository(tmp_path)
    _patch_release_git(monkeypatch, release_manifest)
    touched: list[str] = []
    monkeypatch.setattr(
        bound_command,
        "run_bound_command",
        lambda *_args, **_kwargs: touched.append("worker"),
    )
    descriptor = release_manifest._repository_release_lock(tmp_path)
    try:
        result = collector.main(
            [
                "collect",
                "--repository-root",
                str(tmp_path),
                "--proof-id",
                "safepay_v2",
                "--submit",
            ]
        )
    finally:
        os.close(descriptor)

    assert result == 2
    assert touched == []


def test_submit_refuses_preexisting_fixed_output_before_worker_or_live_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shared import bound_command, release_manifest
    from shared.live_collector_provenance import LIVE_COLLECTOR_RAW_PATHS

    _init_preflight_repository(tmp_path)
    _patch_release_git(monkeypatch, release_manifest)
    existing = tmp_path / LIVE_COLLECTOR_RAW_PATHS["safepay_v2"]
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"already-captured\n")
    subprocess.run(("/usr/bin/git", "add", "."), cwd=tmp_path, check=True)
    subprocess.run(
        ("/usr/bin/git", "commit", "-qm", "existing capture"),
        cwd=tmp_path,
        check=True,
    )
    touched: list[str] = []
    monkeypatch.setattr(
        collector,
        "_load_collector_plan",
        lambda *_args, **_kwargs: (
            tmp_path / "plan.json",
            b"{}\n",
            {},
            "11" * 20,
            "22" * 32,
        ),
    )
    monkeypatch.setattr(
        bound_command,
        "run_bound_command",
        lambda *_args, **_kwargs: touched.append("worker"),
    )

    result = collector.main(
        [
            "collect",
            "--repository-root",
            str(tmp_path),
            "--proof-id",
            "safepay_v2",
            "--submit",
        ]
    )

    assert result == 2
    assert touched == []
    assert existing.read_bytes() == b"already-captured\n"


def test_dry_run_emits_only_bounded_plan_digests_and_has_zero_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = _minimal_plan()
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(_canonical(plan))
    touched: list[str] = []

    monkeypatch.setattr(
        collector,
        "_fixed_plan_path",
        lambda _root, _proof_id: plan_path,
    )
    monkeypatch.setattr(
        collector,
        "_immutable_plan_binding",
        lambda *_args, **_kwargs: "33" * 20,
    )
    monkeypatch.setattr(
        collector,
        "_collect_worker",
        lambda *_args, **_kwargs: touched.append("worker"),
    )
    monkeypatch.setattr(
        collector,
        "_docker_json",
        lambda *_args, **_kwargs: touched.append("docker"),
    )
    monkeypatch.setattr(
        collector,
        "_http_request",
        lambda *_args, **_kwargs: touched.append("http"),
    )
    monkeypatch.setattr(
        collector,
        "_sqlite_online_backup",
        lambda *_args, **_kwargs: touched.append("sqlite"),
    )

    result = collector.main(
        [
            "collect",
            "--repository-root",
            str(tmp_path),
            "--proof-id",
            "safepay_v2",
            "--dry-run",
        ]
    )

    assert result == 0
    assert touched == []
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {
        "mode",
        "plan_path",
        "plan_sha256",
        "proof_id",
        "request_plan_sha256",
        "status",
    }
    assert output["mode"] == "dry_run"
    assert output["status"] == "validated"


def test_bound_worker_environment_cannot_route_to_another_docker_daemon() -> None:
    assert collector._collector_command_environment(
        {
            "CI": "1",
            "LANG": "C",
            "DOCKER_HOST": "tcp://untrusted.example:2375",
        }
    ) == {"CI": "1", "LANG": "C"}


def test_submit_and_dry_run_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        collector._parser().parse_args(
            [
                "collect",
                "--repository-root",
                str(tmp_path),
                "--proof-id",
                "safepay_v2",
                "--dry-run",
                "--submit",
            ]
        )


def test_sqlite_acquirer_returns_direct_integrity_checked_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "ledger.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE ledger (id TEXT PRIMARY KEY, value TEXT)")
    connection.execute("INSERT INTO ledger VALUES ('one', 'persisted')")
    connection.commit()
    connection.close()
    monkeypatch.setitem(collector._LEDGER_PATHS, "safepay_v2", database)

    raw, observed_at = collector._sqlite_online_backup("safepay_v2")

    replay = sqlite3.connect(":memory:")
    replay.deserialize(raw)
    assert replay.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    assert replay.execute("SELECT * FROM ledger").fetchall() == [
        ("one", "persisted")
    ]
    replay.close()
    assert observed_at.endswith("Z")


@pytest.mark.parametrize(
    "forbidden",
    [
        {"response_status": 200},
        {"runtime_identity": {"container_id": "operator"}},
        {"live": True},
        {"acquisitions": []},
    ],
)
def test_plan_cannot_supply_observations_or_live_labels(
    forbidden: dict[str, object],
) -> None:
    plan = _minimal_plan()
    plan["bundle_skeleton"] = forbidden

    with pytest.raises(collector.LiveCollectorError, match="forbidden observed field"):
        collector._validate_plan_document(plan)


def test_private_output_writer_writes_every_byte(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private.bin"
    path.write_bytes(b"")
    path.chmod(0o600)
    raw = bytes(range(251)) * 17

    collector._write_bound_output(
        path,
        raw,
        limit=len(raw),
        label="test output",
    )

    assert path.read_bytes() == raw


def test_hidden_worker_refuses_without_one_use_outer_arm(
    tmp_path: Path,
) -> None:
    args = argparse.Namespace(
        proof_id="safepay_v2",
        plan_id="release/capture-plans/safepay-v2.json",
        arm_fd=-1,
        arm_digest="aa" * 32,
        plan=str(tmp_path / "missing-plan.json"),
        bundle_output=str(tmp_path / "bundle.json"),
        transcript_output=str(tmp_path / "transcript.json"),
    )

    with pytest.raises(collector.LiveCollectorError, match="ARM_REQUIRED"):
        collector._worker_main(args)


def test_worker_capability_is_inherited_bound_and_one_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(_canonical(_minimal_plan()))
    plan_path.chmod(0o600)
    bundle_output = tmp_path / "raw-bundle.json"
    transcript_output = tmp_path / "acquisitions.json"
    for path in (bundle_output, transcript_output):
        path.write_bytes(b"")
        path.chmod(0o600)
    read_descriptor, write_descriptor = os.pipe()
    nonce = b"\x91" * 32
    os.write(write_descriptor, nonce)
    os.close(write_descriptor)
    digest = collector._worker_arm_binding(
        nonce,
        proof_id="safepay_v2",
        plan_id="release/capture-plans/safepay-v2.json",
        bundle_output=bundle_output.as_posix(),
        transcript_output=transcript_output.as_posix(),
    )
    args = argparse.Namespace(
        proof_id="safepay_v2",
        plan_id="release/capture-plans/safepay-v2.json",
        arm_fd=read_descriptor,
        arm_digest=digest,
        plan=plan_path.as_posix(),
        bundle_output=bundle_output.as_posix(),
        transcript_output=transcript_output.as_posix(),
    )
    monkeypatch.setattr(
        collector,
        "_collect_worker",
        lambda _plan: (b'{"bundle":true}\n', b'{"transcript":true}\n'),
    )
    monkeypatch.setattr(
        collector,
        "_inherited_fifo_descriptors",
        lambda: (read_descriptor,),
    )

    assert collector._worker_main(args) == 0
    assert bundle_output.read_bytes() == b'{"bundle":true}\n'
    assert transcript_output.read_bytes() == b'{"transcript":true}\n'
    with pytest.raises(collector.LiveCollectorError, match="ARM_REQUIRED"):
        collector._worker_main(args)


@pytest.mark.parametrize("payload", [b"short", b"x" * 33])
def test_worker_capability_refuses_wrong_length_before_plan_io(
    tmp_path: Path,
    payload: bytes,
) -> None:
    read_descriptor, write_descriptor = os.pipe()
    os.write(write_descriptor, payload)
    os.close(write_descriptor)
    args = argparse.Namespace(
        proof_id="safepay_v2",
        plan_id="release/capture-plans/safepay-v2.json",
        arm_fd=read_descriptor,
        arm_digest="aa" * 32,
        plan=str(tmp_path / "missing-plan.json"),
        bundle_output=str(tmp_path / "raw-bundle.json"),
        transcript_output=str(tmp_path / "acquisitions.json"),
    )
    with pytest.raises(collector.LiveCollectorError, match="ARM_REQUIRED"):
        collector._worker_main(args)


def test_worker_capability_refuses_extra_inherited_fifo_before_plan_io(
    tmp_path: Path,
) -> None:
    read_descriptor, write_descriptor = os.pipe()
    extra_read, extra_write = os.pipe()
    os.write(write_descriptor, b"x" * 32)
    os.close(write_descriptor)
    os.close(extra_write)
    args = argparse.Namespace(
        proof_id="safepay_v2",
        plan_id="release/capture-plans/safepay-v2.json",
        arm_fd=read_descriptor,
        arm_digest="aa" * 32,
        plan=str(tmp_path / "missing-plan.json"),
        bundle_output=str(tmp_path / "raw-bundle.json"),
        transcript_output=str(tmp_path / "acquisitions.json"),
    )
    try:
        with pytest.raises(collector.LiveCollectorError, match="ARM_REQUIRED"):
            collector._worker_main(args)
    finally:
        os.close(read_descriptor)
        os.close(extra_read)


def test_worker_capability_refuses_regular_file_and_socket_descriptors(
    tmp_path: Path,
) -> None:
    regular = os.open(tmp_path / "arm.bin", os.O_RDONLY | os.O_CREAT, 0o600)
    left, right = socket.socketpair()
    try:
        for descriptor in (regular, left.fileno()):
            with pytest.raises(collector.LiveCollectorError, match="ARM_REQUIRED"):
                collector._consume_worker_capability(
                    descriptor=descriptor,
                    expected_digest="aa" * 32,
                    proof_id="safepay_v2",
                    plan_id="release/capture-plans/safepay-v2.json",
                    bundle_output="raw-bundle.json",
                    transcript_output="acquisitions.json",
                )
    finally:
        os.close(regular)
        left.close()
        right.close()


def test_worker_capability_refuses_missing_eof_before_plan_io() -> None:
    read_descriptor, write_descriptor = os.pipe()
    os.write(write_descriptor, b"x" * 32)
    try:
        with pytest.raises(collector.LiveCollectorError, match="ARM_REQUIRED"):
            collector._consume_worker_capability(
                descriptor=read_descriptor,
                expected_digest="aa" * 32,
                proof_id="safepay_v2",
                plan_id="release/capture-plans/safepay-v2.json",
                bundle_output="raw-bundle.json",
                transcript_output="acquisitions.json",
            )
    finally:
        try:
            os.close(read_descriptor)
        except OSError:
            pass
        os.close(write_descriptor)


def test_secure_token_reader_rejects_public_mode_and_symlink(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "token"
    secret.write_bytes(b"direct-token")
    secret.chmod(0o644)
    with pytest.raises(collector.LiveCollectorError, match="safely"):
        collector._read_secure_secret(secret, limit=128, label="token")

    secret.chmod(0o600)
    assert collector._read_secure_secret(
        secret, limit=128, label="token"
    ) == b"direct-token"
    link = tmp_path / "token-link"
    link.symlink_to(secret)
    with pytest.raises(collector.LiveCollectorError, match="safely"):
        collector._read_secure_secret(link, limit=128, label="token")


def test_secret_reflection_refuses_raw_base64_and_hex() -> None:
    token = b"private-direct-token"
    for reflected in (
        token,
        base64.b64encode(token),
        token.hex().encode("ascii"),
    ):
        with pytest.raises(collector.LiveCollectorError, match="reflected"):
            collector._assert_no_secret_reflection(
                b"prefix:" + reflected + b":suffix",
                secrets_to_scan=(token,),
                label="response",
            )


def test_http_acquirer_obtains_exact_controlled_endpoint_bytes() -> None:
    response_body = b'{"direct":"server-bytes"}'
    captured: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            captured.append(self.rfile.read(length))
            self.send_response(409)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        observed = collector._http_request(
            url=f"http://127.0.0.1:{server.server_port}/fixed",
            request={
                "method": "POST",
                "body_base64": base64.b64encode(b'{"request":"fixed"}').decode(
                    "ascii"
                ),
                "headers": {"content-type": "application/json"},
            },
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert captured == [b'{"request":"fixed"}']
    assert observed["response_status"] == 409
    assert base64.b64decode(observed["response_body_base64"]) == response_body


def test_restart_targets_only_bound_concordia_service_and_new_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        "container_id": "a" * 64,
        "image_digest": "sha256:" + "b" * 64,
        "started_at": "2026-07-24T01:00:00Z",
        "observed_at": "2026-07-24T01:00:01Z",
        "restart_count": 0,
    }
    before["service_instance_id"] = collector._service_instance_id(before)
    after = {
        **before,
        "started_at": "2026-07-24T01:01:00Z",
        "observed_at": "2026-07-24T01:01:01Z",
        "restart_count": 1,
    }
    after["service_instance_id"] = collector._service_instance_id(after)
    posts: list[tuple[str, str]] = []

    def docker_request(method: str, path: str) -> tuple[int, bytes, object | None]:
        posts.append((method, path))
        return 204, b"", None

    monkeypatch.setattr(collector, "_docker_request", docker_request)
    monkeypatch.setattr(
        collector,
        "_docker_runtime_identity",
        lambda proof_id: (after, b"exact-inspect")
        if proof_id == "safepay_v2"
        else (_ for _ in ()).throw(AssertionError("wrong service")),
    )

    observed, raw = collector._docker_restart_and_wait(
        "safepay_v2", before, sleep=lambda _seconds: None
    )

    assert posts == [
        ("POST", f"/containers/{before['container_id']}/restart?t=30")
    ]
    assert observed["service_instance_id"] != before["service_instance_id"]
    assert b"exact-inspect" in raw


def test_restart_refuses_skipped_restart_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        "container_id": "a" * 64,
        "image_digest": "sha256:" + "b" * 64,
        "started_at": "2026-07-24T01:00:00Z",
        "observed_at": "2026-07-24T01:00:01Z",
        "restart_count": 4,
    }
    before["service_instance_id"] = collector._service_instance_id(before)
    after = {
        **before,
        "started_at": "2026-07-24T01:01:00Z",
        "observed_at": "2026-07-24T01:01:01Z",
        "restart_count": 6,
    }
    after["service_instance_id"] = collector._service_instance_id(after)
    monkeypatch.setattr(
        collector,
        "_docker_request",
        lambda _method, _path: (204, b"", None),
    )
    monkeypatch.setattr(
        collector,
        "_docker_runtime_identity",
        lambda _proof_id: (after, b"skipped-counter"),
    )

    with pytest.raises(collector.LiveCollectorError, match="did not become"):
        collector._docker_restart_and_wait(
            "safepay_v2",
            before,
            sleep=lambda _seconds: None,
        )


def test_fixed_plan_must_remain_immutable_first_add(tmp_path: Path) -> None:
    subprocess.run(("/usr/bin/git", "init", "-q"), cwd=tmp_path, check=True)
    subprocess.run(
        ("/usr/bin/git", "config", "user.email", "collector@example.invalid"),
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ("/usr/bin/git", "config", "user.name", "Collector Test"),
        cwd=tmp_path,
        check=True,
    )
    plan = tmp_path / collector._FIXED_PLAN_PATHS["safepay_v2"]
    plan.parent.mkdir(parents=True)
    raw = _canonical(_minimal_plan())
    plan.write_bytes(raw)
    subprocess.run(("/usr/bin/git", "add", "."), cwd=tmp_path, check=True)
    subprocess.run(
        ("/usr/bin/git", "commit", "-qm", "add fixed plan"),
        cwd=tmp_path,
        check=True,
    )

    commit = collector._immutable_plan_binding(
        tmp_path, "safepay_v2", plan, raw
    )
    assert len(commit) == 40

    plan.write_bytes(raw.replace(b"11" * 20, b"33" * 20))
    subprocess.run(("/usr/bin/git", "add", "."), cwd=tmp_path, check=True)
    subprocess.run(
        ("/usr/bin/git", "commit", "-qm", "mutate fixed plan"),
        cwd=tmp_path,
        check=True,
    )
    with pytest.raises(collector.LiveCollectorError, match="immutable first-add"):
        collector._immutable_plan_binding(
            tmp_path, "safepay_v2", plan, plan.read_bytes()
        )


def test_atomic_capture_batch_accepts_only_complete_collector_triplet(
    tmp_path: Path,
) -> None:
    from shared.live_collector_provenance import (
        LIVE_COLLECTOR_ARTIFACT_PATHS,
        LIVE_COLLECTOR_RAW_PATHS,
        LIVE_COLLECTOR_RECEIPT_PATHS,
    )
    from shared.release_manifest import (
        ReleaseManifestError,
        _create_capture_batch_once,
    )

    proof_id = "safepay_v2"
    payloads = {
        LIVE_COLLECTOR_RAW_PATHS[proof_id]: b"raw\n",
        LIVE_COLLECTOR_ARTIFACT_PATHS[proof_id]: b"artifact\n",
        LIVE_COLLECTOR_RECEIPT_PATHS[proof_id]: b"receipt\n",
    }
    _create_capture_batch_once(tmp_path, payloads)
    assert {
        relative: (tmp_path / relative).read_bytes() for relative in payloads
    } == payloads

    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ReleaseManifestError):
        _create_capture_batch_once(
            other,
            {LIVE_COLLECTOR_RAW_PATHS[proof_id]: b"partial"},
        )


def test_safepay_worker_choreography_is_direct_ordered_and_restart_bound() -> None:
    fixture_module = runpy.run_path(
        str(Path(__file__).with_name("test_safepay_v2_capture.py"))
    )
    fixture = fixture_module["base_bundle"]()
    redemption_names = {
        "redemption_first_consumption": "first_consumption",
        "redemption_exact_retry": "exact_retry",
        "redemption_cross_binding_reuse": "cross_binding_reuse",
    }
    rpc_names = {
        acquisition_id: (
            0 if "_rpc_a_" in acquisition_id else 1,
            acquisition_id.split("_", 3)[3],
        )
        for acquisition_id in collector._required_ids("safepay_v2")
        if acquisition_id.startswith("casper_rpc_")
    }
    requests: dict[str, dict[str, object]] = {}
    for acquisition_id, name in redemption_names.items():
        exchange = fixture["redemptions"][name]["exchange"]
        requests[acquisition_id] = {
            "method": "POST",
            "body_base64": exchange["request_body_base64"],
            "headers": {"content-type": "application/json"},
        }
    plan = {
        "schema_version": collector.PLAN_SCHEMA_VERSION,
        "proof_id": "safepay_v2",
        "source_commit": fixture["source_commit"],
        "deployment_commit": fixture["deployment_commit"],
        "bundle_skeleton": {
            "bundle_version": fixture["bundle_version"],
            "provider": {"instances": {}},
            "chain": {
                "payment_hash": fixture["chain"]["payment_hash"],
                "providers": [{}, {}],
            },
            "redemptions": {
                "first_consumption": {},
                "exact_retry": {},
                "cross_binding_reuse": {},
            },
            "ledger_snapshots_observed": {},
        },
        "requests": requests,
    }
    image = fixture["provider"]["image_digest"]
    before = {
        "container_id": "90" * 32,
        "image_digest": image,
        "started_at": "2026-07-23T00:50:00Z",
        "observed_at": "2026-07-23T01:03:55Z",
        "restart_count": 0,
    }
    before["service_instance_id"] = collector._service_instance_id(before)
    after = {
        "container_id": before["container_id"],
        "image_digest": image,
        "started_at": "2026-07-23T01:04:40Z",
        "observed_at": "2026-07-23T01:04:50Z",
        "restart_count": 1,
    }
    after["service_instance_id"] = collector._service_instance_id(after)
    runtime_values = iter(((before, b"before-runtime"), (after, b"after-runtime")))
    calls: list[str] = []

    def runtime_acquire(proof_id: str) -> tuple[dict[str, object], bytes]:
        assert proof_id == "safepay_v2"
        value = next(runtime_values)
        calls.append(
            "runtime_before_restart"
            if value[0]["service_instance_id"] == before["service_instance_id"]
            else "runtime_after_restart"
        )
        return value

    def restart_acquire(
        proof_id: str, observed_before: object
    ) -> tuple[dict[str, object], bytes]:
        assert proof_id == "safepay_v2"
        assert observed_before == before
        calls.append("service_restart")
        return after, b"restart-204-and-reconciled"

    snapshot_names = iter(
        (
            "after_first_consumption",
            "after_exact_retry",
            "after_cross_binding_reuse",
        )
    )
    snapshot_times = iter(
        (
            "2026-07-23T01:04:20Z",
            "2026-07-23T01:05:10Z",
            "2026-07-23T01:05:30Z",
        )
    )

    def sqlite_acquire(proof_id: str) -> tuple[bytes, str]:
        assert proof_id == "safepay_v2"
        name = next(snapshot_names)
        calls.append(f"ledger_{name}")
        return (
            base64.b64decode(
                fixture["ledger_snapshots_observed"][name][
                    "sqlite_backup_base64"
                ]
            ),
            next(snapshot_times),
        )

    http_ids = iter(
        acquisition_id
        for acquisition_id in collector._required_ids("safepay_v2")
        if collector._operation_kind(acquisition_id) in {"https", "casper_rpc"}
    )
    observed_times = iter(
        (
            "2026-07-23T01:04:10Z",
            "2026-07-23T01:04:55Z",
            "2026-07-23T01:05:00Z",
            "2026-07-23T01:05:20Z",
            "2026-07-23T01:05:40Z",
            "2026-07-23T01:05:41Z",
            "2026-07-23T01:05:42Z",
            "2026-07-23T01:05:43Z",
            "2026-07-23T01:05:44Z",
            "2026-07-23T01:05:45Z",
        )
    )

    def http_acquire(
        *,
        url: str,
        request: dict[str, object],
        authorization_secret: bytes | None,
    ) -> dict[str, object]:
        acquisition_id = next(http_ids)
        calls.append(acquisition_id)
        if acquisition_id == "service_health_after_restart":
            return {
                "method": "GET",
                "url": url,
                "request_body_base64": "",
                "request_headers": {"accept": "application/json"},
                "response_status": 200,
                "response_headers": {"content-type": "application/json"},
                "response_content_type": "application/json",
                "response_body_base64": base64.b64encode(b'{"ok":true}').decode(
                    "ascii"
                ),
                "observed_at": next(observed_times),
            }
        if acquisition_id in redemption_names:
            source = fixture["redemptions"][redemption_names[acquisition_id]][
                "exchange"
            ]
        else:
            provider_index, rpc_name = rpc_names[acquisition_id]
            source = fixture["chain"]["providers"][provider_index][rpc_name]
            assert request["body_base64"] == source["request_body_base64"]
        if "rpc_b" in acquisition_id:
            assert authorization_secret == b"token-not-reflected"
        return {
            "method": "POST",
            "url": url,
            "request_body_base64": request["body_base64"],
            "request_headers": copy.deepcopy(request["headers"]),
            "response_status": source["response_status"],
            "response_headers": {"content-type": source["response_content_type"]},
            "response_content_type": source["response_content_type"],
            "response_body_base64": source["response_body_base64"],
            "observed_at": next(observed_times),
        }

    raw_bundle, transcript_raw = collector._collect_worker(
        plan,
        http_acquire=http_acquire,
        runtime_acquire=runtime_acquire,
        restart_acquire=restart_acquire,
        sqlite_acquire=sqlite_acquire,
        secret_acquire=lambda *_args, **_kwargs: b"token-not-reflected",
    )
    transcript = json.loads(transcript_raw)

    assert [row["acquisition_id"] for row in transcript["acquisitions"]] == list(
        collector._required_ids("safepay_v2")
    )
    assert calls.index("redemption_first_consumption") < calls.index(
        "ledger_after_first_consumption"
    )
    assert calls.index("ledger_after_first_consumption") < calls.index(
        "service_restart"
    )
    assert calls.index("service_restart") < calls.index("runtime_after_restart")
    assert calls.index("runtime_after_restart") < calls.index(
        "redemption_exact_retry"
    )
    bundle = json.loads(raw_bundle)
    assert (
        bundle["provider"]["instances"]["before_restart"]["started_at"]
        != bundle["provider"]["instances"]["after_restart"]["started_at"]
    )
    assert collector._build_artifact("safepay_v2", raw_bundle)


def test_official_choreography_is_proof_ordered_before_paid_release() -> None:
    order = collector._required_ids("official_x402_settlement_v1")

    assert order.index("facilitator_supported") < order.index("wcspr_pre_verify")
    assert order.index("wcspr_pre_verify") < order.index("facilitator_verify")
    assert order.index("facilitator_verify") < order.index("wcspr_pre_settle")
    assert order.index("wcspr_pre_settle") < order.index("paid_first_release")
    assert order.index("paid_first_release") < order.index(
        "journal_after_first_release"
    )
    assert order.index("journal_after_first_release") < order.index(
        "facilitator_settle"
    )
    assert collector._operation_kind("facilitator_settle") == "sqlite_row"
    assert order.index("facilitator_settle") < order.index(
        "settlement_rpc_a_info_get_transaction"
    )
    assert order.index("settlement_rpc_b_info_get_status") < order.index(
        "wcspr_post_settle"
    )


def test_facilitator_settle_is_recovered_from_durable_local_journal() -> None:
    request_body = _canonical({"payment": "frozen"}).rstrip(b"\n")
    response_body = _canonical(
        {
            "success": True,
            "transaction": "44" * 32,
            "network": "casper:casper-test",
            "payer": "00" + "55" * 32,
        }
    ).rstrip(b"\n")
    headers = _canonical({"content-type": "application/json"}).rstrip(b"\n")
    migration = (
        Path("services/x402-official/migrations/0002_upstream_settle_journal.sql")
        .read_text()
    )
    connection = sqlite3.connect(":memory:")
    connection.executescript(migration)
    columns = (
        "event_type,call_id,network,wcspr_contract,"
        "signed_payment_payload_hash,payer_account_hash,authorization_nonce,"
        "resource_id,action_id,envelope_hash,request_method,request_url,"
        "request_headers_canonical_json,request_body,request_body_sha256,"
        "response_status,response_headers_canonical_json,response_body,"
        "response_body_sha256,failure_code,observed_at"
    )
    call_id = "11" * 32
    binding = (
        call_id,
        "casper:casper-test",
        collector._WCSPR_CONTRACT,
        "22" * 32,
        "33" * 32,
        "44" * 32,
        "risk-report",
        "55" * 32,
        "66" * 32,
    )
    placeholders = ",".join("?" for _ in range(21))
    connection.execute(
        f"INSERT INTO x402_upstream_settle_calls ({columns}) "
        f"VALUES ({placeholders})",
        (
            "request_started",
            *binding,
            "POST",
            "https://x402-facilitator.cspr.cloud/settle",
            headers,
            request_body,
            hashlib.sha256(request_body).hexdigest(),
            None,
            None,
            None,
            None,
            None,
            "2026-07-23T01:00:00Z",
        ),
    )
    connection.execute(
        f"INSERT INTO x402_upstream_settle_calls ({columns}) "
        f"VALUES ({placeholders})",
        (
            "response_observed",
            *binding,
            None,
            None,
            None,
            None,
            None,
            200,
            headers,
            response_body,
            hashlib.sha256(response_body).hexdigest(),
            None,
            "2026-07-23T01:00:01Z",
        ),
    )
    connection.commit()
    snapshot = connection.serialize()
    connection.close()

    observed, raw_request, raw_response = (
        collector._facilitator_settle_from_backup(
            snapshot,
            request={
                "method": "POST",
                "body_base64": base64.b64encode(request_body).decode("ascii"),
                "headers": {"content-type": "application/json"},
            },
            authorization_secret=b"token-not-reflected",
        )
    )

    assert raw_request == request_body
    assert raw_response == response_body
    assert observed["url"] == "https://x402-facilitator.cspr.cloud/settle"
    assert observed["observed_at"] == "2026-07-23T01:00:01Z"
    with pytest.raises(collector.LiveCollectorError, match="reflected"):
        collector._facilitator_settle_from_backup(
            snapshot,
            request={
                "method": "POST",
                "body_base64": base64.b64encode(request_body).decode("ascii"),
                "headers": {"content-type": "application/json"},
            },
            # This exact byte sequence appears in the raw response.  The
            # journal path must scan it before any JSON/base64 wrapping.
            authorization_secret=b"casper-test",
        )


def test_collector_uses_the_fixed_host_secret_source_not_container_mount() -> None:
    assert collector._FACILITATOR_TOKEN_PATH == Path(
        "/opt/apps/concordia/secrets/x402_official_cspr_cloud_token"
    )


def test_paid_first_release_polls_only_reconciliation_until_report_release() -> None:
    pending = _canonical({"error": "reconciliation_pending"}).rstrip(b"\n")
    report = _canonical({"report": "released"}).rstrip(b"\n")
    responses = iter(
        (
            (503, pending, "2026-07-23T01:00:00Z"),
            (503, pending, "2026-07-23T01:00:01Z"),
            (200, report, "2026-07-23T01:00:02Z"),
        )
    )
    calls = 0
    sleeps: list[float] = []

    def acquire(**kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        assert kwargs["authorization_secret"] is None
        status, body, observed_at = next(responses)
        return {
            "method": "GET",
            "url": kwargs["url"],
            "request_body_base64": "",
            "request_headers": {"payment-signature": "bound"},
            "response_status": status,
            "response_headers": {"content-type": "application/json"},
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(body).decode("ascii"),
            "observed_at": observed_at,
        }

    observed, transcript = collector._poll_paid_first_release(
        url="https://x402.concordiadao.xyz/resource/risk-report",
        request={
            "method": "GET",
            "body_base64": "",
            "headers": {"payment-signature": "bound"},
        },
        http_acquire=acquire,
        sleep=sleeps.append,
        secrets_to_scan=(b"token-not-reflected",),
    )

    assert calls == 3
    assert len(sleeps) == 2
    assert observed["response_status"] == 200
    assert (
        base64.b64decode(observed["response_body_base64"], validate=True)
        == report
    )
    assert [item["response_status"] for item in json.loads(transcript)] == [
        503,
        503,
        200,
    ]


def test_paid_first_release_scans_unaligned_raw_terminal_body_before_wrapping() -> None:
    token = b"raw-token-that-must-never-enter-evidence"
    # The five-byte prefix puts the reflected token at an alignment that does
    # not appear as base64(token) inside base64(the whole response).
    body = b'{"x":"' + b"a" * 5 + token + b'"}'
    assert base64.b64encode(token) not in base64.b64encode(body)

    def acquire(**kwargs: object) -> dict[str, object]:
        return {
            "method": "GET",
            "url": kwargs["url"],
            "request_body_base64": "",
            "request_headers": {"payment-signature": "bound"},
            "response_status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(body).decode("ascii"),
            "observed_at": "2026-07-23T01:00:02Z",
        }

    with pytest.raises(collector.LiveCollectorError, match="reflected"):
        collector._poll_paid_first_release(
            url="https://x402.concordiadao.xyz/resource/risk-report",
            request={
                "method": "GET",
                "body_base64": "",
                "headers": {"payment-signature": "bound"},
            },
            http_acquire=acquire,
            sleep=lambda _seconds: None,
            secrets_to_scan=(token,),
        )


def test_wcspr_readback_derives_runtime_selectors_from_status_response() -> None:
    tip_hash = "a1" * 32
    state_root = "b1" * 32
    requests = [
        {
            "jsonrpc": "2.0",
            "id": "pre-verify-status",
            "method": "info_get_status",
            "params": [],
        },
        {
            "jsonrpc": "2.0",
            "id": "pre-verify-package",
            "method": "state_get_package",
            "params": {
                "package_identifier": {
                    "ContractPackageHash": (
                        "contract-package-" + collector._WCSPR_PACKAGE
                    )
                },
                "block_identifier": {"Hash": tip_hash},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": "pre-verify-contract",
            "method": "query_global_state",
            "params": {
                "state_identifier": {"StateRootHash": state_root},
                "key": "hash-" + collector._WCSPR_CONTRACT,
                "path": [],
            },
        },
    ]
    responses = [
        {
            "jsonrpc": "2.0",
            "id": "pre-verify-status",
            "result": {
                "chainspec_name": "casper-test",
                "last_added_block_info": {
                    "hash": tip_hash,
                    "state_root_hash": state_root,
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": "pre-verify-package",
            "result": {
                "package": {
                    "ContractPackage": {
                        "versions": [
                            {
                                "protocol_version_major": 2,
                                "contract_version": 7,
                                "contract_hash": "contract-" + "c1" * 32,
                            },
                            {
                                "protocol_version_major": 2,
                                "contract_version": collector._WCSPR_VERSION,
                                "contract_hash": (
                                    "contract-" + collector._WCSPR_CONTRACT
                                ),
                            },
                        ],
                        "disabled_versions": [[2, 7]],
                        "lock_status": "Unlocked",
                    }
                }
            },
        },
        {
            "jsonrpc": "2.0",
            "id": "pre-verify-contract",
            "result": {"stored_value": {}},
        },
    ]
    observed_at = "2026-07-23T01:00:00Z"
    calls: list[dict[str, object]] = []

    def acquire(
        *,
        url: str,
        request: dict[str, object],
        authorization_secret: bytes | None,
    ) -> dict[str, object]:
        index = len(calls)
        request_document = json.loads(base64.b64decode(request["body_base64"]))
        assert request_document == requests[index]
        assert authorization_secret is None
        calls.append(request_document)
        return {
            "method": "POST",
            "url": url,
            "request_body_base64": request["body_base64"],
            "request_headers": {"content-type": "application/json"},
            "response_status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(
                _canonical(responses[index]).rstrip(b"\n")
            ).decode("ascii"),
            "observed_at": observed_at,
        }

    observed = collector._wcspr_readback(
        acquisition_id="wcspr_pre_verify",
        url="https://node.testnet.casper.network/rpc",
        http_acquire=acquire,
    )

    assert calls == requests
    assert json.loads(base64.b64decode(observed["request_body_base64"])) == requests
    assert json.loads(base64.b64decode(observed["response_body_base64"])) == responses


def test_wcspr_readback_refuses_package_that_does_not_select_frozen_v8() -> None:
    tip_hash = "a1" * 32
    state_root = "b1" * 32
    responses = iter(
        (
            {
                "jsonrpc": "2.0",
                "id": "pre-verify-status",
                "result": {
                    "chainspec_name": "casper-test",
                    "last_added_block_info": {
                        "hash": tip_hash,
                        "state_root_hash": state_root,
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": "pre-verify-package",
                "result": {
                    "package": {
                        "ContractPackage": {
                            "versions": [
                                {
                                    "protocol_version_major": 2,
                                    "contract_version": collector._WCSPR_VERSION,
                                    "contract_hash": "contract-" + "99" * 32,
                                }
                            ],
                            "disabled_versions": [],
                            "lock_status": "Unlocked",
                        }
                    }
                },
            },
        )
    )
    calls = 0

    def acquire(**kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        body = _canonical(next(responses)).rstrip(b"\n")
        request = kwargs["request"]
        assert isinstance(request, dict)
        return {
            "method": "POST",
            "url": kwargs["url"],
            "request_body_base64": request["body_base64"],
            "request_headers": {"content-type": "application/json"},
            "response_status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(body).decode("ascii"),
            "observed_at": "2026-07-23T01:00:00Z",
        }

    with pytest.raises(collector.LiveCollectorError, match="active v8"):
        collector._wcspr_readback(
            acquisition_id="wcspr_pre_verify",
            url="https://node.testnet.casper.network/rpc",
            http_acquire=acquire,
        )
    assert calls == 2


def test_settlement_status_polls_until_eight_confirmations_and_then_allows_post_readback() -> None:
    block_hash = "44" * 32
    block_height = 8_400_000

    def observation(document: dict[str, object], observed_at: str) -> dict[str, object]:
        return {
            "response_status": 200,
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(
                _canonical(document).rstrip(b"\n")
            ).decode("ascii"),
            "observed_at": observed_at,
        }

    block_response = {
        "jsonrpc": "2.0",
        "id": "block",
        "result": {
            "block_with_signatures": {
                "block": {
                    "Version2": {
                        "hash": block_hash,
                        "header": {"height": block_height},
                    }
                }
            }
        },
    }
    observations: dict[str, dict[str, object]] = {
        f"settlement_rpc_{provider}_chain_get_block": observation(
            block_response, "2026-07-23T01:00:00Z"
        )
        for provider in ("a", "b")
    }
    heights = iter((block_height + 7, block_height + 8))

    def acquire(**kwargs: object) -> dict[str, object]:
        assert kwargs["authorization_secret"] is None
        height = next(heights)
        return observation(
            {
                "jsonrpc": "2.0",
                "id": "status",
                "result": {
                    "chainspec_name": "casper-test",
                    "last_added_block_info": {"height": height},
                },
            },
            "2026-07-23T01:00:01Z",
        )

    status = collector._poll_finalized_settlement_status(
        acquisition_id="settlement_rpc_a_info_get_status",
        url="https://node.testnet.casper.network/rpc",
        request=collector._rpc_request(
            request_id="status",
            method="info_get_status",
            params=[],
        ),
        observations=observations,
        http_acquire=acquire,
        sleep=lambda _seconds: None,
        authorization_secret=None,
    )
    observations["settlement_rpc_a_info_get_status"] = status
    observations["settlement_rpc_b_info_get_status"] = observation(
        {
            "jsonrpc": "2.0",
            "id": "status",
            "result": {
                "chainspec_name": "casper-test",
                "last_added_block_info": {"height": block_height + 8},
            },
        },
        "2026-07-23T01:00:02Z",
    )

    collector._require_shared_settlement_finality(observations)


def test_settlement_status_poll_uses_direct_auth_only_for_provider_b() -> None:
    block_hash = "55" * 32
    block_height = 8_500_000
    token = b"direct-cspr-cloud-token"

    def observation(document: dict[str, object]) -> dict[str, object]:
        return {
            "method": "POST",
            "url": "https://node.testnet.cspr.cloud/rpc",
            "request_body_base64": "",
            "request_headers": {"content-type": "application/json"},
            "response_status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(
                _canonical(document).rstrip(b"\n")
            ).decode("ascii"),
            "observed_at": "2026-07-23T01:00:01Z",
        }

    block_response = observation(
        {
            "jsonrpc": "2.0",
            "id": "block",
            "result": {
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": block_hash,
                            "header": {"height": block_height},
                        }
                    }
                }
            },
        }
    )
    authorizations: list[bytes | None] = []
    heights = iter((block_height + 7, block_height + 8))

    def acquire(
        *,
        url: str,
        request: dict[str, object],
        authorization_secret: bytes | None,
    ) -> dict[str, object]:
        assert url == "https://node.testnet.cspr.cloud/rpc"
        assert request["headers"] == {"content-type": "application/json"}
        authorizations.append(authorization_secret)
        return observation(
            {
                "jsonrpc": "2.0",
                "id": "status",
                "result": {
                    "chainspec_name": "casper-test",
                    "last_added_block_info": {"height": next(heights)},
                },
            }
        )

    result = collector._poll_finalized_settlement_status(
        acquisition_id="settlement_rpc_b_info_get_status",
        url="https://node.testnet.cspr.cloud/rpc",
        request=collector._rpc_request(
            request_id="status",
            method="info_get_status",
            params=[],
        ),
        observations={"settlement_rpc_b_chain_get_block": block_response},
        http_acquire=acquire,
        sleep=lambda _seconds: None,
        authorization_secret=token,
    )

    assert authorizations == [token, token]
    assert collector._status_tip_height(
        result, label="provider b final status"
    ) == block_height + 8


def test_settlement_status_poll_refuses_reflected_direct_token() -> None:
    block_hash = "66" * 32
    token = b"direct-cspr-cloud-token"
    block_response = {
        "response_status": 200,
        "response_content_type": "application/json",
        "response_body_base64": base64.b64encode(
            _canonical(
                {
                    "jsonrpc": "2.0",
                    "id": "block",
                    "result": {
                        "block_with_signatures": {
                            "block": {
                                "Version2": {
                                    "hash": block_hash,
                                    "header": {"height": 8_500_000},
                                }
                            }
                        }
                    },
                }
            ).rstrip(b"\n")
        ).decode("ascii"),
        "observed_at": "2026-07-23T01:00:00Z",
    }

    def acquire(**_kwargs: object) -> dict[str, object]:
        return {
            "response_status": 200,
            "response_headers": {"content-type": "application/json"},
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(
                _canonical({"reflected": token.decode("ascii")}).rstrip(b"\n")
            ).decode("ascii"),
            "observed_at": "2026-07-23T01:00:01Z",
        }

    with pytest.raises(collector.LiveCollectorError, match="reflected"):
        collector._poll_finalized_settlement_status(
            acquisition_id="settlement_rpc_b_info_get_status",
            url="https://node.testnet.cspr.cloud/rpc",
            request=collector._rpc_request(
                request_id="status",
                method="info_get_status",
                params=[],
            ),
            observations={
                "settlement_rpc_b_chain_get_block": block_response,
            },
            http_acquire=acquire,
            sleep=lambda _seconds: None,
            authorization_secret=token,
        )


def test_post_settle_readback_refuses_disagreeing_provider_blocks() -> None:
    def observed(block_hash: str) -> dict[str, object]:
        return {
            "response_status": 200,
            "response_content_type": "application/json",
            "response_body_base64": base64.b64encode(
                _canonical(
                    {
                        "jsonrpc": "2.0",
                        "id": "block",
                        "result": {
                            "block_with_signatures": {
                                "block": {
                                    "Version2": {
                                        "hash": block_hash,
                                        "header": {"height": 10},
                                    }
                                }
                            }
                        },
                    }
                ).rstrip(b"\n")
            ).decode("ascii"),
            "observed_at": "2026-07-23T01:00:00Z",
        }

    with pytest.raises(collector.LiveCollectorError, match="disagree"):
        collector._require_shared_settlement_finality(
            {
                "settlement_rpc_a_chain_get_block": observed("11" * 32),
                "settlement_rpc_b_chain_get_block": observed("22" * 32),
            }
        )
