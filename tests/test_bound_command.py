from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import MappingProxyType

import pytest

from shared import bound_command, release_gate_contract
from shared.bound_command import BoundCommandError, PrivateOutputSpec, ToolSpec


def _tool_spec(
    tool_id: str,
    candidate: Path,
    *,
    launcher_tool_id: str | None = None,
    script_policy: str = "absolute_system_shebang",
) -> ToolSpec:
    return ToolSpec(
        tool_id=tool_id,
        absolute_candidates=(candidate.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=False,
        launcher_tool_id=launcher_tool_id,
        version_argv=(tool_id, "--version"),
        exact_version=None,
        script_policy=script_policy,
    )


def _git(repository: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ("/usr/bin/git", *arguments),
        cwd=repository,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=Concordia Tests",
        "-c",
        "user.email=tests@concordia.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD").decode("ascii").strip()


def test_fixed_tool_contract_is_immutable_and_exposes_host_receipt_schema() -> None:
    assert release_gate_contract.BOUND_COMMAND_SCHEMA_VERSION == (
        "concordia.bound_command.v1"
    )
    assert release_gate_contract.BOUND_TOOL_IDENTITY_SCHEMA_VERSION == (
        "concordia.bound_tool_identity.v1"
    )
    assert release_gate_contract.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH == (
        "release/receipts/HOST_TOOLCHAIN.json"
    )
    assert release_gate_contract.BOUND_HOST_TOOLCHAIN_RUNNER_PATH == (
        "scripts/build_release_manifest.py"
    )
    assert release_gate_contract.BOUND_HOST_AUTHORITY_DESCENDANT_PREFIXES == (
        "release/receipts/",
        "release/captures/",
        "release/g13/",
    )
    assert release_gate_contract.BOUND_HOST_AUTHORITY_DESCENDANT_PATHS == (
        "release/organizer/G12_RENDERED_LINK_AUDIT.json",
        "release/organizer/G12_RENDERED_LINK_INVOCATION.json",
        "release/RELEASE_MANIFEST.json",
        "release/G13_SUBMISSION_RECEIPT.json",
    )
    assert set(release_gate_contract.BOUND_TOOL_SPECS) == {
        "dig",
        "docker",
        "gh",
        "git",
        "node",
        "npm",
        "python",
    }
    assert release_gate_contract.BOUND_TOOL_POLICY["caller_path"] == "ignored"
    assert release_gate_contract.BOUND_TOOL_POLICY["mutable_tool_execution"] == (
        "private_fsync_snapshot"
    )
    assert release_gate_contract.BOUND_TOOL_POLICY["version_policy"] == (
        "exact_contract_or_accepted_host_receipt"
    )
    assert (
        release_gate_contract.BOUND_TOOL_POLICY["node_command_asset_execution"]
        == "explicit_closed_tree_private_fsync_snapshot"
    )
    assert (
        release_gate_contract.BOUND_TOOL_POLICY["python_command_asset_execution"]
        == "explicit_closed_tree_private_fsync_snapshot"
    )
    assert (
        release_gate_contract.BOUND_TOOL_POLICY["process_exit_observation"]
        == "nonreaping_darwin_kqueue_linux_waitid_or_pidfd"
    )
    assert (
        release_gate_contract.BOUND_TOOL_POLICY["leader_reap_order"]
        == "after_group_and_detached_descendant_containment"
    )
    assert (
        release_gate_contract.BOUND_TOOL_POLICY["bound_data_input_execution"]
        == "explicit_exact_regular_file_private_fsync_snapshot"
    )
    assert release_gate_contract.BOUND_TOOL_POLICY[
        "detached_descendant_containment"
    ] == ("inherited_descriptor_scan_plus_darwin_active_tree_or_linux_nonce_sweep")
    assert (
        release_gate_contract.BOUND_TOOL_POLICY["malicious_descendant_evasion_sandbox"]
        is False
    )
    assert release_gate_contract.BOUND_TOOL_POLICY["tree_scan_binding"] == (
        "path_pre_post_stat_and_content_revalidation_not_openat"
    )
    with pytest.raises(TypeError):
        release_gate_contract.BOUND_TOOL_SPECS["git"] = {}  # type: ignore[index]


def test_bound_command_ignores_path_and_executes_private_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    safe = tmp_path / "safe-tool"
    safe.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'safe 1.0\\n\'; exit; fi\n'
        "printf 'SAFE\\n'\n",
        encoding="utf-8",
    )
    safe.chmod(0o755)
    malicious_bin = tmp_path / "malicious-bin"
    malicious_bin.mkdir()
    marker = tmp_path / "path-tool-executed"
    malicious = malicious_bin / "safe"
    malicious.write_text(
        f"#!/bin/sh\ntouch \"{marker}\"\nprintf 'EVIL\\n'\n",
        encoding="utf-8",
    )
    malicious.chmod(0o755)
    spec = _tool_spec("safe", safe)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"safe": spec}),
    )
    result = bound_command.run_bound_command(
        cwd=tmp_path,
        tool_id="safe",
        argv=("safe",),
        env={"LANG": "C", "PATH": malicious_bin.as_posix()},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
    )

    assert result.returncode == 0
    assert result.stdout == b"SAFE\n"
    assert result.stderr == b""
    assert result.private_outputs == ()
    assert (
        result.tool_identity["source_sha256"]
        == hashlib.sha256(safe.read_bytes()).hexdigest()
    )
    assert not marker.exists()


def test_sys_executable_identity_uses_stable_resolved_runtime_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    executable = runtime / "bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_text(
        "#!/bin/sh\nprintf 'Python 3.12.11\\n'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    first_alias = tmp_path / "ephemeral-a/python"
    second_alias = tmp_path / "ephemeral-b/python"
    first_alias.parent.mkdir()
    second_alias.parent.mkdir()
    first_alias.symlink_to(executable)
    second_alias.symlink_to(executable)
    spec = ToolSpec(
        tool_id="python",
        absolute_candidates=(),
        use_sys_executable=True,
        manifest_required_when_mutable=False,
        launcher_tool_id=None,
        version_argv=("python", "--version"),
        exact_version="Python 3.12.11",
        script_policy="binary",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"python": spec}),
    )

    monkeypatch.setattr(bound_command.sys, "executable", first_alias.as_posix())
    first = bound_command.inspect_bound_tool("python").to_dict()
    monkeypatch.setattr(bound_command.sys, "executable", second_alias.as_posix())
    second = bound_command.inspect_bound_tool("python").to_dict()

    assert first == second
    assert (
        first["resolved_path_sha256"]
        == hashlib.sha256(str(executable).encode()).hexdigest()
    )


def test_private_snapshot_defeats_symlink_swap_execute_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked = tmp_path / "tool"
    good = tmp_path / "good"
    evil = tmp_path / "evil"
    saved = tmp_path / "saved-tool-link"
    evil_link = tmp_path / "evil-tool-link"
    marker = tmp_path / "evil-ran"
    good.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'tool 1.0\\n\'; exit; fi\n'
        'mv "$1" "$2"\n'
        'mv "$3" "$1"\n'
        'mv "$1" "$3"\n'
        'mv "$2" "$1"\n'
        "printf 'GOOD\\n'\n",
        encoding="utf-8",
    )
    evil.write_text(
        f"#!/bin/sh\ntouch \"{marker}\"\nprintf 'EVIL\\n'\n",
        encoding="utf-8",
    )
    good.chmod(0o755)
    evil.chmod(0o755)
    invoked.symlink_to(good)
    evil_link.symlink_to(evil)
    spec = _tool_spec("tool", invoked)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"tool": spec}),
    )
    with pytest.raises(BoundCommandError, match="identity changed"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="tool",
            argv=(
                "tool",
                invoked.as_posix(),
                saved.as_posix(),
                evil_link.as_posix(),
            ),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
        )

    assert not marker.exists()


def test_bound_command_rejects_env_shebang_instead_of_path_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "env-tool"
    tool.write_text("#!/usr/bin/env sh\nprintf 'unsafe\\n'\n", encoding="utf-8")
    tool.chmod(0o755)
    spec = _tool_spec("env-tool", tool)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"env-tool": spec}),
    )

    with pytest.raises(BoundCommandError, match="shebang|interpreter"):
        bound_command.inspect_bound_tool("env-tool")


def test_npm_plan_binds_node_and_script_without_usr_bin_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = tmp_path / "node"
    npm = tmp_path / "npm-package/bin/npm-cli.js"
    npm.parent.mkdir(parents=True)
    (tmp_path / "npm-package/lib").mkdir()
    marker = tmp_path / "path-node-ran"
    node.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'node 1.0\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        'exec /bin/sh "$script" "$@"\n',
        encoding="utf-8",
    )
    npm.write_text(
        "#!/usr/bin/env node\n"
        'if [ "${1:-}" = "--version" ]; then printf \'npm 1.0\\n\'; exit; fi\n'
        "printf 'NPM-SAFE\\n'\n",
        encoding="utf-8",
    )
    node.chmod(0o755)
    npm.chmod(0o755)
    malicious_bin = tmp_path / "malicious-bin"
    malicious_bin.mkdir()
    malicious_node = malicious_bin / "node"
    malicious_node.write_text(
        f"#!/bin/sh\ntouch \"{marker}\"\nprintf 'EVIL\\n'\n",
        encoding="utf-8",
    )
    malicious_node.chmod(0o755)
    specs = {
        "node": _tool_spec("node", node),
        "npm": _tool_spec(
            "npm",
            npm,
            launcher_tool_id="node",
            script_policy="node_launcher",
        ),
    }
    monkeypatch.setattr(bound_command, "_TOOL_SPECS", MappingProxyType(specs))
    result = bound_command.run_bound_command(
        cwd=tmp_path,
        tool_id="npm",
        argv=("npm", "test"),
        env={"LANG": "C", "PATH": malicious_bin.as_posix()},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
    )

    assert result.stdout == b"NPM-SAFE\n"
    assert result.tool_identity["dependencies"]["node"]["source_sha256"]
    assert not marker.exists()


def test_stream_limits_kill_process_group_before_command_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "overflow-tool"
    marker = tmp_path / "continued-after-overflow"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'overflow 1.0\\n\'; exit; fi\n'
        "printf '012345678901234567890123456789012'\n"
        "sleep 1\n"
        f'touch "{marker}"\n',
        encoding="utf-8",
    )
    tool.chmod(0o755)
    spec = _tool_spec("overflow", tool)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"overflow": spec}),
    )
    with pytest.raises(BoundCommandError, match="output limit"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="overflow",
            argv=("overflow",),
            env={"LANG": "C"},
            stdout_limit=32,
            stderr_limit=32,
            timeout_s=5,
        )

    assert not marker.exists()


def test_successful_leader_exit_kills_surviving_process_group_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "forking-tool"
    marker = tmp_path / "surviving-child-ran"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'forking 1.0\\n\'; exit; fi\n'
        f'(sleep 0.3; touch "{marker}") &\n'
        "exit 0\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    spec = _tool_spec("forking", tool)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"forking": spec}),
    )
    result = bound_command.run_bound_command(
        cwd=tmp_path,
        tool_id="forking",
        argv=("forking",),
        env={"LANG": "C"},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
    )

    assert result.returncode == 0
    time.sleep(0.5)
    assert not marker.exists()


def test_successful_leader_exit_kills_setsid_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "detached-tool"
    marker = tmp_path / "setsid-child-ran"
    tool.write_text(
        "#!/usr/bin/python3\n"
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "import time\n"
        "if len(sys.argv) > 1 and sys.argv[1] == '--version':\n"
        "    print('detached 1.0')\n"
        "    raise SystemExit(0)\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    time.sleep(0.3)\n"
        f"    pathlib.Path({marker.as_posix()!r}).touch()\n"
        "    os._exit(0)\n"
        "os._exit(0)\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    spec = _tool_spec("detached", tool)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"detached": spec}),
    )

    result = bound_command.run_bound_command(
        cwd=tmp_path,
        tool_id="detached",
        argv=("detached",),
        env={"LANG": "C"},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
    )

    assert result.returncode == 0
    time.sleep(0.5)
    assert not marker.exists()


def test_process_group_and_detached_descendants_are_contained_before_single_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeProcess:
        pid = 4242
        returncode: int | None = None

        def poll(self) -> int:
            events.append("poll-reaped")
            self.returncode = 0
            return 0

        def kill(self) -> None:
            events.append("leader-killed")

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            events.append("wait-reaped")
            self.returncode = 0
            return 0

    class FakeObserver:
        def __init__(self, pid: int) -> None:
            assert pid == 4242
            events.append("observer-opened")

        def exited(self) -> bool:
            events.append("exit-observed-without-reap")
            return True

        def close(self) -> None:
            events.append("observer-closed")

    class FakeTracker:
        def start(self, root_pid: int) -> None:
            assert root_pid == 4242
            events.append("tracker-started")

        def contain(self) -> None:
            events.append("detached-contained")

    monkeypatch.setattr(
        bound_command.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(),
    )
    monkeypatch.setattr(
        bound_command,
        "_NonReapingExitObserver",
        FakeObserver,
        raising=False,
    )
    monkeypatch.setattr(
        bound_command.os,
        "killpg",
        lambda pid, _signal: events.append(f"group-killed:{pid}"),
    )

    result = bound_command._run_bounded_process_once(
        cwd=tmp_path,
        argv=("fake",),
        executable=Path("/bin/sh"),
        env={"LANG": "C"},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
        tracker=FakeTracker(),  # type: ignore[arg-type]
        inherited_descriptor=-1,
    )

    assert result.returncode == 0
    assert "poll-reaped" not in events
    assert events.count("wait-reaped") == 1
    assert events.index("group-killed:4242") < events.index("detached-contained")
    assert events.index("detached-contained") < events.index("wait-reaped")


def test_process_group_signal_failure_contains_reaps_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeProcess:
        pid = 4242

        def kill(self) -> None:
            events.append("leader-killed")

        def wait(self) -> int:
            events.append("wait-reaped")
            return -9

    class FakeTracker:
        def contain(self) -> None:
            events.append("detached-contained")

    monkeypatch.setattr(
        bound_command.os,
        "killpg",
        lambda _pid, _signal: (_ for _ in ()).throw(PermissionError("denied")),
    )

    with pytest.raises(BoundCommandError, match="process group"):
        bound_command._contain_and_reap_process(
            FakeProcess(),  # type: ignore[arg-type]
            FakeTracker(),  # type: ignore[arg-type]
            leader_exited=False,
        )

    assert events == ["leader-killed", "detached-contained", "wait-reaped"]


def test_darwin_completed_leader_eperm_is_not_a_group_kill_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeProcess:
        pid = 4242

        def kill(self) -> None:
            events.append("leader-killed")

        def wait(self) -> int:
            events.append("wait-reaped")
            return 0

    class FakeTracker:
        def contain(self) -> None:
            events.append("detached-contained")

    monkeypatch.setattr(bound_command.sys, "platform", "darwin")
    monkeypatch.setattr(
        bound_command.os,
        "killpg",
        lambda _pid, _signal: (_ for _ in ()).throw(PermissionError("zombie")),
    )

    returncode = bound_command._contain_and_reap_process(
        FakeProcess(),  # type: ignore[arg-type]
        FakeTracker(),  # type: ignore[arg-type]
        leader_exited=True,
    )

    assert returncode == 0
    assert events == ["detached-contained", "wait-reaped"]


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin kqueue contract")
def test_darwin_exit_observer_does_not_reap_leader() -> None:
    process = subprocess.Popen(
        ("/bin/sh", "-c", "exit 7"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    observer = bound_command._NonReapingExitObserver(process.pid)
    try:
        deadline = time.monotonic() + 5
        while not observer.exited() and time.monotonic() < deadline:
            time.sleep(0.002)
        assert observer.exited()
        assert process.returncode is None
    finally:
        observer.close()
    assert process.wait() == 7


def test_linux_exit_observer_uses_waitid_with_wnowait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int]] = []

    class Observation:
        si_pid = 4242

    monkeypatch.setattr(bound_command.sys, "platform", "linux")
    monkeypatch.setattr(
        bound_command.os,
        "waitid",
        lambda selector, pid, flags: (
            calls.append((selector, pid, flags)) or Observation()
        ),
        raising=False,
    )
    observer = bound_command._NonReapingExitObserver(4242)
    try:
        assert observer.exited()
    finally:
        observer.close()

    assert calls == [
        (
            bound_command.os.P_PID,
            4242,
            bound_command.os.WEXITED
            | bound_command.os.WNOHANG
            | bound_command.os.WNOWAIT,
        )
    ]


def test_nonreaping_exit_observer_fails_closed_without_supported_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bound_command.sys, "platform", "linux")
    monkeypatch.delattr(bound_command.os, "waitid", raising=False)
    monkeypatch.delattr(bound_command.os, "pidfd_open", raising=False)

    with pytest.raises(BoundCommandError, match="unsupported"):
        bound_command._NonReapingExitObserver(4242)


def test_bounded_process_preserves_nonzero_and_signal_returncodes(
    tmp_path: Path,
) -> None:
    nonzero = bound_command.run_bounded_process(
        cwd=tmp_path,
        argv=("sh", "-c", "exit 23"),
        executable=Path("/bin/sh"),
        env={"LANG": "C"},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
    )
    signaled = bound_command.run_bounded_process(
        cwd=tmp_path,
        argv=("sh", "-c", "kill -TERM $$"),
        executable=Path("/bin/sh"),
        env={"LANG": "C"},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
    )

    assert nonzero.returncode == 23
    assert signaled.returncode == -15


def test_bounded_process_timeout_kills_and_reaps_leader(
    tmp_path: Path,
) -> None:
    pid_path = tmp_path / "leader.pid"
    with pytest.raises(BoundCommandError, match="timed out"):
        bound_command.run_bounded_process(
            cwd=tmp_path,
            argv=(
                "sh",
                "-c",
                f"printf '%s' $$ > '{pid_path}'; exec /bin/sleep 30",
            ),
            executable=Path("/bin/sh"),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=1,
        )

    leader_pid = int(pid_path.read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(leader_pid, 0)


def test_descendant_tracker_never_kills_reused_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "descriptor-marker"
    marker.write_bytes(b"")
    tracker = bound_command._DescendantTracker("a" * 64, marker)
    tracker._root_pid = 101
    tracker._root_identity = (101, 1, 0)
    tracker._seen = {202: (202, 1, 0)}
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        bound_command,
        "_process_identity",
        lambda pid: (202, 2, 0) if pid == 202 else None,
    )
    monkeypatch.setattr(bound_command, "_linux_nonce_pids", lambda _nonce: ())
    monkeypatch.setattr(
        bound_command,
        "_descriptor_holder_pids",
        lambda _marker_path: (),
    )
    monkeypatch.setattr(
        bound_command.os,
        "kill",
        lambda pid, sig: killed.append((pid, sig)),
    )

    tracker.contain()

    assert killed == []


def test_bound_command_rejects_symlink_cwd_and_self_inspected_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_cwd = tmp_path / "real"
    real_cwd.mkdir()
    linked_cwd = tmp_path / "linked"
    linked_cwd.symlink_to(real_cwd, target_is_directory=True)
    tool = tmp_path / "tool"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'tool 1.0\\n\'; exit; fi\n'
        "printf 'ok\\n'\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    spec = ToolSpec(
        tool_id="tool",
        absolute_candidates=(tool.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=True,
        launcher_tool_id=None,
        version_argv=("tool", "--version"),
        exact_version=None,
        script_policy="absolute_system_shebang",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"tool": spec}),
    )
    candidate = bound_command.inspect_bound_tool("tool")

    with pytest.raises(BoundCommandError, match="working directory|symlink"):
        bound_command.run_bound_command(
            cwd=linked_cwd,
            tool_id="tool",
            argv=("tool",),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
        )

    with pytest.raises(BoundCommandError, match="authority provenance"):
        bound_command.run_bound_command(
            cwd=real_cwd,
            tool_id="tool",
            argv=("tool",),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
            accepted_authority=candidate.to_dict(),  # type: ignore[arg-type]
        )


def test_host_toolchain_receipt_requires_exact_commit_runner_host_and_tool_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "tool"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'tool 1.0\\n\'; exit; fi\n'
        "printf 'ok\\n'\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    spec = _tool_spec("tool", tool)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"tool": spec}),
    )
    source_commit = "a" * 40
    runner_sha256 = "b" * 64
    host_id = "c" * 64
    derived = {"runner_sha256": runner_sha256, "host_id": host_id}
    monkeypatch.setattr(
        bound_command,
        "derive_candidate_runner_sha256",
        lambda _root, *, source_commit: derived["runner_sha256"],
    )
    monkeypatch.setattr(
        bound_command,
        "derive_accepted_runner_sha256",
        lambda _root, *, source_commit, receipt: derived["runner_sha256"],
    )
    monkeypatch.setattr(
        bound_command,
        "derive_bound_host_id",
        lambda: derived["host_id"],
    )
    receipt = bound_command.build_host_toolchain_receipt_candidate(
        repository_root=tmp_path,
        source_commit=source_commit,
    )
    assert json.loads(json.dumps(receipt))["source_commit"] == source_commit

    selected = bound_command.accepted_tool_authority_from_receipt(
        receipt,
        repository_root=tmp_path,
        source_commit=source_commit,
    )
    assert selected.source_commit == source_commit

    forged = dict(receipt)
    forged["runner_sha256"] = "d" * 64
    with pytest.raises(BoundCommandError, match="receipt binding"):
        bound_command.accepted_tool_authority_from_receipt(
            forged,
            repository_root=tmp_path,
            source_commit=source_commit,
        )

    derived["host_id"] = "d" * 64
    with pytest.raises(BoundCommandError, match="receipt binding"):
        bound_command.accepted_tool_authority_from_receipt(
            receipt,
            repository_root=tmp_path,
            source_commit=source_commit,
        )
    with pytest.raises(BoundCommandError, match="receipt binding"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="tool",
            argv=("tool",),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
            accepted_authority=selected,
        )
    derived["host_id"] = host_id

    with pytest.raises(BoundCommandError, match="receipt binding"):
        bound_command.accepted_tool_authority_from_receipt(
            receipt,
            repository_root=tmp_path,
            source_commit="e" * 40,
        )

    uppercase = dict(receipt)
    uppercase["source_commit"] = source_commit.upper()
    with pytest.raises(BoundCommandError, match="malformed"):
        bound_command.accepted_tool_authority_from_receipt(
            uppercase,
            repository_root=tmp_path,
            source_commit=source_commit.upper(),
        )


def test_runner_authority_accepts_release_only_descendant_and_rejects_source_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "tool"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'tool 1.0\\n\'; exit; fi\n'
        "printf 'AUTHORITY-BOUND\\n'\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    spec = ToolSpec(
        tool_id="tool",
        absolute_candidates=(tool.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=True,
        launcher_tool_id=None,
        version_argv=("tool", "--version"),
        exact_version="tool 1.0",
        script_policy="absolute_system_shebang",
    )
    git_spec = bound_command.tool_spec("git")
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"git": git_spec, "tool": spec}),
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    arbitrary_ancestor = _commit(repository, "base")
    runner = repository / release_gate_contract.BOUND_HOST_TOOLCHAIN_RUNNER_PATH
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/usr/bin/env python3\nprint('runner')\n", encoding="utf-8")
    source_commit = _commit(repository, "source A")

    receipt = dict(
        bound_command.build_host_toolchain_receipt_candidate(
            repository_root=repository,
            source_commit=source_commit,
        )
    )
    expected_runner = str(receipt["runner_sha256"])
    assert expected_runner == bound_command.derive_candidate_runner_sha256(
        repository,
        source_commit=source_commit,
    )
    assert expected_runner == hashlib.sha256(runner.read_bytes()).hexdigest()

    receipt_path = repository / release_gate_contract.BOUND_HOST_TOOLCHAIN_RECEIPT_PATH
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_bytes(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )
    authority_commit = _commit(repository, "authority B")
    assert authority_commit != source_commit
    authority = bound_command.accepted_tool_authority_from_receipt(
        receipt,
        repository_root=repository,
        source_commit=source_commit,
    )
    result = bound_command.run_bound_command(
        cwd=repository,
        tool_id="tool",
        argv=("tool",),
        env={"LANG": "C"},
        stdout_limit=4096,
        stderr_limit=4096,
        timeout_s=5,
        accepted_authority=authority,
    )
    assert result.stdout == b"AUTHORITY-BOUND\n"
    assert (
        bound_command.derive_accepted_runner_sha256(
            repository,
            source_commit=source_commit,
            receipt=receipt,
        )
        == expected_runner
    )

    allowed = repository / "release/receipts/G2_COMPONENT_GATES.json"
    allowed.write_text("{}\n", encoding="utf-8")
    second_allowed = repository / "release/captures/npm-pack.json"
    second_allowed.parent.mkdir()
    second_allowed.write_text("{}\n", encoding="utf-8")
    release_commit = _commit(repository, "release-only C")
    assert release_commit != authority_commit
    assert (
        bound_command.derive_accepted_runner_sha256(
            repository,
            source_commit=source_commit,
            receipt=receipt,
        )
        == expected_runner
    )
    receipt_path.chmod(0o666)
    with pytest.raises(BoundCommandError, match="ownership or mode"):
        bound_command.derive_accepted_runner_sha256(
            repository,
            source_commit=source_commit,
            receipt=receipt,
        )
    receipt_path.chmod(0o644)
    with pytest.raises(BoundCommandError, match="lineage differs"):
        bound_command.derive_accepted_runner_sha256(
            repository,
            source_commit=arbitrary_ancestor,
            receipt=receipt,
        )

    source = repository / "shared/changed.py"
    source.parent.mkdir()
    source.write_text("CHANGED = True\n", encoding="utf-8")
    _commit(repository, "forbidden source descendant")
    with pytest.raises(BoundCommandError, match="changed source code"):
        bound_command.derive_accepted_runner_sha256(
            repository,
            source_commit=source_commit,
            receipt=receipt,
        )
    source.unlink()
    _commit(repository, "revert forbidden source descendant")
    with pytest.raises(BoundCommandError, match="changed source code"):
        bound_command.derive_accepted_runner_sha256(
            repository,
            source_commit=source_commit,
            receipt=receipt,
        )


def test_bound_git_ignores_repository_fsmonitor_configuration(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    runner = repository / release_gate_contract.BOUND_HOST_TOOLCHAIN_RUNNER_PATH
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/usr/bin/env python3\nprint('runner')\n", encoding="utf-8")
    source_commit = _commit(repository, "source A")
    marker = tmp_path / "fsmonitor-executed"
    hook = tmp_path / "fsmonitor-hook"
    hook.write_text(
        f"#!/bin/sh\ntouch {marker.as_posix()!r}\nprintf '2\\n'\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    _git(repository, "config", "core.fsmonitor", hook.as_posix())

    digest = bound_command.derive_candidate_runner_sha256(
        repository,
        source_commit=source_commit,
    )

    assert digest == hashlib.sha256(runner.read_bytes()).hexdigest()
    assert not marker.exists()


def test_bound_host_id_is_domain_separated_and_never_raw() -> None:
    host_id = bound_command.derive_bound_host_id()

    assert len(host_id) == 64
    assert set(host_id) <= set("0123456789abcdef")
    kind, raw = bound_command._host_identity_material()
    assert kind in {"darwin_ioplatformuuid", "linux_machine_id"}
    assert raw.decode("ascii").lower() not in host_id


def test_node_command_stages_package_tree_and_explicit_bound_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = tmp_path / "node"
    node.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'v22.12.0\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        'exec /bin/sh "$script" "$@"\n',
        encoding="utf-8",
    )
    node.chmod(0o755)
    package = tmp_path / "materialized/packages/verify"
    cli = package / "dist/cli.js"
    helper = package / "dist/helper.sh"
    cli.parent.mkdir(parents=True)
    cli.write_text(
        "#!/bin/sh\n"
        '. "$(dirname "$0")/helper.sh"\n'
        "printf '%s:' \"$HELPER_VALUE\"\n"
        'cat "$1"\n',
        encoding="utf-8",
    )
    helper.write_text("HELPER_VALUE=PACKAGE\n", encoding="utf-8")
    data = tmp_path / "repository/artifacts/registry.json"
    data.parent.mkdir(parents=True)
    data.write_text("BOUND-DATA\n", encoding="utf-8")
    spec = ToolSpec(
        tool_id="node",
        absolute_candidates=(node.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=False,
        launcher_tool_id=None,
        version_argv=("node", "--version"),
        exact_version="v22.12.0",
        script_policy="binary",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"node": spec}),
    )
    result = bound_command.run_bound_command(
        cwd=(tmp_path / "repository").resolve(),
        tool_id="node",
        argv=("node", cli.as_posix(), data.as_posix()),
        env={"LANG": "C"},
        stdout_limit=4096,
        stderr_limit=4096,
        timeout_s=5,
        command_asset_root=package,
        bound_data_inputs=(data,),
    )

    assert result.stdout == b"PACKAGE:BOUND-DATA\n"
    assert {row["kind"] for row in result.command_assets} == {
        "data",
        "node_package",
    }


def test_python_command_executes_from_private_bound_asset_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python = tmp_path / "python"
    python.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'Python 3.12.11\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        f'exec "{sys.executable}" "$script" "$@"\n',
        encoding="utf-8",
    )
    python.chmod(0o755)
    package = tmp_path / "materialized/verifier"
    package.mkdir(parents=True)
    entrypoint = package / "verify.py"
    helper = package / "helper.py"
    entrypoint.write_text(
        "from helper import VALUE\nprint(VALUE)\n",
        encoding="utf-8",
    )
    helper.write_text("VALUE = 'BOUND-PYTHON-TREE'\n", encoding="utf-8")
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"python": _tool_spec("python", python)}),
    )

    result = bound_command.run_bound_command(
        cwd=tmp_path,
        tool_id="python",
        argv=("python", entrypoint.as_posix()),
        env={"LANG": "C"},
        stdout_limit=4096,
        stderr_limit=4096,
        timeout_s=5,
        command_asset_root=package,
    )

    assert result.stdout == b"BOUND-PYTHON-TREE\n"
    assert result.command_assets[0]["kind"] == "python_package"


def test_python_command_asset_tree_rejects_mutation_symlink_and_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python = tmp_path / "python"
    python.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'Python 3.12.11\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        f'exec "{sys.executable}" "$script" "$@"\n',
        encoding="utf-8",
    )
    python.chmod(0o755)
    package = tmp_path / "materialized/verifier"
    package.mkdir(parents=True)
    entrypoint = package / "verify.py"
    helper = package / "helper.py"
    helper.write_text("VALUE = 'ORIGINAL'\n", encoding="utf-8")
    entrypoint.write_text(
        "from pathlib import Path\n"
        f"Path({helper.as_posix()!r}).write_text(\"VALUE = 'MUTATED'\\n\")\n"
        "from helper import VALUE\n"
        "print(VALUE)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"python": _tool_spec("python", python)}),
    )

    with pytest.raises(BoundCommandError, match="python package"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="python",
            argv=("python", entrypoint.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            command_asset_root=package,
        )

    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    linked_entrypoint = package / "linked.py"
    linked_entrypoint.symlink_to(outside)
    with pytest.raises(BoundCommandError, match="regular file|symlink"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="python",
            argv=("python", linked_entrypoint.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            command_asset_root=package,
        )

    with pytest.raises(BoundCommandError, match="escapes"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="python",
            argv=("python", outside.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            command_asset_root=package,
        )


def test_python_command_asset_tree_rejects_source_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python = tmp_path / "python"
    python.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'Python 3.12.11\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        f'exec "{sys.executable}" "$script" "$@"\n',
        encoding="utf-8",
    )
    python.chmod(0o755)
    package = tmp_path / "materialized/verifier"
    package.mkdir(parents=True)
    entrypoint = package / "verify.py"
    helper = package / "helper.py"
    displaced = package / "helper.original.py"
    helper.write_text("VALUE = 'ORIGINAL'\n", encoding="utf-8")
    entrypoint.write_text(
        "from pathlib import Path\n"
        f"source = Path({helper.as_posix()!r})\n"
        f"source.rename(Path({displaced.as_posix()!r}))\n"
        "source.write_text(\"VALUE = 'SUBSTITUTE'\\n\")\n"
        "from helper import VALUE\n"
        "print(VALUE)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"python": _tool_spec("python", python)}),
    )

    with pytest.raises(BoundCommandError, match="python package"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="python",
            argv=("python", entrypoint.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            command_asset_root=package,
        )


def test_node_package_and_data_sources_are_revalidated_after_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = tmp_path / "node"
    node.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'v22.12.0\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        'exec /bin/sh "$script" "$@"\n',
        encoding="utf-8",
    )
    node.chmod(0o755)
    package = tmp_path / "materialized/packages/verify"
    cli = package / "dist/cli.js"
    helper = package / "dist/helper.sh"
    cli.parent.mkdir(parents=True)
    data = tmp_path / "repository/artifacts/registry.json"
    data.parent.mkdir(parents=True)
    data.write_text("BOUND-DATA\n", encoding="utf-8")
    helper.write_text("HELPER_VALUE=PACKAGE\n", encoding="utf-8")
    cli.write_text(
        "#!/bin/sh\n"
        f"printf 'changed\\n' > '{helper.as_posix()}'\n"
        f"printf 'changed\\n' > '{data.as_posix()}'\n"
        '. "$(dirname "$0")/helper.sh"\n'
        "printf '%s:' \"$HELPER_VALUE\"\n"
        'cat "$1"\n',
        encoding="utf-8",
    )
    spec = ToolSpec(
        tool_id="node",
        absolute_candidates=(node.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=False,
        launcher_tool_id=None,
        version_argv=("node", "--version"),
        exact_version="v22.12.0",
        script_policy="binary",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"node": spec}),
    )
    with pytest.raises(BoundCommandError, match="node package|bound data"):
        bound_command.run_bound_command(
            cwd=(tmp_path / "repository").resolve(),
            tool_id="node",
            argv=("node", cli.as_posix(), data.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            command_asset_root=package,
            bound_data_inputs=(data,),
        )


def test_node_asset_root_preserves_clean_consumer_dependency_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = tmp_path / "node"
    node.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'v22.12.0\\n\'; exit; fi\n'
        'script="$1"; shift\n'
        'exec /bin/sh "$script" "$@"\n',
        encoding="utf-8",
    )
    node.chmod(0o755)
    consumer = tmp_path / "consumer"
    cli = consumer / "node_modules/@concordia-dao/verify/dist/cli.js"
    dependency = consumer / "node_modules/@noble/hashes/value.sh"
    cli.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    dependency.write_text("DEPENDENCY_VALUE=NOBLE\n", encoding="utf-8")
    cli.write_text(
        "#!/bin/sh\n"
        '. "$(dirname "$0")/../../../@noble/hashes/value.sh"\n'
        "printf '%s\\n' \"$DEPENDENCY_VALUE\"\n",
        encoding="utf-8",
    )
    spec = ToolSpec(
        tool_id="node",
        absolute_candidates=(node.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=False,
        launcher_tool_id=None,
        version_argv=("node", "--version"),
        exact_version="v22.12.0",
        script_policy="binary",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"node": spec}),
    )
    result = bound_command.run_bound_command(
        cwd=consumer,
        tool_id="node",
        argv=("node", cli.as_posix()),
        env={"LANG": "C"},
        stdout_limit=4096,
        stderr_limit=4096,
        timeout_s=5,
        command_asset_root=consumer,
    )

    assert result.stdout == b"NOBLE\n"
    assert result.command_assets[0]["kind"] == "node_package"
    assert result.command_assets[0]["file_count"] == 2


def test_node_package_rejects_unbound_or_escaping_entrypoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = tmp_path / "node"
    node.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'v22.12.0\\n\'; exit; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    node.chmod(0o755)
    package = tmp_path / "package"
    package.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("outside\n", encoding="utf-8")
    spec = ToolSpec(
        tool_id="node",
        absolute_candidates=(node.as_posix(),),
        use_sys_executable=False,
        manifest_required_when_mutable=False,
        launcher_tool_id=None,
        version_argv=("node", "--version"),
        exact_version="v22.12.0",
        script_policy="binary",
    )
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"node": spec}),
    )
    with pytest.raises(BoundCommandError, match="escapes"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="node",
            argv=("node", outside.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            command_asset_root=package,
        )

    inside = package / "cli.js"
    inside.write_text("inside\n", encoding="utf-8")
    with pytest.raises(BoundCommandError, match="package binding"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="node",
            argv=("node", inside.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
        )


def test_bound_data_requires_one_exact_nonsymlink_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "tool"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'tool 1.0\\n\'; exit; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    data = tmp_path / "data.json"
    data.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(data)
    spec = _tool_spec("tool", tool)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"tool": spec}),
    )
    with pytest.raises(BoundCommandError, match="one exact"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="tool",
            argv=("tool", "unbound"),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            bound_data_inputs=(data,),
        )

    with pytest.raises(BoundCommandError, match="regular file"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="tool",
            argv=("tool", linked.as_posix()),
            env={"LANG": "C"},
            stdout_limit=4096,
            stderr_limit=4096,
            timeout_s=5,
            bound_data_inputs=(linked,),
        )


def test_bound_command_returns_descriptor_bound_private_output_without_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "collector"
    secret = b'{"authorization":"do-not-print","rows":[1,2,3]}\n'
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'collector 1.0\\n\'; exit; fi\n'
        "printf '%s' '{\"authorization\":\"do-not-print\",\"rows\":[1,2,3]}'"
        ' > "$1"\n'
        "printf '\\n' >> \"$1\"\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"collector": _tool_spec("collector", tool)}),
    )

    result = bound_command.run_bound_command(
        cwd=tmp_path,
        tool_id="collector",
        argv=("collector", "raw-capture.json"),
        env={"LANG": "C"},
        stdout_limit=1024,
        stderr_limit=1024,
        timeout_s=5,
        private_output_specs=(
            PrivateOutputSpec(
                argument_index=1,
                name="raw-capture.json",
                size_limit=1024,
            ),
        ),
    )

    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
    assert len(result.private_outputs) == 1
    output = result.private_outputs[0]
    assert output.name == "raw-capture.json"
    assert output.raw == secret
    assert output.size == len(secret)
    assert output.sha256 == hashlib.sha256(secret).hexdigest()
    identity = json.dumps(dict(result.tool_identity), sort_keys=True)
    assets = json.dumps([dict(value) for value in result.command_assets], sort_keys=True)
    assert "do-not-print" not in identity
    assert "do-not-print" not in assets
    assert str(tmp_path) not in identity


@pytest.mark.parametrize(
    ("spec", "match"),
    (
        (
            PrivateOutputSpec(
                argument_index=0,
                name="raw.json",
                size_limit=1024,
            ),
            "argument",
        ),
        (
            PrivateOutputSpec(
                argument_index=1,
                name="../raw.json",
                size_limit=1024,
            ),
            "name",
        ),
        (
            PrivateOutputSpec(
                argument_index=1,
                name="raw.json",
                size_limit=0,
            ),
            "size",
        ),
    ),
)
def test_private_output_spec_is_exact_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spec: PrivateOutputSpec,
    match: str,
) -> None:
    tool = tmp_path / "collector"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'collector 1.0\\n\'; exit; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"collector": _tool_spec("collector", tool)}),
    )

    with pytest.raises(BoundCommandError, match=match):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="collector",
            argv=("collector", "raw.json"),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
            private_output_specs=(spec,),
        )


def test_private_output_requires_one_exact_declared_argument(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "collector"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'collector 1.0\\n\'; exit; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"collector": _tool_spec("collector", tool)}),
    )

    with pytest.raises(BoundCommandError, match="exact command argument"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="collector",
            argv=("collector", "different.json"),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
            private_output_specs=(
                PrivateOutputSpec(
                    argument_index=1,
                    name="raw.json",
                    size_limit=1024,
                ),
            ),
        )


@pytest.mark.parametrize("replacement", ("symlink", "regular"))
def test_private_output_rejects_path_substitution_after_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: str,
) -> None:
    tool = tmp_path / "collector"
    target = tmp_path / "outside"
    target.write_bytes(b"outside\n")
    replacement_command = (
        f"ln -s '{target.as_posix()}' \"$1\""
        if replacement == "symlink"
        else "printf 'replacement\\n' > \"$1\""
    )
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'collector 1.0\\n\'; exit; fi\n'
        "printf 'original\\n' > \"$1\"\n"
        "mv \"$1\" \"$1.saved\"\n"
        f"{replacement_command}\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"collector": _tool_spec("collector", tool)}),
    )

    with pytest.raises(BoundCommandError, match="private output.*(changed|substituted)"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="collector",
            argv=("collector", "raw.json"),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
            private_output_specs=(
                PrivateOutputSpec(
                    argument_index=1,
                    name="raw.json",
                    size_limit=1024,
                ),
            ),
        )


def test_private_output_refuses_oversized_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "collector"
    tool.write_text(
        "#!/bin/sh\n"
        'if [ "${1:-}" = "--version" ]; then printf \'collector 1.0\\n\'; exit; fi\n'
        "printf '123456789' > \"$1\"\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setattr(
        bound_command,
        "_TOOL_SPECS",
        MappingProxyType({"collector": _tool_spec("collector", tool)}),
    )

    with pytest.raises(BoundCommandError, match="private output is oversized"):
        bound_command.run_bound_command(
            cwd=tmp_path,
            tool_id="collector",
            argv=("collector", "raw.bin"),
            env={"LANG": "C"},
            stdout_limit=1024,
            stderr_limit=1024,
            timeout_s=5,
            private_output_specs=(
                PrivateOutputSpec(
                    argument_index=1,
                    name="raw.bin",
                    size_limit=8,
                ),
            ),
        )
