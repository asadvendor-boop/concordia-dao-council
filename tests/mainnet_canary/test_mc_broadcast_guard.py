"""No code path can broadcast: guard-surface tests for the disabled lane."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import mc_support

import tools.mainnet_canary.broadcast as broadcast_module
from mc_support import build_valid_plan, write_json
from tools.mainnet_canary.broadcast import run_broadcast_guard
from tools.mainnet_canary.cli import build_parser
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.stage import run_stage


def _staged(plan_inputs: dict[str, Path], tmp_path: Path) -> dict[str, object]:
    plan = build_valid_plan(plan_inputs)
    run_stage(
        plan_inputs["repo"],
        plan_document=plan,
        rc_declaration_path=plan_inputs["rc"],
        snapshot_path=plan_inputs["snapshot"],
        status_path=plan_inputs["status"],
        ceiling_path=plan_inputs["ceiling"],
        measured_costs_path=plan_inputs["measured"],
        journal_path=tmp_path / "journal.jsonl",
        output_dir=tmp_path / "staged",
        **mc_support.stage_gate_kwargs(plan_inputs, tmp_path),
    )
    return plan


def _guard(
    plan_inputs: dict[str, Path],
    plan: dict[str, object],
    tmp_path: Path,
) -> dict[str, object]:
    return run_broadcast_guard(
        plan_inputs["repo"],
        plan_document=plan,
        journal_path=tmp_path / "journal.jsonl",
        ceiling_path=plan_inputs["ceiling"],
        measured_costs_path=plan_inputs["measured"],
    )


def test_broadcast_refuses_with_stable_code_when_authorization_absent(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    """THE preparation-lane refusal: the Codex live authorization mount does
    not exist, so broadcasting is disabled with a stable code."""

    plan = _staged(plan_inputs, tmp_path)
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == (
        RefusalCode.BROADCAST_DISABLED_AUTHORIZATION_ABSENT
    )


def test_environment_variables_cannot_bypass_the_guard(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    plan = _staged(plan_inputs, tmp_path)
    for name in (
        "CONCORDIA_CANARY_YES",
        "CONCORDIA_CANARY_FORCE",
        "CANARY_DEV_BYPASS",
        "CI",
    ):
        monkeypatch.setenv(name, "1")
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == (
        RefusalCode.BROADCAST_DISABLED_AUTHORIZATION_ABSENT
    )


def test_broadcast_parser_has_no_bypass_flags() -> None:
    parser = build_parser()
    for forbidden in (
        ["broadcast", "--plan", "p", "--journal", "j", "--yes"],
        ["broadcast", "--plan", "p", "--journal", "j", "--force"],
        ["broadcast", "--plan", "p", "--journal", "j", "--authorization-file", "x"],
        ["broadcast", "--plan", "p", "--journal", "j", "--no-confirm"],
    ):
        with pytest.raises(SystemExit):
            parser.parse_args(forbidden)


def test_broadcast_requires_journal_before_authorization(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.JOURNAL_ABSENT


def _authorization_for(plan: dict[str, object]) -> dict[str, object]:
    return {
        "schema_id": "concordia.mainnet-canary.live-authorization.v1",
        "issued_by": "codex-integration-operator",
        "rc_tag": plan["rc"]["tag"],
        "plan_hash": plan["canary_plan_sha256"],
        "max_total_motes": "1000000000000",
        "per_step_confirmation_required": True,
        "expires_at_unix": 2_000_000_000,
    }


def test_even_a_crafted_authorization_cannot_reach_submission_without_tty(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    """With a file at the (patched) mount and every earlier gate satisfied,
    a non-interactive session still refuses at the confirmation gate."""

    plan = _staged(plan_inputs, tmp_path)
    authorization = write_json(
        tmp_path / "live-authorization.json", _authorization_for(plan)
    )
    monkeypatch.setattr(
        broadcast_module, "LIVE_AUTHORIZATION_MOUNT_PATH", str(authorization)
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.CONFIRMATION_REQUIRED


class _FakeTty(io.StringIO):
    def isatty(self) -> bool:  # pragma: no cover - trivial
        return True


def test_submission_is_not_implemented_even_after_every_confirmation(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch, capsys
) -> None:
    """The terminal gate: full confirmations still cannot broadcast."""

    plan = _staged(plan_inputs, tmp_path)
    authorization = write_json(
        tmp_path / "live-authorization.json", _authorization_for(plan)
    )
    monkeypatch.setattr(
        broadcast_module, "LIVE_AUTHORIZATION_MOUNT_PATH", str(authorization)
    )
    economic_ids = [
        str(step["step_id"]) for step in plan["steps"] if step["economic"]
    ]
    monkeypatch.setattr("sys.stdin", _FakeTty("\n".join(economic_ids) + "\n"))
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.SUBMISSION_NOT_IMPLEMENTED_IN_PREP
    capsys.readouterr()


def test_authorization_with_wrong_plan_hash_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    plan = _staged(plan_inputs, tmp_path)
    document = _authorization_for(plan)
    document["plan_hash"] = "0" * 64
    authorization = write_json(tmp_path / "live-authorization.json", document)
    monkeypatch.setattr(
        broadcast_module, "LIVE_AUTHORIZATION_MOUNT_PATH", str(authorization)
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.AUTHORIZATION_INVALID


def test_authorization_waiving_confirmation_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    plan = _staged(plan_inputs, tmp_path)
    document = _authorization_for(plan)
    document["per_step_confirmation_required"] = False
    authorization = write_json(tmp_path / "live-authorization.json", document)
    monkeypatch.setattr(
        broadcast_module, "LIVE_AUTHORIZATION_MOUNT_PATH", str(authorization)
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.AUTHORIZATION_INVALID


def test_authorization_ceiling_below_estimate_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    plan = _staged(plan_inputs, tmp_path)
    document = _authorization_for(plan)
    document["max_total_motes"] = "1"
    authorization = write_json(tmp_path / "live-authorization.json", document)
    monkeypatch.setattr(
        broadcast_module, "LIVE_AUTHORIZATION_MOUNT_PATH", str(authorization)
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.COST_CEILING_EXCEEDED


def test_in_flight_journal_blocks_broadcast_before_confirmation(
    plan_inputs: dict[str, Path], tmp_path: Path, monkeypatch
) -> None:
    from tools.mainnet_canary.journal import CanaryJournal

    plan = _staged(plan_inputs, tmp_path)
    journal = CanaryJournal.load(tmp_path / "journal.jsonl")
    plan_hash = str(plan["canary_plan_sha256"])
    journal.transition(
        "B-install-rc-wasm", "AUTHORIZATION_VALIDATED", plan_hash=plan_hash
    )
    journal.transition(
        "B-install-rc-wasm",
        "SIGNED",
        plan_hash=plan_hash,
        deploy_hash="d0" * 32,
        signed_bytes_sha256="b1" * 32,
    )
    journal.close()
    authorization = write_json(
        tmp_path / "live-authorization.json", _authorization_for(plan)
    )
    monkeypatch.setattr(
        broadcast_module, "LIVE_AUTHORIZATION_MOUNT_PATH", str(authorization)
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _guard(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.RECONCILIATION_REQUIRED


def test_module_has_no_submission_capability() -> None:
    """Static assertion: the package never imports a signing/submission
    surface (pycspr factories, sockets, or subprocess casper clients)."""

    import tools.mainnet_canary as package

    package_dir = Path(package.__file__).resolve().parent
    forbidden_tokens = (
        "create_deploy",
        "put_deploy",
        "account_put_deploy",
        "sign(",
        "PrivateKey",
        "ed25519.SigningKey",
    )
    for source_file in sorted(package_dir.glob("*.py")):
        text = source_file.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in text, f"{source_file.name} contains {token}"


def test_json_source_has_no_authorization_header_usage() -> None:
    import tools.mainnet_canary as package

    package_dir = Path(package.__file__).resolve().parent
    for source_file in sorted(package_dir.glob("*.py")):
        text = source_file.read_text(encoding="utf-8")
        assert 'headers={"Authorization"' not in text
        assert "'Authorization':" not in text


def test_cli_broadcast_mode_refuses_end_to_end(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    from tools.mainnet_canary.cli import main

    plan = _staged(plan_inputs, tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    exit_code = main(
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "broadcast",
            "--plan",
            str(plan_path),
            "--journal",
            str(tmp_path / "journal.jsonl"),
            "--ceiling",
            str(plan_inputs["ceiling"]),
            "--measured-costs",
            str(plan_inputs["measured"]),
        ]
    )
    assert exit_code == 2
    output = json.loads(capsys.readouterr().out)
    assert output["refusal"]["code"] == (
        RefusalCode.BROADCAST_DISABLED_AUTHORIZATION_ABSENT
    )
