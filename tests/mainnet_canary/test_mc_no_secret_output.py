"""Secrets must never appear in stdout, stderr, exceptions, or outputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mc_support import build_valid_plan, make_key_inventory, write_json
from tools.mainnet_canary.cli import main
from tools.mainnet_canary.errors import CanaryRefusal
from tools.mainnet_canary.keys import load_key_inventory
from tools.mainnet_canary.secret_guard import scan_for_secret_material
from tools.mainnet_canary.stage import run_stage

FAKE_PEM = "-----BEGIN PRIVATE KEY-----\nMIIfaketestbytesnotarealkey0000\n-----END PRIVATE KEY-----"


def test_hostile_inventory_is_never_echoed_anywhere(
    tmp_path: Path, capsys
) -> None:
    document = make_key_inventory()
    document["roles"]["proposer"]["public_key_hex"] = FAKE_PEM
    path = write_json(tmp_path / "inventory.json", document)
    with pytest.raises(CanaryRefusal) as refusal:
        load_key_inventory(path)
    combined = capsys.readouterr()
    for stream in (combined.out, combined.err, str(refusal.value)):
        assert "BEGIN PRIVATE KEY" not in stream
        assert "MIIfake" not in stream


def test_cli_refusal_output_never_contains_hostile_content(
    tmp_path: Path, capsys
) -> None:
    document = make_key_inventory()
    document["roles"]["proposer"]["public_key_hex"] = FAKE_PEM
    inventory = write_json(tmp_path / "inventory.json", document)
    exit_code = main(
        [
            "inventory",
            "--key-inventory",
            str(inventory),
            "--rc-declaration",
            str(tmp_path / "absent-rc.json"),
        ]
    )
    assert exit_code == 2
    output = capsys.readouterr()
    assert "BEGIN PRIVATE KEY" not in output.out
    assert "BEGIN PRIVATE KEY" not in output.err
    refusal = json.loads(output.out)["refusal"]
    assert refusal["code"] == "KEY_INVENTORY_SECRET_MATERIAL"


def test_all_lane_outputs_are_secret_free_after_full_stage(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    """Scan every byte the tooling writes (journal, staged intents, plan)."""

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
    )
    written: list[Path] = [tmp_path / "journal.jsonl"]
    written.extend(sorted((tmp_path / "staged").glob("*")))
    plan_text = json.dumps(plan, sort_keys=True)
    assert not scan_for_secret_material(plan_text)
    for path in written:
        text = path.read_text(encoding="utf-8", errors="replace")
        assert not scan_for_secret_material(text), f"secret-like content in {path}"


def test_fixtures_and_package_sources_are_secret_free() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    scan_roots = (
        repo_root / "tools" / "mainnet_canary",
        repo_root / "tests" / "mainnet_canary" / "fixtures",
    )
    for root in scan_roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in (".py", ".json", ".md"):
                continue
            if path.name == "secret_guard.py":
                # The guard module defines the detection patterns and
                # therefore legitimately contains the pattern text.
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = scan_for_secret_material(text)
            assert not matches, f"{path} matched {matches}"


def test_key_inventory_never_contains_balance_or_secret_reads(
    plan_inputs: dict[str, Path],
) -> None:
    inventory = load_key_inventory(plan_inputs["inventory"])
    for role in inventory.roles.values():
        assert role.key_file_mount_path.startswith("/run/secrets/mainnet_canary/")
        # The reference is a string only; the path was never opened, and it
        # does not exist on this machine.
        assert not Path(role.key_file_mount_path).exists()
