from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from shared import release_manifest
from shared.bound_command import BoundCommandResult
from shared.release_manifest import ReleaseManifestError


ROOT = Path(__file__).parents[1]


def test_g12_and_g13_have_distinct_immutable_rendered_link_receipts() -> None:
    assert release_manifest.ORGANIZER_LINK_REQUEST_PATH == (
        "handoff/ORGANIZER_LINK_GATE_REQUEST.json"
    )
    assert release_manifest.ORGANIZER_LINK_CORE_PATH == (
        "scripts/organizer-link-gate-core.mjs"
    )
    assert release_manifest.ORGANIZER_LINK_RUNNER_PATH == (
        "scripts/run_organizer_link_gate.mjs"
    )
    assert release_manifest.ORGANIZER_LINK_VERIFIER_PATH == (
        "scripts/verify_organizer_link_audit.mjs"
    )
    assert release_manifest.ORGANIZER_G12_AUDIT_PATH == (
        "release/organizer/G12_RENDERED_LINK_AUDIT.json"
    )
    assert release_manifest.ORGANIZER_G13_AUDIT_PATH == (
        "release/g13/ORGANIZER_RENDERED_LINK_AUDIT.json"
    )
    assert release_manifest.ORGANIZER_G12_INVOCATION_PATH == (
        "release/organizer/G12_RENDERED_LINK_INVOCATION.json"
    )
    assert release_manifest.ORGANIZER_G13_INVOCATION_PATH == (
        "release/g13/ORGANIZER_RENDERED_LINK_INVOCATION.json"
    )


def test_fixture_output_is_explicitly_non_qualifying_for_release_binding() -> None:
    fixture = json.loads(
        (
            ROOT / "tests/fixtures/organizer-link-gate-pass.json"
        ).read_text()
    )
    document = {
        "schema_version": "concordia.organizer_rendered_link_audit.v2",
        "verdict": "NON_QUALIFYING",
        "release_qualified": False,
        "collection_mode": "fixture",
        "started_at": fixture["started_at"],
        "captured_at": fixture["captured_at"],
        "request_sha256": "11" * 32,
        "runtime": fixture["runtime"],
        "inventory": {
            "dashboard_route_ids": [],
            "proof_tab_ids": [],
            "known_link_ids": [],
        },
        "summary": {},
        "dashboard_routes": [],
        "proof_tabs": [],
        "links": [],
    }
    with pytest.raises(
        ReleaseManifestError,
        match="live-incognito|qualifying|collection",
    ):
        release_manifest._validate_organizer_link_audit_document(
            document,
            phase="G12",
        )


def test_release_manifest_source_names_both_authoritative_bindings() -> None:
    source = Path(release_manifest.__file__).read_text()
    assert '"organizer_rendered_link_audit"' in source
    assert "ORGANIZER_G12_AUDIT_PATH" in source
    assert "ORGANIZER_G13_AUDIT_PATH" in source
    assert "only a live-incognito PASS" in source


def test_default_verifier_executes_from_a_closed_command_asset_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = b"{}\n"
    audit = release_manifest._BoundFile(
        path="release/organizer/example.json",
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        artifact_commit="a" * 40,
        fingerprint=(1, 2, len(raw), 3),
    )
    materialized: dict[str, Path] = {}

    def materialize(_root: Path, target: Path) -> Path:
        materialized["root"] = target
        entrypoint = target / "scripts/verify_organizer_link_audit.mjs"
        entrypoint.parent.mkdir(parents=True)
        entrypoint.write_text("// closed verifier\n")
        return entrypoint

    observed: dict[str, object] = {}

    def run(
        root: Path,
        argv: list[str],
        **kwargs: object,
    ) -> BoundCommandResult:
        observed.update({"root": root, "argv": argv, **kwargs})
        projection = {
            "schema_version": release_manifest.ORGANIZER_LINK_AUDIT_SCHEMA_VERSION,
            "verdict": "PASS",
            "release_qualified": True,
            "collection_mode": "live_incognito",
            "audit_sha256": audit.sha256,
        }
        return BoundCommandResult(
            returncode=0,
            stdout=release_manifest._canonical_json(projection),
            stderr=b"",
            tool_identity={},
            command_assets=(),
        )

    monkeypatch.setattr(
        release_manifest,
        "_materialize_organizer_verifier_package",
        materialize,
    )
    monkeypatch.setattr(release_manifest, "_run", run)

    assert release_manifest._default_organizer_link_audit_verifier(
        tmp_path,
        audit,
    )["audit_sha256"] == audit.sha256
    assert observed["command_asset_root"] == materialized["root"]
    assert observed["bound_data_inputs"] == (tmp_path / audit.path,)
    assert "--fixture" not in observed["argv"]


def test_invocation_receipt_rejects_fixture_or_unbound_stdout() -> None:
    sources = [
        {"path": release_manifest.ORGANIZER_LINK_CORE_PATH, "sha256": "1" * 64},
        {"path": release_manifest.ORGANIZER_LINK_RUNNER_PATH, "sha256": "2" * 64},
    ]
    audit_sha256 = "3" * 64
    request_sha256 = "4" * 64
    receipt = {
        "schema_version": (
            release_manifest.ORGANIZER_LINK_INVOCATION_SCHEMA_VERSION
        ),
        "phase": "G12",
        "status": "passed",
        "collection_mode": "live_incognito",
        "started_at": "2026-07-24T00:00:00Z",
        "ended_at": "2026-07-24T00:02:00Z",
        "command": {
            "argv": [
                "node",
                release_manifest.ORGANIZER_LINK_RUNNER_PATH,
                "--input",
                release_manifest.ORGANIZER_LINK_REQUEST_PATH,
            ],
            "exit_code": 0,
            "fixture_argument_present": False,
            "stdout_sha256": audit_sha256,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "tool_identity_sha256": "5" * 64,
            "command_assets_sha256": "6" * 64,
        },
        "request": {
            "path": release_manifest.ORGANIZER_LINK_REQUEST_PATH,
            "sha256": request_sha256,
        },
        "source_bindings": sources,
        "host_toolchain": {
            "path": "release/receipts/HOST_TOOLCHAIN.json",
            "sha256": "8" * 64,
            "artifact_commit": "9" * 40,
        },
        "audit": {
            "path": release_manifest.ORGANIZER_G12_AUDIT_PATH,
            "sha256": audit_sha256,
        },
    }
    release_manifest._validate_organizer_link_invocation_document(
        receipt,
        phase="G12",
        audit_path=release_manifest.ORGANIZER_G12_AUDIT_PATH,
        audit_sha256=audit_sha256,
        audit_started_at="2026-07-24T00:00:30Z",
        audit_captured_at="2026-07-24T00:01:30Z",
        request_sha256=request_sha256,
        source_bindings=sources,
        host_toolchain=receipt["host_toolchain"],
    )

    fixture = json.loads(json.dumps(receipt))
    fixture["command"]["argv"].extend(
        ["--fixture", "tests/fixtures/organizer-link-gate-pass.json"]
    )
    fixture["command"]["fixture_argument_present"] = True
    with pytest.raises(ReleaseManifestError, match="no-fixture|fixture"):
        release_manifest._validate_organizer_link_invocation_document(
            fixture,
            phase="G12",
            audit_path=release_manifest.ORGANIZER_G12_AUDIT_PATH,
            audit_sha256=audit_sha256,
            audit_started_at="2026-07-24T00:00:30Z",
            audit_captured_at="2026-07-24T00:01:30Z",
            request_sha256=request_sha256,
            source_bindings=sources,
            host_toolchain=receipt["host_toolchain"],
        )

    unbound = json.loads(json.dumps(receipt))
    unbound["command"]["stdout_sha256"] = "7" * 64
    with pytest.raises(ReleaseManifestError, match="stdout|audit"):
        release_manifest._validate_organizer_link_invocation_document(
            unbound,
            phase="G12",
            audit_path=release_manifest.ORGANIZER_G12_AUDIT_PATH,
            audit_sha256=audit_sha256,
            audit_started_at="2026-07-24T00:00:30Z",
            audit_captured_at="2026-07-24T00:01:30Z",
            request_sha256=request_sha256,
            source_bindings=sources,
            host_toolchain=receipt["host_toolchain"],
        )
