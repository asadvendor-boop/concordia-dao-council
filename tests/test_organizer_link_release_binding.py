from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared import release_manifest
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
