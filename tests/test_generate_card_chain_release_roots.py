from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.generate_card_chain_release_roots import (
    ReleaseRootsError,
    derive_card_chain_release_roots,
    verify_existing_release_roots,
    write_release_roots_once,
)
from tests.test_historical_odra_artifact import _fixture


def test_release_root_is_derived_only_from_verified_historical_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    payload = derive_card_chain_release_roots(
        json.dumps(artifact, separators=(",", ":")).encode(),
        inventory_bytes=inventory_bytes,
    )

    assert json.loads(payload) == {
        "schema_version": "concordia.card_chain_roots.v1",
        "roots": {
            artifact["proposal_id"]: artifact["card_chain"]["cards"][-1]["card_hash"]
        },
    }


def test_release_root_derivation_rejects_self_asserted_intermediate_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    forged = copy.deepcopy(artifact)
    forged["card_chain"]["cards"].pop()

    with pytest.raises(ReleaseRootsError, match="historical artifact"):
        derive_card_chain_release_roots(
            json.dumps(forged, separators=(",", ":")).encode(),
            inventory_bytes=inventory_bytes,
        )


def test_release_root_file_is_create_once_or_exactly_equal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    payload = derive_card_chain_release_roots(
        json.dumps(artifact, separators=(",", ":")).encode(),
        inventory_bytes=inventory_bytes,
    )
    target = tmp_path / "card-chain-roots-v1.json"
    write_release_roots_once(target, payload)
    verify_existing_release_roots(target, payload)

    wrong = (
        json.dumps(
            {
                "schema_version": "concordia.card_chain_roots.v1",
                "roots": {artifact["proposal_id"]: "ff" * 32},
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    target.unlink()
    target.write_bytes(wrong)
    with pytest.raises(ReleaseRootsError, match="does not equal"):
        verify_existing_release_roots(target, payload)
    with pytest.raises(ReleaseRootsError, match="already exists"):
        write_release_roots_once(target, payload)
