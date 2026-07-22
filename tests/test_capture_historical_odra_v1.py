from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.capture_historical_odra_v1 import (
    HistoricalCaptureError,
    capture_historical_odra_v1,
    write_capture_atomically,
)
from shared.historical_odra_artifact import verify_historical_odra_artifact
from tests.test_historical_odra_artifact import _fixture


NODE_A = "https://rpc-a.example/rpc"
NODE_B = "https://rpc-b.example/rpc"


class _FakeRpc:
    def __init__(self, raw_rpc: dict[str, object], *, corrupt_second: bool = False):
        self.endpoints = (NODE_A, NODE_B)
        self.calls: list[tuple[str, str, dict[str, object], object]] = []
        self._by_method = {}
        for item in raw_rpc.values():
            method = item["request"]["method"]
            discriminator = item["request"]["params"].get("key")
            self._by_method[(method, discriminator)] = item
        self._corrupt_second = corrupt_second

    def call(
        self,
        endpoint: str,
        method: str,
        params: dict[str, object],
        request_id: object,
        *,
        allow_submit: bool = False,
    ) -> dict[str, object]:
        assert allow_submit is False
        self.calls.append((endpoint, method, copy.deepcopy(params), request_id))
        transcript = self._by_method[(method, params.get("key"))]
        assert transcript["request"]["params"] == params
        response = copy.deepcopy(transcript["response"])
        response["id"] = request_id
        if self._corrupt_second and endpoint == NODE_B and method == "query_global_state":
            stored = response["result"]["value"]["stored_value"]
            contract = stored.get("Contract")
            if contract is not None:
                contract["contract_wasm_hash"] = "contract-wasm-" + "ff" * 32
        return response


def _proposal_payload(card_chain: dict[str, object]) -> dict[str, object]:
    cards = []
    for card in card_chain["cards"]:
        cards.append(
            {
                "proposal_id": card_chain["proposal_id"],
                "sequence_number": card["sequence_number"],
                "card_type": card["card_type"],
                "card_hash": card["card_hash"],
                "card_json": card["canonical_card_json"],
                "published_at": card["published_at"],
            }
        )
    terminal = cards[-1]
    later_json = json.dumps(
        {
            "card_type": "GovernanceSummary",
            "proposal_id": card_chain["proposal_id"],
            "previous_card_hash": terminal["card_hash"],
            "sequence_number": len(cards) + 1,
        },
        separators=(",", ":"),
    )
    cards.append(
        {
            "proposal_id": card_chain["proposal_id"],
            "sequence_number": len(cards) + 1,
            "card_type": "GovernanceSummary",
            "card_hash": hashlib.sha256(later_json.encode()).hexdigest(),
            "card_json": later_json,
            "published_at": "2026-07-23T03:00:01Z",
        }
    )
    return {
        "proposal": {
            "proposal_id": card_chain["proposal_id"],
            "state": "RESOLVED",
        },
        "cards": cards,
        "card_count": len(cards),
    }


def test_capture_uses_two_read_only_nodes_and_receipt_selected_card_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, inventory_bytes, _, _ = _fixture(monkeypatch)
    rpc = _FakeRpc(fixture["raw_rpc"])

    artifact = capture_historical_odra_v1(
        proposal_payload=_proposal_payload(fixture["card_chain"]),
        rpc=rpc,
        captured_at=fixture["captured_at"],
        source_commit=fixture["source_commit"],
        deployment_commit=fixture["deployment_commit"],
        public_base_url="https://concordia.example",
        inventory_bytes=inventory_bytes,
    )

    facts = verify_historical_odra_artifact(
        json.dumps(artifact, separators=(",", ":")),
        inventory_bytes=inventory_bytes,
    )
    assert facts["deployHash"] == fixture["raw_rpc"]["deploy"]["request"]["params"]["deploy_hash"]
    assert len(artifact["card_chain"]["cards"]) == 2
    assert artifact["card_chain"]["cards"][-1]["card_hash"] == facts["finalCardHash"]
    assert len(rpc.calls) == 10
    assert {endpoint for endpoint, *_ in rpc.calls} == {NODE_A, NODE_B}
    assert {method for _, method, *_ in rpc.calls} == {
        "info_get_deploy",
        "chain_get_block",
        "chain_get_state_root_hash",
        "query_global_state",
    }


def test_capture_fails_closed_when_second_public_node_disagrees(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, inventory_bytes, _, _ = _fixture(monkeypatch)

    with pytest.raises(HistoricalCaptureError, match="second public RPC|disagree|invalid"):
        capture_historical_odra_v1(
            proposal_payload=_proposal_payload(fixture["card_chain"]),
            rpc=_FakeRpc(fixture["raw_rpc"], corrupt_second=True),
            captured_at=fixture["captured_at"],
            source_commit=fixture["source_commit"],
            deployment_commit=fixture["deployment_commit"],
            public_base_url="https://concordia.example",
            inventory_bytes=inventory_bytes,
        )


def test_capture_rejects_truncated_or_rewritten_public_card_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, inventory_bytes, _, _ = _fixture(monkeypatch)
    payload = _proposal_payload(fixture["card_chain"])
    payload["cards"][0]["card_json"] += " "

    with pytest.raises(HistoricalCaptureError, match="card"):
        capture_historical_odra_v1(
            proposal_payload=payload,
            rpc=_FakeRpc(fixture["raw_rpc"]),
            captured_at=fixture["captured_at"],
            source_commit=fixture["source_commit"],
            deployment_commit=fixture["deployment_commit"],
            public_base_url="https://concordia.example",
            inventory_bytes=inventory_bytes,
        )


def test_capture_output_is_new_atomic_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "historical.json"
    write_capture_atomically(target, b'{"schema_version":"test"}\n')
    assert target.read_bytes() == b'{"schema_version":"test"}\n'

    with pytest.raises(HistoricalCaptureError, match="already exists"):
        write_capture_atomically(target, b"replacement")

    outside = tmp_path / "outside.json"
    outside.write_bytes(b"untouched")
    link = tmp_path / "link.json"
    link.symlink_to(outside)
    with pytest.raises(HistoricalCaptureError, match="already exists|regular"):
        write_capture_atomically(link, b"replacement")
    assert outside.read_bytes() == b"untouched"
