"""Pinned-transport acceptance tests for v3 checkpoint/readback capture."""

from __future__ import annotations

import ast
import copy
import socket
from pathlib import Path

import httpx
import pytest

import scripts.read_v3_state as readback
from scripts.read_v3_state import (
    ReadbackValidationError,
    capture_v3_checkpoint_state,
    capture_v3_state,
    verify_and_seal_readback_artifact,
)
from tests.test_clvalue_roundtrip import _readback_fixture


NODE_A = "https://rpc-a.example/rpc"
NODE_B = "https://rpc-b.example/rpc"


class FakePinnedReadbackRpc:
    endpoints = (NODE_A, NODE_B)

    def __init__(self) -> None:
        self.transcripts, self.ids = _readback_fixture()
        self.calls: list[tuple[str, str, object, bool]] = []

    def call(
        self,
        endpoint: str,
        method: str,
        params: dict[str, object],
        request_id: object,
        *,
        allow_submit: bool = False,
    ) -> dict[str, object]:
        self.calls.append((endpoint, method, request_id, allow_submit))
        if allow_submit:
            raise AssertionError("readback capture may never acquire submit authority")
        for transcript in self.transcripts:
            if transcript["method"] == method and transcript["params"] == params:
                response = copy.deepcopy(transcript["response"])
                response["id"] = request_id
                return response
        if method == "chain_get_block" and params == {}:
            response = copy.deepcopy(self.transcripts[0]["response"])
            response["id"] = request_id
            return response
        raise AssertionError(f"unexpected readback RPC call: {method}")


def _disable_fresh_network_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda *args, **kwargs: pytest.fail("capture must not create httpx.Client"),
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("capture must not re-resolve DNS"),
    )


def test_full_readback_uses_only_injected_pinned_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_fresh_network_clients(monkeypatch)
    rpc = FakePinnedReadbackRpc()

    artifact = capture_v3_state(
        rpc_transport=rpc,
        rpc_url=NODE_A,
        package_hash=rpc.ids["package"],
        contract_hash=rpc.ids["contract"],
        proposal_id=rpc.ids["proposal"],
        action_id=rpc.ids["action"],
        block_hash=rpc.ids["block"],
    )

    verified = verify_and_seal_readback_artifact(artifact)
    assert verified.observed_block_hash.hex() == rpc.ids["block"]
    assert {endpoint for endpoint, _, _, _ in rpc.calls} == {NODE_A}
    assert all(allow_submit is False for _, _, _, allow_submit in rpc.calls)


def test_deployed_odra_storage_layout_maps_every_field_exactly() -> None:
    assert readback.ODRA_STORAGE_LAYOUT == (
        ("owner", 1),
        ("schema_version", 2),
        ("deployment_domain", 3),
        ("casper_chain_name", 4),
        ("proposer", 5),
        ("finalizer", 6),
        ("signer_a", 7),
        ("signer_b", 8),
        ("signer_c", 9),
        ("threshold", 10),
        ("signers", 11),
        ("proposed_envelope", 12),
        ("approval_count", 13),
        ("approvals", 14),
        ("finalized", 15),
        ("finalized_envelope", 16),
        ("action_authorized", 17),
    )


def test_full_readback_uses_current_contract_named_key_request_shape() -> None:
    rpc = FakePinnedReadbackRpc()
    artifact = capture_v3_state(
        rpc_transport=rpc,
        rpc_url=NODE_A,
        package_hash=rpc.ids["package"],
        contract_hash=rpc.ids["contract"],
        proposal_id=rpc.ids["proposal"],
        action_id=rpc.ids["action"],
        block_hash=rpc.ids["block"],
    )

    dictionary_calls = [
        item
        for item in artifact["transcripts"]
        if item["method"] == "state_get_dictionary_item"
    ]
    assert len(dictionary_calls) == 15
    for item in dictionary_calls:
        params = item["params"]
        assert set(params) == {"state_root_hash", "dictionary_identifier"}
        identifier = params["dictionary_identifier"]
        assert set(identifier) == {"ContractNamedKey"}
        named_key = identifier["ContractNamedKey"]
        assert set(named_key) == {
            "key",
            "dictionary_name",
            "dictionary_item_key",
        }
        assert named_key["key"] == "hash-" + rpc.ids["contract"]
        assert named_key["dictionary_name"] == "state"
        assert len(named_key["dictionary_item_key"]) == 64


def test_full_readback_decodes_every_deployed_field_and_two_nodes_agree() -> None:
    rpc = FakePinnedReadbackRpc()
    artifacts = [
        capture_v3_state(
            rpc_transport=rpc,
            rpc_url=endpoint,
            package_hash=rpc.ids["package"],
            contract_hash=rpc.ids["contract"],
            proposal_id=rpc.ids["proposal"],
            action_id=rpc.ids["action"],
            block_hash=rpc.ids["block"],
        )
        for endpoint in (NODE_A, NODE_B)
    ]
    facts = [verify_and_seal_readback_artifact(item) for item in artifacts]

    assert facts[0].owner.hex() == "06" * 32
    assert facts[0].schema_version == 3
    assert facts[0].deployment_domain.hex() == rpc.ids["domain"]
    assert facts[0].casper_chain_name == "casper-test"
    assert facts[0].proposer.hex() == "01" * 32
    assert facts[0].finalizer.hex() == "02" * 32
    assert [item.hex() for item in facts[0].signers] == [
        "03" * 32,
        "04" * 32,
        "05" * 32,
    ]
    assert facts[0].threshold == 2
    assert facts[0].proposal_id == rpc.ids["proposal"]
    assert facts[0].proposed_envelope.hex() == rpc.ids["envelope"]
    assert facts[0].approval_count == 2
    assert facts[0].finalized is True
    assert facts[0].finalized_envelope.hex() == rpc.ids["envelope"]
    assert facts[0].action_id.hex() == rpc.ids["action"]
    assert facts[0].action_authorized is True
    assert facts[0].observed_block_hash == facts[1].observed_block_hash
    assert facts[0].observed_block_height == facts[1].observed_block_height
    assert facts[0].observed_state_root_hash == facts[1].observed_state_root_hash
    assert facts[0].persisted_artifact()["facts"] == facts[1].persisted_artifact()[
        "facts"
    ]


def test_checkpoint_capture_reuses_same_transport_for_latest_and_pinned_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_fresh_network_clients(monkeypatch)
    rpc = FakePinnedReadbackRpc()

    artifact = capture_v3_checkpoint_state(
        rpc_transport=rpc,
        rpc_url=NODE_A,
        package_hash=rpc.ids["package"],
        contract_hash=rpc.ids["contract"],
        proposal_id=rpc.ids["proposal"],
        action_id=rpc.ids["action"],
        completed_steps=[],
    )

    assert artifact["facts"]["observed_block_hash"] == rpc.ids["block"]
    assert [method for _, method, _, _ in rpc.calls] == [
        "chain_get_block",
        "chain_get_block",
        "query_global_state",
    ]
    assert all(allow_submit is False for _, _, _, allow_submit in rpc.calls)


def test_readback_rejects_endpoint_outside_injected_transport() -> None:
    rpc = FakePinnedReadbackRpc()
    with pytest.raises(ReadbackValidationError, match="pinned transport"):
        capture_v3_state(
            rpc_transport=rpc,
            rpc_url="https://rpc-c.example/rpc",
            package_hash=rpc.ids["package"],
            contract_hash=rpc.ids["contract"],
            proposal_id=rpc.ids["proposal"],
            action_id=rpc.ids["action"],
            block_hash=rpc.ids["block"],
        )


def test_live_runner_threads_one_transport_into_both_readback_call_sites() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "scripts/run_v3_live_proof.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls: dict[str, list[ast.Call]] = {
        "capture_v3_checkpoint_state": [],
        "capture_v3_state": [],
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in calls:
                calls[node.func.id].append(node)
    assert all(len(items) == 1 for items in calls.values())
    for items in calls.values():
        keywords = {item.arg: item.value for item in items[0].keywords}
        assert isinstance(keywords["rpc_transport"], ast.Name)
        assert keywords["rpc_transport"].id == "rpc_transport"
        assert isinstance(keywords["rpc_url"], ast.Attribute)
        assert keywords["rpc_url"].attr == "rpc_url"
