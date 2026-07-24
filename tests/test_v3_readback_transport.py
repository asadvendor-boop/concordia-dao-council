"""Pinned-transport acceptance tests for v3 checkpoint/readback capture."""

from __future__ import annotations

import ast
import copy
import socket
from pathlib import Path

import httpx
import pytest

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
