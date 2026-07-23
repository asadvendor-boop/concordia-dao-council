"""Failure-first tests for the NativeTransferV1 production input builder."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from scripts.prepare_v3_envelope import prepare_v3_envelope
from shared.native_transfer_input_v3 import (
    EXACT_APPROVED_ALLOCATION_BPS,
    EXACT_REQUESTED_ALLOCATION_BPS,
    EXACT_TRANSFER_MOTES,
    EXACT_TREASURY_BALANCE_MOTES,
    NativeTransferInputError,
    build_native_transfer_input,
)
from tests.native_transfer_input_fixtures import (
    RECIPIENT_ACCOUNT,
    SOURCE_ACCOUNT,
    canonical_bytes,
    source_documents,
)


def _build(sources: dict[str, object]):
    return build_native_transfer_input(
        historical_receipt_bytes=sources["historical"],
        historical_inventory_bytes=sources["inventory"],
        canonical_receipt_bytes=sources["canonical_receipt"],
        deployment_manifest_bytes=sources["deployment"],
        treasury_snapshot_bytes=sources["snapshot"],
        intent_bytes=sources["intent"],
    )


def _document(sources: dict[str, object], name: str) -> dict[str, object]:
    value = json.loads(sources[name])
    assert isinstance(value, dict)
    return value


def test_builder_derives_complete_exact_native_transfer_input(monkeypatch) -> None:
    sources = source_documents(monkeypatch)

    built = _build(sources)
    typed = built.typed_input
    header = typed["header"]
    body = typed["body"]
    prepared = prepare_v3_envelope(typed)

    assert set(typed) == {"schema_id", "action", "header", "body"}
    assert typed["schema_id"] == "concordia.exact-envelope-v3.input.v1"
    assert typed["action"] == "NativeTransferV1"
    assert header["casper_chain_name"] == "casper-test"
    assert header["requested_allocation_bps"] == str(EXACT_REQUESTED_ALLOCATION_BPS)
    assert header["approved_allocation_bps"] == str(EXACT_APPROVED_ALLOCATION_BPS)
    assert header["decision_code"] == "2"
    assert body["source_account"] == SOURCE_ACCOUNT.hex()
    assert body["recipient_account"] == RECIPIENT_ACCOUNT.hex()
    assert body["treasury_snapshot_balance_motes"] == str(EXACT_TREASURY_BALANCE_MOTES)
    assert body["amount_motes"] == str(EXACT_TRANSFER_MOTES)
    assert int(str(body["amount_motes"])) == (
        int(str(body["treasury_snapshot_balance_motes"]))
        * int(str(header["approved_allocation_bps"]))
        // 10_000
    )
    assert header["action_id"] == prepared["action_id"]
    assert body["transfer_id"] == prepared["transfer_id"]
    assert header["proposal_nonce"] != "00" * 32
    assert body["action_nonce"] != "00" * 32
    assert header["proposal_nonce"] != body["action_nonce"]
    assert (
        built.derivation_manifest["derived"]["envelope_hash"]
        == prepared["envelope_hash"]
    )
    assert (
        built.derivation_manifest["derived"]["preauth_evidence_root"]
        == header["preauth_evidence_root"]
    )
    assert (
        built.derivation_manifest["derived"]["authorized_metadata_root"]
        == header["authorized_metadata_root"]
    )
    assert built.derivation_manifest["verification_authorities"] == {
        "historical_inventory_sha256": hashlib.sha256(sources["inventory"]).hexdigest(),
        "historical_inventory_byte_length": str(len(sources["inventory"])),
    }


def test_builder_is_byte_deterministic_for_the_same_exact_sources(monkeypatch) -> None:
    sources = source_documents(monkeypatch)

    first = _build(sources)
    second = _build(copy.deepcopy(sources))

    assert canonical_bytes(first.typed_input) == canonical_bytes(second.typed_input)
    assert canonical_bytes(first.derivation_manifest) == canonical_bytes(
        second.derivation_manifest
    )


def test_builder_binds_derived_identifiers_to_the_exact_intent_bytes(
    monkeypatch,
) -> None:
    sources = source_documents(monkeypatch)
    first = _build(sources)
    intent = _document(sources, "intent")
    intent["intent_id"] = "finals_native_transfer_reissued"
    sources["intent"] = canonical_bytes(intent)

    second = _build(sources)

    assert (
        first.typed_input["header"]["proposal_nonce"]
        != second.typed_input["header"]["proposal_nonce"]
    )
    assert (
        first.typed_input["header"]["action_id"]
        != second.typed_input["header"]["action_id"]
    )
    assert (
        first.typed_input["body"]["transfer_id"]
        != second.typed_input["body"]["transfer_id"]
    )
    assert (
        first.derivation_manifest["input_sha256"]
        != second.derivation_manifest["input_sha256"]
    )


def test_builder_rejects_duplicate_json_keys_before_derivation(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    sources["intent"] = (
        b'{"schema_id":"concordia.native-transfer-v3-intent.v1",'
        b'"network":"casper-test","network":"casper-test"}'
    )

    with pytest.raises(NativeTransferInputError, match="duplicate JSON key"):
        _build(sources)


@pytest.mark.parametrize(
    ("source_name", "mutation"),
    [
        ("intent", lambda value: value.__setitem__("network", "casper-testnet")),
        (
            "canonical_receipt",
            lambda value: value.__setitem__("network", "casper-testnet"),
        ),
        ("deployment", lambda value: value.__setitem__("network", "casper-testnet")),
        ("snapshot", lambda value: value.__setitem__("network", "casper-testnet")),
    ],
)
def test_builder_rejects_every_network_alias(
    monkeypatch,
    source_name: str,
    mutation,
) -> None:
    sources = source_documents(monkeypatch)
    document = _document(sources, source_name)
    mutation(document)
    sources[source_name] = canonical_bytes(document)

    with pytest.raises(NativeTransferInputError, match="casper-test|network"):
        _build(sources)


@pytest.mark.parametrize(
    "root",
    (
        "proposal_hash",
        "policy_hash",
        "plan_hash",
        "final_card_hash",
        "dissent_hash",
        "agent_action_hash",
    ),
)
def test_builder_rejects_canonical_root_disagreement(
    monkeypatch,
    root: str,
) -> None:
    sources = source_documents(monkeypatch)
    receipt = _document(sources, "canonical_receipt")
    receipt[root] = "ff" * 32
    sources["canonical_receipt"] = canonical_bytes(receipt)

    with pytest.raises(NativeTransferInputError, match=root):
        _build(sources)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("caller_hash", "f1" * 32),
        ("caller_public_key", "01" + ("f2" * 32)),
        ("evidence_uri", "https://example.invalid/not-the-receipt-evidence"),
        ("typed_args", {"proposal_id": "String"}),
    ],
)
def test_builder_rejects_canonical_receipt_metadata_disagreement(
    monkeypatch,
    field: str,
    value: object,
) -> None:
    sources = source_documents(monkeypatch)
    receipt = _document(sources, "canonical_receipt")
    receipt[field] = value
    sources["canonical_receipt"] = canonical_bytes(receipt)

    with pytest.raises(NativeTransferInputError, match=field.split("_")[0]):
        _build(sources)


def test_builder_rejects_unfinalized_v3_deployment(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    deployment = _document(sources, "deployment")
    deployment["two_node_finality"]["node_observations"] = deployment[
        "two_node_finality"
    ]["node_observations"][:1]
    sources["deployment"] = canonical_bytes(deployment)

    with pytest.raises(NativeTransferInputError, match="two-node|two node|final"):
        _build(sources)


def test_builder_rejects_v3_deployment_provider_disagreement(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    deployment = _document(sources, "deployment")
    observations = deployment["two_node_finality"]["node_observations"]
    second_block = observations[1]["block_response"]["result"]["block_with_signatures"][
        "block"
    ]["Version2"]
    second_block["header"]["state_root_hash"] = "ee" * 32
    sources["deployment"] = canonical_bytes(deployment)

    with pytest.raises(NativeTransferInputError, match="disagree|final"):
        _build(sources)


def test_builder_rejects_v3_state_root_query_not_pinned_to_install_block(
    monkeypatch,
) -> None:
    sources = source_documents(monkeypatch)
    deployment = _document(sources, "deployment")
    deployment["raw_rpc"]["state_root"]["request"]["params"] = {}
    sources["deployment"] = canonical_bytes(deployment)

    with pytest.raises(NativeTransferInputError, match="block-pinned"):
        _build(sources)


def test_builder_rejects_upgrade_capability_in_v3_package_state(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    deployment = _document(sources, "deployment")
    package = deployment["raw_rpc"]["package"]["response"]["result"]["stored_value"][
        "ContractPackage"
    ]
    package["groups"][0]["group_users"] = ["uref-" + ("f3" * 32) + "-007"]
    sources["deployment"] = canonical_bytes(deployment)

    with pytest.raises(NativeTransferInputError, match="upgrade"):
        _build(sources)


def test_builder_rejects_snapshot_provider_disagreement(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    snapshot = _document(sources, "snapshot")
    snapshot["observations"][1]["balance_response"]["result"]["value"][
        "total_balance"
    ] = "624999999999"
    snapshot["observations"][1]["balance_response"]["result"]["value"][
        "available_balance"
    ] = "624999999999"
    sources["snapshot"] = canonical_bytes(snapshot)

    with pytest.raises(NativeTransferInputError, match="snapshot|balance|agree"):
        _build(sources)


def test_builder_rejects_snapshot_not_observed_at_a_final_tip(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    snapshot = _document(sources, "snapshot")
    selected = snapshot["observations"][0]["block_response"]["result"]["block"]
    selected_height = selected["header"]["height"]
    snapshot["observations"][1]["status_response"]["result"]["last_added_block_info"][
        "height"
    ] = selected_height - 1
    sources["snapshot"] = canonical_bytes(snapshot)

    with pytest.raises(NativeTransferInputError, match="final|tip|height"):
        _build(sources)


def test_builder_rejects_any_treasury_baseline_except_exact_625_cspr(
    monkeypatch,
) -> None:
    sources = source_documents(monkeypatch)
    snapshot = _document(sources, "snapshot")
    snapshot["expected_balance_motes"] = "624999999999"
    for observation in snapshot["observations"]:
        value = observation["balance_response"]["result"]["value"]
        value["total_balance"] = "624999999999"
        value["available_balance"] = "624999999999"
    sources["snapshot"] = canonical_bytes(snapshot)

    with pytest.raises(NativeTransferInputError, match="625|baseline|balance"):
        _build(sources)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("source_account_hash", "00" * 32, "source"),
        ("recipient_account_hash", "not-hex", "recipient"),
        ("requested_allocation_bps", 2_999, "3000|requested"),
    ],
)
def test_builder_rejects_malformed_or_nonfinal_intent(
    monkeypatch,
    field: str,
    value: object,
    expected: str,
) -> None:
    sources = source_documents(monkeypatch)
    intent = _document(sources, "intent")
    intent[field] = value
    sources["intent"] = canonical_bytes(intent)

    with pytest.raises(NativeTransferInputError, match=expected):
        _build(sources)


def test_builder_rejects_source_as_recipient(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    intent = _document(sources, "intent")
    intent["recipient_account_hash"] = intent["source_account_hash"]
    sources["intent"] = canonical_bytes(intent)

    with pytest.raises(NativeTransferInputError, match="differ|recipient"):
        _build(sources)


def test_builder_rejects_intent_that_predates_verified_evidence(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    intent = _document(sources, "intent")
    intent["captured_at"] = "2026-01-23T12:34:58Z"
    sources["intent"] = canonical_bytes(intent)

    with pytest.raises(NativeTransferInputError, match="predates"):
        _build(sources)


def test_builder_rejects_operator_supplied_derived_hashes(monkeypatch) -> None:
    sources = source_documents(monkeypatch)
    intent = _document(sources, "intent")
    intent["action_id"] = "ff" * 32
    sources["intent"] = canonical_bytes(intent)

    with pytest.raises(NativeTransferInputError, match="fields|schema"):
        _build(sources)
