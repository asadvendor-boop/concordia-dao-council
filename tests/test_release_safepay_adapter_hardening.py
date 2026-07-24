from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_release_proof_adapters as base  # noqa: E402

import shared.release_proof_adapters as adapters  # noqa: E402
from shared.release_proof_adapters import (  # noqa: E402
    ReleaseProofAdapterError,
    verify_safepay_v2_artifact,
)
from shared.x402_payments import safepay_v2_response_hash  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "handoff" / "schemas"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _artifact() -> dict[str, Any]:
    return copy.deepcopy(base.safepay_artifact())


def _verify(document: dict[str, Any]) -> dict[str, Any]:
    return verify_safepay_v2_artifact(document, _canonical(document))


def _exchange_json(exchange: dict[str, Any], side: str) -> tuple[bytes, dict[str, Any]]:
    encoded = exchange[f"{side}_body_base64"]
    raw = base64.b64decode(encoded, validate=True)
    return raw, json.loads(raw)


def _replace_exchange_json(
    exchange: dict[str, Any], side: str, value: dict[str, Any]
) -> None:
    raw = _canonical(value)
    exchange[f"{side}_body_base64"] = base64.b64encode(raw).decode("ascii")
    exchange[f"{side}_body_sha256"] = hashlib.sha256(raw).hexdigest()


def _mutate_each_rpc_response(
    artifact: dict[str, Any],
    exchange_name: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    for provider in artifact["chain_evidence"]["providers"]:
        exchange = provider[exchange_name]
        _, response = _exchange_json(exchange, "response")
        mutate(response)
        _replace_exchange_json(exchange, "response", response)


def _persist_fulfillment(artifact: dict[str, Any], fulfillment: dict[str, Any]) -> None:
    fulfillment_json = json.dumps(
        fulfillment,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    for key in ("before_restart", "after_restart"):
        row_observation = artifact["consumption_rows"][key]
        row_observation["row"]["fulfillment_json"] = fulfillment_json
        row_observation["row_canonical_json_sha256"] = hashlib.sha256(
            _canonical(row_observation["row"])
        ).hexdigest()
    for key in ("first_consumption", "exact_retry"):
        exchange = artifact["redemption_observations"][key]["exchange"]
        _, response = _exchange_json(exchange, "response")
        response["fulfillment"] = copy.deepcopy(fulfillment)
        _replace_exchange_json(exchange, "response", response)


def _rebind_consumed_at(artifact: dict[str, Any], consumed_at: int) -> None:
    quote = artifact["quote"]
    transfer = artifact["chain_evidence"]["parsed_transfer"]
    report = artifact["protected_report"]
    response_hash = safepay_v2_response_hash(
        quote_hash=quote["quote_hash"],
        payment_hash=transfer["payment_hash"],
        block_hash=transfer["block_hash"],
        block_height=transfer["block_height"],
        report_hash=report["report_hash"],
        consumed_at=consumed_at,
    )
    fulfillment = json.loads(
        artifact["consumption_rows"]["before_restart"]["row"]["fulfillment_json"]
    )
    fulfillment["consumption"]["consumed_at"] = consumed_at
    fulfillment["consumption"]["response_hash"] = response_hash
    fulfillment["observed_at"] = str(consumed_at)
    fulfillment["response_hash"] = response_hash

    for key in ("before_restart", "after_restart"):
        row = artifact["consumption_rows"][key]["row"]
        row["consumed_at"] = consumed_at
        row["response_hash"] = response_hash
    _persist_fulfillment(artifact, fulfillment)

    report["response_hash"] = response_hash
    for key in ("first_consumption", "exact_retry", "cross_binding_reuse"):
        observation = artifact["redemption_observations"][key]
        observation["observed_at"] = consumed_at + 1
        observation["consumed_response_hash"] = response_hash
    for key in ("first_consumption", "exact_retry"):
        artifact["redemption_observations"][key]["response_digest"] = response_hash


def _noncanonical_base64_same_bytes(canonical: str) -> str:
    decoded = base64.b64decode(canonical, validate=True)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    padding = len(canonical) - len(canonical.rstrip("="))
    if padding == 0:
        # A complete 3-byte quantum has no unused pad bits to vary.  A
        # permissive decoder still treats ASCII whitespace as the same bytes,
        # while the release adapter must reject that non-canonical spelling.
        return canonical[:4] + "\n" + canonical[4:]
    if padding not in (1, 2):
        raise AssertionError("fixture must contain a padded base64 value")
    index = len(canonical) - padding - 1
    for replacement in alphabet:
        if replacement == canonical[index]:
            continue
        candidate = canonical[:index] + replacement + canonical[index + 1 :]
        try:
            if base64.b64decode(candidate, validate=True) == decoded:
                return candidate
        except ValueError:
            continue
    raise AssertionError("no non-canonical equivalent base64 spelling found")


def test_adapter_accepts_current_casper_v2_rpc_shapes() -> None:
    artifact = _artifact()
    deploy_raw, deploy_response = _exchange_json(
        artifact["chain_evidence"]["providers"][0]["info_get_deploy"],
        "response",
    )
    block_raw, block_response = _exchange_json(
        artifact["chain_evidence"]["providers"][0]["chain_get_block"],
        "response",
    )

    assert deploy_raw
    assert set(deploy_response["result"]["execution_info"]["execution_result"]) == {
        "Version2"
    }
    assert block_raw
    assert set(block_response["result"]["block_with_signatures"]["block"]) == {
        "Version2"
    }
    assert _verify(artifact)["derived_facts"]["payment_hash"] == base.PAYMENT_HASH


def test_adapter_accepts_real_wp2_fulfillment_field_names_and_nested_consumption() -> (
    None
):
    artifact = _artifact()
    fulfillment = json.loads(
        artifact["consumption_rows"]["before_restart"]["row"]["fulfillment_json"]
    )

    assert set(fulfillment["payment_observation"]) == {
        "network",
        "payment_hash",
        "block_hash",
        "block_height",
        "execution_status",
        "finality_status",
        "from_account_hash",
        "to_account_hash",
        "amount_motes",
        "transfer_id",
        "execution_error",
        "observed_at",
    }
    assert set(fulfillment["consumption"]) == {
        "network",
        "payment_hash",
        "quote_id",
        "resource_id",
        "quote_hash",
        "response_hash",
        "consumed_at",
    }
    assert _verify(artifact)["derived_facts"]["consumption_count"] == 1


RpcMutation = Callable[[dict[str, Any], dict[str, Any]], None]


def _request_wrong_version(request: dict[str, Any], _response: dict[str, Any]) -> None:
    request["jsonrpc"] = "1.0"


def _response_wrong_id(request: dict[str, Any], response: dict[str, Any]) -> None:
    response["id"] = int(request["id"]) + 100


def _response_has_result_and_error(
    _request: dict[str, Any], response: dict[str, Any]
) -> None:
    response["error"] = {"code": -32000, "message": "indeterminate"}


@pytest.mark.parametrize(
    "mutate",
    [
        _request_wrong_version,
        _response_wrong_id,
        _response_has_result_and_error,
    ],
    ids=("request-jsonrpc-version", "response-id", "result-plus-error"),
)
def test_adapter_requires_exact_jsonrpc_2_success_envelope(
    mutate: RpcMutation,
) -> None:
    artifact = _artifact()
    exchange = artifact["chain_evidence"]["providers"][0]["info_get_deploy"]
    _, request = _exchange_json(exchange, "request")
    _, response = _exchange_json(exchange, "response")
    mutate(request, response)
    _replace_exchange_json(exchange, "request", request)
    _replace_exchange_json(exchange, "response", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match="payment_deploy_finalized_without_execution_error.*JSON-RPC",
    ):
        _verify(artifact)


ClMutation = Callable[[dict[str, Any]], None]


def _amount_wrong_type(arg: dict[str, Any]) -> None:
    arg["cl_type"] = "U64"


def _amount_wrong_bytes(arg: dict[str, Any]) -> None:
    arg["bytes"] = "0401f90295"


def _target_wrong_type(arg: dict[str, Any]) -> None:
    arg["cl_type"] = "Key"


def _transfer_id_wrong_bytes(arg: dict[str, Any]) -> None:
    raw = bytes.fromhex(arg["bytes"])
    arg["bytes"] = (raw[:1] + raw[1:][::-1]).hex()


@pytest.mark.parametrize(
    ("argument_name", "mutate"),
    [
        ("amount", _amount_wrong_type),
        ("amount", _amount_wrong_bytes),
        ("target", _target_wrong_type),
        ("id", _transfer_id_wrong_bytes),
    ],
    ids=(
        "amount-type",
        "amount-bytes",
        "target-type",
        "transfer-id-bytes",
    ),
)
def test_adapter_requires_exact_native_transfer_cl_type_and_bytes(
    argument_name: str,
    mutate: ClMutation,
) -> None:
    artifact = _artifact()

    def mutate_response(response: dict[str, Any]) -> None:
        args = response["result"]["deploy"]["session"]["Transfer"]["args"]
        target = next(item[1] for item in args if item[0] == argument_name)
        mutate(target)

    _mutate_each_rpc_response(artifact, "info_get_deploy", mutate_response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"native Transfer (?:amount|target|id).*(?:CLValue|bytes)",
    ):
        _verify(artifact)


def test_adapter_validates_nested_consumption_binding_not_only_row_columns() -> None:
    artifact = _artifact()
    fulfillment = json.loads(
        artifact["consumption_rows"]["before_restart"]["row"]["fulfillment_json"]
    )
    fulfillment["consumption"]["resource_id"] = "risk-report:other"
    _persist_fulfillment(artifact, fulfillment)

    with pytest.raises(
        ReleaseProofAdapterError,
        match="provider_consumption_row_matches_payment_and_binding",
    ):
        _verify(artifact)


def test_adapter_binds_cross_resource_request_to_observation_metadata() -> None:
    artifact = _artifact()
    cross = artifact["redemption_observations"]["cross_binding_reuse"]
    exchange = cross["exchange"]
    _, request = _exchange_json(exchange, "request")
    request["quote_id"] = "323e4567-e89b-42d3-a456-426614174000"
    request["resource_id"] = "risk-report:third"
    _replace_exchange_json(exchange, "request", request)

    assert request["quote_id"] != artifact["quote"]["quote_id"]
    assert request["resource_id"] != artifact["quote"]["resource_id"]
    assert request["quote_id"] != cross["quote_id"]
    assert request["resource_id"] != cross["resource_id"]
    with pytest.raises(
        ReleaseProofAdapterError,
        match="cross_binding_reuse_returned_terminal_409",
    ):
        _verify(artifact)


def test_adapter_rejects_first_consumption_at_or_after_quote_expiry() -> None:
    artifact = _artifact()
    consumed_at = int(artifact["quote"]["expires_at"])
    _rebind_consumed_at(artifact, consumed_at)

    with pytest.raises(
        ReleaseProofAdapterError,
        match="provider_consumption_row_matches_payment_and_binding.*expir",
    ):
        _verify(artifact)


def test_adapter_rejects_report_released_before_finalized_payment_block() -> None:
    artifact = _artifact()
    artifact["protected_report"]["persisted_at"] = "2026-07-23T01:00:00Z"
    artifact["protected_report"]["released_at"] = "2026-07-23T01:01:00Z"
    assert (
        artifact["protected_report"]["released_at"]
        < artifact["chain_evidence"]["parsed_transfer"]["block_timestamp"]
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match="report_hash_recomputed_and_matches_quote.*final",
    ):
        _verify(artifact)


def test_adapter_rejects_capture_timestamp_even_one_second_in_the_future(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 7, 23, 1, 5, 0, tzinfo=tz or UTC)

    artifact = _artifact()
    artifact["captured_at"] = "2026-07-23T01:05:01Z"
    monkeypatch.setattr(adapters, "datetime", FrozenDateTime)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"captured_at.*future",
    ):
        _verify(artifact)


def test_adapter_binds_capture_provider_origin_to_every_redemption_url() -> None:
    artifact = _artifact()
    artifact["redemption_observations"]["exact_retry"]["exchange"]["url"] = (
        "https://other-provider.example/x402/v2/redemptions"
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"(?:provider|capture).*origin|redemption.*origin",
    ):
        _verify(artifact)


def test_adapter_rejects_noncanonical_base64_even_when_decoded_bytes_match() -> None:
    artifact = _artifact()
    exchange = artifact["redemption_observations"]["first_consumption"]["exchange"]
    canonical = exchange["request_body_base64"]
    replacement = _noncanonical_base64_same_bytes(canonical)
    assert replacement != canonical
    assert base64.b64decode(replacement) == base64.b64decode(canonical)
    exchange["request_body_base64"] = replacement

    with pytest.raises(
        ReleaseProofAdapterError,
        match="canonical base64|artifact schema mismatch",
    ):
        _verify(artifact)


def test_adapter_pins_the_frozen_safepay_artifact_schema_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    schema_root = tmp_path / "schemas"
    schema_root.mkdir()
    for name in (
        "safepay-v2-live-artifact.schema.json",
        "safepay-v2-adapter-result.schema.json",
    ):
        shutil.copyfile(SCHEMA_ROOT / name, schema_root / name)
    schema_path = schema_root / "safepay-v2-live-artifact.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["$comment"] = "semantically harmless drift must still fail the release pin"
    schema_path.write_bytes(_canonical(schema))
    monkeypatch.setattr(adapters, "_SCHEMA_ROOT", schema_root)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"schema.*(?:digest|hash|pin)",
    ):
        _verify(_artifact())


def test_adapter_derives_eight_block_confirmation_depth_from_raw_status() -> None:
    artifact = _artifact()
    provider = artifact["chain_evidence"]["providers"][0]
    exchange = provider["info_get_status"]
    _, response = _exchange_json(exchange, "response")
    response["result"]["last_added_block_info"]["height"] = (
        artifact["chain_evidence"]["parsed_transfer"]["block_height"] + 7
    )
    _replace_exchange_json(exchange, "response", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match="payment_deploy_finalized_without_execution_error.*eight",
    ):
        _verify(artifact)


def test_adapter_rejects_raw_payment_deploy_from_wrong_chain() -> None:
    artifact = _artifact()

    def mutate(response: dict[str, Any]) -> None:
        response["result"]["deploy"]["header"]["chain_name"] = "casper"

    _mutate_each_rpc_response(artifact, "info_get_deploy", mutate)

    with pytest.raises(
        ReleaseProofAdapterError,
        match="payment_deploy_finalized_without_execution_error.*casper-test",
    ):
        _verify(artifact)


def _rewrite_snapshot(
    artifact: dict[str, Any],
    stage: str,
    statement: str,
    parameters: tuple[object, ...],
) -> None:
    snapshot = artifact["ledger_evidence"][stage]
    raw = base64.b64decode(snapshot["sqlite_backup_base64"], validate=True)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "snapshot.sqlite3"
        path.write_bytes(raw)
        connection = sqlite3.connect(path)
        try:
            connection.execute(statement, parameters)
            connection.commit()
        finally:
            connection.close()
        changed = path.read_bytes()
    snapshot["sqlite_backup_base64"] = base64.b64encode(changed).decode("ascii")
    snapshot["sqlite_backup_sha256"] = hashlib.sha256(changed).hexdigest()


def test_adapter_queries_immutable_consumption_from_each_sqlite_backup() -> None:
    artifact = _artifact()
    _rewrite_snapshot(
        artifact,
        "after_cross_binding_reuse",
        "UPDATE payment_consumptions SET resource_id = ?",
        ("risk-report:forged",),
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match="provider_consumption_row_matches_payment_and_binding.*authoritative rows",
    ):
        _verify(artifact)


def test_adapter_queries_progressive_redemption_journal_from_backups() -> None:
    artifact = _artifact()
    _rewrite_snapshot(
        artifact,
        "after_exact_retry",
        "DELETE FROM safepay_redemption_observations "
        "WHERE kind = 'idempotent_replay'",
        (),
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match="provider_consumption_row_matches_payment_and_binding.*progression",
    ):
        _verify(artifact)


def test_adapter_rejects_first_snapshot_before_first_redemption_observation() -> None:
    artifact = _artifact()
    artifact["ledger_evidence"]["after_first_consumption"]["observed_at"] = (
        "2026-07-23T01:03:00Z"
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            "provider_consumption_row_matches_payment_and_binding.*snapshot.*redemption"
            "|provider restart observation differs"
        ),
    ):
        _verify(artifact)


def test_adapter_rejects_retry_snapshot_before_retry_observation() -> None:
    artifact = _artifact()
    retry_observed_at = base.CONSUMED_AT + 15
    artifact["redemption_observations"]["exact_retry"]["observed_at"] = (
        retry_observed_at
    )
    for stage in ("after_exact_retry", "after_cross_binding_reuse"):
        _rewrite_snapshot(
            artifact,
            stage,
            "UPDATE safepay_redemption_observations SET observed_at = ? "
            "WHERE kind = 'idempotent_replay'",
            (retry_observed_at,),
        )
    artifact["ledger_evidence"]["after_exact_retry"]["observed_at"] = (
        "2026-07-23T01:03:12Z"
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            "provider_consumption_row_matches_payment_and_binding.*snapshot.*redemption"
            "|provider restart observation differs"
        ),
    ):
        _verify(artifact)


def test_adapter_rejects_cross_binding_snapshot_before_rejection_observation() -> None:
    artifact = _artifact()
    artifact["ledger_evidence"]["after_cross_binding_reuse"]["observed_at"] = (
        "2026-07-23T01:04:05Z"
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            "provider_consumption_row_matches_payment_and_binding.*snapshot.*redemption"
            "|provider restart observation differs"
        ),
    ):
        _verify(artifact)


def test_adapter_rejects_a_second_consumption_for_the_same_quote() -> None:
    artifact = _artifact()
    statement = (
        "INSERT INTO payment_consumptions("
        "network, payment_hash, quote_id, proposal_id, resource_id, quote_hash, "
        "report_hash, correlation_id, fulfillment_json, response_hash, consumed_at"
        ") SELECT network, ?, quote_id, proposal_id, resource_id, quote_hash, "
        "report_hash, correlation_id, fulfillment_json, response_hash, consumed_at "
        "FROM payment_consumptions WHERE quote_id = ?"
    )
    for stage in (
        "after_first_consumption",
        "after_exact_retry",
        "after_cross_binding_reuse",
    ):
        _rewrite_snapshot(
            artifact,
            stage,
            statement,
            ("aa" * 32, base.QUOTE_ID),
        )

    with pytest.raises(
        ReleaseProofAdapterError,
        match="provider_consumption_row_matches_payment_and_binding.*one consumption",
    ):
        _verify(artifact)


def test_adapter_rejects_retry_observed_before_first_consumption() -> None:
    artifact = _artifact()
    retry = artifact["redemption_observations"]["exact_retry"]
    retry["observed_at"] = base.CONSUMED_AT - 1
    for stage in ("after_exact_retry", "after_cross_binding_reuse"):
        _rewrite_snapshot(
            artifact,
            stage,
            "UPDATE safepay_redemption_observations SET observed_at = ? "
            "WHERE kind = 'idempotent_replay'",
            (base.CONSUMED_AT - 1,),
        )

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            "exact_retry_returned_same_fulfillment_hash_without_second_consumption.*chronolog"
            "|redemption exchange does not straddle"
        ),
    ):
        _verify(artifact)


def test_adapter_rejects_retry_exchange_captured_before_first_consumption() -> None:
    artifact = _artifact()
    artifact["redemption_observations"]["exact_retry"]["exchange"]["observed_at"] = (
        "2026-07-23T01:02:59Z"
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            "exact_retry_returned_same_fulfillment_hash_without_second_consumption.*chronolog"
            "|redemption exchange does not straddle"
        ),
    ):
        _verify(artifact)


def test_adapter_rejects_rpc_exchange_url_detached_from_provider_origin() -> None:
    artifact = _artifact()
    provider = artifact["chain_evidence"]["providers"][1]
    provider["info_get_deploy"]["url"] = (
        artifact["chain_evidence"]["providers"][0]["info_get_deploy"]["url"]
    )

    with pytest.raises(
        ReleaseProofAdapterError,
        match="payment_deploy_finalized_without_execution_error.*origin",
    ):
        _verify(artifact)


def test_adapter_binds_capture_tool_commit_to_the_release_source() -> None:
    artifact = _artifact()
    artifact["capture_identity"]["capture_tool_commit"] = "fe" * 20

    with pytest.raises(
        ReleaseProofAdapterError,
        match="capture.*commit",
    ):
        _verify(artifact)


def test_adapter_rejects_consistent_but_ungrounded_restart_labels() -> None:
    artifact = _artifact()
    before = "fa" * 32
    after = "fb" * 32
    artifact["issued_quote_rows"]["before_restart"]["provider_instance_id"] = before
    artifact["issued_quote_rows"]["after_restart"]["provider_instance_id"] = after
    artifact["consumption_rows"]["before_restart"]["provider_instance_id"] = before
    artifact["consumption_rows"]["after_restart"]["provider_instance_id"] = after
    artifact["ledger_evidence"]["after_first_consumption"][
        "provider_instance_id"
    ] = before
    artifact["ledger_evidence"]["after_exact_retry"]["provider_instance_id"] = before
    artifact["ledger_evidence"]["after_cross_binding_reuse"][
        "provider_instance_id"
    ] = after

    with pytest.raises(
        ReleaseProofAdapterError,
        match="restart.*runtime identity|runtime identity.*restart",
    ):
        _verify(artifact)
