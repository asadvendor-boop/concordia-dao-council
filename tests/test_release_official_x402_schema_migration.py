from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
LIVE_SCHEMA_PATH = (
    ROOT / "handoff" / "schemas" / "official-x402-live-artifact.schema.json"
)
RESULT_SCHEMA_PATH = (
    ROOT / "handoff" / "schemas" / "official-x402-adapter-result.schema.json"
)
PIN_PATH = ROOT / "handoff" / "RELEASE_REGISTRY_ADAPTER_SCHEMAS.json"
CONTRACT_PATH = ROOT / "handoff" / "RELEASE_REGISTRY_ADAPTER_CONTRACT.md"


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_official_live_schema_uses_current_casper_transaction_rpc() -> None:
    schema = _load(LIVE_SCHEMA_PATH)
    provider = schema["$defs"]["rpc_provider_observation"]

    assert "info_get_transaction" in provider["required"]
    assert "info_get_deploy" not in provider["required"]
    assert "info_get_transaction" in provider["properties"]
    assert "info_get_deploy" not in provider["properties"]


def test_official_release_schema_requires_ed25519_payer_key() -> None:
    schema = _load(LIVE_SCHEMA_PATH)

    assert schema["properties"]["authorization"]["properties"][
        "public_key_hex"
    ]["pattern"] == "^01[0-9a-f]{64}$"


def test_paid_resource_exchanges_capture_headers_and_decoded_values() -> None:
    schema = _load(LIVE_SCHEMA_PATH)
    fulfillment = schema["properties"]["fulfillment"]

    assert fulfillment["required"] == [
        "first_row",
        "post_restart_row",
        "first_release",
        "exact_retry",
        "cross_binding_reuse",
        "upstream_settle_journal",
    ]
    assert (
        fulfillment["properties"]["first_release"]["$ref"]
        == "#/$defs/paid_resource_success_exchange"
    )
    assert (
        fulfillment["properties"]["exact_retry"]["$ref"]
        == "#/$defs/paid_resource_success_exchange"
    )
    assert (
        fulfillment["properties"]["cross_binding_reuse"]["$ref"]
        == "#/$defs/paid_resource_rejection_exchange"
    )

    common = schema["$defs"]["paid_resource_exchange"]
    assert common["additionalProperties"] is False
    assert set(common["required"]) == {
        "method",
        "url",
        "request_headers_canonical_json_base64",
        "request_headers_canonical_json_sha256",
        "request_body_base64",
        "request_body_sha256",
        "payment_signature_raw_value_base64",
        "payment_signature_raw_value_sha256",
        "payment_signature_decoded_payload_base64",
        "payment_signature_decoded_payload_sha256",
        "response_status",
        "response_headers_canonical_json_base64",
        "response_headers_canonical_json_sha256",
        "response_content_type",
        "response_body_base64",
        "response_body_sha256",
        "observed_at",
    }
    assert common["properties"]["method"]["const"] == "GET"

    success = schema["$defs"]["paid_resource_success_exchange"]
    assert success["allOf"][0]["$ref"] == "#/$defs/paid_resource_exchange"
    success_overlay = success["allOf"][1]
    assert success_overlay["properties"]["response_status"]["const"] == 200
    assert set(success_overlay["required"]) == {
        "payment_response_raw_value_base64",
        "payment_response_raw_value_sha256",
        "payment_response_decoded_settlement_base64",
        "payment_response_decoded_settlement_sha256",
    }

    rejection = schema["$defs"]["paid_resource_rejection_exchange"]
    assert rejection["allOf"][0]["$ref"] == "#/$defs/paid_resource_exchange"
    rejection_overlay = rejection["allOf"][1]
    assert rejection_overlay["properties"]["response_status"]["const"] == 409
    assert set(rejection_overlay["properties"]) >= {
        "payment_response_raw_value_base64",
        "payment_response_raw_value_sha256",
        "payment_response_decoded_settlement_base64",
        "payment_response_decoded_settlement_sha256",
    }
    assert all(
        rejection_overlay["properties"][name] is False
        for name in (
            "payment_response_raw_value_base64",
            "payment_response_raw_value_sha256",
            "payment_response_decoded_settlement_base64",
            "payment_response_decoded_settlement_sha256",
        )
    )


def test_upstream_settle_journal_uses_three_sqlite_snapshots_not_counts() -> None:
    schema = _load(LIVE_SCHEMA_PATH)
    fulfillment = schema["properties"]["fulfillment"]
    properties = fulfillment["properties"]

    assert "upstream_settle_call_count_before_reuse" not in properties
    assert "upstream_settle_call_count_after_reuse" not in properties

    journal = schema["$defs"]["upstream_settle_journal"]
    assert journal["additionalProperties"] is False
    assert set(journal["required"]) == {
        "schema_id",
        "authoritative_database_id",
        "migration_sql_base64",
        "migration_sql_sha256",
        "snapshots",
    }
    assert (
        journal["properties"]["schema_id"]["const"]
        == "concordia.x402_upstream_settle_journal.v1"
    )
    assert journal["properties"]["migration_sql_sha256"]["const"] == (
        "c660abcce78e05edfebb475661dd8ee636a699e822956ac05a990cbe1fb51c5f"
    )

    snapshots = journal["properties"]["snapshots"]
    assert snapshots["additionalProperties"] is False
    assert snapshots["required"] == [
        "after_first_release",
        "after_exact_retry",
        "after_cross_binding_reuse",
    ]
    for name in snapshots["required"]:
        assert snapshots["properties"][name]["$ref"] == "#/$defs/journal_snapshot"

    snapshot = schema["$defs"]["journal_snapshot"]
    assert snapshot["additionalProperties"] is False
    assert set(snapshot["required"]) == {
        "sqlite_backup_base64",
        "sqlite_backup_sha256",
        "rows_canonical_json_base64",
        "rows_canonical_json_sha256",
        "journal_root_sha256",
        "observed_at",
        "service_instance_id",
    }


def test_contract_and_mutation_pointers_describe_raw_migrated_evidence() -> None:
    contract = _load(PIN_PATH)
    official = contract["official_x402_settlement_v1"]
    mutations = {
        item["id"]: item["mutation"]
        for item in official["required_mutation_tests"]
    }

    assert mutations["OX-ADAPTER-16"] == (
        "/settlement_chain_evidence/providers/0/"
        "info_get_transaction/response_body_base64"
    )
    assert mutations["OX-ADAPTER-20"] == (
        "/fulfillment/exact_retry/payment_response_raw_value_base64"
    )
    assert mutations["OX-ADAPTER-21"] == (
        "/fulfillment/cross_binding_reuse/response_status"
    )
    assert mutations["OX-ADAPTER-22"] == (
        "/fulfillment/first_release/observed_at"
    )

    transcripts = official["transcript_requirements"]
    assert "exact_info_get_transaction_requests_and_responses" in transcripts[
        "finality"
    ]
    assert "exact_info_get_status_requests_and_responses" in transcripts[
        "finality"
    ]
    assert "minimum_eight_confirmation_depth" in transcripts["finality"]
    assert "distinct_node_signing_identities" in transcripts["finality"]
    assert "exact_info_get_deploy_requests_and_responses" not in transcripts[
        "finality"
    ]
    assert "v8_is_latest_enabled_version" in transcripts["wcspr_v8"]
    assert set(transcripts["fulfillment"]) >= {
        "first_paid_resource_request_and_response_with_payment_headers",
        "exact_retry_paid_resource_request_and_response_with_payment_headers",
        "cross_binding_request_and_terminal_409_without_payment_response",
        "three_sqlite_upstream_settle_journal_snapshots",
        "canonical_journal_rows_and_root_recomputed_from_each_snapshot",
        "single_settle_attempt_as_two_append_only_events_bound_to_transcript_and_finalized_fulfillment",
    }
    assert all(
        "call_count" not in requirement
        for requirement in transcripts["fulfillment"]
    )

    prose = CONTRACT_PATH.read_text(encoding="utf-8")
    official_prose = prose.split("## Official x402 adapter", 1)[1].split(
        "## Adapter API and release behavior", 1
    )[0]
    assert "`info_get_transaction`" in official_prose
    assert "`info_get_deploy`" not in official_prose
    assert "PAYMENT-SIGNATURE" in official_prose
    assert "PAYMENT-RESPONSE" in official_prose
    assert "x402_upstream_settle_calls" in official_prose
    assert "producer-supplied call counts" in official_prose.lower()
    assert "`request_started`" in official_prose
    assert "`response_observed`" in official_prose
    assert "`request_failed`" in official_prose
    assert "one request-start row and one response-observed row" in " ".join(
        official_prose.split()
    )


def test_schema_files_are_valid_and_sha256_pins_are_atomic() -> None:
    live_schema = _load(LIVE_SCHEMA_PATH)
    result_schema = _load(RESULT_SCHEMA_PATH)
    pins = _load(PIN_PATH)["exact_json_schemas"]

    Draft202012Validator.check_schema(live_schema)
    Draft202012Validator.check_schema(result_schema)
    assert live_schema["properties"]["schema_version"]["const"] == (
        "concordia.official_x402_settlement.v2"
    )
    assert pins["official_x402_artifact"]["sha256"] == _sha256(LIVE_SCHEMA_PATH)
    assert pins["official_x402_result"]["sha256"] == _sha256(RESULT_SCHEMA_PATH)
