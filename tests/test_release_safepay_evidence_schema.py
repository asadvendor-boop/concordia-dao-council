from __future__ import annotations

import base64
import hashlib
import json
import runpy
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "handoff/schemas/safepay-v2-live-artifact.schema.json"
MIGRATION_PATH = ROOT / "x402_provider/migrations/0001_safepay_v2.sql"
LEGACY_FIXTURE = runpy.run_path(str(ROOT / "tests/test_release_proof_adapters.py"))
UTC = "2026-07-23T01:02:03Z"
TIP_HASH = "aa" * 32
TIP_STATE_ROOT = "bb" * 32
DATABASE_ID = "safepay-provider-ledger"
DATABASE_SCHEMA_ID = "concordia.safepay-provider-ledger.sqlite.v1"


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _rpc_exchange(request: object, response: object) -> dict[str, object]:
    request_bytes = _canonical(request)
    response_bytes = _canonical(response)
    return {
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "response_status": 200,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": hashlib.sha256(response_bytes).hexdigest(),
        "observed_at": UTC,
    }


def _status_exchange(*, request_id: int, block_height: int) -> dict[str, object]:
    return _rpc_exchange(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "info_get_status",
            "params": [],
        },
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "api_version": "2.0.0",
                "chainspec_name": "casper-test",
                "last_added_block_info": {
                    "hash": TIP_HASH,
                    "height": block_height + 8,
                    "state_root_hash": TIP_STATE_ROOT,
                    "timestamp": UTC,
                },
                "starting_state_root_hash": TIP_STATE_ROOT,
            },
        },
    )


def _backup_bytes(connection: sqlite3.Connection, directory: Path, name: str) -> bytes:
    destination_path = directory / name
    destination = sqlite3.connect(destination_path)
    try:
        connection.backup(destination)
    finally:
        destination.close()
    return destination_path.read_bytes()


def _snapshot(
    database_bytes: bytes,
    *,
    provider_instance_id: str,
) -> dict[str, object]:
    return {
        "sqlite_backup_base64": _b64(database_bytes),
        "sqlite_backup_sha256": hashlib.sha256(database_bytes).hexdigest(),
        "observed_at": UTC,
        "provider_instance_id": provider_instance_id,
    }


def _ledger_evidence(artifact: dict[str, Any]) -> dict[str, Any]:
    migration_bytes = MIGRATION_PATH.read_bytes()
    quote_row = artifact["issued_quote_rows"]["before_restart"]["row"]
    consumption_row = artifact["consumption_rows"]["before_restart"]["row"]
    protected_report = artifact["protected_report"]
    redemption = artifact["redemption_observations"]

    with TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        connection = sqlite3.connect(directory / "authoritative.sqlite3")
        try:
            connection.executescript(migration_bytes.decode("utf-8"))
            connection.execute(
                """
                INSERT INTO safepay_reports (
                    report_hash, report_media_type, report_bytes,
                    decoded_length, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    protected_report["report_hash"],
                    protected_report["media_type"],
                    base64.b64decode(protected_report["content_base64"]),
                    protected_report["decoded_length"],
                    quote_row["issued_at"],
                ),
            )
            connection.execute(
                """
                INSERT INTO safepay_quotes (
                    quote_id, proposal_id, resource_id, network,
                    payee_account_hash, amount_motes, correlation_id,
                    report_version, report_hash, issued_at, expires_at,
                    quote_nonce, quote_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(
                    quote_row[field]
                    for field in (
                        "quote_id",
                        "proposal_id",
                        "resource_id",
                        "network",
                        "payee_account_hash",
                        "amount_motes",
                        "correlation_id",
                        "report_version",
                        "report_hash",
                        "issued_at",
                        "expires_at",
                        "quote_nonce",
                        "quote_hash",
                    )
                ),
            )
            connection.execute(
                """
                INSERT INTO payment_consumptions (
                    network, payment_hash, quote_id, proposal_id, resource_id,
                    quote_hash, report_hash, correlation_id, fulfillment_json,
                    response_hash, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(
                    consumption_row[field]
                    for field in (
                        "network",
                        "payment_hash",
                        "quote_id",
                        "proposal_id",
                        "resource_id",
                        "quote_hash",
                        "report_hash",
                        "correlation_id",
                        "fulfillment_json",
                        "response_hash",
                        "consumed_at",
                    )
                ),
            )

            def add_observation(name: str) -> None:
                observation = redemption[name]
                connection.execute(
                    """
                    INSERT INTO safepay_redemption_observations (
                        kind, http_status, network, payment_hash, quote_id,
                        resource_id, observed_at, response_digest,
                        consumed_response_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    tuple(
                        observation[field]
                        for field in (
                            "kind",
                            "http_status",
                            "network",
                            "payment_hash",
                            "quote_id",
                            "resource_id",
                            "observed_at",
                            "response_digest",
                            "consumed_response_hash",
                        )
                    ),
                )
                connection.commit()

            add_observation("first_consumption")
            after_first = _backup_bytes(connection, directory, "after-first.sqlite3")
            add_observation("exact_retry")
            after_retry = _backup_bytes(connection, directory, "after-retry.sqlite3")
            add_observation("cross_binding_reuse")
            after_cross = _backup_bytes(connection, directory, "after-cross.sqlite3")
        finally:
            connection.close()

    return {
        "authoritative_database_id": DATABASE_ID,
        "authoritative_schema_id": DATABASE_SCHEMA_ID,
        "migration_sql_base64": _b64(migration_bytes),
        "migration_sql_sha256": hashlib.sha256(migration_bytes).hexdigest(),
        "after_first_consumption": _snapshot(
            after_first,
            provider_instance_id="provider-before-restart",
        ),
        "after_exact_retry": _snapshot(
            after_retry,
            provider_instance_id="provider-before-restart",
        ),
        "after_cross_binding_reuse": _snapshot(
            after_cross,
            provider_instance_id="provider-after-restart",
        ),
    }


def safepay_evidence_artifact() -> dict[str, Any]:
    return LEGACY_FIXTURE["safepay_artifact"]()


def _decode_snapshot(snapshot: dict[str, Any], directory: Path, name: str) -> Path:
    database_bytes = base64.b64decode(snapshot["sqlite_backup_base64"], validate=True)
    assert base64.b64encode(database_bytes).decode("ascii") == snapshot[
        "sqlite_backup_base64"
    ]
    assert hashlib.sha256(database_bytes).hexdigest() == snapshot[
        "sqlite_backup_sha256"
    ]
    path = directory / name
    path.write_bytes(database_bytes)
    return path


def _snapshot_counts(snapshot: dict[str, Any]) -> tuple[int, list[str]]:
    with TemporaryDirectory() as temporary_directory:
        database_path = _decode_snapshot(
            snapshot,
            Path(temporary_directory),
            "snapshot.sqlite3",
        )
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        try:
            assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            consumption_count = connection.execute(
                "SELECT COUNT(*) FROM payment_consumptions"
            ).fetchone()[0]
            kinds = [
                row[0]
                for row in connection.execute(
                    """
                    SELECT kind
                    FROM safepay_redemption_observations
                    ORDER BY observation_id
                    """
                ).fetchall()
            ]
        finally:
            connection.close()
    return consumption_count, kinds


def _delete_path(value: dict[str, Any], path: tuple[str | int, ...]) -> None:
    cursor: Any = value
    for part in path[:-1]:
        cursor = cursor[part]
    del cursor[path[-1]]


def _set_path(
    value: dict[str, Any],
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    cursor: Any = value
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement


def test_safepay_evidence_fixture_matches_extended_schema() -> None:
    Draft202012Validator(_schema()).validate(safepay_evidence_artifact())


def test_safepay_ledger_snapshots_are_real_progressive_sqlite_backups() -> None:
    evidence = safepay_evidence_artifact()["ledger_evidence"]

    assert _snapshot_counts(evidence["after_first_consumption"]) == (
        1,
        ["first_consumption"],
    )
    assert _snapshot_counts(evidence["after_exact_retry"]) == (
        1,
        ["first_consumption", "idempotent_replay"],
    )
    assert _snapshot_counts(evidence["after_cross_binding_reuse"]) == (
        1,
        [
            "first_consumption",
            "idempotent_replay",
            "cross_binding_rejected",
        ],
    )


def test_safepay_migration_evidence_is_exact_repository_migration() -> None:
    evidence = safepay_evidence_artifact()["ledger_evidence"]
    decoded = base64.b64decode(evidence["migration_sql_base64"], validate=True)

    assert decoded == MIGRATION_PATH.read_bytes()
    assert hashlib.sha256(decoded).hexdigest() == evidence["migration_sql_sha256"]


def test_safepay_status_exchanges_support_confirmation_depth_derivation() -> None:
    artifact = safepay_evidence_artifact()
    payment_height = artifact["chain_evidence"]["parsed_transfer"]["block_height"]

    for provider in artifact["chain_evidence"]["providers"]:
        exchange = provider["info_get_status"]
        request = json.loads(base64.b64decode(exchange["request_body_base64"]))
        response = json.loads(base64.b64decode(exchange["response_body_base64"]))
        assert request["method"] == "info_get_status"
        assert response["result"]["chainspec_name"] == "casper-test"
        assert (
            response["result"]["last_added_block_info"]["height"] - payment_height >= 8
        )


@pytest.mark.parametrize(
    "path",
    [
        ("ledger_evidence",),
        ("ledger_evidence", "authoritative_database_id"),
        ("ledger_evidence", "authoritative_schema_id"),
        ("ledger_evidence", "migration_sql_base64"),
        ("ledger_evidence", "migration_sql_sha256"),
        ("ledger_evidence", "after_first_consumption"),
        ("ledger_evidence", "after_exact_retry"),
        ("ledger_evidence", "after_cross_binding_reuse"),
        (
            "ledger_evidence",
            "after_first_consumption",
            "sqlite_backup_base64",
        ),
        (
            "ledger_evidence",
            "after_first_consumption",
            "sqlite_backup_sha256",
        ),
        ("ledger_evidence", "after_first_consumption", "observed_at"),
        (
            "ledger_evidence",
            "after_first_consumption",
            "provider_instance_id",
        ),
        ("chain_evidence", "providers", 0, "info_get_status"),
        ("chain_evidence", "providers", 1, "info_get_status"),
    ],
    ids=lambda path: "-".join(str(part) for part in path),
)
def test_safepay_evidence_schema_rejects_missing_required_field(
    path: tuple[str | int, ...],
) -> None:
    artifact = safepay_evidence_artifact()
    _delete_path(artifact, path)

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(artifact)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (
            ("ledger_evidence", "authoritative_database_id"),
            "another-database",
        ),
        (
            ("ledger_evidence", "authoritative_schema_id"),
            "another-schema",
        ),
        (
            ("ledger_evidence", "migration_sql_base64"),
            "***not-base64***",
        ),
        (
            ("ledger_evidence", "migration_sql_sha256"),
            "00",
        ),
        (
            (
                "ledger_evidence",
                "after_exact_retry",
                "sqlite_backup_base64",
            ),
            "***not-base64***",
        ),
        (
            (
                "ledger_evidence",
                "after_exact_retry",
                "sqlite_backup_sha256",
            ),
            "00",
        ),
        (
            ("ledger_evidence", "after_exact_retry", "observed_at"),
            "2026-07-23T01:02:03+00:00",
        ),
        (
            (
                "ledger_evidence",
                "after_exact_retry",
                "provider_instance_id",
            ),
            "",
        ),
    ],
)
def test_safepay_evidence_schema_rejects_malformed_evidence(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    artifact = safepay_evidence_artifact()
    _set_path(artifact, path, replacement)

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(artifact)


@pytest.mark.parametrize(
    ("path", "name", "value"),
    [
        (("ledger_evidence",), "passed", True),
        (("ledger_evidence",), "count", 1),
        (
            ("ledger_evidence", "after_cross_binding_reuse"),
            "passed",
            True,
        ),
        (
            ("ledger_evidence", "after_cross_binding_reuse"),
            "count",
            1,
        ),
        (
            ("chain_evidence", "providers", 0, "info_get_status"),
            "derived_confirmation_depth",
            8,
        ),
    ],
)
def test_safepay_evidence_schema_rejects_unmodeled_or_trusted_assertions(
    path: tuple[str | int, ...],
    name: str,
    value: object,
) -> None:
    artifact = safepay_evidence_artifact()
    cursor: Any = artifact
    for part in path:
        cursor = cursor[part]
    cursor[name] = value

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(artifact)


def test_safepay_schema_rejects_legacy_trusted_exact_count() -> None:
    artifact = safepay_evidence_artifact()
    artifact["consumption_rows"]["exact_count"] = 1

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(artifact)
