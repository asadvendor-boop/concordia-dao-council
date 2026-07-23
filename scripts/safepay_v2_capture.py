#!/usr/bin/env python3
"""Assemble the SafePay v2 live-evidence artifact from raw captured inputs.

This tool is deliberately read-only over live systems. It consumes one JSON
"capture bundle" that embeds only *raw* evidence: two-node Casper RPC
transcripts, exact provider redemption exchanges, three actual SQLite online
backups, and two provider runtime identities that straddle a restart. It
independently derives every value the frozen adapter recomputes:

  * the per-quote correlation id, immutable quote hash, report hash and
    fulfillment/response hash (via the frozen ``shared.x402_payments`` crypto),
  * the parsed native transfer, by re-parsing the raw RPC deploy/block/status
    transcripts through the very adapter routine that will judge them,
  * the provider runtime instance ids and the quote, report, consumption, and
    redemption rows read from the supplied immutable SQLite backups,
  * the first-consumption, idempotent-retry, and cross-binding HTTP evidence
    from the supplied raw request and response bytes, and
  * all canonical row digests and base64 encodings.

No producer boolean, count, hash or parsed field from the bundle is trusted:
each is recomputed and cross-checked.  The assembled document is then verified
in-process by ``verify_safepay_v2_artifact`` against its own canonical bytes,
and only on success are those exact canonical bytes written with an atomic,
owner-private, create-once write.  A single inconsistency -- an amount that does
not match the chain, a payee substring, a pending execution, a forged restart,
stale chronology or a malformed row -- makes the tool refuse to emit anything.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from shared.atomic_private_file import AtomicPrivateFileError, write_private_file_once
from shared.release_proof_adapters import (
    ReleaseProofAdapterError,
    _canonical,
    _verify_rpc_providers,
    verify_safepay_v2_artifact,
)
from shared.secure_secret_file import (
    SecureSecretFileError,
    read_secure_secret_file,
)
from shared.x402_payments import (
    SAFEPAY_V2_QUOTE_FIELDS,
    safepay_v2_correlation_id,
    safepay_v2_quote_hash,
)

BUNDLE_VERSION = "concordia.safepay_v2_capture_bundle.v1"
NETWORK = "casper:casper-test"
REPORT_VERSION = "safepay-report-v2"
MEDIA_TYPE = "application/json"
AUTHORITATIVE_DATABASE_ID = "safepay-provider-ledger"
AUTHORITATIVE_SCHEMA_ID = "concordia.safepay-provider-ledger.sqlite.v1"
REDEMPTIONS_PATH = "/x402/v2/redemptions"
_PROVIDER_INSTANCE_DOMAIN = b"CONCORDIA_SAFEPAY_PROVIDER_INSTANCE_V1\x00"

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024

_ROOT = Path(__file__).resolve().parents[1]
_MIGRATION_PATH = _ROOT / "x402_provider" / "migrations" / "0001_safepay_v2.sql"

_RUNTIME_IDENTITY_FIELDS = (
    "container_id",
    "deployment_id",
    "image_digest",
    "started_at",
    "observed_at",
    "restart_count",
)
_QUOTE_ROW_FIELDS = (
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
_CONSUMPTION_ROW_FIELDS = (
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
_REPORT_ROW_FIELDS = (
    "report_hash",
    "report_media_type",
    "report_bytes",
    "decoded_length",
    "created_at",
)
_REDEMPTION_ROW_FIELDS = (
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


class SafePayV2CaptureError(RuntimeError):
    """The raw bundle does not prove a replay-safe SafePay v2 fulfillment."""


# ---------------------------------------------------------------------------
# Strict bundle parsing and typed accessors
# ---------------------------------------------------------------------------


class _DuplicateKey(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _load_bundle_document(raw: bytes, *, limit: int) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise SafePayV2CaptureError("capture bundle is empty or too large")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SafePayV2CaptureError("capture bundle is not strict JSON") from exc
    if type(value) is not dict:
        raise SafePayV2CaptureError("capture bundle must be one JSON object")
    return value


def _obj(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise SafePayV2CaptureError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise SafePayV2CaptureError(f"{label} must be an array")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise SafePayV2CaptureError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    # ``bool`` is a subclass of ``int`` -- reject it so a forged boolean can
    # never masquerade as a chronology field.
    if type(value) is not int:
        raise SafePayV2CaptureError(f"{label} must be an integer")
    return value


def _require_keys(mapping: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(mapping) != expected:
        raise SafePayV2CaptureError(f"{label} keys differ from the frozen bundle shape")


def _canonical_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode_b64(
    value: object, label: str, *, allow_empty: bool = False
) -> bytes:
    text = _text(value, label)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SafePayV2CaptureError(f"{label} is not canonical base64") from exc
    if (
        (not decoded and not allow_empty)
        or base64.b64encode(decoded).decode("ascii") != text
    ):
        raise SafePayV2CaptureError(f"{label} is not canonical base64")
    return decoded


def _parse_utc(value: object, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise SafePayV2CaptureError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SafePayV2CaptureError(f"{label} is not a real UTC instant") from exc
    if parsed.tzinfo != UTC:
        raise SafePayV2CaptureError(f"{label} must be UTC")
    return parsed


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_row_digest(row: Mapping[str, Any]) -> str:
    return _sha(_canonical(row))


# ---------------------------------------------------------------------------
# Derived sub-builders
# ---------------------------------------------------------------------------


def _runtime_identity(raw: object, *, label: str) -> dict[str, Any]:
    identity = _obj(raw, label)
    _require_keys(identity, set(_RUNTIME_IDENTITY_FIELDS), label)
    payload = {field: identity[field] for field in _RUNTIME_IDENTITY_FIELDS}
    _text(payload["container_id"], f"{label} container_id")
    _text(payload["deployment_id"], f"{label} deployment_id")
    _text(payload["image_digest"], f"{label} image_digest")
    _parse_utc(payload["started_at"], f"{label} started_at")
    _parse_utc(payload["observed_at"], f"{label} observed_at")
    _integer(payload["restart_count"], f"{label} restart_count")
    instance_id = _sha(_PROVIDER_INSTANCE_DOMAIN + _canonical(payload))
    return {**payload, "instance_id": instance_id}


def _raw_wire_exchange(
    raw: object,
    *,
    label: str,
    expected_url: str,
    expected_method: str | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    entry = _obj(raw, label)
    expected_keys = {
        "url",
        "request_body_base64",
        "response_status",
        "response_content_type",
        "response_body_base64",
        "observed_at",
    }
    if expected_method is not None:
        expected_keys.add("method")
    _require_keys(entry, expected_keys, label)
    request_bytes = _decode_b64(
        entry["request_body_base64"],
        f"{label} request body",
        allow_empty=True,
    )
    response_bytes = _decode_b64(
        entry["response_body_base64"], f"{label} response body"
    )
    if (
        entry["url"] != expected_url
        or entry["response_content_type"] != MEDIA_TYPE
        or (
            expected_method is not None
            and entry["method"] != expected_method
        )
    ):
        raise SafePayV2CaptureError(
            f"{label} method, URL or content type differs"
        )
    status = _integer(entry["response_status"], f"{label} response status")
    observed_at = _text(entry["observed_at"], f"{label} observed_at")
    _parse_utc(observed_at, f"{label} observed_at")
    request = _load_bundle_document(
        request_bytes, limit=max(1, len(request_bytes))
    )
    response = _load_bundle_document(
        response_bytes, limit=max(1, len(response_bytes))
    )
    exchange: dict[str, Any] = {}
    if expected_method is not None:
        exchange["method"] = expected_method
    exchange.update(
        {
            "url": expected_url,
            "request_body_base64": _canonical_b64(request_bytes),
            "request_body_sha256": _sha(request_bytes),
            "response_status": status,
            "response_content_type": MEDIA_TYPE,
            "response_body_base64": _canonical_b64(response_bytes),
            "response_body_sha256": _sha(response_bytes),
            "observed_at": observed_at,
        }
    )
    return exchange, request, response


def _rpc_provider_observation(raw: object, *, label: str) -> dict[str, Any]:
    provider = _obj(raw, label)
    _require_keys(
        provider,
        {
            "endpoint_id",
            "origin",
            "info_get_deploy",
            "chain_get_block",
            "info_get_status",
        },
        label,
    )
    origin = _text(provider["origin"], f"{label} origin")
    exchanges: dict[str, Any] = {}
    for method in ("info_get_deploy", "chain_get_block", "info_get_status"):
        exchange, _request, _response = _raw_wire_exchange(
            provider[method],
            label=f"{label} {method}",
            expected_url=origin,
            expected_method=None,
        )
        exchanges[method] = exchange
    return {
        "endpoint_id": _text(provider["endpoint_id"], f"{label} endpoint_id"),
        "origin": origin,
        "info_get_deploy": exchanges["info_get_deploy"],
        "chain_get_block": exchanges["chain_get_block"],
        "info_get_status": exchanges["info_get_status"],
    }


def _derive_parsed_transfer(
    *, payment_hash: str, providers: Sequence[dict[str, Any]], captured_at: datetime
) -> dict[str, Any]:
    chain = {"payment_hash": payment_hash, "providers": list(providers)}
    try:
        observation, _endpoints = _verify_rpc_providers(chain, captured_at=captured_at)
    except ReleaseProofAdapterError as exc:
        raise SafePayV2CaptureError(
            f"raw RPC transcripts do not prove a finalized native transfer: {exc}"
        ) from exc
    return {
        "network": NETWORK,
        "payment_hash": observation["payment_hash"],
        "block_hash": observation["block_hash"],
        "block_height": observation["block_height"],
        "state_root_hash": observation["state_root_hash"],
        "block_timestamp": observation["block_timestamp"],
        "execution_status": "processed",
        "finality_status": "finalized",
        "execution_error": None,
        "native_transfer_count": observation["native_transfer_count"],
        "source_account_hash": observation["source_account_hash"],
        "payee_account_hash": observation["payee_account_hash"],
        "amount_motes": observation["amount_motes"],
        "transfer_id": observation["transfer_id"],
    }


def _one_sqlite_row(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[object, ...],
    *,
    label: str,
) -> dict[str, Any]:
    rows = connection.execute(query, parameters).fetchall()
    if len(rows) != 1:
        raise SafePayV2CaptureError(f"{label} is not exactly one persisted row")
    return dict(rows[0])


def _ledger_snapshot(
    raw: object,
    *,
    label: str,
    network: str,
    payment_hash: str,
    quote_id: str,
) -> dict[str, Any]:
    value = _obj(raw, label)
    _require_keys(value, {"sqlite_backup_base64", "observed_at"}, label)
    backup = _decode_b64(value["sqlite_backup_base64"], f"{label} SQLite backup")
    observed_at = _text(value["observed_at"], f"{label} observed_at")
    _parse_utc(observed_at, f"{label} observed_at")

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.deserialize(backup)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [
            ("ok",)
        ]:
            raise SafePayV2CaptureError(f"{label} SQLite integrity check failed")
        quote_row = _one_sqlite_row(
            connection,
            "SELECT quote_id, proposal_id, resource_id, network, "
            "payee_account_hash, amount_motes, correlation_id, report_version, "
            "report_hash, issued_at, expires_at, quote_nonce, quote_hash "
            "FROM safepay_quotes WHERE quote_id = ?",
            (quote_id,),
            label=f"{label} quote",
        )
        consumption_row = _one_sqlite_row(
            connection,
            "SELECT network, payment_hash, quote_id, proposal_id, resource_id, "
            "quote_hash, report_hash, correlation_id, fulfillment_json, "
            "response_hash, consumed_at FROM payment_consumptions "
            "WHERE network = ? AND payment_hash = ?",
            (network, payment_hash),
            label=f"{label} consumption",
        )
        report_row = _one_sqlite_row(
            connection,
            "SELECT report_hash, report_media_type, report_bytes, decoded_length, "
            "created_at FROM safepay_reports WHERE report_hash = ?",
            (quote_row["report_hash"],),
            label=f"{label} report",
        )
        redemption_rows = [
            dict(row)
            for row in connection.execute(
                "SELECT kind, http_status, network, payment_hash, quote_id, "
                "resource_id, observed_at, response_digest, "
                "consumed_response_hash FROM safepay_redemption_observations "
                "WHERE network = ? AND payment_hash = ? ORDER BY observation_id",
                (network, payment_hash),
            ).fetchall()
        ]
    except sqlite3.Error as exc:
        raise SafePayV2CaptureError(
            f"{label} is not a readable authoritative SQLite backup"
        ) from exc
    finally:
        connection.close()

    if (
        set(quote_row) != set(_QUOTE_ROW_FIELDS)
        or set(consumption_row) != set(_CONSUMPTION_ROW_FIELDS)
        or set(report_row) != set(_REPORT_ROW_FIELDS)
        or any(set(row) != set(_REDEMPTION_ROW_FIELDS) for row in redemption_rows)
    ):
        raise SafePayV2CaptureError(f"{label} rows differ from the frozen ledger shape")
    return {
        "backup": backup,
        "observed_at": observed_at,
        "quote_row": quote_row,
        "consumption_row": consumption_row,
        "report_row": report_row,
        "redemption_rows": redemption_rows,
    }


def _row_observation(
    row: Mapping[str, Any],
    *,
    observed_at: str,
    provider_instance_id: str,
) -> dict[str, Any]:
    return {
        "row": dict(row),
        "row_canonical_json_sha256": _canonical_row_digest(row),
        "observed_at": observed_at,
        "provider_instance_id": provider_instance_id,
    }


def _snapshot_artifact(
    snapshot: Mapping[str, Any], *, provider_instance_id: str
) -> dict[str, Any]:
    backup = snapshot["backup"]
    if type(backup) is not bytes:
        raise SafePayV2CaptureError("ledger backup bytes are unavailable")
    return {
        "sqlite_backup_base64": _canonical_b64(backup),
        "sqlite_backup_sha256": _sha(backup),
        "observed_at": snapshot["observed_at"],
        "provider_instance_id": provider_instance_id,
    }


def _epoch_utc(value: object, *, label: str) -> str:
    seconds = _integer(value, label)
    if seconds < 0:
        raise SafePayV2CaptureError(f"{label} must be non-negative")
    try:
        return (
            datetime.fromtimestamp(seconds, UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise SafePayV2CaptureError(f"{label} is outside the UTC timestamp range") from exc


# ---------------------------------------------------------------------------
# Top-level artifact assembly
# ---------------------------------------------------------------------------


def build_safepay_v2_artifact(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Return one self-verified SafePay v2 artifact derived from a raw bundle.

    Every hash, parsed field, row digest and instance id is recomputed from the
    raw inputs; nothing the producer asserted is trusted.  The assembled
    document is verified in-process by the frozen adapter against its own
    canonical bytes and is returned only when that verification succeeds.
    """

    if type(bundle) is not dict:
        raise SafePayV2CaptureError("capture bundle must be one JSON object")
    _require_keys(
        bundle,
        {
            "bundle_version",
            "captured_at",
            "source_commit",
            "deployment_commit",
            "provider",
            "chain",
            "redemptions",
            "ledger_snapshots_observed",
        },
        "capture bundle",
    )
    if bundle["bundle_version"] != BUNDLE_VERSION:
        raise SafePayV2CaptureError("capture bundle version is not recognised")

    captured_at = _text(bundle["captured_at"], "captured_at")
    captured_instant = _parse_utc(captured_at, "captured_at")
    source_commit = _text(bundle["source_commit"], "source_commit")
    deployment_commit = _text(bundle["deployment_commit"], "deployment_commit")

    # -- provider identity + ordered restart instances -----------------------
    provider = _obj(bundle["provider"], "provider")
    _require_keys(
        provider,
        {"url", "deployment_id", "image_digest", "instances"},
        "provider",
    )
    provider_url = _text(provider["url"], "provider url")
    instances = _obj(provider["instances"], "provider instances")
    _require_keys(instances, {"before_restart", "after_restart"}, "provider instances")
    before_identity = _runtime_identity(
        instances["before_restart"], label="provider runtime identity before restart"
    )
    after_identity = _runtime_identity(
        instances["after_restart"], label="provider runtime identity after restart"
    )
    before_instance_id = before_identity["instance_id"]
    after_instance_id = after_identity["instance_id"]

    capture_identity = {
        "provider_url": provider_url,
        "provider_deployment_id": _text(
            provider["deployment_id"], "provider deployment_id"
        ),
        "provider_image_digest": _text(
            provider["image_digest"], "provider image_digest"
        ),
        "capture_tool_commit": source_commit,
        "provider_instances": {
            "before_restart": before_identity,
            "after_restart": after_identity,
        },
    }

    # -- exact provider HTTP exchanges --------------------------------------
    redemption_input = _obj(bundle["redemptions"], "redemptions")
    redemption_names = (
        "first_consumption",
        "exact_retry",
        "cross_binding_reuse",
    )
    _require_keys(redemption_input, set(redemption_names), "redemptions")
    redemption_exchanges: dict[str, dict[str, Any]] = {}
    redemption_requests: dict[str, dict[str, Any]] = {}
    redemption_url = provider_url.rstrip("/") + REDEMPTIONS_PATH
    for name in redemption_names:
        item = _obj(redemption_input[name], f"{name} redemption")
        _require_keys(item, {"exchange"}, f"{name} redemption")
        exchange, request, _response = _raw_wire_exchange(
            item["exchange"],
            label=f"{name} redemption exchange",
            expected_url=redemption_url,
            expected_method="POST",
        )
        redemption_exchanges[name] = exchange
        redemption_requests[name] = request

    first_request = redemption_requests["first_consumption"]
    _require_keys(
        first_request,
        {"network", "payment_hash", "quote_id", "resource_id"},
        "first redemption request",
    )
    network = _text(first_request["network"], "first redemption network")
    if network != NETWORK:
        raise SafePayV2CaptureError("first redemption network is not casper:casper-test")
    payment_hash = _text(
        first_request["payment_hash"], "first redemption payment_hash"
    )
    quote_id = _text(first_request["quote_id"], "first redemption quote_id")

    # -- chain evidence: parse the raw two-node transcripts ------------------
    chain_input = _obj(bundle["chain"], "chain")
    _require_keys(chain_input, {"payment_hash", "providers"}, "chain")
    if _text(chain_input["payment_hash"], "payment_hash") != payment_hash:
        raise SafePayV2CaptureError(
            "chain payment hash differs from the raw redemption request"
        )
    raw_providers = _list(chain_input["providers"], "chain providers")
    if len(raw_providers) != 2:
        raise SafePayV2CaptureError("exactly two RPC provider transcripts are required")
    providers = [
        _rpc_provider_observation(raw, label=f"chain provider {index}")
        for index, raw in enumerate(raw_providers)
    ]
    parsed_transfer = _derive_parsed_transfer(
        payment_hash=payment_hash,
        providers=providers,
        captured_at=captured_instant,
    )
    chain_evidence = {
        "network": NETWORK,
        "payment_hash": payment_hash,
        "providers": providers,
        "parsed_transfer": parsed_transfer,
    }

    # -- actual progressive SQLite backups ----------------------------------
    snapshots_input = _obj(
        bundle["ledger_snapshots_observed"], "ledger_snapshots_observed"
    )
    stage_specs = (
        ("after_first_consumption", 1, before_instance_id),
        ("after_exact_retry", 2, before_instance_id),
        ("after_cross_binding_reuse", 3, after_instance_id),
    )
    _require_keys(
        snapshots_input,
        {stage for stage, _count, _instance in stage_specs},
        "ledger_snapshots_observed",
    )
    snapshots: dict[str, dict[str, Any]] = {}
    for stage, expected_count, _instance_id in stage_specs:
        snapshot = _ledger_snapshot(
            snapshots_input[stage],
            label=f"ledger {stage}",
            network=network,
            payment_hash=payment_hash,
            quote_id=quote_id,
        )
        if len(snapshot["redemption_rows"]) != expected_count:
            raise SafePayV2CaptureError(
                f"ledger {stage} does not contain the expected redemption progression"
            )
        snapshots[stage] = snapshot

    first_snapshot = snapshots["after_first_consumption"]
    final_snapshot = snapshots["after_cross_binding_reuse"]
    for stage, expected_count, _instance_id in stage_specs:
        snapshot = snapshots[stage]
        if (
            snapshot["quote_row"] != first_snapshot["quote_row"]
            or snapshot["consumption_row"] != first_snapshot["consumption_row"]
            or snapshot["report_row"] != first_snapshot["report_row"]
            or snapshot["redemption_rows"]
            != final_snapshot["redemption_rows"][:expected_count]
        ):
            raise SafePayV2CaptureError(
                f"ledger {stage} is not an append-only progression of one fulfillment"
            )

    quote_row = first_snapshot["quote_row"]
    consumption_row = first_snapshot["consumption_row"]
    report_row = first_snapshot["report_row"]
    report_bytes = report_row["report_bytes"]
    if type(report_bytes) is not bytes:
        raise SafePayV2CaptureError("persisted report bytes are not a SQLite BLOB")
    if (
        report_row["report_media_type"] != MEDIA_TYPE
        or report_row["decoded_length"] != len(report_bytes)
        or report_row["report_hash"] != _sha(report_bytes)
        or quote_row["report_hash"] != report_row["report_hash"]
        or consumption_row["report_hash"] != report_row["report_hash"]
    ):
        raise SafePayV2CaptureError(
            "persisted report bytes, length, media type, or binding differ"
        )

    # -- quote crypto from the persisted row --------------------------------
    quote_nonce_hex = _text(quote_row["quote_nonce"], "persisted quote_nonce")
    try:
        quote_nonce = bytes.fromhex(quote_nonce_hex)
        correlation_id = safepay_v2_correlation_id(
            quote_row["quote_id"],
            quote_row["proposal_id"],
            quote_row["resource_id"],
            quote_nonce,
        )
        quote_hash = safepay_v2_quote_hash(
            quote_id=quote_row["quote_id"],
            proposal_id=quote_row["proposal_id"],
            resource_id=quote_row["resource_id"],
            network=quote_row["network"],
            payee_account_hash=quote_row["payee_account_hash"],
            amount_motes=quote_row["amount_motes"],
            correlation_id=correlation_id,
            report_version=quote_row["report_version"],
            report_hash=quote_row["report_hash"],
            expires_at=quote_row["expires_at"],
            quote_nonce=quote_nonce,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SafePayV2CaptureError(f"persisted quote preimage is invalid: {exc}") from exc
    if (
        quote_row["network"] != NETWORK
        or quote_row["quote_id"] != quote_id
        or quote_row["correlation_id"] != str(correlation_id)
        or quote_row["quote_hash"] != quote_hash
        or quote_row["report_version"] != REPORT_VERSION
    ):
        raise SafePayV2CaptureError(
            "persisted quote differs from its frozen cryptographic preimage"
        )
    quote = {
        "schema_version": "safepay-v2",
        **{field: quote_row[field] for field in _QUOTE_ROW_FIELDS if field != "issued_at"},
    }
    if set(quote) != set(SAFEPAY_V2_QUOTE_FIELDS):
        raise SafePayV2CaptureError(
            "persisted quote fields differ from the frozen schema"
        )

    # -- persisted fulfillment and protected report -------------------------
    fulfillment_json = _text(
        consumption_row["fulfillment_json"], "persisted fulfillment_json"
    )
    fulfillment = _load_bundle_document(
        fulfillment_json.encode("utf-8"),
        limit=max(1, len(fulfillment_json.encode("utf-8"))),
    )
    report_projection = {
        "report_version": quote["report_version"],
        "proposal_id": quote["proposal_id"],
        "resource_id": quote["resource_id"],
        "correlation_id": quote["correlation_id"],
        "media_type": report_row["report_media_type"],
        "content_base64": _canonical_b64(report_bytes),
        "report_hash": report_row["report_hash"],
    }
    if fulfillment.get("report") != report_projection:
        raise SafePayV2CaptureError(
            "persisted fulfillment report differs from the authoritative report row"
        )
    protected_report = {
        **report_projection,
        "decoded_length": report_row["decoded_length"],
        "response_hash": consumption_row["response_hash"],
        "persisted_at": _epoch_utc(
            report_row["created_at"], label="persisted report created_at"
        ),
        "released_at": redemption_exchanges["first_consumption"]["observed_at"],
    }

    # -- durable rows and exact HTTP observations ----------------------------
    issued_quote_rows = {
        "before_restart": _row_observation(
            quote_row,
            observed_at=first_snapshot["observed_at"],
            provider_instance_id=before_instance_id,
        ),
        "after_restart": _row_observation(
            quote_row,
            observed_at=final_snapshot["observed_at"],
            provider_instance_id=after_instance_id,
        ),
    }
    consumption_rows = {
        "before_restart": _row_observation(
            consumption_row,
            observed_at=first_snapshot["observed_at"],
            provider_instance_id=before_instance_id,
        ),
        "after_restart": _row_observation(
            consumption_row,
            observed_at=final_snapshot["observed_at"],
            provider_instance_id=after_instance_id,
        ),
    }
    redemptions = {
        name: {
            **final_snapshot["redemption_rows"][index],
            "exchange": redemption_exchanges[name],
        }
        for index, name in enumerate(redemption_names)
    }

    try:
        migration = _MIGRATION_PATH.read_bytes()
    except OSError as exc:
        raise SafePayV2CaptureError(
            "repository ledger migration is unavailable"
        ) from exc
    ledger_evidence = {
        "authoritative_database_id": AUTHORITATIVE_DATABASE_ID,
        "authoritative_schema_id": AUTHORITATIVE_SCHEMA_ID,
        "migration_sql_base64": _canonical_b64(migration),
        "migration_sql_sha256": _sha(migration),
        **{
            stage: _snapshot_artifact(
                snapshots[stage], provider_instance_id=instance_id
            )
            for stage, _count, instance_id in stage_specs
        },
    }

    document = {
        "schema_version": "safepay-v2",
        "captured_at": captured_at,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "capture_identity": capture_identity,
        "quote": quote,
        "issued_quote_rows": issued_quote_rows,
        "chain_evidence": chain_evidence,
        "consumption_rows": consumption_rows,
        "ledger_evidence": ledger_evidence,
        "redemption_observations": redemptions,
        "protected_report": protected_report,
    }

    # -- self-verify against the frozen in-process adapter -------------------
    raw_bytes = _canonical(document)
    try:
        verify_safepay_v2_artifact(document, raw_bytes)
    except ReleaseProofAdapterError as exc:
        raise SafePayV2CaptureError(f"assembled artifact failed self-verification: {exc}") from exc
    return document


def canonical_artifact_bytes(document: Mapping[str, Any]) -> bytes:
    """Return the exact canonical bytes the adapter binds the document to."""

    return _canonical(document)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _read_bundle_bytes(path_value: str, *, limit: int) -> bytes:
    if path_value == "-":
        raise SafePayV2CaptureError(
            "capture bundle must be an absolute owner-private file, not stdin"
        )
    path = Path(path_value)
    if not path.is_absolute():
        raise SafePayV2CaptureError("capture bundle path must be absolute")
    try:
        return read_secure_secret_file(path, max_bytes=limit)
    except SecureSecretFileError as exc:
        raise SafePayV2CaptureError(
            f"capture bundle could not be read securely: {exc}"
        ) from exc


def capture(*, bundle_path: str, output_path: str) -> dict[str, Any]:
    """Build, self-verify and durably write one SafePay v2 artifact."""

    bundle = _load_bundle_document(
        _read_bundle_bytes(bundle_path, limit=MAX_BUNDLE_BYTES),
        limit=MAX_BUNDLE_BYTES,
    )
    document = build_safepay_v2_artifact(bundle)
    payload = canonical_artifact_bytes(document)
    if not payload or len(payload) > MAX_OUTPUT_BYTES:
        raise SafePayV2CaptureError("assembled artifact is empty or too large")
    output = Path(output_path)
    if not output.is_absolute():
        raise SafePayV2CaptureError("artifact output path must be absolute")
    try:
        write_private_file_once(output, payload)
    except AtomicPrivateFileError as exc:
        raise SafePayV2CaptureError(f"artifact could not be written safely: {exc}") from exc
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser(
        "capture", help="assemble and verify a SafePay v2 artifact from a raw bundle"
    )
    capture_parser.add_argument(
        "--bundle",
        required=True,
        help="absolute path to an owner-private capture bundle JSON file",
    )
    capture_parser.add_argument(
        "--output", required=True, help="absolute artifact output path (create-once)"
    )
    args = parser.parse_args(argv)
    if args.command == "capture":
        try:
            capture(bundle_path=args.bundle, output_path=args.output)
        except SafePayV2CaptureError as exc:
            print(f"safepay v2 capture failed: {exc}", file=sys.stderr)
            return 1
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":  # pragma: no cover - exercised through the operator CLI
    raise SystemExit(main())
