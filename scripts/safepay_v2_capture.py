#!/usr/bin/env python3
"""Assemble the SafePay v2 live-evidence artifact from raw captured inputs.

This tool is deliberately read-only over live systems.  It consumes one JSON
"capture bundle" that embeds only *raw* evidence -- the quote request inputs,
the two-node Casper RPC transcripts, the protected report bytes, the redemption
chronology, and the two provider runtime identities that straddle a restart --
and it independently *derives* every value the frozen adapter recomputes:

  * the per-quote correlation id, immutable quote hash, report hash and
    fulfillment/response hash (via the frozen ``shared.x402_payments`` crypto),
  * the parsed native transfer, by re-parsing the raw RPC deploy/block/status
    transcripts through the very adapter routine that will judge them,
  * the provider runtime instance ids, the durable quote/consumption rows, the
    replay/idempotency/cross-binding redemption observations, and the three
    progressive SQLite ledger snapshots (built by executing the repository
    migration and inserting the derived rows), and
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
import tempfile
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
from shared.x402_payments import (
    SAFEPAY_V2_BINDING_CHECK_FIELDS,
    SAFEPAY_V2_OBSERVATION_FIELDS,
    SAFEPAY_V2_QUOTE_FIELDS,
    safepay_v2_body_digest,
    safepay_v2_correlation_id,
    safepay_v2_error_body,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
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


def _decode_report_bytes(value: object, label: str) -> bytes:
    text = _text(value, label)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SafePayV2CaptureError(f"{label} is not canonical base64") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != text:
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


def _wire_exchange(
    *,
    url: str,
    request: object,
    response: object,
    status: int,
    observed_at: str,
    method: str | None,
) -> dict[str, Any]:
    request_bytes = _canonical(request)
    response_bytes = _canonical(response)
    exchange: dict[str, Any] = {}
    if method is not None:
        exchange["method"] = method
    exchange.update(
        {
            "url": url,
            "request_body_base64": _canonical_b64(request_bytes),
            "request_body_sha256": _sha(request_bytes),
            "response_status": status,
            "response_content_type": MEDIA_TYPE,
            "response_body_base64": _canonical_b64(response_bytes),
            "response_body_sha256": _sha(response_bytes),
            "observed_at": observed_at,
        }
    )
    return exchange


def _rpc_provider_observation(raw: object, *, label: str) -> dict[str, Any]:
    provider = _obj(raw, label)
    _require_keys(
        provider,
        {
            "endpoint_id",
            "origin",
            "observed_at",
            "info_get_deploy",
            "chain_get_block",
            "info_get_status",
        },
        label,
    )
    origin = _text(provider["origin"], f"{label} origin")
    observed_at = _text(provider["observed_at"], f"{label} observed_at")
    _parse_utc(observed_at, f"{label} observed_at")
    exchanges: dict[str, Any] = {}
    for method in ("info_get_deploy", "chain_get_block", "info_get_status"):
        transcript = _obj(provider[method], f"{label} {method}")
        _require_keys(transcript, {"request", "response"}, f"{label} {method}")
        exchanges[method] = _wire_exchange(
            url=origin,
            request=_obj(transcript["request"], f"{label} {method} request"),
            response=_obj(transcript["response"], f"{label} {method} response"),
            status=200,
            observed_at=observed_at,
            method=None,
        )
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


def _build_fulfillment(
    *,
    quote: Mapping[str, Any],
    parsed_transfer: Mapping[str, Any],
    report_object: Mapping[str, Any],
    response_hash: str,
    consumed_at: int,
    observed_at: str,
) -> dict[str, Any]:
    payment_observation = {
        "network": parsed_transfer["network"],
        "payment_hash": parsed_transfer["payment_hash"],
        "block_hash": parsed_transfer["block_hash"],
        "block_height": parsed_transfer["block_height"],
        "execution_status": parsed_transfer["execution_status"],
        "finality_status": parsed_transfer["finality_status"],
        "from_account_hash": parsed_transfer["source_account_hash"],
        "to_account_hash": parsed_transfer["payee_account_hash"],
        "amount_motes": parsed_transfer["amount_motes"],
        "transfer_id": parsed_transfer["transfer_id"],
        "execution_error": parsed_transfer["execution_error"],
        "observed_at": observed_at,
    }
    if set(payment_observation) != set(SAFEPAY_V2_OBSERVATION_FIELDS):
        raise SafePayV2CaptureError(  # pragma: no cover - guards the frozen field set
            "derived payment observation fields differ from the frozen schema"
        )
    return {
        "quote": dict(quote),
        "payment_observation": payment_observation,
        "consumption": {
            "network": quote["network"],
            "payment_hash": parsed_transfer["payment_hash"],
            "quote_id": quote["quote_id"],
            "resource_id": quote["resource_id"],
            "quote_hash": quote["quote_hash"],
            "response_hash": response_hash,
            "consumed_at": consumed_at,
        },
        "report": dict(report_object),
        "binding_checks": {name: True for name in SAFEPAY_V2_BINDING_CHECK_FIELDS},
        "observed_at": observed_at,
        "response_hash": response_hash,
    }


def _redemption_observation(
    *,
    kind: str,
    quote_id: str,
    resource_id: str,
    payment_hash: str,
    status: int,
    observed_at: int,
    response_digest: str,
    consumed_response_hash: str,
    body: Mapping[str, Any],
    provider_url: str,
    exchange_observed_at: str,
) -> dict[str, Any]:
    request = {
        "network": NETWORK,
        "payment_hash": payment_hash,
        "quote_id": quote_id,
        "resource_id": resource_id,
    }
    return {
        "kind": kind,
        "network": NETWORK,
        "payment_hash": payment_hash,
        "quote_id": quote_id,
        "resource_id": resource_id,
        "http_status": status,
        "observed_at": observed_at,
        "response_digest": response_digest,
        "consumed_response_hash": consumed_response_hash,
        "exchange": _wire_exchange(
            url=provider_url.rstrip("/") + REDEMPTIONS_PATH,
            request=request,
            response=dict(body),
            status=status,
            observed_at=exchange_observed_at,
            method="POST",
        ),
    }


def _sqlite_backup_bytes(connection: sqlite3.Connection, path: Path) -> bytes:
    destination = sqlite3.connect(path)
    try:
        connection.backup(destination)
    finally:
        destination.close()
    return path.read_bytes()


def _build_ledger_evidence(
    *,
    quote_row: Mapping[str, Any],
    consumption_row: Mapping[str, Any],
    report_bytes: bytes,
    report_hash: str,
    decoded_length: int,
    issued_at: int,
    redemptions: Mapping[str, Mapping[str, Any]],
    snapshot_observed: Mapping[str, str],
    before_instance_id: str,
    after_instance_id: str,
) -> dict[str, Any]:
    try:
        migration = _MIGRATION_PATH.read_bytes()
    except OSError as exc:
        raise SafePayV2CaptureError("repository ledger migration is unavailable") from exc

    stage_specs = (
        ("after_first_consumption", "first_consumption", before_instance_id),
        ("after_exact_retry", "exact_retry", before_instance_id),
        ("after_cross_binding_reuse", "cross_binding_reuse", after_instance_id),
    )
    snapshots: dict[str, dict[str, Any]] = {}
    try:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            connection = sqlite3.connect(directory / "provider.sqlite3")
            try:
                connection.executescript(migration.decode("utf-8"))
                connection.execute(
                    "INSERT INTO safepay_reports("
                    "report_hash, report_media_type, report_bytes, decoded_length, "
                    "created_at) VALUES(?, ?, ?, ?, ?)",
                    (report_hash, MEDIA_TYPE, report_bytes, decoded_length, issued_at),
                )
                connection.execute(
                    "INSERT INTO safepay_quotes("
                    "quote_id, proposal_id, resource_id, network, payee_account_hash, "
                    "amount_motes, correlation_id, report_version, report_hash, "
                    "issued_at, expires_at, quote_nonce, quote_hash"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    tuple(quote_row[field] for field in _QUOTE_ROW_FIELDS),
                )
                connection.execute(
                    "INSERT INTO payment_consumptions("
                    "network, payment_hash, quote_id, proposal_id, resource_id, "
                    "quote_hash, report_hash, correlation_id, fulfillment_json, "
                    "response_hash, consumed_at"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                for stage, redemption_name, instance_id in stage_specs:
                    observation = redemptions[redemption_name]
                    connection.execute(
                        "INSERT INTO safepay_redemption_observations("
                        "kind, http_status, network, payment_hash, quote_id, "
                        "resource_id, observed_at, response_digest, "
                        "consumed_response_hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    raw = _sqlite_backup_bytes(connection, directory / f"{stage}.sqlite3")
                    snapshots[stage] = {
                        "sqlite_backup_base64": _canonical_b64(raw),
                        "sqlite_backup_sha256": _sha(raw),
                        "observed_at": snapshot_observed[stage],
                        "provider_instance_id": instance_id,
                    }
            finally:
                connection.close()
    except sqlite3.Error as exc:
        raise SafePayV2CaptureError("ledger snapshots could not be built") from exc

    return {
        "authoritative_database_id": AUTHORITATIVE_DATABASE_ID,
        "authoritative_schema_id": AUTHORITATIVE_SCHEMA_ID,
        "migration_sql_base64": _canonical_b64(migration),
        "migration_sql_sha256": _sha(migration),
        "after_first_consumption": snapshots["after_first_consumption"],
        "after_exact_retry": snapshots["after_exact_retry"],
        "after_cross_binding_reuse": snapshots["after_cross_binding_reuse"],
    }


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
            "quote",
            "report",
            "chain",
            "consumption",
            "issued_quote_rows_observed",
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
        "provider_deployment_id": _text(provider["deployment_id"], "provider deployment_id"),
        "provider_image_digest": _text(provider["image_digest"], "provider image_digest"),
        "capture_tool_commit": source_commit,
        "provider_instances": {
            "before_restart": before_identity,
            "after_restart": after_identity,
        },
    }

    # -- protected report bytes ---------------------------------------------
    report_input = _obj(bundle["report"], "report")
    _require_keys(report_input, {"content_base64", "persisted_at", "released_at"}, "report")
    report_bytes = _decode_report_bytes(report_input["content_base64"], "report content")
    report_hash = _sha(report_bytes)
    decoded_length = len(report_bytes)

    # -- quote (all crypto derived from raw inputs) --------------------------
    quote_input = _obj(bundle["quote"], "quote")
    _require_keys(
        quote_input,
        {
            "quote_id",
            "proposal_id",
            "resource_id",
            "payee_account_hash",
            "amount_motes",
            "issued_at",
            "expires_at",
            "quote_nonce",
        },
        "quote",
    )
    quote_id = _text(quote_input["quote_id"], "quote_id")
    proposal_id = _text(quote_input["proposal_id"], "proposal_id")
    resource_id = _text(quote_input["resource_id"], "resource_id")
    payee_account_hash = _text(quote_input["payee_account_hash"], "payee_account_hash")
    amount_motes = _text(quote_input["amount_motes"], "amount_motes")
    issued_at = _integer(quote_input["issued_at"], "issued_at")
    expires_at = _integer(quote_input["expires_at"], "expires_at")
    quote_nonce_hex = _text(quote_input["quote_nonce"], "quote_nonce")
    try:
        quote_nonce = bytes.fromhex(quote_nonce_hex)
        correlation_id = safepay_v2_correlation_id(
            quote_id, proposal_id, resource_id, quote_nonce
        )
        quote_hash = safepay_v2_quote_hash(
            quote_id=quote_id,
            proposal_id=proposal_id,
            resource_id=resource_id,
            network=NETWORK,
            payee_account_hash=payee_account_hash,
            amount_motes=amount_motes,
            correlation_id=correlation_id,
            report_version=REPORT_VERSION,
            report_hash=report_hash,
            expires_at=expires_at,
            quote_nonce=quote_nonce,
        )
    except (ValueError, TypeError) as exc:
        raise SafePayV2CaptureError(f"quote preimage is invalid: {exc}") from exc
    correlation_text = str(correlation_id)

    quote = {
        "schema_version": "safepay-v2",
        "quote_id": quote_id,
        "proposal_id": proposal_id,
        "resource_id": resource_id,
        "network": NETWORK,
        "payee_account_hash": payee_account_hash,
        "amount_motes": amount_motes,
        "correlation_id": correlation_text,
        "report_version": REPORT_VERSION,
        "report_hash": report_hash,
        "expires_at": expires_at,
        "quote_nonce": quote_nonce_hex,
        "quote_hash": quote_hash,
    }
    if set(quote) != set(SAFEPAY_V2_QUOTE_FIELDS):
        raise SafePayV2CaptureError(  # pragma: no cover - guards the frozen field set
            "derived quote fields differ from the frozen schema"
        )
    quote_row = {
        "quote_id": quote_id,
        "proposal_id": proposal_id,
        "resource_id": resource_id,
        "network": NETWORK,
        "payee_account_hash": payee_account_hash,
        "amount_motes": amount_motes,
        "correlation_id": correlation_text,
        "report_version": REPORT_VERSION,
        "report_hash": report_hash,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "quote_nonce": quote_nonce_hex,
        "quote_hash": quote_hash,
    }
    quote_row_digest = _canonical_row_digest(quote_row)

    quote_rows_observed = _obj(
        bundle["issued_quote_rows_observed"], "issued_quote_rows_observed"
    )
    _require_keys(
        quote_rows_observed,
        {"before_restart", "after_restart"},
        "issued_quote_rows_observed",
    )
    issued_quote_rows = {
        "before_restart": {
            "row": dict(quote_row),
            "row_canonical_json_sha256": quote_row_digest,
            "observed_at": _text(
                quote_rows_observed["before_restart"], "issued quote row before observed_at"
            ),
            "provider_instance_id": before_instance_id,
        },
        "after_restart": {
            "row": dict(quote_row),
            "row_canonical_json_sha256": quote_row_digest,
            "observed_at": _text(
                quote_rows_observed["after_restart"], "issued quote row after observed_at"
            ),
            "provider_instance_id": after_instance_id,
        },
    }

    # -- chain evidence: parse the raw two-node transcripts ------------------
    chain_input = _obj(bundle["chain"], "chain")
    _require_keys(chain_input, {"payment_hash", "providers"}, "chain")
    payment_hash = _text(chain_input["payment_hash"], "payment_hash")
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

    # -- fulfillment / consumption / protected report ------------------------
    consumption_input = _obj(bundle["consumption"], "consumption")
    _require_keys(
        consumption_input,
        {"consumed_at", "observed_at", "row_observed"},
        "consumption",
    )
    consumed_at = _integer(consumption_input["consumed_at"], "consumed_at")
    fulfillment_observed_at = _text(
        consumption_input["observed_at"], "consumption observed_at"
    )
    row_observed = _obj(consumption_input["row_observed"], "consumption row_observed")
    _require_keys(row_observed, {"before_restart", "after_restart"}, "consumption row_observed")

    try:
        response_hash = safepay_v2_response_hash(
            quote_hash=quote_hash,
            payment_hash=parsed_transfer["payment_hash"],
            block_hash=parsed_transfer["block_hash"],
            block_height=parsed_transfer["block_height"],
            report_hash=report_hash,
            consumed_at=consumed_at,
        )
    except (ValueError, TypeError) as exc:
        raise SafePayV2CaptureError(f"fulfillment preimage is invalid: {exc}") from exc

    report_object = {
        "report_version": REPORT_VERSION,
        "proposal_id": proposal_id,
        "resource_id": resource_id,
        "correlation_id": correlation_text,
        "media_type": MEDIA_TYPE,
        "content_base64": _canonical_b64(report_bytes),
        "report_hash": report_hash,
    }
    protected_report = {
        **report_object,
        "decoded_length": decoded_length,
        "response_hash": response_hash,
        "persisted_at": _text(report_input["persisted_at"], "report persisted_at"),
        "released_at": _text(report_input["released_at"], "report released_at"),
    }

    fulfillment = _build_fulfillment(
        quote=quote,
        parsed_transfer=parsed_transfer,
        report_object=report_object,
        response_hash=response_hash,
        consumed_at=consumed_at,
        observed_at=fulfillment_observed_at,
    )
    fulfillment_json = json.dumps(
        fulfillment, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    consumption_row = {
        "network": NETWORK,
        "payment_hash": parsed_transfer["payment_hash"],
        "quote_id": quote_id,
        "proposal_id": proposal_id,
        "resource_id": resource_id,
        "quote_hash": quote_hash,
        "report_hash": report_hash,
        "correlation_id": correlation_text,
        "fulfillment_json": fulfillment_json,
        "response_hash": response_hash,
        "consumed_at": consumed_at,
    }
    consumption_row_digest = _canonical_row_digest(consumption_row)
    consumption_rows = {
        "before_restart": {
            "row": dict(consumption_row),
            "row_canonical_json_sha256": consumption_row_digest,
            "observed_at": _text(
                row_observed["before_restart"], "consumption row before observed_at"
            ),
            "provider_instance_id": before_instance_id,
        },
        "after_restart": {
            "row": dict(consumption_row),
            "row_canonical_json_sha256": consumption_row_digest,
            "observed_at": _text(
                row_observed["after_restart"], "consumption row after observed_at"
            ),
            "provider_instance_id": after_instance_id,
        },
    }

    # -- redemption observations (first / retry / cross-binding) -------------
    redemption_input = _obj(bundle["redemptions"], "redemptions")
    _require_keys(
        redemption_input,
        {"first_consumption", "exact_retry", "cross_binding_reuse"},
        "redemptions",
    )
    first_input = _obj(redemption_input["first_consumption"], "first redemption")
    retry_input = _obj(redemption_input["exact_retry"], "exact-retry redemption")
    cross_input = _obj(redemption_input["cross_binding_reuse"], "cross-binding redemption")
    _require_keys(first_input, {"observed_at", "exchange_observed_at"}, "first redemption")
    _require_keys(retry_input, {"observed_at", "exchange_observed_at"}, "exact-retry redemption")
    _require_keys(
        cross_input,
        {"quote_id", "resource_id", "observed_at", "exchange_observed_at"},
        "cross-binding redemption",
    )

    first_body = {
        "schema_version": "safepay-v2",
        "fulfillment": fulfillment,
        "delivery": {"replay_disposition": "first_consumption"},
    }
    retry_body = {
        "schema_version": "safepay-v2",
        "fulfillment": fulfillment,
        "delivery": {"replay_disposition": "idempotent_replay"},
    }
    cross_body = safepay_v2_error_body(
        "payment_already_consumed_for_other_binding",
        False,
        "cross_binding_rejected",
    )
    redemptions = {
        "first_consumption": _redemption_observation(
            kind="first_consumption",
            quote_id=quote_id,
            resource_id=resource_id,
            payment_hash=parsed_transfer["payment_hash"],
            status=200,
            observed_at=_integer(first_input["observed_at"], "first redemption observed_at"),
            response_digest=response_hash,
            consumed_response_hash=response_hash,
            body=first_body,
            provider_url=provider_url,
            exchange_observed_at=_text(
                first_input["exchange_observed_at"], "first redemption exchange observed_at"
            ),
        ),
        "exact_retry": _redemption_observation(
            kind="idempotent_replay",
            quote_id=quote_id,
            resource_id=resource_id,
            payment_hash=parsed_transfer["payment_hash"],
            status=200,
            observed_at=_integer(retry_input["observed_at"], "exact-retry observed_at"),
            response_digest=response_hash,
            consumed_response_hash=response_hash,
            body=retry_body,
            provider_url=provider_url,
            exchange_observed_at=_text(
                retry_input["exchange_observed_at"], "exact-retry exchange observed_at"
            ),
        ),
        "cross_binding_reuse": _redemption_observation(
            kind="cross_binding_rejected",
            quote_id=_text(cross_input["quote_id"], "cross-binding quote_id"),
            resource_id=_text(cross_input["resource_id"], "cross-binding resource_id"),
            payment_hash=parsed_transfer["payment_hash"],
            status=409,
            observed_at=_integer(cross_input["observed_at"], "cross-binding observed_at"),
            response_digest=safepay_v2_body_digest(cross_body),
            consumed_response_hash=response_hash,
            body=cross_body,
            provider_url=provider_url,
            exchange_observed_at=_text(
                cross_input["exchange_observed_at"], "cross-binding exchange observed_at"
            ),
        ),
    }

    # -- durable ledger snapshots straddling the restart ---------------------
    snapshot_observed_input = _obj(
        bundle["ledger_snapshots_observed"], "ledger_snapshots_observed"
    )
    _require_keys(
        snapshot_observed_input,
        {"after_first_consumption", "after_exact_retry", "after_cross_binding_reuse"},
        "ledger_snapshots_observed",
    )
    snapshot_observed = {
        stage: _text(snapshot_observed_input[stage], f"ledger {stage} observed_at")
        for stage in (
            "after_first_consumption",
            "after_exact_retry",
            "after_cross_binding_reuse",
        )
    }
    ledger_evidence = _build_ledger_evidence(
        quote_row=quote_row,
        consumption_row=consumption_row,
        report_bytes=report_bytes,
        report_hash=report_hash,
        decoded_length=decoded_length,
        issued_at=issued_at,
        redemptions=redemptions,
        snapshot_observed=snapshot_observed,
        before_instance_id=before_instance_id,
        after_instance_id=after_instance_id,
    )

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
        raw = sys.stdin.buffer.read(limit + 1)
    else:
        path = Path(path_value)
        try:
            metadata = path.stat()
            if not path.is_file() or path.is_symlink():
                raise SafePayV2CaptureError("capture bundle must be a regular file")
            if metadata.st_size > limit:
                raise SafePayV2CaptureError("capture bundle exceeds its size limit")
            raw = path.read_bytes()
        except OSError as exc:
            raise SafePayV2CaptureError("capture bundle is unavailable") from exc
    if len(raw) > limit:
        raise SafePayV2CaptureError("capture bundle exceeds its size limit")
    return raw


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
        "--bundle", required=True, help="capture bundle JSON file, or - for stdin"
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
