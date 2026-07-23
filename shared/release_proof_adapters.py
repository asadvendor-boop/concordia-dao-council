"""Fail-closed raw-artifact adapters for release proof-registry assembly."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from shared.x402_payments import (
    SAFEPAY_V2_BINDING_CHECK_FIELDS,
    safepay_v2_account_hash_from_public_key,
    safepay_v2_body_digest,
    safepay_v2_correlation_id,
    safepay_v2_error_body,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
)


class ReleaseProofAdapterError(ValueError):
    """Raw evidence does not prove the requested release fact."""


_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA_ROOT = _ROOT / "handoff" / "schemas"
_SAFEPAY_ARTIFACT_SCHEMA = "safepay-v2-live-artifact.schema.json"
_SAFEPAY_RESULT_SCHEMA = "safepay-v2-adapter-result.schema.json"
_SCHEMA_BINDING_MANIFEST = _ROOT / "handoff" / "RELEASE_REGISTRY_ADAPTER_SCHEMAS.json"
_SAFEPAY_MIGRATION = _ROOT / "x402_provider" / "migrations" / "0001_safepay_v2.sql"
_SAFEPAY_SOURCE = "artifacts/live/safepay-lite-replaysafe-v2.json"
_SAFEPAY_CHECKS = (
    "quote_hash_recomputed",
    "issued_quote_row_matches_and_survives_restart",
    "per_quote_correlation_id_recomputed_and_equals_native_transfer_id",
    "payment_deploy_finalized_without_execution_error",
    "single_native_transfer_exact",
    "payee_amount_and_transfer_id_exact",
    "proposal_resource_and_correlation_exact",
    "report_hash_recomputed_and_matches_quote",
    "provider_consumption_row_matches_payment_and_binding",
    "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
    "cross_binding_reuse_returned_terminal_409",
)
_SAFEPAY_SCHEMA_PATH_CHECKS = (
    (("quote", "quote_hash"), _SAFEPAY_CHECKS[0]),
    (("issued_quote_rows",), _SAFEPAY_CHECKS[1]),
    (("quote", "correlation_id"), _SAFEPAY_CHECKS[2]),
    (("chain_evidence", "providers"), _SAFEPAY_CHECKS[3]),
    (
        ("chain_evidence", "parsed_transfer", "native_transfer_count"),
        _SAFEPAY_CHECKS[4],
    ),
    (("chain_evidence", "parsed_transfer"), _SAFEPAY_CHECKS[5]),
    (("redemption_observations", "first_consumption"), _SAFEPAY_CHECKS[6]),
    (("protected_report",), _SAFEPAY_CHECKS[7]),
    (("consumption_rows",), _SAFEPAY_CHECKS[8]),
    (("redemption_observations", "exact_retry"), _SAFEPAY_CHECKS[9]),
    (("redemption_observations", "cross_binding_reuse"), _SAFEPAY_CHECKS[10]),
)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ReleaseProofAdapterError("evidence is not canonical JSON data") from exc


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReleaseProofAdapterError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise ReleaseProofAdapterError(f"{label} must be one JSON object")
    return value


def _schema(name: str) -> dict[str, Any]:
    try:
        return _strict_json((_SCHEMA_ROOT / name).read_bytes(), f"{name} schema")
    except OSError as exc:
        raise ReleaseProofAdapterError(f"{name} schema is unavailable") from exc


def _assert_schema_pin(binding_name: str, schema_name: str) -> None:
    try:
        manifest = _strict_json(
            _SCHEMA_BINDING_MANIFEST.read_bytes(),
            "release adapter schema-binding manifest",
        )
        bindings = _mapping(
            manifest.get("exact_json_schemas"),
            "release adapter schema bindings",
        )
        binding = _mapping(bindings.get(binding_name), f"{binding_name} schema pin")
        raw = (_SCHEMA_ROOT / schema_name).read_bytes()
    except OSError as exc:
        raise ReleaseProofAdapterError("schema digest pin is unavailable") from exc
    expected_path = f"handoff/schemas/{schema_name}"
    if (
        set(binding) != {"path", "sha256"}
        or binding.get("path") != expected_path
        or binding.get("sha256") != _sha(raw)
    ):
        raise ReleaseProofAdapterError(
            f"{schema_name} schema digest differs from the release pin"
        )


def _path_has_prefix(path: Sequence[object], prefix: Sequence[object]) -> bool:
    return tuple(path[: len(prefix)]) == tuple(prefix)


def _validate_safepay_schema(document: Mapping[str, Any]) -> None:
    validator = Draft202012Validator(_schema(_SAFEPAY_ARTIFACT_SCHEMA))
    errors = sorted(
        validator.iter_errors(document), key=lambda item: list(item.absolute_path)
    )
    if not errors:
        return
    error = errors[0]
    path = tuple(error.absolute_path)
    for prefix, check in _SAFEPAY_SCHEMA_PATH_CHECKS:
        if _path_has_prefix(path, prefix):
            raise ReleaseProofAdapterError(
                f"{check}: artifact schema mismatch"
            ) from error
    raise ReleaseProofAdapterError("SafePay v2 artifact schema mismatch") from error


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseProofAdapterError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise ReleaseProofAdapterError(f"{label} must be an array")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ReleaseProofAdapterError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseProofAdapterError(f"{label} is not a real UTC instant") from exc
    if parsed.tzinfo != UTC:
        raise ReleaseProofAdapterError(f"{label} must be UTC")
    return parsed


def _b64(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise ReleaseProofAdapterError(f"{label} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseProofAdapterError(f"{label} is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ReleaseProofAdapterError(f"{label} is not canonical base64")
    return decoded


def _https_origin(value: object, label: str) -> tuple[str, str]:
    if type(value) is not str:
        raise ReleaseProofAdapterError(f"{label} is not an HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
    ):
        raise ReleaseProofAdapterError(f"{label} is not an HTTPS URL")
    return f"https://{parsed.hostname}:{parsed.port or 443}", parsed.path


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_hash(value: object) -> str:
    return _sha(_canonical(value))


_SAFEPAY_PROVIDER_INSTANCE_DOMAIN = (
    b"CONCORDIA_SAFEPAY_PROVIDER_INSTANCE_V1\x00"
)


def _provider_runtime_identity(
    value: object,
    *,
    label: str,
) -> tuple[str, datetime, datetime, dict[str, Any]]:
    identity = _mapping(value, label)
    expected_fields = {
        "container_id",
        "deployment_id",
        "image_digest",
        "started_at",
        "observed_at",
        "restart_count",
        "instance_id",
    }
    if set(identity) != expected_fields:
        raise ReleaseProofAdapterError(f"{label} schema differs")
    payload = {
        field: identity[field]
        for field in (
            "container_id",
            "deployment_id",
            "image_digest",
            "started_at",
            "observed_at",
            "restart_count",
        )
    }
    expected_instance_id = _sha(
        _SAFEPAY_PROVIDER_INSTANCE_DOMAIN + _canonical(payload)
    )
    if identity.get("instance_id") != expected_instance_id:
        raise ReleaseProofAdapterError(
            f"{label} instance ID differs from its runtime identity"
        )
    started_at = _timestamp(identity.get("started_at"), f"{label} started_at")
    observed_at = _timestamp(identity.get("observed_at"), f"{label} observed_at")
    if started_at > observed_at:
        raise ReleaseProofAdapterError(f"{label} was observed before it started")
    return expected_instance_id, started_at, observed_at, identity


def _verify_provider_restart_identity(
    document: Mapping[str, Any],
    *,
    captured_at: datetime,
) -> tuple[str, str]:
    capture = _mapping(document.get("capture_identity"), "capture identity")
    instances = _mapping(
        capture.get("provider_instances"),
        "provider restart runtime identities",
    )
    if set(instances) != {"before_restart", "after_restart"}:
        raise ReleaseProofAdapterError(
            "provider restart runtime identity inventory differs"
        )
    before_id, before_started, before_observed, before = _provider_runtime_identity(
        instances["before_restart"],
        label="provider runtime identity before restart",
    )
    after_id, after_started, after_observed, after = _provider_runtime_identity(
        instances["after_restart"],
        label="provider runtime identity after restart",
    )
    if (
        before_id == after_id
        or before.get("container_id") == after.get("container_id")
        or before.get("deployment_id") != capture.get("provider_deployment_id")
        or after.get("deployment_id") != capture.get("provider_deployment_id")
        or before.get("image_digest") != capture.get("provider_image_digest")
        or after.get("image_digest") != capture.get("provider_image_digest")
        or not before_started < before_observed < after_started
        or not after_started <= after_observed <= captured_at
    ):
        raise ReleaseProofAdapterError(
            "provider restart runtime identity does not prove two ordered "
            "instances of the captured deployment"
        )

    observations = (
        (
            document["issued_quote_rows"]["before_restart"],
            before_id,
            before_observed,
            None,
        ),
        (
            document["consumption_rows"]["before_restart"],
            before_id,
            before_observed,
            None,
        ),
        (
            document["ledger_evidence"]["after_first_consumption"],
            before_id,
            before_observed,
            None,
        ),
        (
            document["ledger_evidence"]["after_exact_retry"],
            before_id,
            before_observed,
            None,
        ),
        (
            document["issued_quote_rows"]["after_restart"],
            after_id,
            after_observed,
            after_started,
        ),
        (
            document["consumption_rows"]["after_restart"],
            after_id,
            after_observed,
            after_started,
        ),
        (
            document["ledger_evidence"]["after_cross_binding_reuse"],
            after_id,
            after_observed,
            after_started,
        ),
    )
    for raw, expected_id, upper_bound, lower_bound in observations:
        observation = _mapping(raw, "provider restart-bound observation")
        observed = _timestamp(
            observation.get("observed_at"),
            "provider restart-bound observation time",
        )
        if (
            observation.get("provider_instance_id") != expected_id
            or observed > upper_bound
            or (lower_bound is None and observed >= after_started)
            or (lower_bound is not None and observed < lower_bound)
        ):
            raise ReleaseProofAdapterError(
                "provider restart observation differs from its runtime identity"
            )
    return before_id, after_id


def _json_pointer_get(document: object, pointer: str) -> object:
    value = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if type(value) is list:
            value = value[int(token)]
        elif type(value) is dict:
            value = value[token]
        else:
            raise ReleaseProofAdapterError("evidence path does not resolve")
    return value


def _check(
    document: Mapping[str, Any],
    *,
    name: str,
    paths: Sequence[str],
    observed_at: str,
    source: str = _SAFEPAY_SOURCE,
) -> dict[str, Any]:
    projection = {path: _json_pointer_get(document, path) for path in paths}
    return {
        "name": name,
        "passed": True,
        "source": source,
        "observed_at": observed_at,
        "evidence_paths": list(paths),
        "evidence_sha256": _canonical_hash(projection),
    }


def _fail(check: str, message: str) -> None:
    raise ReleaseProofAdapterError(f"{check}: {message}")


def _decode_exchange(
    exchange: Mapping[str, Any],
    *,
    label: str,
    check: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request_raw = _b64(exchange.get("request_body_base64"), f"{label} request")
    response_raw = _b64(exchange.get("response_body_base64"), f"{label} response")
    if _sha(request_raw) != exchange.get("request_body_sha256"):
        _fail(check, f"{label} request digest differs")
    if _sha(response_raw) != exchange.get("response_body_sha256"):
        _fail(check, f"{label} response digest differs")
    request = _strict_json(request_raw, f"{label} request")
    response = _strict_json(response_raw, f"{label} response")
    if _canonical(request) != request_raw or _canonical(response) != response_raw:
        _fail(check, f"{label} transcript is not canonical JSON")
    return request, response


def _account_hash(value: object, label: str) -> str:
    if type(value) is not str:
        raise ReleaseProofAdapterError(f"{label} is not an account hash")
    candidate = value.removeprefix("account-hash-")
    if len(candidate) != 64 or candidate != candidate.lower():
        raise ReleaseProofAdapterError(f"{label} is not an account hash")
    try:
        bytes.fromhex(candidate)
    except ValueError as exc:
        raise ReleaseProofAdapterError(f"{label} is not an account hash") from exc
    return candidate


def _rpc_result(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    method: str,
    params: object,
    label: str,
    check: str,
) -> dict[str, Any]:
    if (
        set(request) != {"jsonrpc", "id", "method", "params"}
        or request.get("jsonrpc") != "2.0"
        or request.get("method") != method
        or request.get("params") != params
    ):
        _fail(check, f"{label} JSON-RPC request is not exact")
    if (
        set(response) != {"jsonrpc", "id", "result"}
        or response.get("jsonrpc") != "2.0"
        or response.get("id") != request.get("id")
    ):
        _fail(check, f"{label} JSON-RPC response is not an exact success")
    return _mapping(response["result"], f"{label} result")


def _public_key_account_hash(value: object, label: str) -> str:
    if type(value) is not str:
        raise ReleaseProofAdapterError(f"{label} is not a public key")
    try:
        return safepay_v2_account_hash_from_public_key(value)
    except ValueError as exc:
        raise ReleaseProofAdapterError(f"{label} is not a public key") from exc


def _u512_clvalue(value: object, label: str) -> str:
    wrapper = _mapping(value, label)
    parsed = wrapper.get("parsed")
    encoded_hex = wrapper.get("bytes")
    if (
        set(wrapper) != {"bytes", "cl_type", "parsed"}
        or wrapper.get("cl_type") != "U512"
        or type(parsed) is not str
        or not parsed.isdecimal()
        or (parsed.startswith("0") and parsed != "0")
        or type(encoded_hex) is not str
    ):
        raise ReleaseProofAdapterError(f"{label} is not a canonical U512 CLValue")
    integer = int(parsed)
    integer_bytes = (
        b"" if integer == 0 else integer.to_bytes((integer.bit_length() + 7) // 8, "little")
    )
    try:
        encoded = bytes.fromhex(encoded_hex)
    except ValueError as exc:
        raise ReleaseProofAdapterError(f"{label} has invalid CLValue bytes") from exc
    if len(integer_bytes) > 64 or encoded != bytes([len(integer_bytes)]) + integer_bytes:
        raise ReleaseProofAdapterError(f"{label} CLValue bytes disagree")
    return parsed


def _public_key_clvalue(value: object, label: str) -> tuple[str, str]:
    wrapper = _mapping(value, label)
    if (
        set(wrapper) != {"bytes", "cl_type", "parsed"}
        or wrapper.get("cl_type") != "PublicKey"
        or wrapper.get("bytes") != wrapper.get("parsed")
    ):
        raise ReleaseProofAdapterError(
            f"{label} is not one canonical PublicKey CLValue"
        )
    public_key = wrapper.get("parsed")
    return str(public_key), _public_key_account_hash(public_key, label)


def _option_u64_clvalue(value: object, label: str) -> str:
    wrapper = _mapping(value, label)
    parsed = wrapper.get("parsed")
    if (
        set(wrapper) != {"bytes", "cl_type", "parsed"}
        or wrapper.get("cl_type") != {"Option": "U64"}
        or type(parsed) is not int
        or type(parsed) is bool
        or not 0 <= parsed < 2**64
    ):
        raise ReleaseProofAdapterError(
            f"{label} is not one canonical Option<U64> CLValue"
        )
    try:
        encoded = bytes.fromhex(str(wrapper.get("bytes")))
    except ValueError as exc:
        raise ReleaseProofAdapterError(f"{label} has invalid CLValue bytes") from exc
    if encoded != b"\x01" + parsed.to_bytes(8, "little"):
        raise ReleaseProofAdapterError(f"{label} CLValue bytes disagree")
    return str(parsed)


def _native_transfer_from_deploy(
    payload: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    expected_hash: str,
    check: str,
) -> dict[str, Any]:
    result = _rpc_result(
        request,
        payload,
        method="info_get_deploy",
        params={"deploy_hash": expected_hash, "finalized_approvals": True},
        label="info_get_deploy",
        check=check,
    )
    deploy = _mapping(result.get("deploy"), "returned deploy")
    if deploy.get("hash") != expected_hash:
        _fail(check, "returned deploy hash differs")
    header = _mapping(deploy.get("header"), "returned deploy header")
    source_public_key = header.get("account")
    source = _public_key_account_hash(
        source_public_key, "native transfer source public key"
    )
    session = _mapping(deploy.get("session"), "returned deploy session")
    if set(session) != {"Transfer"}:
        _fail(check, "session is not exactly one native Transfer")
    transfer = _mapping(session["Transfer"], "native Transfer")
    args = _sequence(transfer.get("args"), "native Transfer args")
    parsed: dict[str, dict[str, Any]] = {}
    for raw in args:
        pair = _sequence(raw, "native Transfer arg")
        if len(pair) != 2 or type(pair[0]) is not str or pair[0] in parsed:
            _fail(check, "native Transfer args are malformed or duplicated")
        parsed[pair[0]] = _mapping(pair[1], f"native Transfer {pair[0]}")
    if set(parsed) != {"target", "amount", "id"}:
        _fail(check, "native Transfer args are not exact")
    _, payee = _public_key_clvalue(parsed["target"], "native Transfer target")
    amount = _u512_clvalue(parsed["amount"], "native Transfer amount")
    transfer_id = _option_u64_clvalue(parsed["id"], "native Transfer id")

    execution = _mapping(result.get("execution_info"), "execution info")
    outcome = _mapping(execution.get("execution_result"), "execution result")
    if set(outcome) != {"Version2"}:
        _fail(check, "payment execution is not one Version2 result")
    version = _mapping(outcome["Version2"], "Version2 execution result")
    if version.get("error_message") is not None:
        _fail(check, "payment execution contains an error")
    if _mapping(version.get("initiator"), "execution initiator") != {
        "PublicKey": source_public_key
    }:
        _fail(check, "execution initiator differs from the deploy signer")
    transfers = _sequence(version.get("transfers"), "execution transfers")
    if len(transfers) != 1:
        _fail(_SAFEPAY_CHECKS[4], "execution does not contain exactly one transfer")
    tagged_transfer = _mapping(transfers[0], "execution transfer")
    if set(tagged_transfer) != {"Version2"}:
        _fail(check, "execution transfer is not Version2")
    executed = _mapping(tagged_transfer["Version2"], "Version2 transfer")
    if (
        executed.get("transaction_hash") != {"Deploy": expected_hash}
        or _mapping(executed.get("from"), "execution transfer source")
        != {"AccountHash": f"account-hash-{source}"}
        or _account_hash(executed.get("to"), "execution transfer target") != payee
        or str(executed.get("amount")) != amount
        or str(executed.get("id")) != transfer_id
    ):
        _fail(check, "execution transfer differs from the typed session")
    block_height = execution.get("block_height")
    if type(block_height) is not int or block_height < 0:
        _fail(check, "execution block height is invalid")
    return {
        "payment_hash": expected_hash,
        "block_hash": execution.get("block_hash"),
        "block_height": block_height,
        "source_account_hash": source,
        "payee_account_hash": payee,
        "amount_motes": amount,
        "transfer_id": transfer_id,
        "native_transfer_count": len(transfers),
    }


def _canonical_block(
    payload: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    expected_payment_hash: str,
    expected_block_hash: str,
    check: str,
) -> dict[str, Any]:
    result = _rpc_result(
        request,
        payload,
        method="chain_get_block",
        params={"block_identifier": {"Hash": expected_block_hash}},
        label="chain_get_block",
        check=check,
    )
    signed = _mapping(result.get("block_with_signatures"), "block with signatures")
    versioned = _mapping(signed.get("block"), "canonical versioned block")
    if set(versioned) != {"Version2"}:
        _fail(check, "canonical block is not Version2")
    block = _mapping(versioned["Version2"], "canonical Version2 block")
    if block.get("hash") != expected_block_hash:
        _fail(check, "canonical block hash differs")
    header = _mapping(block.get("header"), "canonical block header")
    body = _mapping(block.get("body"), "canonical block body")
    transaction_buckets = _mapping(
        body.get("transactions"), "canonical block transactions"
    )
    transaction_hashes: list[str] = []
    for bucket in transaction_buckets.values():
        for tagged in _sequence(bucket, "canonical transaction bucket"):
            item = _mapping(tagged, "canonical transaction")
            if len(item) != 1:
                _fail(check, "canonical transaction tag is ambiguous")
            transaction_hashes.append(str(next(iter(item.values()))))
    if transaction_hashes.count(expected_payment_hash) != 1:
        _fail(check, "payment deploy is not included exactly once")
    height = header.get("height")
    if type(height) is not int or height < 0:
        _fail(check, "canonical block height is invalid")
    return {
        "block_hash": block["hash"],
        "block_height": height,
        "state_root_hash": header.get("state_root_hash"),
        "block_timestamp": header.get("timestamp"),
    }


def _confirmation_depth(
    payload: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    payment_height: int,
    payment_block_timestamp: str,
    exchange_observed_at: object,
    check: str,
) -> int:
    result = _rpc_result(
        request,
        payload,
        method="info_get_status",
        params=[],
        label="info_get_status",
        check=check,
    )
    if result.get("chainspec_name") != "casper-test":
        _fail(check, "status observation is not for casper-test")
    tip = _mapping(result.get("last_added_block_info"), "last added block info")
    tip_height = tip.get("height")
    if type(tip_height) is not int or type(tip_height) is bool:
        _fail(check, "status tip height is invalid")
    for field in ("hash", "state_root_hash"):
        _account_hash(tip.get(field), f"status tip {field}")
    tip_timestamp = _timestamp(tip.get("timestamp"), "status tip timestamp")
    observed = _timestamp(exchange_observed_at, "status exchange observed_at")
    payment_time = _timestamp(payment_block_timestamp, "payment block timestamp")
    depth = tip_height - payment_height
    if depth < 8 or tip_timestamp < payment_time or observed < tip_timestamp:
        _fail(check, "payment has fewer than eight observed confirmations")
    return depth


def _verify_rpc_providers(
    chain: Mapping[str, Any],
    *,
    captured_at: datetime,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    check = _SAFEPAY_CHECKS[3]
    payment_hash = chain["payment_hash"]
    providers = _sequence(chain.get("providers"), "SafePay RPC providers")
    if len(providers) != 2:
        _fail(check, "exactly two RPC observations are required")
    endpoint_ids: list[str] = []
    origins: list[str] = []
    observations: list[dict[str, Any]] = []
    for index, raw_provider in enumerate(providers):
        provider = _mapping(raw_provider, f"RPC provider {index}")
        endpoint_ids.append(str(provider.get("endpoint_id")))
        origin = str(provider.get("origin"))
        rpc_origin, rpc_path = _https_origin(origin, f"RPC provider {index} origin")
        if rpc_path != "/rpc":
            _fail(check, "RPC provider origin is invalid")
        origins.append(rpc_origin)
        deploy_exchange = _mapping(
            provider.get("info_get_deploy"),
            f"RPC provider {index} deploy exchange",
        )
        if (
            deploy_exchange.get("url") != origin
            or deploy_exchange.get("response_status") != 200
            or deploy_exchange.get("response_content_type") != "application/json"
            or _timestamp(
                deploy_exchange.get("observed_at"),
                f"RPC provider {index} deploy observed_at",
            )
            > captured_at
        ):
            _fail(check, "deploy transcript origin or metadata is invalid")
        deploy_request, deploy_response = _decode_exchange(
            deploy_exchange,
            label=f"RPC provider {index} info_get_deploy",
            check=check,
        )
        transfer = _native_transfer_from_deploy(
            deploy_response,
            request=deploy_request,
            expected_hash=payment_hash,
            check=check,
        )
        block_exchange = _mapping(
            provider.get("chain_get_block"),
            f"RPC provider {index} block exchange",
        )
        if (
            block_exchange.get("url") != origin
            or block_exchange.get("response_status") != 200
            or block_exchange.get("response_content_type") != "application/json"
            or _timestamp(
                block_exchange.get("observed_at"),
                f"RPC provider {index} block observed_at",
            )
            > captured_at
        ):
            _fail(check, "block transcript origin or metadata is invalid")
        block_request, block_response = _decode_exchange(
            block_exchange,
            label=f"RPC provider {index} chain_get_block",
            check=check,
        )
        block = _canonical_block(
            block_response,
            request=block_request,
            expected_payment_hash=payment_hash,
            expected_block_hash=str(transfer["block_hash"]),
            check=check,
        )
        if block["block_height"] != transfer["block_height"]:
            _fail(check, "execution and canonical block heights differ")
        status_exchange = _mapping(
            provider.get("info_get_status"),
            f"RPC provider {index} status exchange",
        )
        if (
            status_exchange.get("url") != origin
            or status_exchange.get("response_status") != 200
            or status_exchange.get("response_content_type") != "application/json"
            or _timestamp(
                status_exchange.get("observed_at"),
                f"RPC provider {index} status observed_at",
            )
            > captured_at
        ):
            _fail(check, "status transcript origin or metadata is invalid")
        status_request, status_response = _decode_exchange(
            status_exchange,
            label=f"RPC provider {index} info_get_status",
            check=check,
        )
        _confirmation_depth(
            status_response,
            request=status_request,
            payment_height=transfer["block_height"],
            payment_block_timestamp=str(block["block_timestamp"]),
            exchange_observed_at=status_exchange.get("observed_at"),
            check=check,
        )
        observations.append({**transfer, **block})
    if len(set(endpoint_ids)) != 2 or len(set(origins)) != 2:
        _fail(check, "RPC providers are not independently named and hosted")
    if observations[0] != observations[1]:
        _fail(check, "RPC providers disagree")
    return observations[0], tuple(endpoint_ids)


def _quote_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result.pop("issued_at", None)
    return {"schema_version": "safepay-v2", **result}


def _row_observation(
    value: object,
    *,
    label: str,
    check: str,
) -> dict[str, Any]:
    observation = _mapping(value, label)
    row = _mapping(observation.get("row"), f"{label} row")
    if _canonical_hash(row) != observation.get("row_canonical_json_sha256"):
        _fail(check, f"{label} canonical row digest differs")
    return row


def _fulfillment_from_row(row: Mapping[str, Any], check: str) -> dict[str, Any]:
    raw = row.get("fulfillment_json")
    if type(raw) is not str:
        _fail(check, "persisted fulfillment is absent")
    return _strict_json(raw.encode("utf-8"), "persisted fulfillment")


def _sqlite_connection(raw: bytes, label: str) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.deserialize(raw)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
    except sqlite3.Error as exc:
        connection.close()
        raise ReleaseProofAdapterError(
            f"{label} is not a readable SQLite backup"
        ) from exc
    return connection


def _sqlite_schema(connection: sqlite3.Connection) -> list[tuple[object, ...]]:
    return [
        tuple(row)
        for row in connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    ]


def _sqlite_row(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[object, ...],
    *,
    label: str,
) -> dict[str, Any]:
    rows = connection.execute(query, parameters).fetchall()
    if len(rows) != 1:
        raise ReleaseProofAdapterError(f"{label} is not exactly one row")
    return dict(rows[0])


def _verify_safepay_ledger(
    document: Mapping[str, Any],
    *,
    quote_row: Mapping[str, Any],
    consumption_row: Mapping[str, Any],
    report: Mapping[str, Any],
    redemptions: Mapping[str, Any],
    captured_at: datetime,
) -> None:
    check = _SAFEPAY_CHECKS[8]
    evidence = _mapping(document.get("ledger_evidence"), "SafePay ledger evidence")
    migration = _b64(
        evidence.get("migration_sql_base64"),
        "SafePay ledger migration",
    )
    try:
        repository_migration = _SAFEPAY_MIGRATION.read_bytes()
    except OSError as exc:
        _fail(check, "repository ledger migration is unavailable")
        raise AssertionError from exc
    if (
        evidence.get("authoritative_database_id") != "safepay-provider-ledger"
        or evidence.get("authoritative_schema_id")
        != "concordia.safepay-provider-ledger.sqlite.v1"
        or _sha(migration) != evidence.get("migration_sql_sha256")
        or migration != repository_migration
    ):
        _fail(check, "ledger migration differs from the repository schema")

    reference = sqlite3.connect(":memory:")
    try:
        reference.executescript(repository_migration.decode("utf-8"))
        reference_schema = _sqlite_schema(reference)
    except (sqlite3.Error, UnicodeDecodeError) as exc:
        _fail(check, "repository ledger migration cannot be reproduced")
        raise AssertionError from exc
    finally:
        reference.close()

    report_bytes = _b64(report.get("content_base64"), "protected report bytes")
    expected_report = {
        "report_hash": report["report_hash"],
        "report_media_type": report["media_type"],
        "report_bytes": report_bytes,
        "decoded_length": report["decoded_length"],
        "created_at": quote_row["issued_at"],
    }
    stage_specs = (
        (
            "after_first_consumption",
            ("first_consumption",),
        ),
        (
            "after_exact_retry",
            ("first_consumption", "exact_retry"),
        ),
        (
            "after_cross_binding_reuse",
            ("first_consumption", "exact_retry", "cross_binding_reuse"),
        ),
    )
    instance_ids: list[str] = []
    previous_snapshot_time: datetime | None = None
    for stage, observation_names in stage_specs:
        snapshot = _mapping(evidence.get(stage), f"SafePay ledger {stage}")
        raw = _b64(
            snapshot.get("sqlite_backup_base64"),
            f"SafePay ledger {stage} backup",
        )
        if _sha(raw) != snapshot.get("sqlite_backup_sha256"):
            _fail(check, f"{stage} SQLite backup digest differs")
        snapshot_time = _timestamp(
            snapshot.get("observed_at"),
            f"SafePay ledger {stage} observed_at",
        )
        if previous_snapshot_time is not None and snapshot_time < previous_snapshot_time:
            _fail(check, "ledger snapshots are not chronologically ordered")
        if snapshot_time > captured_at:
            _fail(check, "ledger snapshot postdates artifact capture")
        previous_snapshot_time = snapshot_time
        instance_ids.append(str(snapshot.get("provider_instance_id")))

        connection = _sqlite_connection(raw, f"SafePay ledger {stage}")
        try:
            if _sqlite_schema(connection) != reference_schema:
                _fail(check, f"{stage} SQLite schema differs from the migration")
            if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [
                ("ok",)
            ]:
                _fail(check, f"{stage} SQLite integrity check failed")
            persisted_quote = _sqlite_row(
                connection,
                "SELECT quote_id, proposal_id, resource_id, network, "
                "payee_account_hash, amount_motes, correlation_id, report_version, "
                "report_hash, issued_at, expires_at, quote_nonce, quote_hash "
                "FROM safepay_quotes WHERE quote_id = ?",
                (quote_row["quote_id"],),
                label=f"{stage} quote",
            )
            persisted_consumption = _sqlite_row(
                connection,
                "SELECT network, payment_hash, quote_id, proposal_id, resource_id, "
                "quote_hash, report_hash, correlation_id, fulfillment_json, "
                "response_hash, consumed_at FROM payment_consumptions "
                "WHERE network = ? AND payment_hash = ?",
                (consumption_row["network"], consumption_row["payment_hash"]),
                label=f"{stage} consumption",
            )
            persisted_report = _sqlite_row(
                connection,
                "SELECT report_hash, report_media_type, report_bytes, decoded_length, "
                "created_at FROM safepay_reports WHERE report_hash = ?",
                (report["report_hash"],),
                label=f"{stage} protected report",
            )
            if (
                persisted_quote != dict(quote_row)
                or persisted_consumption != dict(consumption_row)
                or persisted_report != expected_report
            ):
                _fail(check, f"{stage} authoritative rows differ from the artifact")
            target_count = connection.execute(
                "SELECT COUNT(*) FROM payment_consumptions "
                "WHERE network = ? AND payment_hash = ?",
                (consumption_row["network"], consumption_row["payment_hash"]),
            ).fetchone()[0]
            if type(target_count) is not int or target_count != 1:
                _fail(check, f"{stage} does not contain one consumption")
            binding_count = connection.execute(
                "SELECT COUNT(*) FROM payment_consumptions "
                "WHERE payment_hash = ? OR quote_id = ? OR quote_hash = ? "
                "OR correlation_id = ?",
                (
                    consumption_row["payment_hash"],
                    consumption_row["quote_id"],
                    consumption_row["quote_hash"],
                    consumption_row["correlation_id"],
                ),
            ).fetchone()[0]
            if type(binding_count) is not int or binding_count != 1:
                _fail(
                    check,
                    f"{stage} does not contain exactly one consumption for "
                    "the payment and quote binding",
                )
            observed_rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT kind, http_status, network, payment_hash, quote_id, "
                    "resource_id, observed_at, response_digest, "
                    "consumed_response_hash FROM safepay_redemption_observations "
                    "WHERE network = ? AND payment_hash = ? ORDER BY observation_id",
                    (consumption_row["network"], consumption_row["payment_hash"]),
                ).fetchall()
            ]
            expected_rows = [
                {
                    field: redemptions[name][field]
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
                }
                for name in observation_names
            ]
            if observed_rows != expected_rows:
                _fail(check, f"{stage} redemption journal progression differs")
        except sqlite3.Error as exc:
            _fail(check, f"{stage} SQLite query failed closed")
            raise AssertionError from exc
        finally:
            connection.close()
    if (
        instance_ids[0] != instance_ids[1]
        or instance_ids[2] == instance_ids[0]
        or instance_ids[0]
        != document["consumption_rows"]["before_restart"]["provider_instance_id"]
        or instance_ids[2]
        != document["consumption_rows"]["after_restart"]["provider_instance_id"]
    ):
        _fail(check, "ledger snapshots do not prove a distinct provider restart")


def _http_observation(
    value: object,
    *,
    label: str,
    check: str,
    provider_origin: str,
    captured_at: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], datetime]:
    observation = _mapping(value, label)
    exchange = _mapping(observation.get("exchange"), f"{label} exchange")
    request, response = _decode_exchange(exchange, label=label, check=check)
    exchange_origin, exchange_path = _https_origin(
        exchange.get("url"), f"{label} URL"
    )
    if (
        observation.get("http_status") != exchange.get("response_status")
        or exchange.get("method") != "POST"
        or exchange.get("response_content_type") != "application/json"
        or exchange_origin != provider_origin
        or exchange_path != "/x402/v2/redemptions"
    ):
        _fail(check, f"{label} provider origin or HTTP result differs from transcript")
    exchange_observed_at = _timestamp(
        exchange.get("observed_at"), f"{label} exchange observed_at"
    )
    if exchange_observed_at > captured_at:
        _fail(check, f"{label} exchange postdates artifact capture")
    return observation, request, response, exchange_observed_at


def verify_safepay_v2_artifact(
    document: dict[str, Any], raw_bytes: bytes
) -> dict[str, Any]:
    """Independently derive all release facts from a SafePay v2 artifact."""

    if type(document) is not dict or type(raw_bytes) is not bytes:
        raise ReleaseProofAdapterError("SafePay v2 adapter input is invalid")
    reparsed = _strict_json(raw_bytes, "SafePay v2 artifact")
    if reparsed != document or raw_bytes != _canonical(document):
        raise ReleaseProofAdapterError(
            "SafePay v2 document differs from the canonical raw artifact"
        )
    _assert_schema_pin("safepay_artifact", _SAFEPAY_ARTIFACT_SCHEMA)
    _assert_schema_pin("safepay_result", _SAFEPAY_RESULT_SCHEMA)
    _validate_safepay_schema(document)
    captured_at = document["captured_at"]
    captured_at_instant = _timestamp(captured_at, "SafePay captured_at")
    if captured_at_instant > datetime.now(UTC) + timedelta(minutes=5):
        raise ReleaseProofAdapterError("SafePay captured_at is in the future")
    capture_identity = _mapping(document["capture_identity"], "capture identity")
    if capture_identity.get("capture_tool_commit") != document["source_commit"]:
        raise ReleaseProofAdapterError(
            "capture tool commit differs from the release source commit"
        )
    provider_origin, provider_path = _https_origin(
        capture_identity.get("provider_url"), "capture provider URL"
    )
    if provider_path not in {"", "/"}:
        raise ReleaseProofAdapterError(
            "capture provider URL must identify the provider origin"
        )
    _verify_provider_restart_identity(
        document,
        captured_at=captured_at_instant,
    )

    quote = _mapping(document["quote"], "SafePay quote")
    try:
        recomputed_correlation = safepay_v2_correlation_id(
            quote["quote_id"],
            quote["proposal_id"],
            quote["resource_id"],
            bytes.fromhex(quote["quote_nonce"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(_SAFEPAY_CHECKS[2], "correlation preimage is invalid")
        raise AssertionError from exc
    if str(recomputed_correlation) != quote.get("correlation_id"):
        _fail(_SAFEPAY_CHECKS[2], "correlation ID differs from its frozen preimage")
    try:
        recomputed_quote_hash = safepay_v2_quote_hash(
            quote_id=quote["quote_id"],
            proposal_id=quote["proposal_id"],
            resource_id=quote["resource_id"],
            network=quote["network"],
            payee_account_hash=quote["payee_account_hash"],
            amount_motes=quote["amount_motes"],
            correlation_id=recomputed_correlation,
            report_version=quote["report_version"],
            report_hash=quote["report_hash"],
            expires_at=quote["expires_at"],
            quote_nonce=bytes.fromhex(quote["quote_nonce"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        _fail(_SAFEPAY_CHECKS[0], "quote preimage is invalid")
        raise AssertionError from exc
    if recomputed_quote_hash != quote.get("quote_hash"):
        _fail(_SAFEPAY_CHECKS[0], "quote hash differs from its frozen preimage")

    quote_rows = _mapping(document["issued_quote_rows"], "issued quote rows")
    before_quote = _row_observation(
        quote_rows["before_restart"],
        label="quote row before restart",
        check=_SAFEPAY_CHECKS[1],
    )
    after_quote = _row_observation(
        quote_rows["after_restart"],
        label="quote row after restart",
        check=_SAFEPAY_CHECKS[1],
    )
    if (
        before_quote != after_quote
        or _quote_projection(before_quote) != quote
        or quote_rows["before_restart"]["provider_instance_id"]
        == quote_rows["after_restart"]["provider_instance_id"]
    ):
        _fail(_SAFEPAY_CHECKS[1], "issued quote did not survive a distinct restart")
    if not before_quote["issued_at"] < before_quote["expires_at"]:
        _fail(_SAFEPAY_CHECKS[1], "issued quote chronology is invalid")

    chain = _mapping(document["chain_evidence"], "SafePay chain evidence")
    rpc_transfer, _ = _verify_rpc_providers(
        chain,
        captured_at=captured_at_instant,
    )
    parsed_transfer = _mapping(chain["parsed_transfer"], "parsed native transfer")
    expected_rpc_finality = {
        "payment_hash": parsed_transfer["payment_hash"],
        "block_hash": parsed_transfer["block_hash"],
        "block_height": parsed_transfer["block_height"],
        "state_root_hash": parsed_transfer["state_root_hash"],
        "block_timestamp": parsed_transfer["block_timestamp"],
        "source_account_hash": parsed_transfer["source_account_hash"],
    }
    if {
        key: rpc_transfer[key] for key in expected_rpc_finality
    } != expected_rpc_finality:
        _fail(
            _SAFEPAY_CHECKS[3], "parsed finality differs from both raw RPC transcripts"
        )
    expected_rpc_transfer = {
        "payee_account_hash": parsed_transfer["payee_account_hash"],
        "amount_motes": parsed_transfer["amount_motes"],
        "transfer_id": parsed_transfer["transfer_id"],
    }
    if {
        key: rpc_transfer[key] for key in expected_rpc_transfer
    } != expected_rpc_transfer:
        _fail(
            _SAFEPAY_CHECKS[5],
            "parsed transfer fields differ from both raw RPC transcripts",
        )
    if (
        parsed_transfer["execution_status"] != "processed"
        or parsed_transfer["finality_status"] != "finalized"
        or parsed_transfer["execution_error"] is not None
    ):
        _fail(_SAFEPAY_CHECKS[3], "payment deploy is not finalized successfully")
    if parsed_transfer["native_transfer_count"] != 1:
        _fail(_SAFEPAY_CHECKS[4], "payment contains other or multiple native transfers")
    if (
        parsed_transfer["payee_account_hash"] != quote["payee_account_hash"]
        or parsed_transfer["amount_motes"] != quote["amount_motes"]
        or parsed_transfer["transfer_id"] != quote["correlation_id"]
    ):
        _fail(_SAFEPAY_CHECKS[5], "native transfer fields differ from the quote")

    report = _mapping(document["protected_report"], "protected report")
    report_bytes = _b64(report["content_base64"], "protected report bytes")
    if len(report_bytes) != report["decoded_length"]:
        _fail(_SAFEPAY_CHECKS[7], "protected report length differs")
    recomputed_report_hash = _sha(report_bytes)
    if (
        recomputed_report_hash != report["report_hash"]
        or report["report_hash"] != quote["report_hash"]
        or report["proposal_id"] != quote["proposal_id"]
        or report["resource_id"] != quote["resource_id"]
        or report["correlation_id"] != quote["correlation_id"]
    ):
        _fail(_SAFEPAY_CHECKS[7], "protected report bytes or quote binding differ")
    if _timestamp(report["persisted_at"], "report persisted_at") > _timestamp(
        report["released_at"], "report released_at"
    ):
        _fail(_SAFEPAY_CHECKS[7], "report was released before persistence")
    if _timestamp(report["released_at"], "report released_at") < _timestamp(
        parsed_transfer["block_timestamp"], "finalized payment block timestamp"
    ):
        _fail(
            _SAFEPAY_CHECKS[7],
            "report was released before the finalized payment block",
        )

    consumption = _mapping(document["consumption_rows"], "consumption rows")
    before_consumption = _row_observation(
        consumption["before_restart"],
        label="consumption row before restart",
        check=_SAFEPAY_CHECKS[8],
    )
    after_consumption = _row_observation(
        consumption["after_restart"],
        label="consumption row after restart",
        check=_SAFEPAY_CHECKS[8],
    )
    if (
        before_consumption != after_consumption
        or consumption["before_restart"]["provider_instance_id"]
        == consumption["after_restart"]["provider_instance_id"]
    ):
        _fail(_SAFEPAY_CHECKS[8], "consumption did not survive a distinct restart")
    expected_consumption_fields = {
        "network": quote["network"],
        "payment_hash": parsed_transfer["payment_hash"],
        "quote_id": quote["quote_id"],
        "proposal_id": quote["proposal_id"],
        "resource_id": quote["resource_id"],
        "quote_hash": quote["quote_hash"],
        "report_hash": quote["report_hash"],
        "correlation_id": quote["correlation_id"],
    }
    if any(
        before_consumption.get(field) != value
        for field, value in expected_consumption_fields.items()
    ):
        _fail(_SAFEPAY_CHECKS[8], "consumption binding differs")
    try:
        expected_response_hash = safepay_v2_response_hash(
            quote_hash=quote["quote_hash"],
            payment_hash=parsed_transfer["payment_hash"],
            block_hash=parsed_transfer["block_hash"],
            block_height=parsed_transfer["block_height"],
            report_hash=report["report_hash"],
            consumed_at=before_consumption["consumed_at"],
        )
    except (TypeError, ValueError) as exc:
        _fail(_SAFEPAY_CHECKS[8], "consumption response preimage is invalid")
        raise AssertionError from exc
    if (
        expected_response_hash != before_consumption["response_hash"]
        or report["response_hash"] != expected_response_hash
    ):
        _fail(_SAFEPAY_CHECKS[8], "consumption response hash differs")
    if not (
        int(before_quote["issued_at"])
        <= int(before_consumption["consumed_at"])
        < int(before_quote["expires_at"])
    ):
        _fail(
            _SAFEPAY_CHECKS[8],
            "consumption chronology violates quote issuance or expiry",
        )
    block_instant = _timestamp(
        parsed_transfer["block_timestamp"],
        "payment block timestamp",
    )
    consumed_instant = datetime.fromtimestamp(
        int(before_consumption["consumed_at"]),
        UTC,
    )
    issued_instant = datetime.fromtimestamp(int(before_quote["issued_at"]), UTC)
    if not issued_instant <= block_instant <= consumed_instant:
        _fail(
            _SAFEPAY_CHECKS[8],
            "payment block is outside the issued-to-consumed chronology",
        )
    if (
        _timestamp(report["released_at"], "report released_at") < consumed_instant
        or _timestamp(report["released_at"], "report released_at")
        > captured_at_instant
    ):
        _fail(
            _SAFEPAY_CHECKS[7],
            "report release is outside the consumed-to-captured chronology",
        )
    fulfillment = _fulfillment_from_row(before_consumption, _SAFEPAY_CHECKS[8])
    payment_observation = _mapping(
        fulfillment.get("payment_observation"),
        "persisted payment observation",
    )
    observed_at = payment_observation.get("observed_at")
    if type(observed_at) is not str or not observed_at:
        _fail(_SAFEPAY_CHECKS[8], "persisted observation time is absent")
    observed_instant = _timestamp(observed_at, "persisted observation time")
    if not block_instant <= observed_instant <= captured_at_instant:
        _fail(_SAFEPAY_CHECKS[8], "persisted observation chronology is invalid")
    expected_payment_observation = {
        "network": quote["network"],
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
    expected_fulfillment_consumption = {
        "network": quote["network"],
        "payment_hash": parsed_transfer["payment_hash"],
        "quote_id": quote["quote_id"],
        "resource_id": quote["resource_id"],
        "quote_hash": quote["quote_hash"],
        "response_hash": expected_response_hash,
        "consumed_at": before_consumption["consumed_at"],
    }
    if (
        set(fulfillment)
        != {
            "quote",
            "payment_observation",
            "consumption",
            "report",
            "binding_checks",
            "observed_at",
            "response_hash",
        }
        or fulfillment.get("quote") != quote
        or fulfillment.get("response_hash") != expected_response_hash
        or payment_observation != expected_payment_observation
        or fulfillment.get("consumption") != expected_fulfillment_consumption
        or fulfillment.get("observed_at") != observed_at
        or fulfillment.get("report")
        != {
            key: report[key]
            for key in (
                "report_version",
                "proposal_id",
                "resource_id",
                "correlation_id",
                "media_type",
                "content_base64",
                "report_hash",
            )
        }
    ):
        _fail(_SAFEPAY_CHECKS[8], "persisted fulfillment differs from verified facts")
    checks = fulfillment.get("binding_checks")
    if (
        type(checks) is not dict
        or set(checks) != set(SAFEPAY_V2_BINDING_CHECK_FIELDS)
        or not all(checks.get(name) is True for name in SAFEPAY_V2_BINDING_CHECK_FIELDS)
    ):
        _fail(_SAFEPAY_CHECKS[8], "persisted binding checklist differs")

    redemptions = _mapping(
        document["redemption_observations"], "redemption observations"
    )
    first, first_request, first_response, first_exchange_time = _http_observation(
        redemptions["first_consumption"],
        label="first consumption",
        check=_SAFEPAY_CHECKS[6],
        provider_origin=provider_origin,
        captured_at=captured_at_instant,
    )
    expected_first_request = {
        "network": quote["network"],
        "payment_hash": parsed_transfer["payment_hash"],
        "quote_id": quote["quote_id"],
        "resource_id": quote["resource_id"],
    }
    if (
        first_request != expected_first_request
        or first.get("network") != quote["network"]
        or first.get("payment_hash") != parsed_transfer["payment_hash"]
        or first.get("quote_id") != quote["quote_id"]
        or first.get("resource_id") != quote["resource_id"]
        or first.get("consumed_response_hash") != expected_response_hash
        or first.get("response_digest") != expected_response_hash
        or first_response.get("fulfillment") != fulfillment
        or first_response.get("delivery") != {"replay_disposition": "first_consumption"}
    ):
        _fail(_SAFEPAY_CHECKS[6], "first redemption binding differs")

    retry, retry_request, retry_response, retry_exchange_time = _http_observation(
        redemptions["exact_retry"],
        label="exact retry",
        check=_SAFEPAY_CHECKS[9],
        provider_origin=provider_origin,
        captured_at=captured_at_instant,
    )
    if (
        retry_request != expected_first_request
        or retry.get("network") != quote["network"]
        or retry.get("payment_hash") != parsed_transfer["payment_hash"]
        or retry.get("quote_id") != quote["quote_id"]
        or retry.get("resource_id") != quote["resource_id"]
        or retry.get("consumed_response_hash") != expected_response_hash
        or retry.get("response_digest") != expected_response_hash
        or retry_response.get("fulfillment") != fulfillment
        or retry_response.get("delivery") != {"replay_disposition": "idempotent_replay"}
    ):
        _fail(_SAFEPAY_CHECKS[9], "exact retry did not return stored fulfillment")

    cross, cross_request, cross_response, cross_exchange_time = _http_observation(
        redemptions["cross_binding_reuse"],
        label="cross-binding reuse",
        check=_SAFEPAY_CHECKS[10],
        provider_origin=provider_origin,
        captured_at=captured_at_instant,
    )
    expected_cross_body = safepay_v2_error_body(
        "payment_already_consumed_for_other_binding",
        False,
        "cross_binding_rejected",
    )
    expected_cross_request = {
        "network": cross.get("network"),
        "payment_hash": cross.get("payment_hash"),
        "quote_id": cross.get("quote_id"),
        "resource_id": cross.get("resource_id"),
    }
    if (
        cross.get("http_status") != 409
        or cross.get("network") != quote["network"]
        or cross.get("payment_hash") != parsed_transfer["payment_hash"]
        or cross.get("consumed_response_hash") != expected_response_hash
        or cross.get("response_digest") != safepay_v2_body_digest(expected_cross_body)
        or cross_response != expected_cross_body
        or cross_request.get("network") != quote["network"]
        or cross_request.get("payment_hash") != parsed_transfer["payment_hash"]
        or cross_request != expected_cross_request
        or (
            cross.get("quote_id") == quote["quote_id"]
            and cross.get("resource_id") == quote["resource_id"]
        )
        or int(cross.get("observed_at", -1)) < before_consumption["consumed_at"]
    ):
        _fail(_SAFEPAY_CHECKS[10], "terminal cross-binding rejection is not proven")
    first_observed_at = int(first["observed_at"])
    retry_observed_at = int(retry["observed_at"])
    cross_observed_at = int(cross["observed_at"])
    if first_observed_at < int(before_consumption["consumed_at"]):
        _fail(
            _SAFEPAY_CHECKS[6],
            "first redemption chronology predates payment consumption",
        )
    if retry_observed_at < first_observed_at:
        _fail(
            _SAFEPAY_CHECKS[9],
            "exact retry chronology predates first consumption",
        )
    if cross_observed_at < retry_observed_at:
        _fail(
            _SAFEPAY_CHECKS[10],
            "cross-binding rejection chronology predates exact retry",
        )
    observation_times = (
        datetime.fromtimestamp(first_observed_at, UTC),
        datetime.fromtimestamp(retry_observed_at, UTC),
        datetime.fromtimestamp(cross_observed_at, UTC),
    )
    exchange_times = (
        first_exchange_time,
        retry_exchange_time,
        cross_exchange_time,
    )
    for index, (observed, exchanged) in enumerate(
        zip(observation_times, exchange_times, strict=True)
    ):
        if exchanged < observed:
            _fail(
                (
                    _SAFEPAY_CHECKS[6],
                    _SAFEPAY_CHECKS[9],
                    _SAFEPAY_CHECKS[10],
                )[index],
                "HTTP exchange chronology predates its durable observation",
            )
    if not (
        first_exchange_time <= retry_exchange_time <= cross_exchange_time
    ):
        _fail(
            _SAFEPAY_CHECKS[9],
            "HTTP exchange chronology is not first, retry, then rejection",
        )
    _verify_safepay_ledger(
        document,
        quote_row=before_quote,
        consumption_row=before_consumption,
        report=report,
        redemptions=redemptions,
        captured_at=captured_at_instant,
    )

    fulfillment_hash = _canonical_hash(fulfillment)
    checks_result = [
        _check(
            document,
            name=_SAFEPAY_CHECKS[0],
            paths=("/quote",),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[1],
            paths=("/quote", "/issued_quote_rows"),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[2],
            paths=(
                "/quote/quote_id",
                "/quote/proposal_id",
                "/quote/resource_id",
                "/quote/quote_nonce",
                "/quote/correlation_id",
                "/chain_evidence/parsed_transfer/transfer_id",
            ),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[3],
            paths=("/chain_evidence/providers", "/chain_evidence/parsed_transfer"),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[4],
            paths=("/chain_evidence/parsed_transfer/native_transfer_count",),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[5],
            paths=(
                "/quote/payee_account_hash",
                "/quote/amount_motes",
                "/quote/correlation_id",
                "/chain_evidence/parsed_transfer",
            ),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[6],
            paths=("/quote", "/redemption_observations/first_consumption"),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[7],
            paths=("/quote/report_hash", "/protected_report"),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[8],
            paths=(
                "/quote",
                "/chain_evidence/parsed_transfer",
                "/consumption_rows",
                "/ledger_evidence",
            ),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[9],
            paths=(
                "/consumption_rows",
                "/ledger_evidence/after_exact_retry",
                "/redemption_observations/exact_retry",
            ),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[10],
            paths=(
                "/consumption_rows",
                "/ledger_evidence/after_cross_binding_reuse",
                "/redemption_observations/cross_binding_reuse",
            ),
            observed_at=captured_at,
        ),
    ]
    result = {
        "schema_version": "concordia.safepay_v2_adapter_result.v1",
        "proof_type": "safepay_v2",
        "artifact_sha256": _sha(raw_bytes),
        "derived_facts": {
            "proposal_id": quote["proposal_id"],
            "resource_id": quote["resource_id"],
            "network": quote["network"],
            "quote_id": quote["quote_id"],
            "quote_hash": quote["quote_hash"],
            "correlation_id": quote["correlation_id"],
            "payment_hash": parsed_transfer["payment_hash"],
            "report_hash": report["report_hash"],
            "first_fulfillment_hash": fulfillment_hash,
            "retry_fulfillment_hash": fulfillment_hash,
            "consumption_count": 1,
            "source_commit": document["source_commit"],
            "deployment_commit": document["deployment_commit"],
            "captured_at": captured_at,
        },
        "checks": checks_result,
    }
    try:
        Draft202012Validator(_schema(_SAFEPAY_RESULT_SCHEMA)).validate(result)
    except ValidationError as exc:
        raise ReleaseProofAdapterError(
            "SafePay adapter result schema mismatch"
        ) from exc
    return result


def verify_official_x402_artifact(
    document: dict[str, Any], raw_bytes: bytes
) -> dict[str, Any]:
    if type(document) is not dict or type(raw_bytes) is not bytes:
        raise ReleaseProofAdapterError("official x402 adapter input is invalid")
    if _strict_json(raw_bytes, "official x402 artifact") != document:
        raise ReleaseProofAdapterError(
            "official x402 document differs from its raw artifact"
        )
    from shared.official_x402_release_adapter import (
        OfficialX402ReleaseAdapterError,
        verify_official_x402_artifact as verify,
    )

    try:
        return verify(raw_bytes, "official-x402-settlement-v1.json")
    except OfficialX402ReleaseAdapterError as exc:
        raise ReleaseProofAdapterError(str(exc)) from exc
