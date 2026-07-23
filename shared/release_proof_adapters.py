"""Fail-closed raw-artifact adapters for release proof-registry assembly."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from shared.x402_payments import (
    SAFEPAY_V2_BINDING_CHECK_FIELDS,
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
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ReleaseProofAdapterError(f"{label} is not canonical base64") from exc


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_hash(value: object) -> str:
    return _sha(_canonical(value))


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
    return (
        _strict_json(request_raw, f"{label} request"),
        _strict_json(response_raw, f"{label} response"),
    )


def _account_hash(value: object, label: str) -> str:
    if type(value) is not str:
        raise ReleaseProofAdapterError(f"{label} is not an account hash")
    candidate = value.removeprefix("account-hash-").lower()
    if len(candidate) != 64:
        raise ReleaseProofAdapterError(f"{label} is not an account hash")
    try:
        bytes.fromhex(candidate)
    except ValueError as exc:
        raise ReleaseProofAdapterError(f"{label} is not an account hash") from exc
    return candidate


def _cl_parsed(value: object, label: str) -> object:
    wrapper = _mapping(value, label)
    if set(wrapper) == {"parsed"}:
        return wrapper["parsed"]
    if "parsed" in wrapper and set(wrapper) <= {"parsed", "cl_type"}:
        return wrapper["parsed"]
    raise ReleaseProofAdapterError(f"{label} lacks one structured parsed value")


def _native_transfer_from_deploy(
    payload: Mapping[str, Any],
    *,
    expected_hash: str,
    check: str,
) -> dict[str, Any]:
    result = _mapping(payload.get("result"), "info_get_deploy result")
    deploy = _mapping(result.get("deploy"), "returned deploy")
    if deploy.get("hash") != expected_hash:
        _fail(check, "returned deploy hash differs")
    header = _mapping(deploy.get("header"), "returned deploy header")
    source = _account_hash(header.get("account"), "native transfer source")
    session = _mapping(deploy.get("session"), "returned deploy session")
    if set(session) != {"Transfer"}:
        _fail(check, "session is not exactly one native Transfer")
    transfer = _mapping(session["Transfer"], "native Transfer")
    args = _sequence(transfer.get("args"), "native Transfer args")
    parsed: dict[str, object] = {}
    for raw in args:
        pair = _sequence(raw, "native Transfer arg")
        if len(pair) != 2 or type(pair[0]) is not str or pair[0] in parsed:
            _fail(check, "native Transfer args are malformed or duplicated")
        parsed[pair[0]] = _cl_parsed(pair[1], f"native Transfer {pair[0]}")
    if set(parsed) != {"target", "amount", "id"}:
        _fail(check, "native Transfer args are not exact")
    results = _sequence(result.get("execution_results"), "execution results")
    if len(results) != 1:
        _fail(check, "exactly one execution result is required")
    execution = _mapping(results[0], "execution result")
    outcome = _mapping(execution.get("result"), "execution outcome")
    if set(outcome) != {"Success"}:
        _fail(check, "payment execution is not an explicit success")
    success = _mapping(outcome["Success"], "successful execution")
    if success.get("error_message") not in (None, ""):
        _fail(check, "payment execution contains an error")
    block_height = execution.get("block_height")
    if type(block_height) is not int or block_height < 0:
        _fail(check, "execution block height is invalid")
    return {
        "payment_hash": expected_hash,
        "block_hash": execution.get("block_hash"),
        "block_height": block_height,
        "source_account_hash": source,
        "payee_account_hash": _account_hash(parsed["target"], "native transfer target"),
        "amount_motes": str(parsed["amount"]),
        "transfer_id": str(parsed["id"]),
    }


def _canonical_block(
    payload: Mapping[str, Any],
    *,
    expected_payment_hash: str,
    expected_block_hash: str,
    check: str,
) -> dict[str, Any]:
    result = _mapping(payload.get("result"), "chain_get_block result")
    block = _mapping(result.get("block"), "canonical block")
    if block.get("hash") != expected_block_hash:
        _fail(check, "canonical block hash differs")
    header = _mapping(block.get("header"), "canonical block header")
    body = _mapping(block.get("body"), "canonical block body")
    deploys = _sequence(body.get("deploy_hashes"), "canonical deploy hashes")
    transfers = _sequence(body.get("transfer_hashes"), "canonical transfer hashes")
    if (
        deploys.count(expected_payment_hash) + transfers.count(expected_payment_hash)
        != 1
    ):
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


def _verify_rpc_providers(
    chain: Mapping[str, Any],
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
        split = urlsplit(origin)
        if split.scheme != "https" or not split.hostname:
            _fail(check, "RPC provider origin is invalid")
        origins.append(f"{split.scheme}://{split.hostname}:{split.port or 443}")
        deploy_exchange = _mapping(
            provider.get("info_get_deploy"),
            f"RPC provider {index} deploy exchange",
        )
        deploy_request, deploy_response = _decode_exchange(
            deploy_exchange,
            label=f"RPC provider {index} info_get_deploy",
            check=check,
        )
        expected_deploy_request = {
            "deploy_hash": payment_hash,
            "finalized_approvals": True,
        }
        if (
            deploy_request.get("method") != "info_get_deploy"
            or deploy_request.get("params") != expected_deploy_request
        ):
            _fail(check, "info_get_deploy request is not exact")
        transfer = _native_transfer_from_deploy(
            deploy_response,
            expected_hash=payment_hash,
            check=check,
        )
        block_exchange = _mapping(
            provider.get("chain_get_block"),
            f"RPC provider {index} block exchange",
        )
        block_request, block_response = _decode_exchange(
            block_exchange,
            label=f"RPC provider {index} chain_get_block",
            check=check,
        )
        if block_request.get("method") != "chain_get_block" or block_request.get(
            "params"
        ) != {"block_identifier": {"Hash": transfer["block_hash"]}}:
            _fail(check, "chain_get_block request is not exact")
        block = _canonical_block(
            block_response,
            expected_payment_hash=payment_hash,
            expected_block_hash=str(transfer["block_hash"]),
            check=check,
        )
        if block["block_height"] != transfer["block_height"]:
            _fail(check, "execution and canonical block heights differ")
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


def _http_observation(
    value: object,
    *,
    label: str,
    check: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    observation = _mapping(value, label)
    exchange = _mapping(observation.get("exchange"), f"{label} exchange")
    request, response = _decode_exchange(exchange, label=label, check=check)
    if (
        observation.get("http_status") != exchange.get("response_status")
        or exchange.get("method") != "POST"
    ):
        _fail(check, f"{label} HTTP result differs from transcript")
    return observation, request, response


def verify_safepay_v2_artifact(
    document: dict[str, Any], raw_bytes: bytes
) -> dict[str, Any]:
    """Independently derive all release facts from a SafePay v2 artifact."""

    if type(document) is not dict or type(raw_bytes) is not bytes:
        raise ReleaseProofAdapterError("SafePay v2 adapter input is invalid")
    reparsed = _strict_json(raw_bytes, "SafePay v2 artifact")
    if reparsed != document:
        raise ReleaseProofAdapterError(
            "SafePay v2 document differs from the supplied raw artifact"
        )
    _validate_safepay_schema(document)
    captured_at = document["captured_at"]
    _timestamp(captured_at, "SafePay captured_at")

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
    rpc_transfer, _ = _verify_rpc_providers(chain)
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

    consumption = _mapping(document["consumption_rows"], "consumption rows")
    if consumption["exact_count"] != 1:
        _fail(_SAFEPAY_CHECKS[8], "payment was not consumed exactly once")
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
    fulfillment = _fulfillment_from_row(before_consumption, _SAFEPAY_CHECKS[8])
    if (
        fulfillment.get("quote") != quote
        or fulfillment.get("response_hash") != expected_response_hash
        or fulfillment.get("payment_observation")
        != {
            key: value
            for key, value in parsed_transfer.items()
            if key != "native_transfer_count"
        }
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
    first, first_request, first_response = _http_observation(
        redemptions["first_consumption"],
        label="first consumption",
        check=_SAFEPAY_CHECKS[6],
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

    retry, retry_request, retry_response = _http_observation(
        redemptions["exact_retry"],
        label="exact retry",
        check=_SAFEPAY_CHECKS[9],
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

    cross, cross_request, cross_response = _http_observation(
        redemptions["cross_binding_reuse"],
        label="cross-binding reuse",
        check=_SAFEPAY_CHECKS[10],
    )
    expected_cross_body = safepay_v2_error_body(
        "payment_already_consumed_for_other_binding",
        False,
        "cross_binding_rejected",
    )
    if (
        cross.get("http_status") != 409
        or cross.get("network") != quote["network"]
        or cross.get("payment_hash") != parsed_transfer["payment_hash"]
        or cross.get("consumed_response_hash") != expected_response_hash
        or cross.get("response_digest") != safepay_v2_body_digest(expected_cross_body)
        or cross_response != expected_cross_body
        or cross_request.get("network") != quote["network"]
        or cross_request.get("payment_hash") != parsed_transfer["payment_hash"]
        or (
            cross.get("quote_id") == quote["quote_id"]
            and cross.get("resource_id") == quote["resource_id"]
        )
        or int(cross.get("observed_at", -1)) < before_consumption["consumed_at"]
    ):
        _fail(_SAFEPAY_CHECKS[10], "terminal cross-binding rejection is not proven")

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
            paths=("/quote", "/chain_evidence/parsed_transfer", "/consumption_rows"),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[9],
            paths=("/consumption_rows", "/redemption_observations/exact_retry"),
            observed_at=captured_at,
        ),
        _check(
            document,
            name=_SAFEPAY_CHECKS[10],
            paths=("/consumption_rows", "/redemption_observations/cross_binding_reuse"),
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
    raise ReleaseProofAdapterError("official x402 adapter is not implemented")
