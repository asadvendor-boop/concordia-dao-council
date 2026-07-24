#!/usr/bin/env python3
"""Build immutable, offline request plans for the bounded live collector.

The input is canonical output from the already-validated SafePay wallet-intent
or official-x402 import flow.  It contains only the pre-known request facts;
the collector obtains all observed evidence and derives selectors that depend
on runtime responses.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from scripts import bound_live_proof_collector as collector
from shared.x402_payments import (
    SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
    SAFEPAY_V2_WALLET_INTENT_SCHEMA,
    validate_safepay_v2_quote_integrity,
)


SAFE_INPUT_SCHEMA = "concordia.safepay_v2_capture_plan_input.v1"
OFFICIAL_INPUT_SCHEMA = "concordia.official_x402_capture_plan_input.v1"
IMPORTED_AUTHORIZATION_SCHEMA = "concordia.official_x402_imported_authorization.v1"
BUNDLE_VERSION = "concordia.safepay_v2_capture_bundle.v1"
NETWORK = "casper:casper-test"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OFFICIAL_ORIGIN = "https://x402.concordiadao.xyz"
_PATHS = {
    "safepay_v2": "release/capture-plans/safepay-v2.json",
    "official_x402_settlement_v1": "release/capture-plans/official-x402-settlement-v1.json",
}


class CapturePlanError(ValueError):
    """A capture-plan input is not an exact, offline-safe binding."""


class _DuplicateKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CapturePlanError("plan input is not canonical JSON") from exc


def load_canonical_input(raw: bytes) -> dict[str, Any]:
    """Accept exactly one canonical JSON object, never a permissive variant."""

    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError) as exc:
        raise CapturePlanError("plan input is not strict JSON") from exc
    if type(value) is not dict or raw != _canonical(value):
        raise CapturePlanError("plan input is not canonical JSON")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CapturePlanError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise CapturePlanError(f"{label} must be non-empty text")
    return value


def _hex(value: object, label: str) -> str:
    text = _text(value, label)
    if _HEX64.fullmatch(text) is None:
        raise CapturePlanError(f"{label} must be lowercase SHA-256 hex")
    return text


def _decode_b64(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise CapturePlanError(f"{label} must be base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CapturePlanError(f"{label} must be canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise CapturePlanError(f"{label} must be canonical base64")
    return raw


def _request(method: str, body: bytes, headers: Mapping[str, str]) -> dict[str, Any]:
    return {
        "method": method,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "headers": dict(headers),
    }


def _safepay_plan(inputs: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if "rpc_requests" in inputs or "settlement_requests" in inputs:
        raise CapturePlanError("runtime request selectors must not be supplied")
    if set(inputs) != {
        "schema_version", "wallet_intent", "payment_hash", "cross_binding_quote"
    } or inputs.get("schema_version") != SAFE_INPUT_SCHEMA:
        raise CapturePlanError("SafePay plan input schema differs")
    intent = _mapping(inputs.get("wallet_intent"), "SafePay wallet intent")
    if intent.get("schema_version") != SAFEPAY_V2_WALLET_INTENT_SCHEMA or intent.get("status") != "ready":
        raise CapturePlanError("SafePay wallet intent is not ready")
    quote = _mapping(intent.get("quote"), "SafePay wallet quote")
    requirements = _mapping(intent.get("payment_requirements"), "SafePay payment requirements")
    if quote.get("network") != NETWORK:
        raise CapturePlanError("SafePay quote network differs")
    if validate_safepay_v2_quote_integrity(quote) is not None:
        raise CapturePlanError("SafePay quote binding differs")
    required_keys = {"network", "payee_account_hash", "amount_motes", "correlation_id", "expires_at"}
    if set(requirements) != required_keys or any(requirements[key] != quote.get(key) for key in required_keys):
        raise CapturePlanError("SafePay wallet intent requirements differ")
    cross_quote = _mapping(inputs.get("cross_binding_quote"), "SafePay cross-binding quote")
    if cross_quote.get("network") != NETWORK:
        raise CapturePlanError("SafePay cross quote network differs")
    if cross_quote.get("resource_id") == quote.get("resource_id") or cross_quote.get("quote_id") == quote.get("quote_id"):
        raise CapturePlanError("SafePay cross quote resource binding differs")
    if validate_safepay_v2_quote_integrity(cross_quote) is not None:
        raise CapturePlanError("SafePay cross quote binding differs")
    payment_hash = _hex(inputs.get("payment_hash"), "SafePay payment hash")
    first = {
        "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
        "quote": quote,
        "payment_hash": payment_hash,
    }
    cross = {**first, "quote": cross_quote}
    requests = {
        "redemption_first_consumption": _request("POST", _canonical(first), {"content-type": "application/json"}),
        "redemption_exact_retry": _request("POST", _canonical(first), {"content-type": "application/json"}),
        "redemption_cross_binding_reuse": _request("POST", _canonical(cross), {"content-type": "application/json"}),
    }
    skeleton = {
        "bundle_version": BUNDLE_VERSION,
        "provider": {"instances": {}},
        "chain": {"payment_hash": payment_hash, "providers": [{}, {}]},
        "redemptions": {},
    }
    return skeleton, requests


def _official_plan(inputs: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    expected = {
        "schema_version", "imported_authorization", "v3_proof_bytes_base64",
        "report_bytes_base64", "cross_binding_resource_url",
    }
    if set(inputs) != expected or inputs.get("schema_version") != OFFICIAL_INPUT_SCHEMA:
        if any(
            key in inputs
            for key in ("settlement_requests", "rpc_requests", "wcspr_requests")
        ):
            raise CapturePlanError("runtime request selectors must not be supplied")
        raise CapturePlanError("official plan input schema differs")
    imported = _mapping(inputs.get("imported_authorization"), "official imported authorization")
    if imported.get("schema_version") != IMPORTED_AUTHORIZATION_SCHEMA or imported.get("network") != NETWORK:
        raise CapturePlanError("official authorization network differs")
    payload = _mapping(imported.get("signed_payment_payload"), "official signed payment payload")
    nested = _mapping(payload.get("payload"), "official signed payment payload data")
    signature = _text(imported.get("signature_hex"), "official signature")
    public_key = _text(imported.get("public_key_hex"), "official public key")
    if nested.get("signature") != signature or nested.get("publicKey") != public_key:
        raise CapturePlanError("official signature binding differs")
    accepted = _mapping(payload.get("accepted"), "official accepted requirements")
    resource = _mapping(payload.get("resource"), "official resource")
    if accepted.get("network") != NETWORK:
        raise CapturePlanError("official resource network differs")
    resource_url = _text(resource.get("url"), "official resource URL")
    parsed = urlsplit(resource_url)
    fixed = urlsplit(_OFFICIAL_ORIGIN)
    if parsed.scheme != fixed.scheme or parsed.netloc != fixed.netloc or not parsed.path.startswith("/resource/") or parsed.query or parsed.fragment:
        raise CapturePlanError("official resource binding differs")
    frozen = _decode_b64(imported.get("frozen_verify_request_body_base64"), "official frozen verify request")
    settle = _decode_b64(imported.get("frozen_settle_request_body_base64"), "official frozen settle request")
    facilitator = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": accepted}
    if frozen != settle or frozen != _canonical(facilitator) or imported.get("facilitator_request") != facilitator or imported.get("frozen_request_body_sha256") != hashlib.sha256(frozen).hexdigest():
        raise CapturePlanError("official frozen request or signature binding differs")
    v3 = _decode_b64(inputs.get("v3_proof_bytes_base64"), "official v3 proof")
    report = _decode_b64(inputs.get("report_bytes_base64"), "official report")
    if not v3 or not report:
        raise CapturePlanError("official static proof material is empty")
    cross_url = _text(inputs.get("cross_binding_resource_url"), "official cross resource URL")
    cross = urlsplit(cross_url)
    if cross.scheme != fixed.scheme or cross.netloc != fixed.netloc or not cross.path.startswith("/resource/") or cross.query or cross.fragment or cross_url == resource_url:
        raise CapturePlanError("official cross resource binding differs")
    cross_payload = {**payload, "resource": {**resource, "url": cross_url}}
    signature_header = base64.b64encode(_canonical(payload)).decode("ascii")
    cross_header = base64.b64encode(_canonical(cross_payload)).decode("ascii")
    requests = {
        "facilitator_supported": _request("GET", b"", {"accept": "application/json"}),
        "facilitator_verify": _request("POST", frozen, {"content-type": "application/json"}),
        "facilitator_settle": _request("POST", frozen, {"content-type": "application/json"}),
        "paid_first_release": _request("GET", b"", {"payment-signature": signature_header}),
        "paid_exact_retry": _request("GET", b"", {"payment-signature": signature_header}),
        "paid_cross_binding_reuse": _request("GET", b"", {"payment-signature": cross_header}),
    }
    skeleton = {
        "bundle_version": "concordia.official_x402_capture_bundle.v1",
        "service_url": _OFFICIAL_ORIGIN,
        "imported_authorization": imported,
        "v3_proof_bytes_base64": inputs["v3_proof_bytes_base64"],
        "report_bytes_base64": inputs["report_bytes_base64"],
        "facilitator": {},
        "wcspr_readbacks": {},
        "settlement_providers": [{}, {}],
        "fulfillment": {"cross_binding_reuse": {"url": cross_url}},
    }
    return skeleton, requests


def build_capture_plan(*, proof_id: str, source_commit: str, deployment_commit: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Build and self-validate one collector plan without contacting anything."""

    if _HEX40.fullmatch(source_commit) is None or _HEX40.fullmatch(deployment_commit) is None:
        raise CapturePlanError("plan commit binding differs")
    if proof_id == "safepay_v2":
        skeleton, requests = _safepay_plan(inputs)
    elif proof_id == "official_x402_settlement_v1":
        skeleton, requests = _official_plan(inputs)
    else:
        raise CapturePlanError("unsupported proof identity")
    plan = {
        "schema_version": collector.PLAN_SCHEMA_VERSION,
        "proof_id": proof_id,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "bundle_skeleton": skeleton,
        "requests": requests,
    }
    try:
        return collector._validate_plan_document(plan)
    except collector.LiveCollectorError as exc:
        raise CapturePlanError(f"collector plan self-validation failed: {exc}") from exc


def write_capture_plan_once(*, repository_root: Path, proof_id: str, source_commit: str, deployment_commit: str, inputs: Mapping[str, Any]) -> Path:
    """Create exactly one fixed-path canonical plan, refusing every overwrite."""

    try:
        relative = _PATHS[proof_id]
    except KeyError as exc:
        raise CapturePlanError("unsupported proof identity") from exc
    root = repository_root.resolve(strict=True)
    output = root / relative
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = _canonical(build_capture_plan(proof_id=proof_id, source_commit=source_commit, deployment_commit=deployment_commit, inputs=inputs))
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as exc:
        raise CapturePlanError("capture plan already exists") from exc
    except OSError as exc:
        raise CapturePlanError("capture plan could not be created safely") from exc
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise CapturePlanError("capture plan write failed")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--proof-id", choices=tuple(_PATHS), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--deployment-commit", required=True)
    parser.add_argument("--input", required=True, help="canonical plan-input JSON")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.input).read_bytes()
        path = write_capture_plan_once(repository_root=Path(args.repository_root), proof_id=args.proof_id, source_commit=args.source_commit, deployment_commit=args.deployment_commit, inputs=load_canonical_input(raw))
    except (OSError, CapturePlanError) as exc:
        parser.error(str(exc))
    print(path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
