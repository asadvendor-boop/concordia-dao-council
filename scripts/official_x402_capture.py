#!/usr/bin/env python3
"""Official x402 production prepare / import / capture generators (Task C2).

Three offline subcommands that produce the inputs and the live-evidence
artifact for the accepted ``official-x402-live-artifact.schema.json`` /
``verify_official_x402_artifact`` adapter, around the frozen settle journal.

    prepare  Build the exact EIP-712 authorization input (domain, 32-byte
             digest, message object, and every governance/resource/report/
             requirements binding) from the frozen /supported requirements,
             the resource, the report bytes, and the v3 typed action. It
             emits bytes for browser signing but NEVER signs.

    import   Accept a CSPR.click signed result, verify the tagged secp256k1
             (preferred) or ed25519 signature locally against the prepared
             digest, derive the payer account hash, and freeze the exact
             serialized signed payload plus /verify and /settle request
             bytes. It never calls the facilitator.

    capture  Assemble the official live artifact strictly from raw
             /supported, /verify, /settle exchanges, three frozen SQLite
             journal snapshots, two independent finalized Casper
             observations, WCSPR readbacks, v3 proof/config/registry
             bindings, retry/restart observations, and exact runtime image/
             source identities. No input success boolean is authoritative:
             every hash, identity, and chronology is recomputed here, and
             the assembled artifact is self-verified with the in-process
             adapter before an atomic mode-0600 write-once.

This tool is prepare/import/offline-capture ONLY. It performs no facilitator
call, settlement, Casper broadcast, service restart, key read, or live
mutation, and it never prints or persists the CSPR.cloud token, an
Authorization header, or any non-2xx response body.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping

# Reuse the accepted adapter's EXACT primitives so every recomputation here
# matches the verifier bit-for-bit. Never reimplement the crypto.
from shared.official_x402_release_adapter import (
    _CASPER_RPC_URL,
    _JOURNAL_MIGRATION_LENGTH,
    _JOURNAL_MIGRATION_SHA256,
    _NETWORK,
    _SETTLE_URL,
    _SUPPORTED_URL,
    _VERIFY_URL,
    _WCSPR_CONTRACT,
    _WCSPR_PACKAGE,
    _WCSPR_VERSION,
    _account_hash_from_public_key,
    _canonical,
    _canonical_journal_rows,
    _casper_public_key,
    _casper_signature,
    _eip712_digest,
    _payment_requirements_hash,
    _report_hash,
    _resource_url_hash,
    _runtime_args_expected,
    _signed_payload_hash,
    _journal_root,
    _verify_casper_eip712_signature,
)
from shared.atomic_private_file import AtomicPrivateFileError, write_private_file_once
from shared.release_proof_adapters import (
    ReleaseProofAdapterError,
    verify_official_x402_artifact,
)
from shared.secure_secret_file import read_secure_secret_file

# The same in-process v3 verifier the accepted adapter uses, so the recomputed
# governance binding matches the verifier's derivation exactly.
from scripts.verify_v3_proof import verify_v3_proof_document

PREPARE_REQUEST_SCHEMA = "concordia.official_x402_prepare_request.v1"
PREPARED_AUTHORIZATION_SCHEMA = "concordia.official_x402_prepared_authorization.v1"
IMPORTED_AUTHORIZATION_SCHEMA = "concordia.official_x402_imported_authorization.v1"
# The frozen capture bundle the ``capture`` subcommand consumes and the exact
# live-artifact schema version it emits. The bundle references/embeds ONLY raw
# inputs; every derived field is recomputed here before the atomic write.
CAPTURE_BUNDLE_SCHEMA = "concordia.official_x402_capture_bundle.v1"
OFFICIAL_X402_ARTIFACT_SCHEMA_VERSION = "concordia.official_x402_settlement.v2"
# The origin the accepted adapter pins the capture identity to.
_SERVICE_ORIGIN = "https://x402.concordiadao.xyz"
# The repository migration whose exact bytes back every journal snapshot.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_JOURNAL_MIGRATION_PATH = (
    _REPO_ROOT
    / "services"
    / "x402-official"
    / "migrations"
    / "0002_upstream_settle_journal.sql"
)
_UPSTREAM_SETTLE_JOURNAL_SCHEMA_ID = "concordia.x402_upstream_settle_journal.v1"
_UPSTREAM_SETTLE_CALL_DOMAIN = b"CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\x00"
_SETTLE_CALL_JOURNAL_DOMAIN = b"CONCORDIA_X402_SETTLE_CALL_JOURNAL_V1\x00"
_CROSS_BINDING_REJECTION_BODY = {"error": "cross_binding_rejected"}
# The append-only journal columns, in physical order, and the four BLOB columns
# whose values project to base64. These mirror the accepted adapter exactly.
_JOURNAL_COLUMNS = (
    "sequence",
    "event_type",
    "call_id",
    "network",
    "wcspr_contract",
    "signed_payment_payload_hash",
    "payer_account_hash",
    "authorization_nonce",
    "resource_id",
    "action_id",
    "envelope_hash",
    "request_method",
    "request_url",
    "request_headers_canonical_json",
    "request_body",
    "request_body_sha256",
    "response_status",
    "response_headers_canonical_json",
    "response_body",
    "response_body_sha256",
    "failure_code",
    "observed_at",
)
_JOURNAL_BLOB_COLUMNS = frozenset(
    {
        "request_headers_canonical_json",
        "request_body",
        "response_headers_canonical_json",
        "response_body",
    }
)


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

# The EIP-712 type strings the official @make-software/casper-x402 scheme uses
# and the Python adapter reimplements. Emitted for the browser signer's
# reference; the 32-byte digest is what is actually signed.
EIP712_DOMAIN_TYPE_STRING = (
    "EIP712Domain(string name,string version,string chain_name,"
    "bytes32 contract_package_hash)"
)
EIP712_MESSAGE_TYPE_STRING = (
    "TransferWithAuthorization(address from,address to,uint256 value,"
    "uint256 validAfter,uint256 validBefore,bytes32 nonce)"
)

# A generous ceiling for the small JSON control files this tool reads. The
# report bytes have their own cap.
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_REPORT_BYTES = 1_048_576


class CaptureError(Exception):
    """A fail-closed refusal with a stable, secret-free message."""


class _DuplicateJsonKey(ValueError):
    pass


def _fail(message: str) -> "CaptureError":
    return CaptureError(message)


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_json(path: Path, *, context: str) -> Any:
    try:
        raw = read_secure_secret_file(path, max_bytes=_MAX_INPUT_BYTES)
    except Exception as exc:  # secure reader raises its own typed error
        raise _fail(f"{context} could not be read securely: {exc}") from exc
    return _strict_json_bytes(raw, context=context)


def _require_mapping(value: Any, *, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"{context} must be a JSON object")
    return value


def _require_str(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise _fail(f"{context} must be a non-empty string")
    return value


def _require_hex(value: Any, *, length: int, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise _fail(f"{context} must be {length} lowercase hex characters")
    return value


def _require_int(value: Any, *, context: str) -> int:
    # Bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _fail(f"{context} must be a non-negative integer")
    return value


def _u256_decimal(value: Any, *, context: str) -> int:
    if isinstance(value, bool):
        raise _fail(f"{context} must be a decimal string")
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise _fail(f"{context} must be a decimal string")
    if not text.isdigit() or (len(text) > 1 and text[0] == "0"):
        raise _fail(f"{context} must be a canonical unsigned decimal")
    return int(text)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------
# prepare
# --------------------------------------------------------------------------


def build_prepared_authorization(request: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministically derive the EIP-712 signing inputs and bindings.

    ``request`` carries the frozen ``accepted`` payment requirements, the
    configured ``resource``, the base64 ``report`` bytes, the v3 typed
    action ``body``, and the ``payer_account_hash`` / ``value`` /
    ``valid_after`` / ``valid_before`` / ``nonce`` of the transfer to be
    authorized. Nothing is signed here.
    """

    request_snapshot = _strict_json_bytes(
        _canonical(request), context="prepare request"
    )
    if not isinstance(request_snapshot, dict):
        raise _fail("prepare request must be one JSON object")
    request = request_snapshot
    if request.get("schema_version") != PREPARE_REQUEST_SCHEMA:
        raise _fail(
            f"prepare request schema must be {PREPARE_REQUEST_SCHEMA}"
        )
    accepted = _require_mapping(request.get("accepted"), context="accepted")
    resource = _require_mapping(request.get("resource"), context="resource")
    body = _require_mapping(request.get("body"), context="v3 action body")

    payer_hex = _require_hex(
        request.get("payer_account_hash"), length=64, context="payer_account_hash"
    )
    payee_hex = _require_hex(
        request.get("payee_account_hash"), length=64, context="payee_account_hash"
    )
    value = _u256_decimal(request.get("value"), context="value")
    valid_after = _require_int(request.get("valid_after"), context="valid_after")
    valid_before = _require_int(request.get("valid_before"), context="valid_before")
    nonce_hex = _require_hex(request.get("nonce"), length=64, context="nonce")

    # --- structural invariants (fail closed) ------------------------------
    if value < 1:
        raise _fail("authorized value must be at least one atomic unit")
    if not valid_after < valid_before:
        raise _fail("valid_after must be strictly before valid_before")
    if payer_hex == payee_hex:
        raise _fail("payer and payee account hashes must differ")
    if nonce_hex == "0" * 64:
        raise _fail("authorization nonce must not be all-zero")

    # The accepted requirements must be internally coherent and match the
    # frozen network + WCSPR asset; the digest and hashes are derived from
    # them, so a drifted requirements object can never be signed.
    if accepted.get("network") != _NETWORK:
        raise _fail(f"accepted network must be {_NETWORK}")
    if accepted.get("asset") != _WCSPR_PACKAGE:
        raise _fail("accepted asset must be the frozen WCSPR package hash")
    if accepted.get("scheme") != "exact":
        raise _fail("accepted scheme must be 'exact'")
    if accepted.get("amount") != str(value):
        raise _fail("accepted amount must equal the authorized value")
    if accepted.get("payTo") != "00" + payee_hex:
        raise _fail("accepted payTo must be the 00-tagged payee account hash")
    extra = _require_mapping(accepted.get("extra"), context="accepted.extra")
    token_name = _require_str(extra.get("name"), context="accepted.extra.name")
    domain_version = _require_str(
        extra.get("version"), context="accepted.extra.version"
    )

    resource_url = _require_str(resource.get("url"), context="resource.url")

    report_bytes = _decode_report(request.get("report_base64"))

    # --- derive every binding via the accepted adapter primitives ---------
    payer = bytes.fromhex(payer_hex)
    payee = bytes.fromhex(payee_hex)
    nonce = bytes.fromhex(nonce_hex)
    package = bytes.fromhex(_WCSPR_PACKAGE)

    requirements_hash = _payment_requirements_hash(accepted)
    resource_url_hash = _resource_url_hash(resource_url)
    report_hash = _report_hash(report_bytes)
    digest = _eip712_digest(
        token_name=token_name,
        domain_version=domain_version,
        network=_NETWORK,
        package_hash=package,
        payer=payer,
        payee=payee,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
    )

    # --- cross-check the v3 typed action body binds the same facts --------
    _require_body_binding(
        body,
        payer_hex=payer_hex,
        payee_hex=payee_hex,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce_hex=nonce_hex,
        resource_url_hash=resource_url_hash.hex(),
        report_hash=report_hash.hex(),
        requirements_hash=requirements_hash.hex(),
    )

    eip712_domain = {
        "name": token_name,
        "version": domain_version,
        "chain_name": _NETWORK,
        "contract_package_hash": "0x" + _WCSPR_PACKAGE,
    }
    authorization_message = {
        "from": "00" + payer_hex,
        "to": "00" + payee_hex,
        "value": str(value),
        "validAfter": str(valid_after),
        "validBefore": str(valid_before),
        "nonce": nonce_hex,
    }

    prepared = {
        "schema_version": PREPARED_AUTHORIZATION_SCHEMA,
        "network": _NETWORK,
        "wcspr_package_hash": _WCSPR_PACKAGE,
        "wcspr_contract_hash": _WCSPR_CONTRACT,
        "facilitator": {
            "supported_url": _SUPPORTED_URL,
            "verify_url": _VERIFY_URL,
            "settle_url": _SETTLE_URL,
        },
        "eip712": {
            "domain_type_string": EIP712_DOMAIN_TYPE_STRING,
            "message_type_string": EIP712_MESSAGE_TYPE_STRING,
            "domain": eip712_domain,
            "message": authorization_message,
            # The 32-byte value the wallet signs (hex + base64 preimage).
            "digest_hex": digest.hex(),
            "digest_base64": _b64(digest),
        },
        "bindings": {
            "payment_requirements_hash": requirements_hash.hex(),
            "resource_url_hash": resource_url_hash.hex(),
            "report_hash": report_hash.hex(),
        },
        "prepare_request": request_snapshot,
        "prepare_request_sha256": _sha256_hex(_canonical(request_snapshot)),
        "accepted": accepted,
        "resource": resource,
        "report_base64": _b64(report_bytes),
        "authorization_fields": {
            "payer_account_hash": payer_hex,
            "payee_account_hash": payee_hex,
            "value_atomic": str(value),
            "valid_after": valid_after,
            "valid_before": valid_before,
            "nonce_hex": nonce_hex,
        },
        "signing_instructions": (
            "Sign the 32-byte digest (eip712.digest_hex) with the payer "
            "wallet. Return {signatureHex, publicKeyHex} to the import "
            "command. Do not sign anything else; do not transmit the token."
        ),
    }
    return prepared


def _decode_report(value: Any) -> bytes:
    text = _require_str(value, context="report_base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise _fail("report_base64 is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise _fail("report_base64 is not canonical base64")
    if not 1 <= len(raw) <= _MAX_REPORT_BYTES:
        raise _fail("report bytes are empty or exceed the report ceiling")
    return raw


def _require_body_binding(
    body: Mapping[str, Any],
    *,
    payer_hex: str,
    payee_hex: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce_hex: str,
    resource_url_hash: str,
    report_hash: str,
    requirements_hash: str,
) -> None:
    """The v3 typed action must bind the identical transfer facts."""

    expected = {
        "payer": payer_hex,
        "payee": payee_hex,
        "value": str(value),
        "valid_after": str(valid_after),
        "valid_before": str(valid_before),
        "eip712_auth_nonce": nonce_hex,
        "resource_url_hash": resource_url_hash,
        "report_hash": report_hash,
        "payment_requirements_hash": requirements_hash,
    }
    mismatched = sorted(
        key for key, want in expected.items() if str(body.get(key)) != want
    )
    if mismatched:
        raise _fail(
            "v3 action body does not bind the authorization on: "
            + ",".join(mismatched)
        )
    if str(body.get("caip2_network")) != _NETWORK:
        raise _fail(f"v3 action body network must be {_NETWORK}")
    if str(body.get("wcspr_package")) != _WCSPR_PACKAGE:
        raise _fail("v3 action body WCSPR package must be frozen")


# --------------------------------------------------------------------------
# import
# --------------------------------------------------------------------------


def build_imported_authorization(
    prepared: Mapping[str, Any], signed: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify a CSPR.click signed result offline and freeze request bytes."""

    if prepared.get("schema_version") != PREPARED_AUTHORIZATION_SCHEMA:
        raise _fail(
            f"prepared authorization schema must be {PREPARED_AUTHORIZATION_SCHEMA}"
        )
    prepare_request = _require_mapping(
        prepared.get("prepare_request"), context="prepared.prepare_request"
    )
    recomputed_prepared = build_prepared_authorization(prepare_request)
    if _canonical(recomputed_prepared) != _canonical(prepared):
        raise _fail("prepared authorization differs from its derived record")
    eip712 = _require_mapping(prepared.get("eip712"), context="prepared.eip712")
    digest_hex = _require_hex(
        eip712.get("digest_hex"), length=64, context="prepared digest"
    )
    fields = _require_mapping(
        prepared.get("authorization_fields"), context="authorization_fields"
    )
    accepted = _require_mapping(prepared.get("accepted"), context="accepted")
    resource = _require_mapping(prepared.get("resource"), context="resource")

    signature_hex = _casper_signature(
        signed.get("signatureHex"), "signed result signature"
    )
    public_key_hex = _casper_public_key(
        signed.get("publicKeyHex"), "signed result public key"
    )
    signature = bytes.fromhex(signature_hex)
    public_key = bytes.fromhex(public_key_hex)
    digest = bytes.fromhex(digest_hex)

    # Tag agreement + offline signature verification over the exact digest
    # (secp256k1 low-S / ed25519), using the accepted adapter routine.
    if signature[0] != public_key[0]:
        raise _fail("signature algorithm tag differs from the public key tag")
    try:
        _verify_casper_eip712_signature(
            public_key=public_key, signature=signature, digest=digest
        )
    except Exception as exc:
        raise _fail(f"signed authorization does not verify: {exc}") from exc

    # Derive the payer account hash from the signing key; it must equal the
    # intended payer. The account hash is never taken from the signed input.
    derived_payer = _account_hash_from_public_key(public_key).hex()
    intended_payer = _require_hex(
        fields.get("payer_account_hash"), length=64, context="payer_account_hash"
    )
    if derived_payer != intended_payer:
        raise _fail(
            "public key account hash differs from the prepared payer"
        )

    payee_hex = _require_hex(
        fields.get("payee_account_hash"), length=64, context="payee_account_hash"
    )
    value = _u256_decimal(fields.get("value_atomic"), context="value_atomic")
    valid_after = _require_int(fields.get("valid_after"), context="valid_after")
    valid_before = _require_int(fields.get("valid_before"), context="valid_before")
    nonce_hex = _require_hex(fields.get("nonce_hex"), length=64, context="nonce_hex")

    authorization_message = {
        "from": "00" + derived_payer,
        "to": "00" + payee_hex,
        "value": str(value),
        "validAfter": str(valid_after),
        "validBefore": str(valid_before),
        "nonce": nonce_hex,
    }
    # Freeze the exact production x402 payload.  Capture must reuse these
    # bytes; it may not reconstruct a second, merely equivalent request.
    signed_payload = {
        "x402Version": 2,
        "resource": resource,
        "accepted": accepted,
        "payload": {
            "signature": signature.hex(),
            "publicKey": public_key.hex(),
            "authorization": authorization_message,
        },
    }

    requirements_hash = bytes.fromhex(prepared["bindings"]["payment_requirements_hash"])
    signed_hash = _signed_payload_hash(
        payment_payload=signed_payload,
        requirements_hash=requirements_hash,
        signature=signature,
        public_key=public_key,
        payer=bytes.fromhex(derived_payer),
        payee=bytes.fromhex(payee_hex),
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=bytes.fromhex(nonce_hex),
    )

    # The /verify and /settle requests are the identical object, serialized
    # exactly once (canonical bytes) and reused verbatim for both calls and
    # for the journal request row.
    facilitator_request = {
        "x402Version": 2,
        "paymentPayload": signed_payload,
        "paymentRequirements": accepted,
    }
    request_bytes = _canonical(facilitator_request)

    return {
        "schema_version": IMPORTED_AUTHORIZATION_SCHEMA,
        "network": _NETWORK,
        "recovered_payer_account_hash": derived_payer,
        "payer_account_hash": derived_payer,
        "payee_account_hash": payee_hex,
        "signature_hex": signature.hex(),
        "public_key_hex": public_key.hex(),
        "signed_payment_payload": signed_payload,
        "signed_payment_payload_json_base64": _b64(_canonical(signed_payload)),
        "signed_payment_payload_hash": signed_hash.hex(),
        "facilitator_request": facilitator_request,
        "frozen_verify_request_body_base64": _b64(request_bytes),
        "frozen_settle_request_body_base64": _b64(request_bytes),
        "frozen_request_body_sha256": __import__("hashlib").sha256(request_bytes).hexdigest(),
        "bindings": dict(prepared["bindings"]),
        "eip712_digest_hex": digest_hex,
    }


# --------------------------------------------------------------------------
# capture
# --------------------------------------------------------------------------


def _require_sequence(value: Any, *, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(f"{context} must be a JSON array")
    return value


def _require_utc(value: Any, *, context: str) -> str:
    # A light structural gate; the accepted adapter enforces the full grammar
    # and every ordering during self-verification.
    if not isinstance(value, str) or not value.endswith("Z") or not 20 <= len(value) <= 32:
        raise _fail(f"{context} must be a UTC RFC3339 timestamp")
    return value


def _bundle_bytes(
    value: Any, *, context: str, allow_empty: bool = False
) -> bytes:
    if not isinstance(value, str) or (not value and not allow_empty):
        qualifier = "base64 text" if allow_empty else "non-empty base64 text"
        raise _fail(f"{context} must be {qualifier}")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise _fail(f"{context} is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise _fail(f"{context} is not canonical base64")
    if not raw and not allow_empty:
        raise _fail(f"{context} must not be empty")
    return raw


def _strict_json_bytes(raw: bytes, *, context: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        ValueError,
    ) as exc:
        raise _fail(f"{context} is not strict UTF-8 JSON: {exc}") from exc


def _resource_id_from_url(url: str) -> str:
    value = url.rsplit("/", 1)[-1]
    if not value or len(value) > 128:
        raise _fail("configured resource URL has no bounded resource id")
    return value


def _http_exchange(
    *,
    method: str,
    url: str,
    request_bytes: bytes,
    response_bytes: bytes,
    status: int,
    observed_at: str,
) -> dict[str, Any]:
    return {
        "method": method,
        "url": url,
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": _sha256_hex(request_bytes),
        "response_status": status,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": _sha256_hex(response_bytes),
        "observed_at": observed_at,
    }


def _raw_http_exchange(
    value: Any,
    *,
    context: str,
    expected_method: str,
    expected_url: str,
    expected_request_bytes: bytes,
) -> tuple[dict[str, Any], bytes]:
    """Project one observed HTTP exchange without inventing wire facts."""

    entry = _require_mapping(value, context=context)
    expected_keys = {
        "method",
        "url",
        "request_body_base64",
        "response_status",
        "response_content_type",
        "response_body_base64",
        "observed_at",
    }
    if set(entry) != expected_keys:
        raise _fail(f"{context} keys differ from the raw HTTP shape")
    request_bytes = _bundle_bytes(
        entry.get("request_body_base64"),
        context=f"{context}.request_body_base64",
        allow_empty=True,
    )
    if (
        entry.get("method") != expected_method
        or entry.get("url") != expected_url
        or request_bytes != expected_request_bytes
        or entry.get("response_content_type") != "application/json"
    ):
        raise _fail(f"{context} method, URL, body or content type differs")
    status = _require_int(
        entry.get("response_status"), context=f"{context}.response_status"
    )
    if status != 200:
        # Refuse before decoding or copying an upstream error body.
        raise _fail(f"{context} did not return HTTP 200")
    response_bytes = _bundle_bytes(
        entry.get("response_body_base64"),
        context=f"{context}.response_body_base64",
    )
    observed_at = _require_utc(
        entry.get("observed_at"), context=f"{context}.observed_at"
    )
    return (
        _http_exchange(
            method=expected_method,
            url=expected_url,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            status=status,
            observed_at=observed_at,
        ),
        response_bytes,
    )


def _raw_rpc_exchange(
    value: Any, *, context: str, expected_url: str
) -> tuple[dict[str, Any], bytes, bytes]:
    entry = _require_mapping(value, context=context)
    if set(entry) != {
        "url",
        "request_body_base64",
        "response_status",
        "response_content_type",
        "response_body_base64",
        "observed_at",
    }:
        raise _fail(f"{context} keys differ from the raw RPC shape")
    request_bytes = _bundle_bytes(
        entry.get("request_body_base64"),
        context=f"{context}.request_body_base64",
    )
    status = _require_int(
        entry.get("response_status"), context=f"{context}.response_status"
    )
    if (
        entry.get("url") != expected_url
        or status != 200
        or entry.get("response_content_type") != "application/json"
    ):
        raise _fail(f"{context} URL or HTTP result differs")
    response_bytes = _bundle_bytes(
        entry.get("response_body_base64"),
        context=f"{context}.response_body_base64",
    )
    observed_at = _require_utc(
        entry.get("observed_at"), context=f"{context}.observed_at"
    )
    exchange = {
        "url": expected_url,
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": _sha256_hex(request_bytes),
        "response_status": status,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": _sha256_hex(response_bytes),
        "observed_at": observed_at,
    }
    return exchange, request_bytes, response_bytes


def _raw_paid_resource_exchange(
    value: Any,
    *,
    context: str,
    expected_payload: Mapping[str, Any],
    expect_payment_response: bool,
) -> dict[str, Any]:
    """Derive adapter fields solely from observed header/body bytes."""

    entry = _require_mapping(value, context=context)
    expected_keys = {
        "method",
        "url",
        "request_headers_canonical_json_base64",
        "request_body_base64",
        "response_status",
        "response_headers_canonical_json_base64",
        "response_content_type",
        "response_body_base64",
        "observed_at",
    }
    if set(entry) != expected_keys:
        raise _fail(f"{context} keys differ from the raw paid-resource shape")
    request_headers = _bundle_bytes(
        entry.get("request_headers_canonical_json_base64"),
        context=f"{context}.request_headers",
    )
    request_headers_object = _strict_json_bytes(
        request_headers, context=f"{context}.request_headers"
    )
    if (
        not isinstance(request_headers_object, dict)
        or _canonical(request_headers_object) != request_headers
        or set(request_headers_object) != {"payment-signature"}
    ):
        raise _fail(f"{context} request headers are not canonical payment evidence")
    signature_value = _require_str(
        request_headers_object.get("payment-signature"),
        context=f"{context}.payment-signature",
    )
    try:
        signed_payload_bytes = base64.b64decode(signature_value, validate=True)
    except Exception as exc:
        raise _fail(f"{context} payment-signature is not base64") from exc
    if (
        base64.b64encode(signed_payload_bytes).decode("ascii")
        != signature_value
        or signed_payload_bytes != _canonical(expected_payload)
    ):
        raise _fail(f"{context} payment-signature differs from the frozen payload")

    request_body = _bundle_bytes(
        entry.get("request_body_base64"),
        context=f"{context}.request_body",
        allow_empty=True,
    )
    response_headers = _bundle_bytes(
        entry.get("response_headers_canonical_json_base64"),
        context=f"{context}.response_headers",
        allow_empty=False,
    )
    response_headers_object = _strict_json_bytes(
        response_headers, context=f"{context}.response_headers"
    )
    if (
        not isinstance(response_headers_object, dict)
        or _canonical(response_headers_object) != response_headers
    ):
        raise _fail(f"{context} response headers are not canonical JSON")
    response_body = _bundle_bytes(
        entry.get("response_body_base64"),
        context=f"{context}.response_body",
    )
    status = _require_int(
        entry.get("response_status"), context=f"{context}.response_status"
    )
    observed_at = _require_utc(
        entry.get("observed_at"), context=f"{context}.observed_at"
    )
    if (
        entry.get("method") != "GET"
        or request_body
        or entry.get("response_content_type") != "application/json"
    ):
        raise _fail(f"{context} method, body or content type differs")

    exchange: dict[str, Any] = {
        "method": "GET",
        "url": _require_str(entry.get("url"), context=f"{context}.url"),
        "request_headers_canonical_json_base64": _b64(request_headers),
        "request_headers_canonical_json_sha256": _sha256_hex(request_headers),
        "request_body_base64": "",
        "request_body_sha256": _sha256_hex(b""),
        "payment_signature_raw_value_base64": _b64(
            signature_value.encode("ascii")
        ),
        "payment_signature_raw_value_sha256": _sha256_hex(
            signature_value.encode("ascii")
        ),
        "payment_signature_decoded_payload_base64": _b64(
            signed_payload_bytes
        ),
        "payment_signature_decoded_payload_sha256": _sha256_hex(
            signed_payload_bytes
        ),
        "response_status": status,
        "response_headers_canonical_json_base64": _b64(response_headers),
        "response_headers_canonical_json_sha256": _sha256_hex(response_headers),
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_body),
        "response_body_sha256": _sha256_hex(response_body),
        "observed_at": observed_at,
    }
    if expect_payment_response:
        if status != 200 or set(response_headers_object) != {"payment-response"}:
            raise _fail(f"{context} successful payment response is absent")
        payment_response_value = _require_str(
            response_headers_object.get("payment-response"),
            context=f"{context}.payment-response",
        )
        try:
            settlement_bytes = base64.b64decode(
                payment_response_value, validate=True
            )
        except Exception as exc:
            raise _fail(f"{context} payment-response is not base64") from exc
        if (
            base64.b64encode(settlement_bytes).decode("ascii")
            != payment_response_value
            or _canonical(
                _strict_json_bytes(
                    settlement_bytes,
                    context=f"{context}.payment-response",
                )
            )
            != settlement_bytes
        ):
            raise _fail(f"{context} payment-response is not canonical")
        exchange.update(
            {
                "payment_response_raw_value_base64": _b64(
                    payment_response_value.encode("ascii")
                ),
                "payment_response_raw_value_sha256": _sha256_hex(
                    payment_response_value.encode("ascii")
                ),
                "payment_response_decoded_settlement_base64": _b64(
                    settlement_bytes
                ),
                "payment_response_decoded_settlement_sha256": _sha256_hex(
                    settlement_bytes
                ),
            }
        )
    elif status != 409 or response_headers_object:
        raise _fail(f"{context} rejection status or response headers differ")
    return exchange


def _raw_row_observation(value: Any, *, context: str) -> dict[str, Any]:
    entry = _require_mapping(value, context=context)
    if set(entry) != {
        "row_canonical_json_base64",
        "observed_at",
        "service_instance_id",
    }:
        raise _fail(f"{context} keys differ from the raw row shape")
    row_bytes = _bundle_bytes(
        entry.get("row_canonical_json_base64"),
        context=f"{context}.row_canonical_json_base64",
    )
    row = _strict_json_bytes(row_bytes, context=f"{context}.row")
    if not isinstance(row, dict) or _canonical(row) != row_bytes:
        raise _fail(f"{context} row is not canonical JSON")
    return {
        "row_canonical_json_base64": _b64(row_bytes),
        "row_canonical_json_sha256": _sha256_hex(row_bytes),
        "observed_at": _require_utc(
            entry.get("observed_at"), context=f"{context}.observed_at"
        ),
        "service_instance_id": _require_str(
            entry.get("service_instance_id"),
            context=f"{context}.service_instance_id",
        ),
    }


def _load_journal_migration() -> bytes:
    try:
        migration = _JOURNAL_MIGRATION_PATH.read_bytes()
    except OSError as exc:
        raise _fail("upstream settle journal migration is unavailable") from exc
    if (
        len(migration) != _JOURNAL_MIGRATION_LENGTH
        or _sha256_hex(migration) != _JOURNAL_MIGRATION_SHA256
    ):
        raise _fail("upstream settle journal migration differs from the release pin")
    return migration


def _build_upstream_settle_journal(
    value: Any,
) -> dict[str, Any]:
    """Project actual SQLite backups; never create or insert evidence rows."""

    entry = _require_mapping(value, context="fulfillment.journal")
    if set(entry) != {"authoritative_database_id", "snapshots"}:
        raise _fail("fulfillment.journal keys differ from the raw journal shape")
    migration = _load_journal_migration()
    snapshots_input = _require_mapping(
        entry.get("snapshots"), context="fulfillment.journal.snapshots"
    )
    names = (
        "after_first_release",
        "after_exact_retry",
        "after_cross_binding_reuse",
    )
    if set(snapshots_input) != set(names):
        raise _fail("journal snapshots differ from the required raw stages")
    snapshots: dict[str, dict[str, Any]] = {}
    for name in names:
        context = f"fulfillment.journal.snapshots.{name}"
        snapshot = _require_mapping(
            snapshots_input.get(name), context=context
        )
        if set(snapshot) != {
            "sqlite_backup_base64",
            "observed_at",
            "service_instance_id",
        }:
            raise _fail(f"{context} keys differ from the raw snapshot shape")
        database_bytes = _bundle_bytes(
            snapshot.get("sqlite_backup_base64"),
            context=f"{context}.sqlite_backup_base64",
        )
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(database_bytes)
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA integrity_check").fetchall() != [
                ("ok",)
            ]:
                raise _fail(f"{context} SQLite integrity check failed")
            canonical_rows = _canonical_journal_rows(connection)
        except sqlite3.Error as exc:
            raise _fail(f"{context} is not a readable SQLite backup") from exc
        finally:
            connection.close()
        rows_bytes = _canonical(canonical_rows)
        snapshots[name] = {
            "sqlite_backup_base64": _b64(database_bytes),
            "sqlite_backup_sha256": _sha256_hex(database_bytes),
            "rows_canonical_json_base64": _b64(rows_bytes),
            "rows_canonical_json_sha256": _sha256_hex(rows_bytes),
            "journal_root_sha256": _journal_root(canonical_rows),
            "observed_at": _require_utc(
                snapshot.get("observed_at"),
                context=f"{context}.observed_at",
            ),
            "service_instance_id": _require_str(
                snapshot.get("service_instance_id"),
                context=f"{context}.service_instance_id",
            ),
        }

    return {
        "schema_id": _UPSTREAM_SETTLE_JOURNAL_SCHEMA_ID,
        "authoritative_database_id": _require_str(
            entry.get("authoritative_database_id"),
            context="fulfillment.journal.authoritative_database_id",
        ),
        "migration_sql_base64": _b64(migration),
        "migration_sql_sha256": _sha256_hex(migration),
        "snapshots": snapshots,
    }


def _build_wcspr_readback(
    value: Any, *, context: str, runtime_args: list[dict[str, str]]
) -> dict[str, Any]:
    entry = _require_mapping(value, context=context)
    if set(entry) != {"rpc_transcript"}:
        raise _fail(f"{context} keys differ from the raw readback shape")
    transcript, _request_bytes, _response_bytes = _raw_rpc_exchange(
        entry.get("rpc_transcript"),
        context=f"{context}.rpc_transcript",
        expected_url=_CASPER_RPC_URL,
    )
    return {
        "package_hash": _WCSPR_PACKAGE,
        "contract_hash": _WCSPR_CONTRACT,
        "contract_version": _WCSPR_VERSION,
        "lock_status": "Unlocked",
        "entry_point": "transfer_with_authorization",
        "runtime_args": runtime_args,
        "observed_at": transcript["observed_at"],
        "rpc_transcript": transcript,
    }


def _build_settlement_provider(value: Any, *, context: str) -> dict[str, Any]:
    entry = _require_mapping(value, context=context)
    endpoint_id = _require_str(entry.get("endpoint_id"), context=f"{context}.endpoint_id")
    origin = _require_str(entry.get("origin"), context=f"{context}.origin")

    def rpc(name: str) -> dict[str, Any]:
        exchange, _request_bytes, _response_bytes = _raw_rpc_exchange(
            entry.get(name),
            context=f"{context}.{name}",
            expected_url=origin,
        )
        return exchange

    return {
        "endpoint_id": endpoint_id,
        "origin": origin,
        "info_get_transaction": rpc("info_get_transaction"),
        "chain_get_block": rpc("chain_get_block"),
        "info_get_status": rpc("info_get_status"),
    }


def _derive_parsed_settlement(
    *,
    transaction_response_bytes: bytes,
    block_response_bytes: bytes,
    runtime_args: list[dict[str, str]],
) -> dict[str, Any]:
    transaction = _strict_json_bytes(
        transaction_response_bytes, context="settlement transaction RPC response"
    )
    block = _strict_json_bytes(
        block_response_bytes, context="settlement block RPC response"
    )
    try:
        execution_info = transaction["result"]["execution_info"]
        block_hash = execution_info["block_hash"]
        block_height = execution_info["block_height"]
        execution_result = execution_info["execution_result"]["Version2"]
        execution_error = execution_result["error_message"]
        header = block["result"]["block_with_signatures"]["block"]["Version2"][
            "header"
        ]
        state_root_hash = header["state_root_hash"]
        block_timestamp = header["timestamp"]
    except (KeyError, TypeError, IndexError) as exc:
        raise _fail("settlement RPC transcripts are malformed") from exc
    if not isinstance(block_height, int) or isinstance(block_height, bool):
        raise _fail("settlement block height is not an integer")
    return {
        "block_hash": block_hash,
        "block_height": block_height,
        "state_root_hash": state_root_hash,
        "block_timestamp": block_timestamp,
        "execution_success": execution_error is None,
        "execution_error": execution_error,
        "target_contract_hash": _WCSPR_CONTRACT,
        "contract_version": _WCSPR_VERSION,
        "entry_point": "transfer_with_authorization",
        "runtime_args": runtime_args,
    }


def _governance_binding(
    *,
    v3_proof_bytes: bytes,
    resource_url_hash_hex: str,
    report_hash_hex: str,
    payment_requirements_hash_hex: str,
    signed_payment_payload_hash_hex: str,
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    proof = _strict_json_bytes(v3_proof_bytes, context="v3 proof")
    if not isinstance(proof, dict):
        raise _fail("v3 proof must be a JSON object")
    if v3_proof_bytes != _canonical(proof):
        raise _fail("v3 proof is not canonical ASCII JSON")
    try:
        verification = verify_v3_proof_document(proof)
    except Exception as exc:  # the v3 verifier raises its own typed errors
        raise _fail(f"v3 proof does not verify: {exc}") from exc
    if verification.get("valid") is not True:
        raise _fail("v3 proof did not finalize the exact envelope")
    input_document = proof.get("input")
    if not isinstance(input_document, dict):
        raise _fail("v3 proof is missing its typed input")
    header = input_document.get("header")
    body = input_document.get("body")
    if not isinstance(header, dict) or not isinstance(body, dict):
        raise _fail("v3 proof is missing its typed header or body")
    try:
        steps = proof["run"]["steps"]
        finalization_step = next(
            step
            for step in steps
            if isinstance(step, dict) and step.get("name") == "finalize_exact"
        )
        finalization = verification["contract_step_outcomes"]["finalize_exact"]
    except (KeyError, TypeError, StopIteration) as exc:
        raise _fail("v3 proof has no exact finalization outcome") from exc
    binding = {
        "proposal_id": header.get("proposal_id"),
        "proposal_hash": header.get("proposal_hash"),
        "proposal_nonce": header.get("proposal_nonce"),
        "action_id": verification.get("action_id"),
        "action_kind": "OfficialX402SettlementV1",
        "action_version": 1,
        "envelope_hash": verification.get("envelope_hash"),
        "deployment_domain": header.get("deployment_domain"),
        "network": body.get("caip2_network"),
        "package_hash": verification.get("package_hash"),
        "contract_hash": verification.get("contract_hash"),
        "finalization_transaction": finalization_step.get("deploy_hash"),
        "finalized_at": finalization.get("finalized_at"),
        "observed_at": finalization.get("observed_at"),
        "resource_url_hash": resource_url_hash_hex,
        "payment_requirements_hash": payment_requirements_hash_hex,
        "signed_payment_payload_hash": signed_payment_payload_hash_hex,
        "report_hash": report_hash_hex,
        "v3_proof_sha256": _sha256_hex(v3_proof_bytes),
        "v3_proof_bytes_base64": _b64(v3_proof_bytes),
    }
    return binding, body


def _facilitator_exchange(
    value: Any, *, context: str, method: str, url: str, request_bytes: bytes
) -> tuple[dict[str, Any], bytes]:
    return _raw_http_exchange(
        value,
        context=context,
        expected_method=method,
        expected_url=url,
        expected_request_bytes=request_bytes,
    )


def build_official_x402_artifact(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Assemble the official live-evidence artifact from raw capture inputs.

    Every hash, sha256, journal_root, call_id, parsed projection, governance
    binding, and chronology field is recomputed here from the raw bytes; no
    producer summary or success boolean is trusted. The assembled artifact is
    self-verified with the accepted in-process adapter before it is returned;
    on any adapter refusal this raises ``CaptureError`` and writes nothing.
    """

    if bundle.get("bundle_version") != CAPTURE_BUNDLE_SCHEMA:
        raise _fail(f"capture bundle schema must be {CAPTURE_BUNDLE_SCHEMA}")

    captured_at = _require_utc(bundle.get("captured_at"), context="captured_at")
    source_commit = _require_hex(
        bundle.get("source_commit"), length=40, context="source_commit"
    )
    deployment_commit = _require_hex(
        bundle.get("deployment_commit"), length=40, context="deployment_commit"
    )
    service_url = _require_str(bundle.get("service_url"), context="service_url")
    service_image_digest = _require_str(
        bundle.get("service_image_digest"), context="service_image_digest"
    )

    # --- authorization inputs (from the imported-authorization output) --------
    imported = _require_mapping(
        bundle.get("imported_authorization"), context="imported_authorization"
    )
    signed_payload_in = _require_mapping(
        imported.get("signed_payment_payload"),
        context="imported_authorization.signed_payment_payload",
    )
    payload_in = _require_mapping(
        signed_payload_in.get("payload"),
        context="imported_authorization.signed_payment_payload.payload",
    )
    authorization_in = _require_mapping(
        payload_in.get("authorization"),
        context=(
            "imported_authorization.signed_payment_payload.payload.authorization"
        ),
    )
    public_key_hex = _casper_public_key(
        imported.get("public_key_hex"), "imported public key"
    )
    signature_hex = _casper_signature(
        imported.get("signature_hex"), "imported signature"
    )
    public_key = bytes.fromhex(public_key_hex)
    signature = bytes.fromhex(signature_hex)

    resource = _require_mapping(
        signed_payload_in.get("resource"), context="configured resource"
    )
    accepted = _require_mapping(
        signed_payload_in.get("accepted"), context="accepted payment requirements"
    )
    resource_url = _require_str(resource.get("url"), context="resource.url")
    payee_hex = _require_hex(
        imported.get("payee_account_hash"), length=64, context="payee_account_hash"
    )
    if payload_in.get("publicKey") != public_key_hex:
        raise _fail("imported public key differs from the frozen payment payload")
    if payload_in.get("signature") != signature_hex:
        raise _fail("imported signature differs from the frozen payment payload")
    payer_tagged = _require_hex(
        authorization_in.get("from"), length=66, context="authorization payer"
    )
    payee_tagged = _require_hex(
        authorization_in.get("to"), length=66, context="authorization payee"
    )
    if not payer_tagged.startswith("00") or not payee_tagged.startswith("00"):
        raise _fail("authorization payer and payee must be account-tagged")
    value = _u256_decimal(
        authorization_in.get("value"), context="authorization value"
    )
    valid_after = _require_int(
        _u256_decimal(
            authorization_in.get("validAfter"), context="valid_after"
        ),
        context="valid_after",
    )
    valid_before = _require_int(
        _u256_decimal(
            authorization_in.get("validBefore"), context="valid_before"
        ),
        context="valid_before",
    )
    nonce_hex = _require_hex(
        authorization_in.get("nonce"), length=64, context="authorization nonce"
    )

    extra = _require_mapping(accepted.get("extra"), context="accepted.extra")
    token_name = _require_str(extra.get("name"), context="accepted.extra.name")
    domain_version = _require_str(
        extra.get("version"), context="accepted.extra.version"
    )
    asset_hex = _require_hex(
        accepted.get("asset"), length=64, context="accepted.asset"
    )
    network_value = _require_str(accepted.get("network"), context="accepted.network")

    # --- recompute payer, digests, and every binding hash --------------------
    payer = _account_hash_from_public_key(public_key)
    payer_hex = payer.hex()
    payee = bytes.fromhex(payee_hex)
    nonce = bytes.fromhex(nonce_hex)
    if payer_tagged != "00" + payer_hex or payee_tagged != "00" + payee_hex:
        raise _fail("frozen authorization accounts differ from imported identities")

    requirements_hash = _payment_requirements_hash(accepted)
    resource_url_hash = _resource_url_hash(resource_url)
    report_bytes = _decode_report(bundle.get("report_bytes_base64"))
    report_hash = _report_hash(report_bytes)
    digest = _eip712_digest(
        token_name=token_name,
        domain_version=domain_version,
        network=network_value,
        package_hash=bytes.fromhex(asset_hex),
        payer=payer,
        payee=payee,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
    )

    signed_payment_payload = dict(signed_payload_in)
    signed_payload_hash = _signed_payload_hash(
        payment_payload=signed_payment_payload,
        requirements_hash=requirements_hash,
        signature=signature,
        public_key=public_key,
        payer=payer,
        payee=payee,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
    )
    facilitator_request = {
        "x402Version": 2,
        "paymentPayload": signed_payment_payload,
        "paymentRequirements": accepted,
    }
    facilitator_request_bytes = _canonical(facilitator_request)
    frozen_verify = _bundle_bytes(
        imported.get("frozen_verify_request_body_base64"),
        context="imported frozen verify request",
    )
    frozen_settle = _bundle_bytes(
        imported.get("frozen_settle_request_body_base64"),
        context="imported frozen settle request",
    )
    if (
        frozen_verify != frozen_settle
        or frozen_verify != facilitator_request_bytes
        or imported.get("facilitator_request") != facilitator_request
        or imported.get("frozen_request_body_sha256")
        != _sha256_hex(facilitator_request_bytes)
        or imported.get("signed_payment_payload_hash")
        != signed_payload_hash.hex()
    ):
        raise _fail("imported frozen request differs from the verified authorization")
    eip712_domain = {
        "name": token_name,
        "version": domain_version,
        "chain_name": network_value,
        "contract_package_hash": "0x" + asset_hex,
    }

    # --- governance binding recomputed from the v3 proof ---------------------
    v3_proof_bytes = _bundle_bytes(
        bundle.get("v3_proof_bytes_base64"), context="v3_proof_bytes_base64"
    )
    governance_binding, _v3_body = _governance_binding(
        v3_proof_bytes=v3_proof_bytes,
        resource_url_hash_hex=resource_url_hash.hex(),
        report_hash_hex=report_hash.hex(),
        payment_requirements_hash_hex=requirements_hash.hex(),
        signed_payment_payload_hash_hex=signed_payload_hash.hex(),
    )

    # --- facilitator exchanges (raw observed responses) ----------------------
    facilitator_in = _require_mapping(
        bundle.get("facilitator"), context="facilitator"
    )
    supported, _supported_response_bytes = _facilitator_exchange(
        facilitator_in.get("supported"),
        context="facilitator.supported",
        method="GET",
        url=_SUPPORTED_URL,
        request_bytes=b"",
    )
    verify_exchange, verify_response_bytes = _facilitator_exchange(
        facilitator_in.get("verify"),
        context="facilitator.verify",
        method="POST",
        url=_VERIFY_URL,
        request_bytes=facilitator_request_bytes,
    )
    settle_exchange, settle_response_bytes = _facilitator_exchange(
        facilitator_in.get("settle"),
        context="facilitator.settle",
        method="POST",
        url=_SETTLE_URL,
        request_bytes=facilitator_request_bytes,
    )
    verify_response = _strict_json_bytes(
        verify_response_bytes, context="verify response"
    )
    if not isinstance(verify_response, dict):
        raise _fail("verify response must be a JSON object")
    settle_response = _strict_json_bytes(
        settle_response_bytes, context="settle response"
    )
    if not isinstance(settle_response, dict):
        raise _fail("settle response must be a JSON object")
    transaction = _require_hex(
        settle_response.get("transaction"), length=64, context="settlement transaction"
    )
    verify_payer = _require_hex(
        verify_response.get("payer"), length=66, context="verify payer"
    )
    settle_payer = _require_hex(
        settle_response.get("payer"), length=66, context="settle payer"
    )
    if not verify_payer.startswith("00") or not settle_payer.startswith("00"):
        raise _fail("facilitator payer must be an account-tagged hash")
    facilitator = {
        "supported": supported,
        "verify": verify_exchange,
        "settle": settle_exchange,
        "parsed_verify": {
            "is_valid": verify_response.get("isValid"),
            "payer_account_hash": verify_payer[2:],
        },
        "parsed_settle": {
            "success": settle_response.get("success"),
            "transaction": transaction,
            "network": settle_response.get("network"),
            "payer_account_hash": settle_payer[2:],
        },
    }

    # --- canonical WCSPR runtime arguments, reused everywhere ------------------
    authorization_context = {
        "payer": payer,
        "payee": payee,
        "value": value,
        "valid_after": valid_after,
        "valid_before": valid_before,
        "nonce": nonce,
        "public_key": public_key,
        "signature": signature,
    }
    runtime_args = _runtime_args_expected(authorization_context)

    readbacks_in = _require_mapping(
        bundle.get("wcspr_readbacks"), context="wcspr_readbacks"
    )
    wcspr_readbacks = {
        name: _build_wcspr_readback(
            readbacks_in.get(name),
            context=f"wcspr_readbacks.{name}",
            runtime_args=runtime_args,
        )
        for name in ("pre_verify", "pre_settle", "post_settle")
    }

    # --- settlement chain evidence + recomputed parsed settlement -------------
    providers_in = _require_sequence(
        bundle.get("settlement_providers"), context="settlement_providers"
    )
    if len(providers_in) != 2:
        raise _fail("settlement_providers must contain exactly two providers")
    providers = [
        _build_settlement_provider(item, context=f"settlement_providers[{index}]")
        for index, item in enumerate(providers_in)
    ]
    parsed_settlement = _derive_parsed_settlement(
        transaction_response_bytes=base64.b64decode(
            providers[0]["info_get_transaction"]["response_body_base64"]
        ),
        block_response_bytes=base64.b64decode(
            providers[0]["chain_get_block"]["response_body_base64"]
        ),
        runtime_args=runtime_args,
    )
    settlement_chain_evidence = {
        "network": _NETWORK,
        "settlement_transaction": transaction,
        "providers": providers,
        "parsed_settlement": parsed_settlement,
    }

    # --- fulfillment: raw rows, raw paid HTTP, raw SQLite backups -----------
    fulfillment_in = _require_mapping(
        bundle.get("fulfillment"), context="fulfillment"
    )
    if set(fulfillment_in) != {
        "first_row",
        "post_restart_row",
        "first_release",
        "exact_retry",
        "cross_binding_reuse",
        "journal",
    }:
        raise _fail("fulfillment keys differ from the raw observation shape")
    first_row = _raw_row_observation(
        fulfillment_in.get("first_row"), context="fulfillment.first_row"
    )
    post_restart_row = _raw_row_observation(
        fulfillment_in.get("post_restart_row"),
        context="fulfillment.post_restart_row",
    )
    first_row_object = _strict_json_bytes(
        base64.b64decode(first_row["row_canonical_json_base64"]),
        context="fulfillment.first_row.row",
    )
    if not isinstance(first_row_object, dict):
        raise _fail("fulfillment first row must be one JSON object")
    settled_at = _require_utc(
        first_row_object.get("settledAt"),
        context="fulfillment.first_row.settledAt",
    )

    cross_in = _require_mapping(
        fulfillment_in.get("cross_binding_reuse"),
        context="fulfillment.cross_binding_reuse",
    )
    cross_url = _require_str(
        cross_in.get("url"),
        context="fulfillment.cross_binding_reuse.url",
    )
    cross_payment_payload = {
        "x402Version": 2,
        "resource": {**resource, "url": cross_url},
        "accepted": accepted,
        "payload": signed_payment_payload["payload"],
    }
    first_release = _raw_paid_resource_exchange(
        fulfillment_in.get("first_release"),
        context="fulfillment.first_release",
        expected_payload=signed_payment_payload,
        expect_payment_response=True,
    )
    exact_retry = _raw_paid_resource_exchange(
        fulfillment_in.get("exact_retry"),
        context="fulfillment.exact_retry",
        expected_payload=signed_payment_payload,
        expect_payment_response=True,
    )
    cross_binding_reuse = _raw_paid_resource_exchange(
        cross_in,
        context="fulfillment.cross_binding_reuse",
        expected_payload=cross_payment_payload,
        expect_payment_response=False,
    )
    first_release_at = first_release["observed_at"]
    upstream_settle_journal = _build_upstream_settle_journal(
        fulfillment_in.get("journal")
    )

    # --- assemble, self-verify against the accepted adapter, then return ------
    document = {
        "schema_version": OFFICIAL_X402_ARTIFACT_SCHEMA_VERSION,
        "captured_at": captured_at,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "capture_identity": {
            "service_url": service_url,
            "service_deployment_id": f"official-x402-{deployment_commit[:12]}",
            "service_image_digest": service_image_digest,
            "capture_tool_commit": source_commit,
        },
        "governance_binding": governance_binding,
        "resource_and_payment": {
            "configured_resource_json_base64": _b64(_canonical(resource)),
            "configured_resource_sha256": _sha256_hex(_canonical(resource)),
            "accepted_json_base64": _b64(_canonical(accepted)),
            "accepted_sha256": _sha256_hex(_canonical(accepted)),
            "payment_requirements_argument_json_base64": _b64(_canonical(accepted)),
            "payment_requirements_argument_sha256": _sha256_hex(_canonical(accepted)),
        },
        "authorization": {
            "eip712_domain_json_base64": _b64(_canonical(eip712_domain)),
            "eip712_authorization_preimage_base64": _b64(digest),
            "signed_payment_payload_json_base64": _b64(
                _canonical(signed_payment_payload)
            ),
            "signature_hex": signature_hex,
            "public_key_hex": public_key_hex,
            "recovered_payer_account_hash": payer_hex,
            "payer_account_hash": payer_hex,
            "payee_account_hash": payee_hex,
            "value_atomic": str(value),
            "nonce_hex": nonce_hex,
            "valid_after": str(valid_after),
            "valid_before": str(valid_before),
            "payment_requirements_hash": requirements_hash.hex(),
            "signed_payment_payload_hash": signed_payload_hash.hex(),
        },
        "facilitator": facilitator,
        "wcspr_readbacks": wcspr_readbacks,
        "settlement_chain_evidence": settlement_chain_evidence,
        "fulfillment": {
            "first_row": first_row,
            "post_restart_row": post_restart_row,
            "first_release": first_release,
            "exact_retry": exact_retry,
            "cross_binding_reuse": cross_binding_reuse,
            "upstream_settle_journal": upstream_settle_journal,
        },
        "protected_report": {
            "media_type": "application/json",
            "content_base64": _b64(report_bytes),
            "decoded_length": len(report_bytes),
            "report_hash": report_hash.hex(),
            "response_hash": _sha256_hex(report_bytes),
        },
        "release_order": {
            "v3_finalized_at": governance_binding["finalized_at"],
            "settlement_finalized_at": settled_at,
            "report_released_at": first_release_at,
        },
    }

    raw = _canonical(document)
    try:
        verify_official_x402_artifact(document, raw)
    except ReleaseProofAdapterError as exc:
        raise _fail(f"assembled artifact failed self-verification: {exc}") from exc
    return document


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _emit(document: Mapping[str, Any], out: str | None) -> int:
    payload = _canonical(document)
    if out is None or not Path(out).is_absolute():
        raise _fail("output path must be absolute and explicitly provided")
    try:
        write_private_file_once(Path(out), payload)
    except AtomicPrivateFileError as exc:
        raise _fail(f"output could not be written safely: {exc}") from exc
    sys.stdout.write(
        json.dumps(
            {
                "written": True,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        + "\n"
    )
    return 0


def _cmd_prepare(args: argparse.Namespace) -> int:
    request = _require_mapping(
        _read_json(Path(args.request), context="prepare request"),
        context="prepare request",
    )
    return _emit(build_prepared_authorization(request), args.out)


def _cmd_import(args: argparse.Namespace) -> int:
    prepared = _require_mapping(
        _read_json(Path(args.prepared), context="prepared authorization"),
        context="prepared authorization",
    )
    signed = _require_mapping(
        _read_json(Path(args.signed), context="signed result"),
        context="signed result",
    )
    return _emit(build_imported_authorization(prepared, signed), args.out)


def _cmd_capture(args: argparse.Namespace) -> int:
    bundle = _require_mapping(
        _read_json(Path(args.bundle), context="capture bundle"),
        context="capture bundle",
    )
    return _emit(build_official_x402_artifact(bundle), args.out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="build EIP-712 signing inputs")
    prepare.add_argument("--request", required=True)
    prepare.add_argument("--out", required=True)
    prepare.set_defaults(handler=_cmd_prepare)

    imp = sub.add_parser("import", help="verify a signed result offline")
    imp.add_argument("--prepared", required=True)
    imp.add_argument("--signed", required=True)
    imp.add_argument("--out", required=True)
    imp.set_defaults(handler=_cmd_import)

    capture = sub.add_parser(
        "capture", help="assemble the official live-evidence artifact"
    )
    capture.add_argument("--bundle", required=True)
    capture.add_argument("--out", required=True)
    capture.set_defaults(handler=_cmd_capture)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except CaptureError as exc:
        sys.stderr.write(json.dumps({"refusal": str(exc)}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
