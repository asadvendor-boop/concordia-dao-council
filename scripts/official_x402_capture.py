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
import json
import sys
from pathlib import Path
from typing import Any, Mapping

# Reuse the accepted adapter's EXACT primitives so every recomputation here
# matches the verifier bit-for-bit. Never reimplement the crypto.
from shared.official_x402_release_adapter import (
    _NETWORK,
    _SETTLE_URL,
    _SUPPORTED_URL,
    _VERIFY_URL,
    _WCSPR_CONTRACT,
    _WCSPR_PACKAGE,
    _account_hash_from_public_key,
    _canonical,
    _casper_public_key,
    _casper_signature,
    _eip712_digest,
    _payment_requirements_hash,
    _report_hash,
    _resource_url_hash,
    _signed_payload_hash,
    _tagged_account_hash,
    _verify_casper_eip712_signature,
)
from shared.atomic_private_file import write_private_file_once
from shared.secure_secret_file import read_secure_secret_file

PREPARE_REQUEST_SCHEMA = "concordia.official_x402_prepare_request.v1"
PREPARED_AUTHORIZATION_SCHEMA = "concordia.official_x402_prepared_authorization.v1"
IMPORTED_AUTHORIZATION_SCHEMA = "concordia.official_x402_imported_authorization.v1"

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


def _fail(message: str) -> "CaptureError":
    return CaptureError(message)


def _read_json(path: Path, *, context: str) -> Any:
    try:
        raw = read_secure_secret_file(path, max_bytes=_MAX_INPUT_BYTES)
    except Exception as exc:  # secure reader raises its own typed error
        raise _fail(f"{context} could not be read securely: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise _fail(f"{context} is not valid UTF-8 JSON") from exc


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

    # The signed payload the runtime submits, matching the shape the adapter
    # cross-checks (§ body fields + resource + accepted + signature/pubkey).
    body = {
        "x402_version": "2",
        "payer": derived_payer,
        "payee": payee_hex,
        "value": str(value),
        "eip712_auth_nonce": nonce_hex,
        "valid_after": str(valid_after),
        "valid_before": str(valid_before),
        "resource_url_hash": prepared["bindings"]["resource_url_hash"],
        "report_hash": prepared["bindings"]["report_hash"],
        "payment_requirements_hash": prepared["bindings"]["payment_requirements_hash"],
    }
    signed_payload = {
        "x402Version": 2,
        "resource": resource,
        "accepted": accepted,
        "signature": signature.hex(),
        "publicKey": public_key.hex(),
        "payer_account_hash": derived_payer,
        "payee_account_hash": payee_hex,
        "value": str(value),
        "valid_after": valid_after,
        "valid_before": valid_before,
        "nonce": nonce_hex,
        "body": body,
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
# CLI
# --------------------------------------------------------------------------


def _emit(document: Mapping[str, Any], out: str | None) -> int:
    payload = _canonical(document)
    if out is None:
        sys.stdout.write(payload.decode("ascii") + "\n")
        return 0
    write_private_file_once(Path(out), payload)
    sys.stdout.write(
        json.dumps({"written": out, "sha256": __import__("hashlib").sha256(payload).hexdigest()})
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="build EIP-712 signing inputs")
    prepare.add_argument("--request", required=True)
    prepare.add_argument("--out", default=None)
    prepare.set_defaults(handler=_cmd_prepare)

    imp = sub.add_parser("import", help="verify a signed result offline")
    imp.add_argument("--prepared", required=True)
    imp.add_argument("--signed", required=True)
    imp.add_argument("--out", default=None)
    imp.set_defaults(handler=_cmd_import)

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
