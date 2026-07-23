#!/usr/bin/env python3
"""Stage the verified official-x402 governance registry before settlement.

This command is deliberately offline and write-once. It accepts an already
finalized OfficialX402SettlementV1 proof, the exact payment inputs, and a full
base registry; it appends the derived internal record to a new combined
registry and never signs, submits, or calls a network.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.verify_v3_proof import (
    ProofVerificationError,
    verify_v3_proof_document,
)
from shared.actions_v3 import derive_x402_material
from shared.atomic_private_file import (
    AtomicPrivateFileError,
    write_private_file_once,
)
from shared.official_x402_release_adapter import (
    OfficialX402ReleaseAdapterError,
    _account_hash_from_public_key,
    _casper_public_key,
    _casper_signature,
    _decimal,
    _eip712_digest,
    _payment_requirements_hash,
    _report_hash,
    _resource_url_hash,
    _signed_payload_hash,
    _tagged_account_hash,
    _verify_casper_eip712_signature,
)
from shared.proof_registry import (
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    validate_internal_record,
    validate_registry_document,
)


STAGING_INPUT_SCHEMA = "concordia.official_x402_staging_input.v1"
NETWORK = "casper:casper-test"
PROOF_SOURCE = "artifacts/live/exact-envelope-v3-official.json"
PAYMENT_ENVELOPE_FIELDS = {
    "schema_version",
    "typed_action_input",
    "configured_resource",
    "payment_requirements",
    "protected_report_base64",
}
RESOURCE_FIELDS = {"url", "description", "mimeType"}
REQUIREMENTS_FIELDS = {
    "scheme",
    "network",
    "asset",
    "amount",
    "payTo",
    "maxTimeoutSeconds",
    "extra",
}
REQUIREMENTS_EXTRA_FIELDS = {"name", "version", "decimals", "symbol"}
SIGNED_PAYLOAD_FIELDS = {"x402Version", "resource", "accepted", "payload"}
PAYLOAD_FIELDS = {"signature", "publicKey", "authorization"}
AUTHORIZATION_FIELDS = {
    "from",
    "to",
    "value",
    "validAfter",
    "validBefore",
    "nonce",
}


class GovernanceStagingError(ValueError):
    """The supplied artifacts cannot form a pre-settlement registry record."""


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise GovernanceStagingError(f"{label} must be one JSON object")
    return copy.deepcopy(value)


def _exact_fields(
    value: object,
    fields: set[str],
    label: str,
) -> dict[str, Any]:
    document = _object(value, label)
    if set(document) != fields:
        raise GovernanceStagingError(f"{label} field set is not exact")
    return document


def _contains_boolean(value: object) -> bool:
    if type(value) is bool:
        return True
    if type(value) is dict:
        return any(_contains_boolean(item) for item in value.values())
    if type(value) is list:
        return any(_contains_boolean(item) for item in value)
    return False


def _canonical_data(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise GovernanceStagingError(
            "staging input is not canonical JSON data"
        ) from exc


def canonical_json_bytes(value: object) -> bytes:
    """Return the exact compact ASCII JSON stored in the internal registry."""

    return _canonical_data(value)


def _decode_report(value: object) -> bytes:
    if type(value) is not str:
        raise GovernanceStagingError("protected_report_base64 must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GovernanceStagingError(
            "protected_report_base64 must be canonical base64"
        ) from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != value:
        raise GovernanceStagingError(
            "protected_report_base64 must be non-empty canonical base64"
        )
    return decoded


def _hex_bytes(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise GovernanceStagingError(f"{label} must be lowercase hexadecimal")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise GovernanceStagingError(f"{label} must be lowercase hexadecimal") from exc
    if raw.hex() != value:
        raise GovernanceStagingError(f"{label} must be lowercase hexadecimal")
    return raw


def _finalization(
    proof: Mapping[str, Any],
    verification: Mapping[str, Any],
) -> tuple[str, str, str]:
    run = _object(proof.get("run"), "v3 proof run")
    steps = run.get("steps")
    if type(steps) is not list:
        raise GovernanceStagingError("v3 proof run steps must be an array")
    exact_steps = [
        step
        for step in steps
        if type(step) is dict and step.get("name") == "finalize_exact"
    ]
    if len(exact_steps) != 1:
        raise GovernanceStagingError("v3 proof must contain one exact finalization")
    outcome_map = _object(
        verification.get("contract_step_outcomes"),
        "verified v3 contract outcomes",
    )
    outcome = _object(
        outcome_map.get("finalize_exact"),
        "verified exact finalization",
    )
    transaction = exact_steps[0].get("deploy_hash")
    finalized_at = outcome.get("finalized_at")
    observed_at = outcome.get("observed_at")
    if not all(
        isinstance(item, str) and item
        for item in (transaction, finalized_at, observed_at)
    ):
        raise GovernanceStagingError(
            "verified exact finalization identity is incomplete"
        )
    return transaction, finalized_at, observed_at


def _derive_payment_binding(
    *,
    typed_input: Mapping[str, Any],
    resource: Mapping[str, Any],
    requirements: Mapping[str, Any],
    report: bytes,
    signed_payload: Mapping[str, Any],
) -> dict[str, str]:
    body = _object(typed_input.get("body"), "typed x402 body")
    payload = _exact_fields(
        signed_payload.get("payload"),
        PAYLOAD_FIELDS,
        "signed payment payload body",
    )
    authorization = _exact_fields(
        payload.get("authorization"),
        AUTHORIZATION_FIELDS,
        "signed payment authorization",
    )
    if signed_payload.get("x402Version") != 2:
        raise GovernanceStagingError("signed payment x402Version must equal 2")
    if signed_payload.get("resource") != resource:
        raise GovernanceStagingError(
            "signed payment resource differs from configured resource"
        )
    if signed_payload.get("accepted") != requirements:
        raise GovernanceStagingError(
            "signed payment requirements differ from configured requirements"
        )

    try:
        public_key = _hex_bytes(
            _casper_public_key(payload.get("publicKey"), "public key"),
            "public key",
        )
        signature = _hex_bytes(
            _casper_signature(payload.get("signature"), "signature"),
            "signature",
        )
        payer = _account_hash_from_public_key(public_key)
        authorization_payer = _tagged_account_hash(
            authorization.get("from"), "authorization from"
        )
        payee = _tagged_account_hash(authorization.get("to"), "authorization to")
        value = _decimal(authorization.get("value"), 256, "authorization value")
        valid_after = _decimal(
            authorization.get("validAfter"),
            64,
            "authorization validAfter",
        )
        valid_before = _decimal(
            authorization.get("validBefore"),
            64,
            "authorization validBefore",
        )
        nonce = _hex_bytes(authorization.get("nonce"), "authorization nonce")
        if len(nonce) != 32:
            raise GovernanceStagingError("authorization nonce must be 32 bytes")
        if authorization_payer != payer:
            raise GovernanceStagingError(
                "signed authorization payer differs from public key"
            )
        extra = _exact_fields(
            requirements.get("extra"),
            REQUIREMENTS_EXTRA_FIELDS,
            "payment requirements extra",
        )
        digest = _eip712_digest(
            token_name=str(extra["name"]),
            domain_version=str(extra["version"]),
            network=str(requirements["network"]),
            package_hash=_hex_bytes(
                requirements.get("asset"),
                "payment requirements asset",
            ),
            payer=payer,
            payee=payee,
            value=value,
            valid_after=valid_after,
            valid_before=valid_before,
            nonce=nonce,
        )
        _verify_casper_eip712_signature(
            public_key=public_key,
            signature=signature,
            digest=digest,
        )
        requirements_hash = _payment_requirements_hash(requirements)
        signed_payload_hash = _signed_payload_hash(
            payment_payload=signed_payload,
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
        resource_hash = _resource_url_hash(str(resource["url"]))
        report_hash = _report_hash(report)
    except GovernanceStagingError:
        raise
    except (OfficialX402ReleaseAdapterError, KeyError, TypeError, ValueError) as exc:
        raise GovernanceStagingError(
            f"official x402 payment binding is invalid: {exc}"
        ) from exc

    exact_requirements = {
        "scheme": body.get("scheme"),
        "network": body.get("caip2_network"),
        "asset": body.get("wcspr_package"),
        "amount": str(value),
        "payTo": "00" + payee.hex(),
        "maxTimeoutSeconds": requirements.get("maxTimeoutSeconds"),
        "extra": {
            "name": body.get("token_name"),
            "version": body.get("eip712_domain_version"),
            "decimals": body.get("token_decimals"),
            "symbol": body.get("token_symbol"),
        },
    }
    expected_body = {
        "payer": payer.hex(),
        "payee": payee.hex(),
        "value": str(value),
        "eip712_auth_nonce": nonce.hex(),
        "valid_after": str(valid_after),
        "valid_before": str(valid_before),
        "resource_url_hash": resource_hash.hex(),
        "report_hash": report_hash.hex(),
        "payment_requirements_hash": requirements_hash.hex(),
        "signed_payment_payload_hash": signed_payload_hash.hex(),
    }
    if requirements != exact_requirements:
        raise GovernanceStagingError(
            "payment requirements differ from the typed x402 envelope"
        )
    for field, expected in expected_body.items():
        if body.get(field) != expected:
            label = field.replace("_", " ")
            raise GovernanceStagingError(
                f"{label} differs from the typed x402 envelope"
            )
    return {
        "resource_url_hash": resource_hash.hex(),
        "report_hash": report_hash.hex(),
        "payment_requirements_hash": requirements_hash.hex(),
        "signed_payment_payload_hash": signed_payload_hash.hex(),
    }


def stage_official_x402_governance(
    *,
    v3_proof: Mapping[str, Any],
    payment_envelope: Mapping[str, Any],
    signed_payment_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive one exact verified internal record without settlement evidence."""

    proof = _object(v3_proof, "v3 proof")
    envelope = _exact_fields(
        payment_envelope,
        PAYMENT_ENVELOPE_FIELDS,
        "payment envelope",
    )
    signed_payload = _exact_fields(
        signed_payment_payload,
        SIGNED_PAYLOAD_FIELDS,
        "signed payment payload",
    )
    if _contains_boolean(envelope) or _contains_boolean(signed_payload):
        raise GovernanceStagingError(
            "payment inputs cannot contain supplied truth booleans"
        )
    if envelope.get("schema_version") != STAGING_INPUT_SCHEMA:
        raise GovernanceStagingError("payment envelope schema is unsupported")
    resource = _exact_fields(
        envelope.get("configured_resource"),
        RESOURCE_FIELDS,
        "configured resource",
    )
    requirements = _exact_fields(
        envelope.get("payment_requirements"),
        REQUIREMENTS_FIELDS,
        "payment requirements",
    )
    _exact_fields(
        requirements.get("extra"),
        REQUIREMENTS_EXTRA_FIELDS,
        "payment requirements extra",
    )
    if requirements.get("network") != NETWORK:
        raise GovernanceStagingError(
            f"payment requirements network must equal {NETWORK}"
        )

    try:
        verification = verify_v3_proof_document(proof)
    except (ProofVerificationError, KeyError, TypeError, ValueError) as exc:
        raise GovernanceStagingError(f"v3 proof verification failed: {exc}") from exc
    if type(verification) is not dict or verification.get("valid") is not True:
        raise GovernanceStagingError(
            "v3 proof verification did not return an exact valid result"
        )

    typed_input = _object(
        envelope.get("typed_action_input"),
        "typed action input",
    )
    proof_input = _object(proof.get("input"), "v3 proof typed input")
    if _canonical_data(typed_input) != _canonical_data(proof_input):
        raise GovernanceStagingError(
            "typed action input differs from the finalized v3 proof"
        )
    if typed_input.get("action") != "OfficialX402SettlementV1":
        raise GovernanceStagingError("typed action must be OfficialX402SettlementV1")
    header = _object(typed_input.get("header"), "typed x402 header")
    body = _object(typed_input.get("body"), "typed x402 body")
    try:
        material = derive_x402_material(header, body)
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernanceStagingError(
            f"typed OfficialX402SettlementV1 envelope is invalid: {exc}"
        ) from exc
    if (
        verification.get("proposal_id") != header.get("proposal_id")
        or verification.get("action_id") != material.action_id.hex()
        or verification.get("envelope_hash") != material.envelope_hash.hex()
        or body.get("caip2_network") != NETWORK
    ):
        raise GovernanceStagingError(
            "verified v3 proposal/action/envelope/network binding differs"
        )

    payment = _derive_payment_binding(
        typed_input=typed_input,
        resource=resource,
        requirements=requirements,
        report=_decode_report(envelope.get("protected_report_base64")),
        signed_payload=signed_payload,
    )
    transaction, finalized_at, observed_at = _finalization(
        proof,
        verification,
    )
    checks = [
        {
            "name": name,
            "required": True,
            "passed": True,
            "source": PROOF_SOURCE,
            "observed_at": observed_at,
        }
        for name in REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]
    ]
    candidate = {
        "schema_version": 1,
        "proposal_id": header["proposal_id"],
        "proposal_hash": header["proposal_hash"],
        "proposal_nonce": header["proposal_nonce"],
        "action_id": material.action_id.hex(),
        "action_kind": "OfficialX402SettlementV1",
        "action_version": 1,
        "envelope_hash": material.envelope_hash.hex(),
        "deployment_domain": header["deployment_domain"],
        "network": NETWORK,
        "package_hash": verification["package_hash"],
        "contract_hash": verification["contract_hash"],
        # Deliberately false on input: validate_internal_record derives this
        # from finalization identity and the complete independent check set.
        "v3_finalized_exact": False,
        "finalization_transaction": transaction,
        "finalized_at": finalized_at,
        **payment,
        "verification_status": "verified",
        "observed_at": observed_at,
        "checks": checks,
    }
    record = validate_internal_record(candidate)
    if (
        record.get("verification_status") != "verified"
        or record.get("v3_finalized_exact") is not True
        or validate_internal_record(record) != record
    ):
        raise GovernanceStagingError(
            "derived internal registry record failed strict validation"
        )
    return record


def write_official_x402_governance(
    *,
    output: Path,
    base_registry: Mapping[str, Any],
    v3_proof: Mapping[str, Any],
    payment_envelope: Mapping[str, Any],
    signed_payment_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive and durably create one complete owner-private staging registry."""

    record = stage_official_x402_governance(
        v3_proof=v3_proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payment_payload,
    )
    try:
        validated_base = validate_registry_document(
            _object(base_registry, "base registry")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernanceStagingError(f"base registry is invalid: {exc}") from exc
    if any(
        item.get("action_id") == record["action_id"]
        for item in validated_base["internal_records"]
        if type(item) is dict
    ):
        raise GovernanceStagingError(
            "base registry contains a duplicate official action_id"
        )
    if any(
        item.get("signed_payment_payload_hash") == record["signed_payment_payload_hash"]
        for item in validated_base["internal_records"]
        if type(item) is dict
    ):
        raise GovernanceStagingError(
            "base registry contains a duplicate signed_payment_payload_hash"
        )
    document = copy.deepcopy(validated_base)
    document["internal_records"].append(record)
    try:
        validated_document = validate_registry_document(document)
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernanceStagingError(
            f"combined staging registry is invalid: {exc}"
        ) from exc
    if (
        validated_document["public_items"] != validated_base["public_items"]
        or validated_document["internal_records"][:-1]
        != validated_base["internal_records"]
        or validated_document["internal_records"][-1] != record
    ):
        raise GovernanceStagingError(
            "combined staging registry changed its validated base document"
        )
    try:
        write_private_file_once(
            Path(output),
            canonical_json_bytes(validated_document),
            allow_identical=False,
        )
    except AtomicPrivateFileError as exc:
        raise GovernanceStagingError(
            "registry output already exists, is a symlink, or cannot be created safely"
        ) from exc
    return validated_document


def _duplicate_rejector(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise GovernanceStagingError(f"duplicate JSON field is forbidden: {name}")
        result[name] = value
    return result


def _constant_rejector(value: str) -> object:
    raise GovernanceStagingError(f"non-standard JSON constant is forbidden: {value}")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise GovernanceStagingError(f"{label} must be a regular non-symlink file")
        raw = path.read_text(encoding="utf-8")
        value = json.loads(
            raw,
            object_pairs_hook=_duplicate_rejector,
            parse_constant=_constant_rejector,
        )
    except GovernanceStagingError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GovernanceStagingError(f"{label} cannot be read as JSON") from exc
    return _object(value, label)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline-verify an OfficialX402SettlementV1 proof and payment, "
            "then create one complete pre-settlement governance registry."
        )
    )
    parser.add_argument("--v3-proof", required=True, type=Path)
    parser.add_argument(
        "--base-registry",
        required=True,
        type=Path,
        help="validated current full registry copied into the isolated staging view",
    )
    parser.add_argument("--payment-envelope", required=True, type=Path)
    parser.add_argument("--signed-payment-payload", required=True, type=Path)
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="absolute write-once mode-0600 canonical JSON output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        document = write_official_x402_governance(
            output=args.out,
            base_registry=_read_json(args.base_registry, "base registry"),
            v3_proof=_read_json(args.v3_proof, "v3 proof"),
            payment_envelope=_read_json(
                args.payment_envelope,
                "payment envelope",
            ),
            signed_payment_payload=_read_json(
                args.signed_payment_payload,
                "signed payment payload",
            ),
        )
    except GovernanceStagingError as exc:
        print(
            json.dumps(
                {"error": str(exc), "valid": False, "written": False},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    record = document["internal_records"][-1]
    print(
        json.dumps(
            {
                "action_id": record["action_id"],
                "output": str(args.out),
                "proposal_id": record["proposal_id"],
                "signed_payment_payload_hash": record["signed_payment_payload_hash"],
                "valid": True,
                "written": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
