"""Spend model v2: plan-derived economic manifest + human authorization.

The manifest is derived from the plan itself — cost lines are 1:1 with the
plan's economic steps, so a step can never spend outside a line and a line
can never exist without a step.  Refusal proofs (pre-quorum, wrong-envelope,
duplicate-finalize) are never treated as free.

Ceilings are immutable integers with checked arithmetic:

    max_total_outlay_motes = transfer_principal_motes + max_fees_motes

Every fee maximum must be grounded in a FINALIZED exact-equivalent Testnet
calibration receipt, or in an explicit conservative operator ceiling — never
a guess, never zero.  The human authorization binds the plan hash, both
economic accounts, the recipient, the principal, every maximum, a
trusted-clock expiry, a nonce, and the chain identity; the executor gate
(:func:`require_within_authorization`) makes spending above the signed
ceiling impossible.
"""

from __future__ import annotations

import hashlib
import json
import re

from tools.mainnet_canary.constants import MAINNET_CHAIN_NAME
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

ECONOMIC_MANIFEST_SCHEMA_ID = "concordia.mainnet-canary.economic-manifest.v1"
CALIBRATION_SCHEMA_ID = "concordia.mainnet-canary.testnet-calibration.v1"
HUMAN_AUTHORIZATION_SCHEMA_ID = "concordia.mainnet-canary.human-authorization.v1"

_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

_AUTHORIZATION_FIELDS = {
    "schema_id",
    "plan_hash",
    "chain_name",
    "treasury_source_account_hash",
    "recipient_account_hash",
    "transfer_principal_motes",
    "max_fees_motes",
    "max_total_outlay_motes",
    "expiry_unix",
    "nonce",
    "authorized_by",
}


def _motes(value: object, *, field: str) -> int:
    if not isinstance(value, str) or _DECIMAL.match(value) is None:
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            f"{field} must be a canonical unsigned decimal motes string",
        )
    return int(value, 10)


def _typed_args_digest(typed_args: object) -> str:
    payload = json.dumps(typed_args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _line_maximum(
    step_id: str,
    calibration_lines: dict[str, object],
    operator_ceilings: dict[str, object],
) -> tuple[int, str]:
    """One grounded fee maximum: finalized calibration or operator ceiling."""

    calibrated = calibration_lines.get(step_id)
    if calibrated is not None:
        if not isinstance(calibrated, dict):
            raise CanaryRefusal(
                RefusalCode.CALIBRATION_RECEIPT_ABSENT,
                f"calibration line for {step_id} malformed",
            )
        receipt = calibrated.get("receipt")
        if (
            not isinstance(receipt, dict)
            or receipt.get("finalized") is not True
            or not isinstance(receipt.get("deploy_hash"), str)
            or _HEX64.match(str(receipt.get("deploy_hash"))) is None
        ):
            raise CanaryRefusal(
                RefusalCode.CALIBRATION_RECEIPT_ABSENT,
                f"calibration for {step_id} lacks a finalized Testnet "
                "receipt; measured maxima require finalized exact-equivalent "
                "deploys",
            )
        maximum = _motes(
            calibrated.get("payment_motes"), field=f"calibration.{step_id}"
        )
        if maximum <= 0:
            raise CanaryRefusal(
                RefusalCode.CEILING_ARITHMETIC_INVALID,
                f"calibrated maximum for {step_id} must be positive; zero or "
                "placeholder fees are refused",
            )
        return maximum, f"calibrated:{receipt['deploy_hash']}"

    ceiling = operator_ceilings.get(step_id)
    if ceiling is not None:
        if (
            not isinstance(ceiling, dict)
            or not isinstance(ceiling.get("declared_by"), str)
            or not ceiling.get("declared_by")
        ):
            raise CanaryRefusal(
                RefusalCode.CALIBRATION_RECEIPT_ABSENT,
                f"operator ceiling for {step_id} must name its declarer",
            )
        maximum = _motes(
            ceiling.get("conservative_ceiling_motes"),
            field=f"operator_ceilings.{step_id}",
        )
        if maximum <= 0:
            raise CanaryRefusal(
                RefusalCode.CEILING_ARITHMETIC_INVALID,
                f"operator ceiling for {step_id} must be positive",
            )
        return maximum, "operator_ceiling"

    raise CanaryRefusal(
        RefusalCode.CALIBRATION_RECEIPT_ABSENT,
        f"economic step {step_id} has neither a finalized Testnet "
        "calibration receipt nor an explicit conservative operator ceiling",
    )


def build_economic_manifest(
    plan: dict[str, object],
    *,
    calibration: dict[str, object],
    operator_ceilings: dict[str, object],
) -> dict[str, object]:
    """Derive the manifest from the plan; refuse anything ungrounded."""

    if (
        not isinstance(calibration, dict)
        or calibration.get("schema_id") != CALIBRATION_SCHEMA_ID
        or not isinstance(calibration.get("lines"), dict)
    ):
        raise CanaryRefusal(
            RefusalCode.CALIBRATION_RECEIPT_ABSENT,
            "calibration document does not match the frozen schema",
        )
    calibration_lines = calibration["lines"]

    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, "plan carries no steps"
        )

    rc = plan.get("rc", {})
    envelope_body = plan.get("envelope", {}).get("body", {})
    lines: list[dict[str, object]] = []
    principal: int | None = None
    treasury_source_account = None
    recipient_account = None
    max_install = 0
    max_governance = 0
    max_transfer_fee = 0

    for step in steps:
        if not step.get("economic"):
            continue
        step_id = str(step["step_id"])
        maximum, basis = _line_maximum(step_id, calibration_lines, operator_ceilings)
        kind = str(step["kind"])
        if kind == "contract_install":
            max_install += maximum
        elif kind == "native_transfer":
            max_transfer_fee += maximum
        else:
            max_governance += maximum
        if kind == "native_transfer":
            amount = _motes(
                step["expected_outcome"]["amount_motes"],
                field=f"{step_id}.amount_motes",
            )
            if principal is not None:
                raise CanaryRefusal(
                    RefusalCode.CEILING_ARITHMETIC_INVALID,
                    "plan carries more than one native transfer; the canary "
                    "authorizes exactly one",
                )
            principal = amount
            treasury_source_account = step["expected_outcome"]["source_account"]
            recipient_account = step["expected_outcome"]["recipient_account"]
        lines.append(
            {
                "step_id": step_id,
                "kind": kind,
                "entry_point": step.get("entry_point"),
                "typed_args_sha256": _typed_args_digest(step.get("typed_args")),
                "signer_role": step.get("signing_role"),
                "signer_account_hash": step.get("signing_account_hash"),
                "max_payment_motes": str(maximum),
                "basis": basis,
                "rc_tag": rc.get("tag", rc.get("rc_tag")),
                "source_commit": rc.get("peeled_commit_sha"),
                "wasm_sha256": (
                    rc.get("mainnet_wasm_sha256")
                    if kind == "contract_install"
                    else None
                ),
            }
        )

    if principal is None:
        raise CanaryRefusal(
            RefusalCode.PRINCIPAL_LINE_ABSENT,
            "the manifest has no native-transfer principal line; a spend "
            "model without its principal is not a spend model",
        )
    if principal <= 0:
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            "transfer principal must be positive",
        )
    if str(principal) != envelope_body.get("amount_motes"):
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            "native-transfer principal does not equal the envelope amount",
        )

    max_fees = sum(int(line["max_payment_motes"]) for line in lines)
    manifest: dict[str, object] = {
        "schema_id": ECONOMIC_MANIFEST_SCHEMA_ID,
        "plan_hash": plan.get("canary_plan_sha256"),
        "chain_name": MAINNET_CHAIN_NAME,
        "treasury_source_account_hash": treasury_source_account,
        "recipient_account_hash": recipient_account,
        "lines": lines,
        "transfer_principal_motes": str(principal),
        "max_install_payment_motes": str(max_install),
        "max_governance_payment_motes": str(max_governance),
        "max_transfer_payment_motes": str(max_transfer_fee),
        "max_fees_motes": str(max_fees),
        "max_total_outlay_motes": str(principal + max_fees),
    }
    validate_economic_manifest(manifest)
    return manifest


def validate_economic_manifest(manifest: dict[str, object]) -> None:
    """Checked arithmetic: every ceiling recomputes from its own lines."""

    if manifest.get("schema_id") != ECONOMIC_MANIFEST_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            "economic manifest schema mismatch",
        )
    lines = manifest.get("lines")
    if not isinstance(lines, list) or not lines:
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID, "manifest carries no lines"
        )
    line_maxima = []
    for line in lines:
        maximum = _motes(
            line.get("max_payment_motes"),
            field=f"lines[{line.get('step_id')}].max_payment_motes",
        )
        if maximum <= 0:
            raise CanaryRefusal(
                RefusalCode.CEILING_ARITHMETIC_INVALID,
                f"line {line.get('step_id')} carries a zero/placeholder fee",
            )
        line_maxima.append(maximum)
    principal = _motes(
        manifest.get("transfer_principal_motes"), field="transfer_principal_motes"
    )
    max_fees = _motes(manifest.get("max_fees_motes"), field="max_fees_motes")
    total = _motes(
        manifest.get("max_total_outlay_motes"), field="max_total_outlay_motes"
    )
    if max_fees != sum(line_maxima):
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            "max_fees_motes does not equal the sum of line maxima",
        )
    if total != principal + max_fees:
        raise CanaryRefusal(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            "max_total_outlay_motes != transfer_principal_motes + "
            "max_fees_motes",
        )


def required_funding_motes(manifest: dict[str, object]) -> str:
    """The exact maximum funding the operator must provision — nothing else."""

    validate_economic_manifest(manifest)
    return str(manifest["max_total_outlay_motes"])


def validate_human_authorization(
    document: object, *, manifest: dict[str, object], clock_unix: int
) -> dict[str, object]:
    """The signed human authorization must bind every economic fact."""

    validate_economic_manifest(manifest)
    if not isinstance(document, dict) or set(document) != _AUTHORIZATION_FIELDS:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            f"authorization must contain exactly {sorted(_AUTHORIZATION_FIELDS)}",
        )
    if document["schema_id"] != HUMAN_AUTHORIZATION_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorization schema mismatch"
        )
    if document["chain_name"] != MAINNET_CHAIN_NAME:
        raise CanaryRefusal(
            RefusalCode.NETWORK_MISMATCH,
            "authorization is not for chain `casper`",
        )
    expiry = document["expiry_unix"]
    if not isinstance(expiry, int) or expiry <= 0 or expiry <= clock_unix:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_EXPIRED,
            "authorization expiry is absent, zero, or in the past against "
            "the trusted clock",
        )
    nonce = document["nonce"]
    if not isinstance(nonce, str) or _HEX64.match(nonce) is None:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorization nonce malformed"
        )
    authorized_by = document["authorized_by"]
    if not isinstance(authorized_by, list) or not authorized_by:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID, "authorized_by must be non-empty"
        )
    bound_fields = (
        "plan_hash",
        "treasury_source_account_hash",
        "recipient_account_hash",
        "transfer_principal_motes",
        "max_fees_motes",
        "max_total_outlay_motes",
    )
    mismatched = sorted(
        field for field in bound_fields if document[field] != manifest[field]
    )
    if mismatched:
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            f"authorization does not bind the manifest on: {mismatched}",
        )
    return document


def require_within_authorization(
    manifest: dict[str, object], authorization_document: dict[str, object]
) -> None:
    """Executor gate: spending above the signed ceiling is impossible."""

    validate_economic_manifest(manifest)
    if (
        manifest["plan_hash"] != authorization_document.get("plan_hash")
        or manifest["max_total_outlay_motes"]
        != authorization_document.get("max_total_outlay_motes")
        or manifest["max_fees_motes"]
        != authorization_document.get("max_fees_motes")
        or manifest["transfer_principal_motes"]
        != authorization_document.get("transfer_principal_motes")
    ):
        raise CanaryRefusal(
            RefusalCode.AUTHORIZATION_INVALID,
            "manifest ceilings do not equal the humanly signed ceilings; "
            "the executor cannot spend outside the authorization",
        )
