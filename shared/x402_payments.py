"""x402 payment helpers for Concordia governance reports.

The demo path keeps the app usable without a live facilitator. When
X402_SETTLEMENT_MODE=real, Concordia can verify Casper transfer proofs directly
against CSPR.live or delegate to a configured facilitator/provider with bounded
indexer-lag retries.
"""
from __future__ import annotations

import asyncio
import datetime as _datetime
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from shared.telemetry import span


CASPER_DEPLOY_HASH_RE = re.compile(r"^(?:casper:)?([0-9a-fA-F]{64})$")

# --- SafePay Lite supplemental v2 (G1 frozen constants; see handoff/G1_INTERFACE_SPEC.md section 12) ---

SAFEPAY_V2_SCHEMA_VERSION = "safepay-v2"
SAFEPAY_V2_NETWORK = "casper:casper-test"
SAFEPAY_V2_REPORT_VERSION = "safepay-report-v2"
SAFEPAY_V2_REPORT_MEDIA_TYPE = "application/json"
SAFEPAY_V2_QUOTE_REQUEST_SCHEMA = "safepay-quote-request-v2"
SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA = "safepay-redemption-v2"
SAFEPAY_V2_QUOTE_SEPARATOR = b"CONCORDIA_SAFEPAY_QUOTE_V2\x00"
SAFEPAY_V2_QUOTE_HASH_SEPARATOR = b"CONCORDIA_SAFEPAY_QUOTE_HASH_V2\x00"
SAFEPAY_V2_FULFILLMENT_SEPARATOR = b"CONCORDIA_SAFEPAY_FULFILLMENT_V2\x00"
SAFEPAY_V2_QUOTE_TTL_SECONDS = 900
SAFEPAY_V2_MAX_REPORT_DECODED_BYTES = 262144

SAFEPAY_V2_QUOTE_FIELDS = (
    "schema_version",
    "quote_id",
    "proposal_id",
    "resource_id",
    "network",
    "payee_account_hash",
    "amount_motes",
    "correlation_id",
    "report_version",
    "report_hash",
    "expires_at",
    "quote_nonce",
    "quote_hash",
)

SAFEPAY_V2_OBSERVATION_FIELDS = (
    "network",
    "payment_hash",
    "block_hash",
    "block_height",
    "execution_status",
    "finality_status",
    "from_account_hash",
    "to_account_hash",
    "amount_motes",
    "transfer_id",
    "execution_error",
    "observed_at",
)

SAFEPAY_V2_BINDING_CHECK_FIELDS = (
    "network_exact",
    "payment_finalized",
    "payment_execution_success",
    "single_transfer_exact",
    "payee_exact",
    "amount_exact",
    "transfer_id_exact",
    "proposal_exact",
    "resource_exact",
    "correlation_exact",
    "report_version_exact",
    "report_hash_exact",
    "quote_hash_recomputed",
)

_PROPOSAL_ID_RE = re.compile(r"^[A-Z0-9-]{1,64}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CANONICAL_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_U64_MAX = 2**64 - 1
_U512_MAX = 2**512 - 1


class SafePayObserverUnavailable(Exception):
    """The Casper payment observer could not produce an observation."""


def _safepay_lp(value: str) -> bytes:
    """Canonical String encoding: u32_be(byte_length) || exact ASCII bytes."""
    if not isinstance(value, str):
        raise ValueError("length-prefixed value must be str")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("length-prefixed value must be ASCII") from exc
    if "\x00" in value:
        raise ValueError("length-prefixed value must not contain NUL")
    return len(raw).to_bytes(4, "big") + raw


def _safepay_blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def safepay_v2_correlation_id(
    quote_id: str, proposal_id: str, resource_id: str, quote_nonce: bytes
) -> int:
    """Frozen per-quote correlation/native-transfer id derivation."""
    if not isinstance(quote_nonce, (bytes, bytearray)) or len(quote_nonce) != 32:
        raise ValueError("quote_nonce must be exactly 32 raw bytes")
    digest = _safepay_blake2b_256(
        SAFEPAY_V2_QUOTE_SEPARATOR
        + _safepay_lp(quote_id)
        + _safepay_lp(proposal_id)
        + _safepay_lp(resource_id)
        + bytes(quote_nonce)
    )
    return int.from_bytes(digest[:8], "big")


def safepay_v2_quote_hash(
    *,
    quote_id: str,
    proposal_id: str,
    resource_id: str,
    network: str,
    payee_account_hash: str,
    amount_motes: str,
    correlation_id: int,
    report_version: str,
    report_hash: str,
    expires_at: int,
    quote_nonce: bytes,
) -> str:
    """Frozen immutable quote hash (schema_version and quote_hash excluded)."""
    if not _HEX64_RE.match(payee_account_hash):
        raise ValueError("payee_account_hash must be 64 lowercase hex characters")
    if not _HEX64_RE.match(report_hash):
        raise ValueError("report_hash must be 64 lowercase hex characters")
    if not _CANONICAL_DECIMAL_RE.match(amount_motes):
        raise ValueError("amount_motes must be a canonical unsigned decimal string")
    amount = int(amount_motes)
    if amount > _U512_MAX:
        raise ValueError("amount_motes exceeds U512")
    if not isinstance(quote_nonce, (bytes, bytearray)) or len(quote_nonce) != 32:
        raise ValueError("quote_nonce must be exactly 32 raw bytes")
    if not 0 <= int(correlation_id) <= _U64_MAX:
        raise ValueError("correlation_id must fit u64")
    if not 0 <= int(expires_at) <= _U64_MAX:
        raise ValueError("expires_at must fit u64")
    preimage = (
        SAFEPAY_V2_QUOTE_HASH_SEPARATOR
        + _safepay_lp(quote_id)
        + _safepay_lp(proposal_id)
        + _safepay_lp(resource_id)
        + _safepay_lp(network)
        + bytes.fromhex(payee_account_hash)
        + amount.to_bytes(64, "big")
        + int(correlation_id).to_bytes(8, "big")
        + _safepay_lp(report_version)
        + bytes.fromhex(report_hash)
        + int(expires_at).to_bytes(8, "big")
        + bytes(quote_nonce)
    )
    return _safepay_blake2b_256(preimage).hex()


def safepay_v2_response_hash(
    *,
    quote_hash: str,
    payment_hash: str,
    block_hash: str,
    block_height: int,
    report_hash: str,
    consumed_at: int,
) -> str:
    """Frozen immutable fulfillment/response hash (SHA-256)."""
    for name, value in (
        ("quote_hash", quote_hash),
        ("payment_hash", payment_hash),
        ("block_hash", block_hash),
        ("report_hash", report_hash),
    ):
        if not _HEX64_RE.match(value):
            raise ValueError(f"{name} must be 64 lowercase hex characters")
    if not 0 <= int(block_height) <= _U64_MAX:
        raise ValueError("block_height must fit u64")
    if not 0 <= int(consumed_at) <= _U64_MAX:
        raise ValueError("consumed_at must fit u64")
    preimage = (
        SAFEPAY_V2_FULFILLMENT_SEPARATOR
        + bytes.fromhex(quote_hash)
        + bytes.fromhex(payment_hash)
        + bytes.fromhex(block_hash)
        + int(block_height).to_bytes(8, "big")
        + bytes.fromhex(report_hash)
        + int(consumed_at).to_bytes(8, "big")
    )
    return hashlib.sha256(preimage).hexdigest()


def safepay_v2_error_body(code: str, retryable: bool, replay_disposition: str) -> dict[str, Any]:
    """The exact frozen SafePay v2 error wire body.

    Single source of truth shared by the provider's HTTP responses AND the
    ledger's evidence-digest recomputation, so the recorded observation digest
    can never drift from the body actually served.
    """
    return {
        "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
        "error": {"code": code, "retryable": retryable},
        "delivery": {"replay_disposition": replay_disposition},
    }


def safepay_v2_body_digest(body: Mapping[str, Any]) -> str:
    """Canonical BLAKE2b-256 digest of an exact HTTP response body.

    Canonical JSON encoding: sorted keys, compact separators, UTF-8. Used to
    bind append-only redemption observations to the response actually served.
    """
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.blake2b(encoded, digest_size=32).hexdigest()


def _is_printable_ascii(value: str) -> bool:
    return all(0x20 <= ord(char) <= 0x7E for char in value)


def validate_safepay_v2_quote(quote: Any) -> str | None:
    """Strict shape validation of a submitted immutable quote object.

    Returns None when valid, otherwise a stable machine reason. Canonical
    network validation happens here, before any ledger lookup; aliases are
    rejected and never normalized.
    """
    if not isinstance(quote, dict):
        return "quote_not_object"
    if set(quote) != set(SAFEPAY_V2_QUOTE_FIELDS):
        return "quote_field_set_mismatch"
    if quote["schema_version"] != SAFEPAY_V2_SCHEMA_VERSION:
        return "schema_version_invalid"
    if not isinstance(quote["quote_id"], str) or not _UUID4_RE.match(quote["quote_id"]):
        return "quote_id_invalid"
    if not isinstance(quote["proposal_id"], str) or not _PROPOSAL_ID_RE.match(quote["proposal_id"]):
        return "proposal_id_invalid"
    resource_id = quote["resource_id"]
    if (
        not isinstance(resource_id, str)
        or not 1 <= len(resource_id.encode("ascii", errors="replace")) <= 200
        or not resource_id.isascii()
        or not _is_printable_ascii(resource_id)
    ):
        return "resource_id_invalid"
    if quote["network"] != SAFEPAY_V2_NETWORK:
        return "network_invalid"
    if not isinstance(quote["payee_account_hash"], str) or not _HEX64_RE.match(quote["payee_account_hash"]):
        return "payee_account_hash_invalid"
    amount = quote["amount_motes"]
    if not isinstance(amount, str) or not _CANONICAL_DECIMAL_RE.match(amount) or int(amount) < 1 or int(amount) > _U512_MAX:
        return "amount_motes_invalid"
    correlation = quote["correlation_id"]
    if not isinstance(correlation, str) or not _CANONICAL_DECIMAL_RE.match(correlation) or int(correlation) > _U64_MAX:
        return "correlation_id_invalid"
    if quote["report_version"] != SAFEPAY_V2_REPORT_VERSION:
        return "report_version_invalid"
    if not isinstance(quote["report_hash"], str) or not _HEX64_RE.match(quote["report_hash"]):
        return "report_hash_invalid"
    expires_at = quote["expires_at"]
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or not 0 <= expires_at <= _U64_MAX:
        return "expires_at_invalid"
    nonce = quote["quote_nonce"]
    if not isinstance(nonce, str) or not _HEX64_RE.match(nonce) or int(nonce, 16) == 0:
        return "quote_nonce_invalid"
    if not isinstance(quote["quote_hash"], str) or not _HEX64_RE.match(quote["quote_hash"]):
        return "quote_hash_invalid"
    return None


def validate_safepay_v2_observation(observation: Any) -> str | None:
    """Strict shape validation of a payment observation destined for a fulfillment."""
    if not isinstance(observation, dict):
        return "observation_not_object"
    if set(observation) != set(SAFEPAY_V2_OBSERVATION_FIELDS):
        return "observation_field_set_mismatch"
    if observation["network"] != SAFEPAY_V2_NETWORK:
        return "network_invalid"
    for field in ("payment_hash", "block_hash", "from_account_hash", "to_account_hash"):
        if not isinstance(observation[field], str) or not _HEX64_RE.match(observation[field]):
            return f"{field}_invalid"
    height = observation["block_height"]
    if not isinstance(height, int) or isinstance(height, bool) or not 0 <= height <= _U64_MAX:
        return "block_height_invalid"
    if observation["execution_status"] not in {"processed", "failed", "pending", "unknown"}:
        return "execution_status_invalid"
    if observation["finality_status"] not in {"finalized", "not_finalized", "unknown"}:
        return "finality_status_invalid"
    amount = observation["amount_motes"]
    if not isinstance(amount, str) or not _CANONICAL_DECIMAL_RE.match(amount):
        return "amount_motes_invalid"
    transfer_id = observation["transfer_id"]
    if transfer_id is not None and (
        not isinstance(transfer_id, str)
        or not _CANONICAL_DECIMAL_RE.match(transfer_id)
        or int(transfer_id) > _U64_MAX
    ):
        return "transfer_id_invalid"
    error = observation["execution_error"]
    if error is not None and not isinstance(error, str):
        return "execution_error_invalid"
    if not isinstance(observation["observed_at"], str) or not observation["observed_at"]:
        return "observed_at_invalid"
    return None


def evaluate_safepay_v2_observation(
    quote: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    native_transfer_count: int = 1,
) -> dict[str, bool]:
    """Exact structured acceptance checks for a chain observation against a quote.

    Every comparison is exact equality: no substring payee matching, no
    greater-or-equal amount matching, no fuzzy transfer-id matching.
    """
    to_account = observation.get("to_account_hash")
    payee = quote.get("payee_account_hash")
    amount_observed = observation.get("amount_motes")
    amount_quoted = quote.get("amount_motes")
    transfer_id = observation.get("transfer_id")
    return {
        "network_exact": (
            observation.get("network") == SAFEPAY_V2_NETWORK
            and quote.get("network") == SAFEPAY_V2_NETWORK
        ),
        "payment_finalized": observation.get("finality_status") == "finalized",
        "payment_execution_success": (
            observation.get("execution_status") == "processed"
            and observation.get("execution_error") is None
        ),
        "single_transfer_exact": native_transfer_count == 1,
        "payee_exact": (
            isinstance(to_account, str)
            and isinstance(payee, str)
            and bool(_HEX64_RE.match(to_account))
            and bool(_HEX64_RE.match(payee))
            and to_account == payee
        ),
        "amount_exact": (
            isinstance(amount_observed, str)
            and isinstance(amount_quoted, str)
            and bool(_CANONICAL_DECIMAL_RE.match(amount_observed))
            and bool(_CANONICAL_DECIMAL_RE.match(amount_quoted))
            and amount_observed == amount_quoted
        ),
        "transfer_id_exact": (
            isinstance(transfer_id, str)
            and bool(_CANONICAL_DECIMAL_RE.match(transfer_id or ""))
            and transfer_id == str(quote.get("correlation_id"))
        ),
    }


def _utc_now_rfc3339() -> str:
    return (
        _datetime.datetime.now(tz=_datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


async def observe_safepay_v2_payment(
    *,
    network: str,
    payment_hash: str,
    transport: httpx.AsyncBaseTransport | None = None,
    base_url: str | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Default Casper observation source for SafePay v2 redemptions.

    Parses the real CSPR.live ``/deploys/{hash}`` record and binds:

    - the exact requested deploy identity (``data.deploy_hash == payment_hash``);
      a record claiming a different deploy is never attributed to this payment;
    - the canonical network (``casper:casper-test``);
    - the block identity (``block_hash`` + ``block_height``);
    - exactly one RAW native transfer (the raw collection length is taken before
      any parsing/filtering, so one valid transfer accompanied by malformed or
      extra transfers fails the single-transfer predicate); and
    - that transfer's source (``initiator_account_hash``), payee
      (``to_account_hash``), amount and transfer id.

    Critically, a CSPR.live ``status == "processed"`` is NOT treated as finality.
    Finality is a *defined, separate* observation of the containing block (see
    :func:`_observe_block_finality`); ``finality_status`` is ``finalized`` only
    when that block observation confirms it, and ``not_finalized`` otherwise.
    Pending, wrong-chain and wrong-deploy responses fail closed as an honest
    non-final status and are never reported as settled/consumed.

    Returns a structured observation dict (plus internal
    ``native_transfer_count``). Transport injection keeps tests fully offline.
    Raises SafePayObserverUnavailable when no observation can be produced.
    """
    if network != SAFEPAY_V2_NETWORK:
        raise SafePayObserverUnavailable("non-canonical network")
    if not _HEX64_RE.match(payment_hash):
        raise SafePayObserverUnavailable("payment hash must be 64 lowercase hex characters")
    base = (base_url or os.getenv("X402_CSPR_LIVE_API", "https://api.testnet.cspr.live")).rstrip("/")
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        try:
            response = await client.get(f"{base}/deploys/{payment_hash}")
        except Exception as exc:  # network failure is an observer outage, never a verdict
            raise SafePayObserverUnavailable(type(exc).__name__) from exc
        if response.status_code == 404:
            return _safepay_pending_observation(network, payment_hash)
        if response.status_code != 200:
            raise SafePayObserverUnavailable(f"http_{response.status_code}")
        try:
            payload = response.json()
        except Exception as exc:
            raise SafePayObserverUnavailable("invalid_json") from exc
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise SafePayObserverUnavailable("missing_deploy_data")

        # Exact deploy identity: never attribute a CSPR.live record to a payment
        # hash the record does not itself claim. A mismatch fails closed.
        returned_deploy_hash = str(data.get("deploy_hash") or "").strip().lower()
        if returned_deploy_hash != payment_hash:
            return _safepay_pending_observation(network, payment_hash)

        status = data.get("status")
        error_message = data.get("error_message")

        # RAW transfer count is taken BEFORE any parsing/filtering. Exactly one
        # raw native transfer may exist; extra or malformed entries push the
        # count past one and fail the frozen single-transfer predicate upstream.
        raw_transfers = data.get("transfers")
        raw_list = raw_transfers if isinstance(raw_transfers, list) else []
        raw_transfer_count = len(raw_list)
        structured_first: dict[str, Any] | None = None
        if raw_transfer_count == 1 and isinstance(raw_list[0], dict):
            structured_first = _structured_transfer_record(raw_list[0])

        # A non-processed deploy is not a verdict: honest pending observation.
        if status != "processed":
            return _safepay_pending_observation(network, payment_hash)

        block_hash = str(data.get("block_hash") or "").strip().lower()
        block_height = _canonical_int(data.get("block_height"))

        def _transfer_fields() -> dict[str, Any]:
            return {
                "from_account_hash": structured_first["source"] if structured_first else "",
                "to_account_hash": structured_first["recipient"] if structured_first else "",
                "amount_motes": (
                    str(structured_first["amount"])
                    if structured_first and structured_first["amount"] is not None
                    else "0"
                ),
                "transfer_id": (
                    str(structured_first["transfer_id"])
                    if structured_first and structured_first["transfer_id"] is not None
                    else None
                ),
            }

        # Executed-but-failed deploy: report the error honestly (the provider
        # maps it to a terminal binding rejection), never a finalized transfer.
        if error_message:
            return {
                "network": network,
                "payment_hash": payment_hash,
                "block_hash": block_hash,
                "block_height": block_height if block_height is not None else 0,
                "execution_status": "processed",
                "finality_status": "not_finalized",
                **_transfer_fields(),
                "execution_error": str(error_message),
                "observed_at": _utc_now_rfc3339(),
                "native_transfer_count": raw_transfer_count,
            }

        # Block identity must be present before any finality claim.
        if not _HEX64_RE.match(block_hash) or block_height is None:
            return _safepay_pending_observation(network, payment_hash)

        # Defined finality observation: "processed" alone is not final.
        finalized = await _observe_block_finality(client, base, block_hash, block_height)

        return {
            "network": network,
            "payment_hash": payment_hash,
            "block_hash": block_hash,
            "block_height": block_height,
            "execution_status": "processed",
            "finality_status": "finalized" if finalized else "not_finalized",
            **_transfer_fields(),
            "execution_error": None,
            "observed_at": _utc_now_rfc3339(),
            "native_transfer_count": raw_transfer_count,
        }


async def _observe_block_finality(
    client: httpx.AsyncClient, base: str, block_hash: str, block_height: int
) -> bool:
    """Defined finality observation for the deploy's containing block.

    A Casper deploy is final iff the block that includes it is finalized. This
    performs a separate, injectable CSPR.live block observation and confirms
    that the returned block's identity exactly matches the deploy's
    ``(block_hash, block_height)``. Any lookup failure, absence, or mismatch
    yields a NON-final result (the provider then reports payment_not_finalized
    and retries), never a fabricated finalization. A transport error or an
    unexpected non-404 HTTP status is surfaced as an observer outage.
    """
    try:
        response = await client.get(f"{base}/blocks/{block_hash}")
    except Exception as exc:  # cannot observe finality -> outage, never "final"
        raise SafePayObserverUnavailable(type(exc).__name__) from exc
    if response.status_code == 404:
        return False
    if response.status_code != 200:
        raise SafePayObserverUnavailable(f"block_http_{response.status_code}")
    try:
        payload = response.json()
    except Exception as exc:
        raise SafePayObserverUnavailable("block_invalid_json") from exc
    block = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(block, dict):
        return False
    observed_hash = str(block.get("block_hash") or block.get("hash") or "").strip().lower()
    height_value = block.get("block_height")
    if height_value is None:
        height_value = block.get("height")
    observed_height = _canonical_int(height_value)
    return observed_hash == block_hash and observed_height == block_height


def _safepay_pending_observation(network: str, payment_hash: str) -> dict[str, Any]:
    return {
        "network": network,
        "payment_hash": payment_hash,
        "execution_status": "pending",
        "finality_status": "unknown",
        "observed_at": _utc_now_rfc3339(),
        "native_transfer_count": 0,
    }


@dataclass(frozen=True)
class X402PaymentRequest:
    payment_address: str
    amount: str
    network: str
    resource: str


def build_payment_request(resource: str) -> X402PaymentRequest:
    return X402PaymentRequest(
        payment_address=os.getenv("X402_PAYMENT_ADDRESS", "casper-testnet-demo-address"),
        amount=os.getenv("X402_PAYMENT_AMOUNT", "1000000"),
        network=os.getenv("X402_PAYMENT_NETWORK", "casper-testnet"),
        resource=resource,
    )


def payment_required_headers(resource: str) -> dict[str, str]:
    request = build_payment_request(resource)
    return {
        "X-Payment-Address": request.payment_address,
        "X-Payment-Amount": request.amount,
        "X-Payment-Network": request.network,
        "X-Payment-Resource": request.resource,
        "X-Accept-Payment": build_x402_accept_payload(resource),
    }


def x402_status() -> dict[str, Any]:
    mode = os.getenv("X402_SETTLEMENT_MODE", "demo").strip().lower()
    facilitator_url = os.getenv("X402_FACILITATOR_URL", "").strip()
    provider_url = os.getenv("X402_PROVIDER_URL", "").strip()
    payment_address = os.getenv("X402_PAYMENT_ADDRESS", "").strip()
    receiver_public_key = os.getenv("X402_PAYMENT_RECEIVER_PUBLIC_KEY", "").strip()
    direct_casper = bool(mode == "real" and (payment_address or receiver_public_key))
    facilitator = bool(mode == "real" and facilitator_url)
    external_provider = bool(mode == "real" and provider_url)
    return {
        "mode": mode,
        "real_settlement_configured": direct_casper or facilitator or external_provider,
        "settlement_driver": (
            "external_paid_provider"
            if external_provider
            else "direct_casper_transfer"
            if direct_casper
            else "x402_facilitator"
            if facilitator
            else "demo"
        ),
        "direct_casper_settlement_configured": direct_casper,
        "concordia_paid_report_provider_configured": direct_casper,
        "active_paid_provider": "external_provider" if external_provider else "concordia_governance_report" if direct_casper else None,
        "provider_settlement_configured": external_provider,
        "facilitator_url_configured": facilitator,
        "provider_url_configured": external_provider,
        "network": os.getenv("X402_PAYMENT_NETWORK", "casper-testnet"),
        "payment_address_configured": bool(payment_address),
        "receiver_public_key_configured": bool(receiver_public_key),
        "cspr_live_api": os.getenv("X402_CSPR_LIVE_API", "https://api.testnet.cspr.live").rstrip("/"),
        "indexer_lag_retry_enabled": True,
        "retry_attempts": int(os.getenv("X402_MAX_ATTEMPTS", "4")),
        "retry_delay_seconds": float(os.getenv("X402_RETRY_DELAY_SECONDS", "5")),
    }


def build_x402_accept_payload(resource: str) -> str:
    request = build_payment_request(resource)
    payload = {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "casper-transfer",
                "network": request.network,
                "payTo": request.payment_address,
                "amount": request.amount,
                "resource": request.resource,
                "mimeType": "application/json",
                "description": "Concordia paid specialist governance report",
            }
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def build_demo_payment_proof(resource: str, signer_secret: str | None = None) -> str:
    """Build a deterministic local proof string for demo and tests.

    Real production x402 verification should use the Casper facilitator and
    wallet signing flow. This helper exists so the API shape is visible without
    exposing a private key in the repository.
    """
    secret = (signer_secret or os.getenv("X402_DEMO_SIGNER_SECRET", "concordia-demo-secret")).encode()
    nonce = str(int(time.time() // 30))
    message = f"{resource}:{nonce}:{build_payment_request(resource).amount}".encode()
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"casper:{resource}:{nonce}:{signature}"


def verify_demo_payment_proof(resource: str, proof: str, signer_secret: str | None = None) -> bool:
    try:
        _, proof_resource, nonce, signature = proof.split(":", 3)
    except ValueError:
        return False
    if proof_resource != resource:
        return False
    secret = (signer_secret or os.getenv("X402_DEMO_SIGNER_SECRET", "concordia-demo-secret")).encode()
    amount = build_payment_request(resource).amount
    for candidate_nonce in {nonce, str(int(time.time() // 30)), str(int(time.time() // 30) - 1)}:
        expected = hmac.new(secret, f"{resource}:{candidate_nonce}:{amount}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return True
    return False


async def settle_x402_payment_with_retry(
    *,
    resource: str,
    payment_header: str,
    request_url: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Verify and settle an x402 payment proof with indexer-lag retry.

    Real providers often observe Casper payments through an off-chain indexer.
    This helper retries verification/settlement for a bounded window so a valid
    on-chain payment is not stranded just because the provider indexer lags.
    """
    status = x402_status()
    if status["mode"] != "real":
        return {
            "status": "demo_verified" if verify_demo_payment_proof(resource, payment_header) else "payment_required",
            "mode": "demo",
            "resource": resource,
            "network": status["network"],
        }
    if not payment_header:
        return {
            "status": "payment_required",
            "mode": "real",
            "resource": resource,
            "network": status["network"],
        }
    facilitator_url = os.getenv("X402_FACILITATOR_URL", "").strip().rstrip("/")
    provider_url = os.getenv("X402_PROVIDER_URL", "").strip().rstrip("/")
    if provider_url and not facilitator_url:
        with span("x402.provider_redeem_flow", resource=resource, provider_url=provider_url):
            return await redeem_provider_x402_with_retry(
                resource=resource,
                payment_header=payment_header,
                provider_url=provider_url,
                request_url=request_url,
                transport=transport,
            )
    if _payment_hash(payment_header) and status["direct_casper_settlement_configured"]:
        with span("x402.direct_casper_verify", resource=resource, network=status["network"]):
            return await verify_casper_transfer_payment_with_retry(
                resource=resource,
                payment_header=payment_header,
                transport=transport,
            )
    if not facilitator_url:
        return {
            "status": "not_configured",
            "mode": "real",
            "error": "X402_FACILITATOR_URL is required for real settlement",
        }
    token = os.getenv("X402_FACILITATOR_TOKEN", "").strip()
    attempts = status["retry_attempts"]
    delay = status["retry_delay_seconds"]
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {
        "resource": resource,
        "payment": payment_header,
        "requestUrl": request_url or resource,
        "requirements": build_payment_request(resource).__dict__,
    }
    last_error: str | None = None
    async with httpx.AsyncClient(timeout=20.0, transport=transport) as client:
        for attempt in range(1, attempts + 1):
            try:
                with span("x402.facilitator_verify", resource=resource, attempt=attempt):
                    verify = await client.post(f"{facilitator_url}/verify", json=payload, headers=headers)
                if verify.status_code == 409:
                    # Terminal duplicate/cross-binding conflict; never retried as lag.
                    return {
                        "status": "duplicate_conflict",
                        "mode": "real",
                        "terminal": True,
                        "attempt": attempt,
                        "stage": "verify",
                    }
                if verify.status_code in {402, 404, 425, 429} and attempt < attempts:
                    last_error = f"verify returned {verify.status_code}; retrying for provider indexer lag"
                    await asyncio.sleep(delay)
                    continue
                verify.raise_for_status()
                verify_payload = verify.json()
                if verify_payload.get("valid") is False:
                    return {
                        "status": "rejected",
                        "mode": "real",
                        "attempt": attempt,
                        "verify": verify_payload,
                    }
                with span("x402.facilitator_settle", resource=resource, attempt=attempt):
                    settle = await client.post(f"{facilitator_url}/settle", json=payload, headers=headers)
                if settle.status_code == 409:
                    return {
                        "status": "duplicate_conflict",
                        "mode": "real",
                        "terminal": True,
                        "attempt": attempt,
                        "stage": "settle",
                    }
                if settle.status_code in {402, 404, 425, 429} and attempt < attempts:
                    last_error = f"settle returned {settle.status_code}; retrying for provider indexer lag"
                    await asyncio.sleep(delay)
                    continue
                settle.raise_for_status()
                return {
                    "status": "settled",
                    "mode": "real",
                    "attempt": attempt,
                    "verify": verify_payload,
                    "settlement": settle.json(),
                }
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < attempts:
                    await asyncio.sleep(delay)
                    continue
    return {
        "status": "stranded_payment",
        "mode": "real",
        "attempts": attempts,
        "last_error": last_error,
        "message": "Provider kept rejecting proof during the indexer-lag retry window.",
    }


async def redeem_provider_x402_with_retry(
    *,
    resource: str,
    payment_header: str,
    provider_url: str,
    request_url: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Redeem a Casper x402 payment proof against a real paid provider.

    Bounded retries absorb genuine provider indexer lag (402/425/429 and
    transient 5xx). Terminal outcomes are surfaced, never retried:
    HTTP 409 is a duplicate/cross-binding conflict (``duplicate_conflict``)
    and 400/404/410/422 are terminal provider rejections. An idempotent
    same-binding replay is surfaced as ``idempotent_replay``.
    """
    status = x402_status()
    attempts = status["retry_attempts"]
    delay = status["retry_delay_seconds"]
    provider_token = os.getenv("X402_PROVIDER_TOKEN", "").strip()
    headers = {
        "Accept": "application/json",
        "X-Payment": payment_header,
        "X-Payment-Resource": resource,
    }
    if provider_token:
        headers["Authorization"] = f"Bearer {provider_token}"
    params = {"resource": resource}
    if request_url:
        params["requestUrl"] = request_url
    last_error: str | None = None
    async with httpx.AsyncClient(timeout=20.0, transport=transport) as client:
        for attempt in range(1, attempts + 1):
            try:
                with span("x402.provider_redeem_attempt", resource=resource, attempt=attempt, provider_url=provider_url):
                    response = await client.get(provider_url, params=params, headers=headers)
                if response.status_code == 409:
                    # Terminal cross-binding/duplicate conflict. Never retried.
                    return {
                        "status": "duplicate_conflict",
                        "mode": "real_provider",
                        "terminal": True,
                        "resource": resource,
                        "attempt": attempt,
                        "provider_url": provider_url,
                    }
                if response.status_code in {400, 404, 410, 422}:
                    # Terminal provider rejections; the gateway never retries these.
                    return {
                        "status": "provider_rejected",
                        "mode": "real_provider",
                        "terminal": True,
                        "resource": resource,
                        "attempt": attempt,
                        "provider_url": provider_url,
                        "provider_status_code": response.status_code,
                    }
                if response.status_code in {402, 425, 429} and attempt < attempts:
                    last_error = f"provider returned {response.status_code}; retrying for indexer lag"
                    await asyncio.sleep(delay)
                    continue
                response.raise_for_status()
                try:
                    provider_payload = response.json()
                except Exception:
                    provider_payload = None
                settled_v1_shape = isinstance(provider_payload, dict) and provider_payload.get("status") == "paid"
                settled_v2_shape = (
                    isinstance(provider_payload, dict)
                    and provider_payload.get("schema_version") == SAFEPAY_V2_SCHEMA_VERSION
                    and isinstance(provider_payload.get("fulfillment"), dict)
                )
                if not (settled_v1_shape or settled_v2_shape):
                    # Malformed or field-incomplete provider success body:
                    # honest safe failure, never "settled".
                    return {
                        "status": "invalid_provider_response",
                        "mode": "real_provider",
                        "terminal": True,
                        "resource": resource,
                        "attempt": attempt,
                        "provider_url": provider_url,
                        "error": "provider returned a success status without a recognizable settlement body",
                    }
                delivery = provider_payload.get("delivery")
                replay_disposition = (
                    delivery.get("replay_disposition") if isinstance(delivery, dict) else None
                )
                settled_status = (
                    "idempotent_replay" if replay_disposition == "idempotent_replay" else "settled"
                )
                return {
                    "status": settled_status,
                    "mode": "real_provider",
                    "resource": resource,
                    "network": status["network"],
                    "attempt": attempt,
                    "provider_url": provider_url,
                    "provider_response": provider_payload,
                }
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < attempts:
                    await asyncio.sleep(delay)
                    continue
    return {
        "status": "stranded_payment",
        "mode": "real_provider",
        "resource": resource,
        "attempts": attempts,
        "provider_url": provider_url,
        "last_error": last_error,
        "message": "Paid provider kept rejecting proof during the indexer-lag retry window.",
    }


def _payment_hash(payment_header: str) -> str | None:
    text = (payment_header or "").strip()
    match = CASPER_DEPLOY_HASH_RE.match(text)
    return match.group(1).lower() if match else None


def x402_payment_correlation_id(resource: str) -> int:
    """Stable transfer memo for a paid report resource."""
    return int(hashlib.sha256(resource.encode("utf-8")).hexdigest()[:12], 16)


def x402_receiver_public_key() -> str:
    return os.getenv("X402_PAYMENT_RECEIVER_PUBLIC_KEY", os.getenv("X402_PAYMENT_ADDRESS", "")).strip()


def _normalize_token(value: Any) -> str:
    return str(value or "").lower().replace("account-hash-", "").replace("hash-", "").replace("0x", "").strip()


_TRANSFER_RECIPIENT_KEYS = ("target_account_hash", "to_account_hash", "to_account", "to", "target")
# CSPR.live native-transfer records carry the payer as ``initiator_account_hash``
# (the account that signed the transfer deploy); it is the authoritative source
# and is consulted before any purse-derived alias.
_TRANSFER_SOURCE_KEYS = ("initiator_account_hash", "from_account_hash", "from_account", "from", "source")
_TRANSFER_ID_KEYS = ("transfer_id", "id", "memo")


def _canonical_int(value: Any) -> int | None:
    """Parse an exact canonical unsigned integer; anything else is None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and _CANONICAL_DECIMAL_RE.match(value):
        return int(value)
    return None


def _structured_transfer_record(record: Any) -> dict[str, Any] | None:
    """Extract the structured fields of one native transfer record.

    Only explicit, well-known field names are consulted; no recursive
    text scraping and no substring matching.
    """
    if not isinstance(record, dict):
        return None
    recipient_raw = next((record[key] for key in _TRANSFER_RECIPIENT_KEYS if key in record), None)
    if recipient_raw is None:
        return None
    source_raw = next((record[key] for key in _TRANSFER_SOURCE_KEYS if key in record), None)
    transfer_id_raw = next((record[key] for key in _TRANSFER_ID_KEYS if key in record), None)
    return {
        "recipient": _normalize_token(recipient_raw),
        "source": _normalize_token(source_raw) if source_raw is not None else "",
        "amount": _canonical_int(record.get("amount")),
        "transfer_id": _canonical_int(transfer_id_raw) if transfer_id_raw is not None else None,
    }


def _extract_transfer_proof_status(data: dict[str, Any], resource: str | None = None) -> dict[str, Any]:
    """Exact structured verification of a legacy Casper transfer proof.

    Replaces the former substring payee matching and greater-or-equal amount
    matching. Requires: processed status (the deploy's execution result) with
    no execution error, exactly one native transfer whose recipient EXACTLY
    equals the configured payee, an amount EXACTLY equal to the configured
    amount, and — when a resource is supplied — a transfer id EXACTLY equal to
    the legacy resource correlation id. Legacy only; SafePay v2 redemptions
    use evaluate_safepay_v2_observation with the immutable quote instead.
    """
    expected_amount = int(os.getenv("X402_PAYMENT_AMOUNT", "1000000"))
    expected_targets = {
        _normalize_token(os.getenv("X402_PAYMENT_ADDRESS", "")),
        _normalize_token(os.getenv("X402_PAYMENT_ACCOUNT_HASH", "")),
        _normalize_token(os.getenv("X402_PAYMENT_RECEIVER_PUBLIC_KEY", "")),
    }
    expected_targets.discard("")
    if not expected_targets:
        return {
            "valid": False,
            "status": "not_configured",
            "error": "X402_PAYMENT_ADDRESS or X402_PAYMENT_RECEIVER_PUBLIC_KEY is required for real Casper settlement",
        }
    if data.get("status") != "processed":
        return {"valid": False, "status": "pending", "error": f"deploy status is {data.get('status')!r}"}
    if data.get("error_message"):
        return {"valid": False, "status": "rejected", "error": str(data.get("error_message"))}

    transfers = data.get("transfers")
    if not isinstance(transfers, list) or not transfers:
        return {"valid": False, "status": "rejected", "error": "deploy has no transfer records"}

    structured = [record for record in (_structured_transfer_record(item) for item in transfers) if record]
    # Exact full-string equality on the normalized recipient; substrings never match.
    matching = [record for record in structured if record["recipient"] in expected_targets]
    if not matching:
        return {
            "valid": False,
            "status": "rejected",
            "error": "transfer target does not exactly match configured x402 payee",
            "expected_targets": sorted(expected_targets),
        }
    if len(matching) != 1:
        return {
            "valid": False,
            "status": "rejected",
            "error": "expected exactly one native transfer to the configured payee",
            "matching_transfer_count": len(matching),
        }
    transfer = matching[0]
    if transfer["amount"] != expected_amount:
        return {
            "valid": False,
            "status": "rejected",
            "error": f"transfer amount does not exactly equal required {expected_amount} motes",
            "observed_amount": transfer["amount"],
        }
    if resource is not None:
        expected_transfer_id = x402_payment_correlation_id(resource)
        if transfer["transfer_id"] is None:
            return {
                "valid": False,
                "status": "rejected",
                "error": "transfer id (memo) is missing; expected the resource correlation id",
                "expected_transfer_id": expected_transfer_id,
            }
        if transfer["transfer_id"] != expected_transfer_id:
            return {
                "valid": False,
                "status": "rejected",
                "error": "transfer id does not exactly equal the resource correlation id",
                "expected_transfer_id": expected_transfer_id,
                "observed_transfer_id": transfer["transfer_id"],
            }
    return {
        "valid": True,
        "status": "settled",
        "expected_amount_motes": expected_amount,
        "observed_amount": transfer["amount"],
        "observed_transfer_id": transfer["transfer_id"],
    }


async def verify_casper_transfer_payment_with_retry(
    *,
    resource: str,
    payment_header: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Verify a real CSPR transfer hash as an x402 payment proof.

    The retry loop is intentionally bounded because CSPR.live/provider indexes
    can lag a successfully processed Casper deploy. HTTP 409 is terminal and
    is never retried as indexer lag.
    """
    deploy_hash = _payment_hash(payment_header)
    if not deploy_hash:
        return {"status": "payment_required", "mode": "real_casper_transfer", "error": "X-Payment must be a Casper deploy hash"}

    status = x402_status()
    attempts = status["retry_attempts"]
    delay = status["retry_delay_seconds"]
    base_url = status["cspr_live_api"]
    last_error: str | None = None
    async with httpx.AsyncClient(timeout=20.0, transport=transport) as client:
        for attempt in range(1, attempts + 1):
            try:
                with span("x402.cspr_live_deploy_lookup", resource=resource, attempt=attempt, deploy_hash=deploy_hash):
                    response = await client.get(f"{base_url}/deploys/{deploy_hash}")
                if response.status_code == 409:
                    return {
                        "status": "duplicate_conflict",
                        "mode": "real_casper_transfer",
                        "terminal": True,
                        "resource": resource,
                        "payment_hash": deploy_hash,
                        "attempt": attempt,
                    }
                if response.status_code in {404, 425, 429} and attempt < attempts:
                    last_error = f"CSPR.live returned {response.status_code}; retrying for indexer lag"
                    await asyncio.sleep(delay)
                    continue
                response.raise_for_status()
                payload = response.json()
                data = payload.get("data") if isinstance(payload, dict) else None
                if not isinstance(data, dict):
                    last_error = "CSPR.live response did not include deploy data"
                    if attempt < attempts:
                        await asyncio.sleep(delay)
                        continue
                    break
                proof = _extract_transfer_proof_status(data, resource=resource)
                if proof["status"] == "pending" and attempt < attempts:
                    last_error = proof.get("error")
                    await asyncio.sleep(delay)
                    continue
                if proof["valid"]:
                    return {
                        "status": "settled",
                        "mode": "real_casper_transfer",
                        "resource": resource,
                        "network": status["network"],
                        "attempt": attempt,
                        "payment_hash": deploy_hash,
                        "proof": proof,
                        "cspr_live_url": f"{base_url}/deploys/{deploy_hash}",
                    }
                return {
                    "status": proof["status"],
                    "mode": "real_casper_transfer",
                    "resource": resource,
                    "payment_hash": deploy_hash,
                    "proof": proof,
                }
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < attempts:
                    await asyncio.sleep(delay)
                    continue
    return {
        "status": "stranded_payment",
        "mode": "real_casper_transfer",
        "resource": resource,
        "payment_hash": deploy_hash,
        "attempts": attempts,
        "last_error": last_error,
        "message": "Casper transfer proof was not visible during the indexer-lag retry window.",
    }
