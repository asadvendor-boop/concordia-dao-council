"""x402 payment helpers for Concordia governance reports.

The demo path keeps the app usable without a live facilitator. When
X402_SETTLEMENT_MODE=real, Concordia can verify Casper transfer proofs directly
against CSPR.live or delegate to a configured facilitator/provider with bounded
indexer-lag retries.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

from shared.telemetry import span


CASPER_DEPLOY_HASH_RE = re.compile(r"^(?:casper:)?([0-9a-fA-F]{64})$")


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
            )
    if _payment_hash(payment_header) and status["direct_casper_settlement_configured"]:
        with span("x402.direct_casper_verify", resource=resource, network=status["network"]):
            return await verify_casper_transfer_payment_with_retry(
                resource=resource,
                payment_header=payment_header,
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
    async with httpx.AsyncClient(timeout=20.0) as client:
        for attempt in range(1, attempts + 1):
            try:
                with span("x402.facilitator_verify", resource=resource, attempt=attempt):
                    verify = await client.post(f"{facilitator_url}/verify", json=payload, headers=headers)
                if verify.status_code in {402, 404, 409, 425, 429} and attempt < attempts:
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
                if settle.status_code in {402, 404, 409, 425, 429} and attempt < attempts:
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
) -> dict[str, Any]:
    """Redeem a Casper x402 payment proof against a real paid provider.

    This mirrors the competitor indexer-lag compensation pattern: a valid CSPR
    transfer may be visible on-chain before the provider's off-chain indexer has
    accepted it, so the proof is retried for a bounded window.
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
    async with httpx.AsyncClient(timeout=20.0) as client:
        for attempt in range(1, attempts + 1):
            try:
                with span("x402.provider_redeem_attempt", resource=resource, attempt=attempt, provider_url=provider_url):
                    response = await client.get(provider_url, params=params, headers=headers)
                if response.status_code in {402, 404, 409, 425, 429} and attempt < attempts:
                    last_error = f"provider returned {response.status_code}; retrying for indexer lag"
                    await asyncio.sleep(delay)
                    continue
                response.raise_for_status()
                return {
                    "status": "settled",
                    "mode": "real_provider",
                    "resource": resource,
                    "network": status["network"],
                    "attempt": attempt,
                    "provider_url": provider_url,
                    "provider_response": response.json() if "json" in response.headers.get("content-type", "") else response.text,
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


def _walk_values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child)
    else:
        yield value


def _amount_candidates(value: Any) -> list[int]:
    amounts: list[int] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if "amount" in str(key).lower():
                try:
                    amounts.append(int(str(child)))
                except (TypeError, ValueError):
                    pass
            amounts.extend(_amount_candidates(child))
    elif isinstance(value, list):
        for child in value:
            amounts.extend(_amount_candidates(child))
    return amounts


def _extract_transfer_proof_status(data: dict[str, Any]) -> dict[str, Any]:
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
    if not transfers:
        return {"valid": False, "status": "rejected", "error": "deploy has no transfer records"}

    transfer_text_values = {_normalize_token(item) for item in _walk_values(transfers)}
    target_ok = any(target and any(target in candidate for candidate in transfer_text_values) for target in expected_targets)
    amounts = _amount_candidates(transfers)
    amount_ok = any(amount >= expected_amount for amount in amounts)
    if not target_ok:
        return {
            "valid": False,
            "status": "rejected",
            "error": "transfer target does not match configured x402 payee",
            "expected_targets": sorted(expected_targets),
        }
    if not amount_ok:
        return {
            "valid": False,
            "status": "rejected",
            "error": f"transfer amount is below required {expected_amount} motes",
            "observed_amounts": amounts,
        }
    return {
        "valid": True,
        "status": "settled",
        "expected_amount_motes": expected_amount,
        "observed_amounts": amounts,
    }


async def verify_casper_transfer_payment_with_retry(
    *,
    resource: str,
    payment_header: str,
) -> dict[str, Any]:
    """Verify a real CSPR transfer hash as an x402 payment proof.

    The retry loop is intentionally bounded because CSPR.live/provider indexes
    can lag a successfully processed Casper deploy. This is the same failure
    mode competitors handle for x402 paid providers.
    """
    deploy_hash = _payment_hash(payment_header)
    if not deploy_hash:
        return {"status": "payment_required", "mode": "real_casper_transfer", "error": "X-Payment must be a Casper deploy hash"}

    status = x402_status()
    attempts = status["retry_attempts"]
    delay = status["retry_delay_seconds"]
    base_url = status["cspr_live_api"]
    last_error: str | None = None
    async with httpx.AsyncClient(timeout=20.0) as client:
        for attempt in range(1, attempts + 1):
            try:
                with span("x402.cspr_live_deploy_lookup", resource=resource, attempt=attempt, deploy_hash=deploy_hash):
                    response = await client.get(f"{base_url}/deploys/{deploy_hash}")
                if response.status_code in {404, 409, 425, 429} and attempt < attempts:
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
                proof = _extract_transfer_proof_status(data)
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
