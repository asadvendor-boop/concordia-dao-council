"""Separate x402 paid risk-report provider for Concordia.

This service is intentionally separate from the main gateway so the public
demo can prove a provider redemption flow instead of treating Concordia's own
report endpoint as the paid data provider.
"""
from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared.telemetry import init_telemetry, instrument_fastapi_app, instrument_httpx, telemetry_status
from shared.x402_payments import payment_required_headers, verify_casper_transfer_payment_with_retry


_LAG_ATTEMPTS: dict[tuple[str, str], int] = defaultdict(int)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def create_app() -> FastAPI:
    init_telemetry(os.getenv("OTEL_SERVICE_NAME", "concordia-x402-provider"))
    instrument_httpx()
    app = FastAPI(title="Concordia Risk Oracle Provider", version="0.1.0")
    instrument_fastapi_app(app)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "concordia-x402-provider",
            "telemetry": telemetry_status(),
        }

    @app.get("/x402/risk-report")
    async def risk_report(request: Request, proposal_id: str = "DAO-PROP-6CB25C", resource: str | None = None):
        paid_resource = resource or f"concordia-governance-report:{proposal_id}"
        payment = request.headers.get("X-Payment", "").strip()
        if not payment:
            return JSONResponse(
                {
                    "error": "payment_required",
                    "provider": "concordia-risk-oracle-provider",
                    "resource": paid_resource,
                    "message": "Send a Casper Testnet transfer deploy hash in X-Payment to unlock this risk report.",
                },
                status_code=402,
                headers=payment_required_headers(paid_resource),
            )

        lag_attempts = max(0, _int_env("X402_PROVIDER_SIMULATE_LAG_ATTEMPTS", 0))
        lag_key = (paid_resource, payment.lower())
        if _LAG_ATTEMPTS[lag_key] < lag_attempts:
            _LAG_ATTEMPTS[lag_key] += 1
            return JSONResponse(
                {
                    "status": "indexer_lag",
                    "provider": "concordia-risk-oracle-provider",
                    "resource": paid_resource,
                    "attempt": _LAG_ATTEMPTS[lag_key],
                    "message": "Payment not visible to provider indexer yet; retry the same X-Payment proof.",
                },
                status_code=425,
            )

        settlement = await verify_casper_transfer_payment_with_retry(
            resource=paid_resource,
            payment_header=payment,
        )
        if settlement.get("status") != "settled":
            return JSONResponse(
                {
                    "error": "payment_not_verified",
                    "provider": "concordia-risk-oracle-provider",
                    "resource": paid_resource,
                    "settlement": settlement,
                },
                status_code=402,
                headers=payment_required_headers(paid_resource),
            )

        return {
            "status": "paid",
            "provider": "concordia-risk-oracle-provider",
            "resource": paid_resource,
            "proposal_id": proposal_id,
            "settlement": settlement,
            "risk_report": {
                "risk_level": "medium-after-policy-cap",
                "requested_allocation_bps": 3000,
                "approved_policy_cap_bps": 800,
                "provider_signal": "external_paid_provider_verified_before_release",
                "recommendation": "Release specialist report only after Casper payment proof settles.",
            },
        }

    return app


app = create_app()

