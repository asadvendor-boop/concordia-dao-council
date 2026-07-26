"""Optional OpenTelemetry bootstrap for Concordia services.

Tracing is deliberately opt-in. Local tests and source-only review builds run
without a collector; the hosted VM enables OTLP export to the Concordia
collector so Casper submit/finality, x402 verification, and IPFS uploads are
visible in Jaeger.
"""
from __future__ import annotations

import contextlib
import os
from typing import Any


_INITIALIZED = False
_HTTPX_INSTRUMENTED = False
_STATUS: dict[str, Any] = {
    "enabled": False,
    "reason": "not_initialized",
}


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _otlp_trace_endpoint() -> str:
    configured = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "").strip()
    if configured:
        return configured
    base = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318").strip().rstrip("/")
    return base if base.endswith("/v1/traces") else f"{base}/v1/traces"


def init_telemetry(service_name: str | None = None) -> dict[str, Any]:
    """Initialize OpenTelemetry once and return the effective status."""
    global _INITIALIZED, _STATUS
    if _INITIALIZED:
        return dict(_STATUS)
    _INITIALIZED = True

    if not _truthy(os.getenv("OTEL_ENABLED", "0")):
        _STATUS = {"enabled": False, "reason": "disabled"}
        return dict(_STATUS)

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # pragma: no cover - optional dependency guard
        _STATUS = {
            "enabled": False,
            "reason": "dependency_missing",
            "error": f"{type(exc).__name__}: {exc}",
        }
        return dict(_STATUS)

    endpoint = _otlp_trace_endpoint()
    name = service_name or os.getenv("OTEL_SERVICE_NAME", "concordia-service")
    resource = Resource.create(
        {
            "service.name": name,
            "service.namespace": "concordia",
            "deployment.environment": os.getenv("APP_ENV", "local"),
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _STATUS = {
        "enabled": True,
        "service_name": name,
        "endpoint": endpoint,
        "exporter": "otlp_http",
    }
    return dict(_STATUS)


def instrument_httpx() -> None:
    """Auto-instrument httpx clients when telemetry dependencies are installed."""
    global _HTTPX_INSTRUMENTED
    if _HTTPX_INSTRUMENTED or not _truthy(os.getenv("OTEL_ENABLED", "0")):
        return
    _HTTPX_INSTRUMENTED = True
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()
    except Exception:
        return


def instrument_fastapi_app(app: Any) -> None:
    """Attach FastAPI request tracing when instrumentation is available."""
    if not _truthy(os.getenv("OTEL_ENABLED", "0")):
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        return


def telemetry_status() -> dict[str, Any]:
    return dict(_STATUS)


@contextlib.contextmanager
def span(name: str, **attributes: Any):
    """Create a span if tracing is enabled, otherwise act as a no-op."""
    try:
        from opentelemetry import trace
    except Exception:  # pragma: no cover - optional dependency guard
        yield None
        return

    tracer = trace.get_tracer("concordia")
    with tracer.start_as_current_span(name) as active_span:
        for key, value in attributes.items():
            if value is not None:
                active_span.set_attribute(key, str(value))
        yield active_span
