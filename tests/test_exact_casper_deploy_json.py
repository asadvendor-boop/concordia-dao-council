"""Regression gates for exact pycspr deploy JSON serialization."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pycspr.factory.deploys as deploy_factory
import pytest
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.factory.deploys import (
    create_deploy,
    create_deploy_parameters,
    create_standard_payment,
)
from pycspr.factory.digests import (
    create_digest_of_deploy,
    create_digest_of_deploy_body,
)
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import Deploy, DeployOfModuleBytes

from scripts.run_v3_live_proof import _build_call
from shared.exact_casper_deploy_json import exact_deploy_rpc_json


ROOT = Path(__file__).resolve().parents[1]


def _signed_deploy(timestamp: float) -> Deploy:
    private_key = parse_private_key_bytes(
        bytes([17]) * 32,
        KeyAlgorithm.ED25519,
    )
    deploy = create_deploy(
        create_deploy_parameters(
            private_key,
            "casper-test",
            timestamp=timestamp,
            ttl="30m",
        ),
        create_standard_payment(5_000_000_000),
        DeployOfModuleBytes(module_bytes=b"", args={}),
    )
    deploy.approve(private_key)
    return deploy


def test_exact_deploy_json_preserves_a_nonzero_whole_second() -> None:
    timestamp = datetime(2026, 7, 24, 4, 6, 37, tzinfo=UTC).timestamp()
    deploy = _signed_deploy(timestamp)

    value = exact_deploy_rpc_json(deploy)
    decoded = serializer.from_json(value, Deploy)

    assert value["header"]["timestamp"] == "2026-07-24T04:06:37.000Z"
    assert serializer.to_bytes(decoded) == serializer.to_bytes(deploy)
    assert decoded.header.body_hash == create_digest_of_deploy_body(
        decoded.payment,
        decoded.session,
    )
    assert decoded.hash == create_digest_of_deploy(decoded.header)


def test_v3_call_builder_survives_pycspr_whole_second_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed = datetime(2026, 7, 24, 4, 6, 37, tzinfo=UTC)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            return fixed if tz is not None else fixed.replace(tzinfo=None)

    monkeypatch.setattr(deploy_factory.datetime, "datetime", FixedDateTime)
    private_key = parse_private_key_bytes(
        bytes([19]) * 32,
        KeyAlgorithm.ED25519,
    )

    value = _build_call(
        signer=private_key.to_public_key(),
        private_key=private_key,
        contract_hash="ab" * 32,
        entry_point="propose_envelope",
        runtime_args=[],
        payment_motes=5_000_000_000,
        ttl="30m",
    )
    decoded = serializer.from_json(value, Deploy)

    assert value["header"]["timestamp"] == "2026-07-24T04:06:37.000Z"
    assert decoded.hash == create_digest_of_deploy(decoded.header)


def test_every_production_deploy_json_path_uses_the_exact_serializer() -> None:
    paths = (
        "scripts/finalize_casper_shared_host.py",
        "scripts/install_governance_receipt_v3.py",
        "scripts/live_odra_module_exercise.py",
        "scripts/run_treasury_execution.py",
        "scripts/run_v3_live_proof.py",
        "scripts/verify_v3_proof.py",
        "shared/casper_executor.py",
        "shared/historical_odra_artifact.py",
    )

    for relative in paths:
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "serializer.to_json(deploy)" not in source, relative
