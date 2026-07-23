"""Failure-first tests for the official x402 prepare/import generators.

Production code (``scripts/official_x402_capture.py``) imports only from
``shared.*``; these tests construct inputs directly (never imported by the
production module) and prove the prepare digest matches the frozen
cross-language golden, that import verifies both signature algorithms
offline and derives the payer, and that every fail-closed guard fires.
"""

from __future__ import annotations

import base64
import copy
import json
import runpy
import stat
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from scripts.official_x402_capture import (
    CAPTURE_BUNDLE_SCHEMA,
    PREPARE_REQUEST_SCHEMA,
    CaptureError,
    build_imported_authorization,
    build_official_x402_artifact,
    build_prepared_authorization,
)
from shared.official_x402_release_adapter import (
    _NETWORK,
    _WCSPR_CONTRACT,
    _WCSPR_PACKAGE,
    _account_hash_from_public_key,
    _canonical,
    _payment_requirements_hash,
    _report_hash,
    _resource_url_hash,
)
from shared.release_proof_adapters import verify_official_x402_artifact

GOLDEN_DIGEST = "51aeaf3aa87aeddde5ccbd96882501eb88b74519efb9d818beb28a4c2b7125dc"
PAYEE_HEX = "ab" * 32
AMOUNT = 1_000_000_000
VALID_AFTER = 1_784_750_400
VALID_BEFORE = 1_784_754_000
NONCE_HEX = "99" * 32
RESOURCE_URL = "https://x402.concordiadao.xyz/resource/finals-report-001"
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _ed25519_key() -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return sk, b"\x01" + raw


def _accepted() -> dict[str, Any]:
    return {
        "scheme": "exact",
        "network": _NETWORK,
        "asset": _WCSPR_PACKAGE,
        "amount": str(AMOUNT),
        "payTo": "00" + PAYEE_HEX,
        "maxTimeoutSeconds": 600,
        "extra": {"name": "Wrapped CSPR", "version": "1", "decimals": "9", "symbol": "WCSPR"},
    }


def _resource() -> dict[str, Any]:
    return {
        "url": RESOURCE_URL,
        "description": "Concordia finals protected report",
        "mimeType": "application/json",
    }


def _report_bytes() -> bytes:
    return _canonical({"proposal_id": "DAO-PROP-FINALS-1", "resource_id": "finals-report-001"})


def _prepare_request(payer_hex: str) -> dict[str, Any]:
    accepted = _accepted()
    resource = _resource()
    report_bytes = _report_bytes()
    body = {
        "x402_version": "2",
        "caip2_network": _NETWORK,
        "wcspr_package": _WCSPR_PACKAGE,
        "wcspr_contract": _WCSPR_CONTRACT,
        "payer": payer_hex,
        "payee": PAYEE_HEX,
        "value": str(AMOUNT),
        "valid_after": str(VALID_AFTER),
        "valid_before": str(VALID_BEFORE),
        "eip712_auth_nonce": NONCE_HEX,
        "resource_url_hash": _resource_url_hash(RESOURCE_URL).hex(),
        "report_hash": _report_hash(report_bytes).hex(),
        "payment_requirements_hash": _payment_requirements_hash(accepted).hex(),
    }
    return {
        "schema_version": PREPARE_REQUEST_SCHEMA,
        "accepted": accepted,
        "resource": resource,
        "report_base64": base64.b64encode(report_bytes).decode("ascii"),
        "body": body,
        "payer_account_hash": payer_hex,
        "payee_account_hash": PAYEE_HEX,
        "value": str(AMOUNT),
        "valid_after": VALID_AFTER,
        "valid_before": VALID_BEFORE,
        "nonce": NONCE_HEX,
    }


def _ed25519_payer() -> str:
    _, public_key = _ed25519_key()
    return _account_hash_from_public_key(public_key).hex()


class TestPrepare:
    def test_prepare_reproduces_the_frozen_golden_digest(self) -> None:
        prepared = build_prepared_authorization(_prepare_request(_ed25519_payer()))
        assert prepared["eip712"]["digest_hex"] == GOLDEN_DIGEST
        # The digest_base64 preimage decodes to the same 32 bytes.
        assert base64.b64decode(prepared["eip712"]["digest_base64"]).hex() == GOLDEN_DIGEST

    def test_prepare_binds_every_hash_and_domain(self) -> None:
        prepared = build_prepared_authorization(_prepare_request(_ed25519_payer()))
        assert prepared["eip712"]["domain"] == {
            "name": "Wrapped CSPR",
            "version": "1",
            "chain_name": _NETWORK,
            "contract_package_hash": "0x" + _WCSPR_PACKAGE,
        }
        assert prepared["bindings"]["payment_requirements_hash"] == (
            _payment_requirements_hash(_accepted()).hex()
        )
        assert prepared["eip712"]["message"]["from"] == "00" + _ed25519_payer()
        assert prepared["eip712"]["message"]["to"] == "00" + PAYEE_HEX

    @pytest.mark.parametrize(
        "mutate,fragment",
        [
            (lambda r: r.__setitem__("schema_version", "wrong"), "prepare request schema"),
            (lambda r: r["accepted"].__setitem__("network", "casper-test"), "accepted network"),
            (lambda r: r["accepted"].__setitem__("asset", "00" * 32), "WCSPR package"),
            (lambda r: r["accepted"].__setitem__("scheme", "upto"), "scheme"),
            (lambda r: r.__setitem__("value", "0"), "at least one atomic"),
            (lambda r: r.__setitem__("valid_before", VALID_AFTER), "strictly before"),
            (lambda r: r.__setitem__("payee_account_hash", _ed25519_payer()), "must differ"),
            (lambda r: r.__setitem__("nonce", "0" * 64), "all-zero"),
            (lambda r: r["accepted"].__setitem__("amount", "999"), "accepted amount"),
            (lambda r: r["accepted"].__setitem__("payTo", "00" + "cd" * 32), "payTo"),
            (lambda r: r["body"].__setitem__("report_hash", "ff" * 32), "does not bind"),
            (lambda r: r["body"].__setitem__("caip2_network", "casper-test"), "network"),
        ],
    )
    def test_prepare_fails_closed(self, mutate, fragment) -> None:
        request = _prepare_request(_ed25519_payer())
        mutate(request)
        with pytest.raises(CaptureError) as exc:
            build_prepared_authorization(request)
        assert fragment in str(exc.value)


def _sign_ed25519() -> dict[str, str]:
    sk, public_key = _ed25519_key()
    signature = b"\x01" + sk.sign(bytes.fromhex(GOLDEN_DIGEST))
    return {"signatureHex": signature.hex(), "publicKeyHex": public_key.hex()}


class TestImport:
    def test_import_verifies_ed25519_and_freezes_identical_request_bytes(self) -> None:
        payer = _ed25519_payer()
        prepared = build_prepared_authorization(_prepare_request(payer))
        imported = build_imported_authorization(prepared, _sign_ed25519())
        assert imported["recovered_payer_account_hash"] == payer
        assert imported["payer_account_hash"] == payer
        # /verify and /settle send byte-identical frozen request bodies.
        assert (
            imported["frozen_verify_request_body_base64"]
            == imported["frozen_settle_request_body_base64"]
        )
        # The frozen request body is the canonical serialization exactly once.
        frozen = base64.b64decode(imported["frozen_verify_request_body_base64"])
        assert frozen == _canonical(imported["facilitator_request"])
        assert set(imported["signed_payment_payload"]) == {
            "x402Version",
            "resource",
            "accepted",
            "payload",
        }
        assert set(imported["signed_payment_payload"]["payload"]) == {
            "signature",
            "publicKey",
            "authorization",
        }
        assert len(imported["signed_payment_payload_hash"]) == 64

    def test_import_verifies_secp256k1(self) -> None:
        sk = ec.derive_private_key(int("11" * 32, 16), ec.SECP256K1())
        numbers = sk.public_key().public_numbers()
        compressed = bytes([2 + (numbers.y & 1)]) + numbers.x.to_bytes(32, "big")
        public_key = b"\x02" + compressed
        payer = _account_hash_from_public_key(public_key).hex()
        request = _prepare_request(payer)
        prepared = build_prepared_authorization(request)
        digest = bytes.fromhex(prepared["eip712"]["digest_hex"])
        der = sk.sign(digest, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        if s > SECP_N // 2:
            s = SECP_N - s
        signature = b"\x02" + r.to_bytes(32, "big") + s.to_bytes(32, "big")
        imported = build_imported_authorization(
            prepared, {"signatureHex": signature.hex(), "publicKeyHex": public_key.hex()}
        )
        assert imported["recovered_payer_account_hash"] == payer
        assert imported["public_key_hex"] == public_key.hex()

    def test_import_rejects_a_tampered_signature(self) -> None:
        prepared = build_prepared_authorization(_prepare_request(_ed25519_payer()))
        signed = _sign_ed25519()
        flipped = bytearray(bytes.fromhex(signed["signatureHex"]))
        flipped[-1] ^= 0x01
        signed["signatureHex"] = flipped.hex()
        with pytest.raises(CaptureError) as exc:
            build_imported_authorization(prepared, signed)
        assert "does not verify" in str(exc.value)

    def test_import_rejects_a_tag_mismatch(self) -> None:
        prepared = build_prepared_authorization(_prepare_request(_ed25519_payer()))
        signed = _sign_ed25519()
        # ed25519 signature (01) presented with a secp256k1-tagged key (02).
        pk = bytearray(bytes.fromhex(signed["publicKeyHex"]))
        pk[0] = 0x02
        pk.append(0x00)  # secp256k1 tagged keys are 34 bytes
        signed["publicKeyHex"] = bytes(pk).hex()
        with pytest.raises(CaptureError):
            build_imported_authorization(prepared, signed)

    def test_import_rejects_a_payer_mismatch(self) -> None:
        # Sign a digest prepared for a DIFFERENT payer than the signing key.
        prepared = build_prepared_authorization(_prepare_request("cd" * 32))
        with pytest.raises(CaptureError) as exc:
            build_imported_authorization(prepared, _sign_ed25519())
        # Either the signature fails against the other payer's digest, or the
        # derived payer differs — both are fail-closed refusals.
        assert isinstance(exc.value, CaptureError)

    def test_import_rejects_a_prepared_record_mutated_after_derivation(self) -> None:
        prepared = build_prepared_authorization(
            _prepare_request(_ed25519_payer())
        )
        signed = _sign_ed25519()
        prepared["resource"]["description"] = "changed after wallet review"

        with pytest.raises(CaptureError, match="prepared|derive|record"):
            build_imported_authorization(prepared, signed)


def test_prepared_output_is_canonical_and_writeonce(tmp_path: Path) -> None:
    from scripts.official_x402_capture import _emit

    prepared = build_prepared_authorization(_prepare_request(_ed25519_payer()))
    out = tmp_path / "prepared.json"
    _emit(prepared, str(out))
    raw = out.read_bytes()
    assert raw == _canonical(prepared)
    # write-once: a second emit to the same path refuses.
    with pytest.raises(Exception):
        _emit(prepared, str(out))


@pytest.mark.parametrize("input_mode", [0o400, 0o600])
def test_control_json_reader_accepts_only_descriptor_safe_private_files(
    tmp_path: Path, input_mode: int
) -> None:
    from scripts.official_x402_capture import _read_json

    path = tmp_path / "control.json"
    expected = {"purpose": "raw-capture-control"}
    path.write_bytes(_canonical(expected))
    path.chmod(input_mode)

    assert _read_json(path, context="control") == expected

    path.chmod(0o644)
    with pytest.raises(CaptureError, match="secure|safely"):
        _read_json(path, context="control")

    path.chmod(0o600)
    link = tmp_path / "control-link.json"
    link.symlink_to(path)
    with pytest.raises(CaptureError, match="secure|safely"):
        _read_json(link, context="control")


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":1,"value":2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
    ],
)
def test_every_official_x402_json_path_rejects_ambiguous_json(raw: bytes) -> None:
    from scripts.official_x402_capture import _strict_json_bytes

    with pytest.raises(CaptureError, match="JSON|duplicate|finite"):
        _strict_json_bytes(raw, context="raw control")


def test_cli_bounds_atomic_write_refusal_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts.official_x402_capture import main

    request = tmp_path / "prepare-request.json"
    request.write_bytes(_canonical(_prepare_request(_ed25519_payer())))
    request.chmod(0o600)
    output = tmp_path / "existing.json"
    output.write_text("existing", encoding="utf-8")
    output.chmod(0o600)

    result = main(
        [
            "prepare",
            "--request",
            str(request),
            "--out",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert json.loads(captured.err)["refusal"]
    assert output.read_text(encoding="utf-8") == "existing"


# ==========================================================================
# capture
# ==========================================================================
#
# These tests construct a synthetic *raw* capture bundle (the generator's only
# input) and prove that ``build_official_x402_artifact`` assembles an artifact
# the accepted in-process adapter accepts, and that mutating any raw evidence
# input makes the generator refuse. Test-only fixtures are reused from the
# accepted adapter's own test module via ``runpy`` (the reference builders emit
# artifact-shaped pieces; here only the *raw* observed bytes are extracted into
# the bundle). Production code never imports any of this.

_REF = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "tests" / "test_release_official_x402_adapter.py")
)
_ref_canonical: Callable[[object], bytes] = _REF["_canonical"]
_ref_b64: Callable[[bytes], str] = _REF["_b64"]

SERVICE_URL = "https://x402.concordiadao.xyz"
CROSS_URL = "https://x402.concordiadao.xyz/resource/other-report"


def _ascii_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _reencode(base64_text: str, mutate: Callable[[Any], None]) -> str:
    document = json.loads(base64.b64decode(base64_text))
    mutate(document)
    return _ascii_b64(_ref_canonical(document))


def _build_legacy_capture_inputs() -> dict[str, Any]:
    """Assemble a synthetic, fully-consistent raw capture bundle."""

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        _REF["ED25519_PRIVATE_SEED"]
    )
    public_key_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_key = b"\x01" + public_key_raw
    payer = _account_hash_from_public_key(public_key)
    payer_hex = payer.hex()

    payee_hex = _REF["PAYEE_ACCOUNT_HASH"].hex()
    amount = _REF["AMOUNT_ATOMIC"]
    valid_after = _REF["VALID_AFTER"]
    valid_before = _REF["VALID_BEFORE"]
    nonce_hex = _REF["NONCE"].hex()
    resource_url = _REF["RESOURCE_URL"]

    resource = {
        "url": resource_url,
        "description": _REF["RESOURCE_DESCRIPTION"],
        "mimeType": _REF["RESOURCE_MIME"],
    }
    requirements = {
        "scheme": "exact",
        "network": _NETWORK,
        "asset": _WCSPR_PACKAGE,
        "amount": str(amount),
        "payTo": "00" + payee_hex,
        "maxTimeoutSeconds": _REF["MAX_TIMEOUT_SECONDS"],
        "extra": {
            "name": _REF["TOKEN_NAME"],
            "version": _REF["TOKEN_DOMAIN_VERSION"],
            "decimals": str(_REF["TOKEN_DECIMALS"]),
            "symbol": _REF["TOKEN_SYMBOL"],
        },
    }
    report_bytes = _ref_canonical(
        {
            "proposal_id": "DAO-PROP-V3-X402",
            "resource_id": _REF["RESOURCE_ID"],
            "result": "official facilitator settlement finalized",
            "schema": "concordia-x402-report-v1",
        }
    )

    # A genuine prepare + import round trip yields the imported-authorization
    # output the capture bundle embeds.
    body = {
        "x402_version": "2",
        "caip2_network": _NETWORK,
        "wcspr_package": _WCSPR_PACKAGE,
        "wcspr_contract": _WCSPR_CONTRACT,
        "payer": payer_hex,
        "payee": payee_hex,
        "value": str(amount),
        "valid_after": str(valid_after),
        "valid_before": str(valid_before),
        "eip712_auth_nonce": nonce_hex,
        "resource_url_hash": _resource_url_hash(resource_url).hex(),
        "report_hash": _report_hash(report_bytes).hex(),
        "payment_requirements_hash": _payment_requirements_hash(requirements).hex(),
    }
    prepare_request = {
        "schema_version": PREPARE_REQUEST_SCHEMA,
        "accepted": requirements,
        "resource": resource,
        "report_base64": _ascii_b64(report_bytes),
        "body": body,
        "payer_account_hash": payer_hex,
        "payee_account_hash": payee_hex,
        "value": str(amount),
        "valid_after": valid_after,
        "valid_before": valid_before,
        "nonce": nonce_hex,
    }
    prepared = build_prepared_authorization(prepare_request)
    digest = bytes.fromhex(prepared["eip712"]["digest_hex"])
    signature = b"\x01" + private_key.sign(digest)
    imported = build_imported_authorization(
        prepared,
        {"signatureHex": signature.hex(), "publicKeyHex": public_key.hex()},
    )

    v3_proof, _prepared, _identities = _REF["_customized_official_v3_proof"](
        payer_account_hash=payer,
        resource_url_hash=_resource_url_hash(resource_url),
        report_hash=_report_hash(report_bytes),
        payment_requirements_hash=_payment_requirements_hash(requirements),
        signed_payment_payload_hash=bytes.fromhex(
            imported["signed_payment_payload_hash"]
        ),
    )
    assert v3_proof["input"]["header"]["proposal_id"] == "DAO-PROP-V3-X402"

    runtime_args = _REF["_runtime_args"](
        payer_account_hash=payer, public_key=public_key, signature=signature
    )

    def _readback(phase: str, observed_at: str) -> dict[str, Any]:
        full = _REF["_wcspr_readback"](
            runtime_args, phase=phase, observed_at=observed_at
        )
        transcript = full["rpc_transcript"]
        return {
            "observed_at": observed_at,
            "rpc_request_body_base64": transcript["request_body_base64"],
            "rpc_response_body_base64": transcript["response_body_base64"],
        }

    def _provider(endpoint_id: str, origin: str) -> dict[str, Any]:
        full = _REF["_settlement_provider"](endpoint_id, origin, runtime_args)

        def _sub(name: str) -> dict[str, Any]:
            exchange = full[name]
            return {
                "request_body_base64": exchange["request_body_base64"],
                "response_body_base64": exchange["response_body_base64"],
                "observed_at": exchange["observed_at"],
            }

        return {
            "endpoint_id": endpoint_id,
            "origin": origin,
            "info_get_transaction": _sub("info_get_transaction"),
            "chain_get_block": _sub("chain_get_block"),
            "info_get_status": _sub("info_get_status"),
        }

    supported_response = {
        "kinds": [{"x402Version": 2, "scheme": "exact", "network": _NETWORK}],
        "extensions": {},
        "signers": [],
    }
    verify_response = {"isValid": True, "payer": "00" + payer_hex}
    settle_response = {
        "success": True,
        "transaction": _REF["SETTLEMENT_TRANSACTION"],
        "network": _NETWORK,
        "payer": "00" + payer_hex,
    }
    settlement_finalized_at = _REF["SETTLEMENT_FINALIZED_AT"]
    report_released_at = _REF["REPORT_RELEASED_AT"]

    return {
        "bundle_version": CAPTURE_BUNDLE_SCHEMA,
        "captured_at": _REF["CAPTURED_AT"],
        "source_commit": _REF["SOURCE_COMMIT"],
        "deployment_commit": _REF["DEPLOYMENT_COMMIT"],
        "service_url": SERVICE_URL,
        "service_image_digest": "sha256:" + "23" * 32,
        "imported_authorization": imported,
        "v3_proof_bytes_base64": _ascii_b64(_ref_canonical(v3_proof)),
        "report_bytes_base64": _ascii_b64(report_bytes),
        "facilitator": {
            "supported": {
                "response_status": 200,
                "observed_at": "2026-07-22T20:18:00Z",
                "response_body_base64": _ascii_b64(_ref_canonical(supported_response)),
            },
            "verify": {
                "response_status": 200,
                "observed_at": "2026-07-22T20:20:00Z",
                "response_body_base64": _ascii_b64(_ref_canonical(verify_response)),
            },
            "settle": {
                "response_status": 200,
                "observed_at": "2026-07-22T20:21:00Z",
                "response_body_base64": _ascii_b64(_ref_canonical(settle_response)),
            },
        },
        "wcspr_readbacks": {
            "pre_verify": _readback("pre-verify", "2026-07-22T20:19:00Z"),
            "pre_settle": _readback("pre-settle", "2026-07-22T20:20:30Z"),
            "post_settle": _readback("post-settle", settlement_finalized_at),
        },
        "settlement_providers": [
            _provider(
                "casper-testnet-rpc", "https://node.testnet.casper.network/rpc"
            ),
            _provider("cspr-cloud-testnet", "https://node.testnet.cspr.cloud/rpc"),
        ],
        "fulfillment": {
            "created_at": "2026-07-22T20:19:00Z",
            "settled_at": settlement_finalized_at,
            "first_row": {
                "observed_at": settlement_finalized_at,
                "service_instance_id": "x402-official-a",
            },
            "post_restart_row": {
                "observed_at": "2026-07-22T20:25:30Z",
                "service_instance_id": "x402-official-b",
            },
            "first_release_observed_at": report_released_at,
            "exact_retry_observed_at": "2026-07-22T20:25:35Z",
            "cross_binding": {
                "url": CROSS_URL,
                "observed_at": "2026-07-22T20:25:40Z",
            },
            "journal": {
                "authoritative_database_id": "x402-official-ledger",
                "request_started_observed_at": "2026-07-22T20:20:59Z",
                "response_observed_observed_at": "2026-07-22T20:21:00Z",
                "snapshots": {
                    "after_first_release": {
                        "observed_at": report_released_at,
                        "service_instance_id": "x402-official-a",
                    },
                    "after_exact_retry": {
                        "observed_at": "2026-07-22T20:25:35Z",
                        "service_instance_id": "x402-official-b",
                    },
                    "after_cross_binding_reuse": {
                        "observed_at": "2026-07-22T20:25:40Z",
                        "service_instance_id": "x402-official-b",
                    },
                },
            },
        },
    }


def _raw_http(exchange: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(exchange[key])
        for key in (
            "method",
            "url",
            "request_body_base64",
            "response_status",
            "response_content_type",
            "response_body_base64",
            "observed_at",
        )
    }


def _raw_rpc(exchange: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(exchange[key])
        for key in (
            "url",
            "request_body_base64",
            "response_status",
            "response_content_type",
            "response_body_base64",
            "observed_at",
        )
    }


def _raw_paid_exchange(exchange: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(exchange[key])
        for key in (
            "method",
            "url",
            "request_headers_canonical_json_base64",
            "request_body_base64",
            "response_status",
            "response_headers_canonical_json_base64",
            "response_content_type",
            "response_body_base64",
            "observed_at",
        )
    }


def _raw_row(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "row_canonical_json_base64": observation[
            "row_canonical_json_base64"
        ],
        "observed_at": observation["observed_at"],
        "service_instance_id": observation["service_instance_id"],
    }


def _raw_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "sqlite_backup_base64": snapshot["sqlite_backup_base64"],
        "observed_at": snapshot["observed_at"],
        "service_instance_id": snapshot["service_instance_id"],
    }


def _build_capture_bundle() -> dict[str, Any]:
    """Build raw observations, never an artifact-shaped producer summary."""

    legacy = _build_legacy_capture_inputs()
    reference_fixture = _REF["official_x402_artifact"]
    reference = reference_fixture.__wrapped__()
    fulfillment = reference["fulfillment"]
    reference_journal = fulfillment["upstream_settle_journal"]
    return {
        key: copy.deepcopy(legacy[key])
        for key in (
            "bundle_version",
            "captured_at",
            "source_commit",
            "deployment_commit",
            "service_url",
            "service_image_digest",
            "imported_authorization",
            "v3_proof_bytes_base64",
            "report_bytes_base64",
        )
    } | {
        "facilitator": {
            name: _raw_http(reference["facilitator"][name])
            for name in ("supported", "verify", "settle")
        },
        "wcspr_readbacks": {
            name: {
                "rpc_transcript": _raw_rpc(
                    reference["wcspr_readbacks"][name]["rpc_transcript"]
                )
            }
            for name in ("pre_verify", "pre_settle", "post_settle")
        },
        "settlement_providers": [
            {
                "endpoint_id": provider["endpoint_id"],
                "origin": provider["origin"],
                **{
                    name: _raw_rpc(provider[name])
                    for name in (
                        "info_get_transaction",
                        "chain_get_block",
                        "info_get_status",
                    )
                },
            }
            for provider in reference["settlement_chain_evidence"][
                "providers"
            ]
        ],
        "fulfillment": {
            "first_row": _raw_row(fulfillment["first_row"]),
            "post_restart_row": _raw_row(
                fulfillment["post_restart_row"]
            ),
            "first_release": _raw_paid_exchange(
                fulfillment["first_release"]
            ),
            "exact_retry": _raw_paid_exchange(fulfillment["exact_retry"]),
            "cross_binding_reuse": _raw_paid_exchange(
                fulfillment["cross_binding_reuse"]
            ),
            "journal": {
                "authoritative_database_id": reference_journal[
                    "authoritative_database_id"
                ],
                "snapshots": {
                    name: _raw_snapshot(
                        reference_journal["snapshots"][name]
                    )
                    for name in (
                        "after_first_release",
                        "after_exact_retry",
                        "after_cross_binding_reuse",
                    )
                },
            },
        },
    }


# Built once (the v3 proof verification is not free); every test deep-copies it.
_BASE_BUNDLE = _build_capture_bundle()


def _bundle() -> dict[str, Any]:
    return copy.deepcopy(_BASE_BUNDLE)


def test_capture_builds_self_verifying_official_x402_artifact() -> None:
    bundle = _bundle()
    imported = bundle["imported_authorization"]
    frozen_request = base64.b64decode(
        imported["frozen_verify_request_body_base64"]
    )
    document = build_official_x402_artifact(bundle)

    # The generator recomputed the derived identity fields from raw inputs.
    binding = document["governance_binding"]
    assert document["schema_version"] == "concordia.official_x402_settlement.v2"
    assert document["capture_identity"]["service_deployment_id"] == (
        "official-x402-" + document["deployment_commit"][:12]
    )
    assert document["capture_identity"]["capture_tool_commit"] == (
        document["source_commit"]
    )
    assert binding["action_kind"] == "OfficialX402SettlementV1"
    assert document["release_order"]["v3_finalized_at"] == binding["finalized_at"]
    assert base64.b64decode(
        document["facilitator"]["verify"]["request_body_base64"]
    ) == frozen_request
    assert base64.b64decode(
        document["facilitator"]["settle"]["request_body_base64"]
    ) == frozen_request

    # And the accepted in-process adapter accepts the assembled artifact.
    raw = _canonical(document)
    result = verify_official_x402_artifact(copy.deepcopy(document), raw)
    assert result["proof_type"] == "official_x402_settlement_v1"
    assert result["derived_facts"]["v3_finalized_exact"] is True
    assert all(check["passed"] is True for check in result["checks"])


def test_capture_refuses_frozen_request_bytes_that_do_not_match_import() -> None:
    bundle = _bundle()
    imported = bundle["imported_authorization"]
    frozen = bytearray(
        base64.b64decode(imported["frozen_verify_request_body_base64"])
    )
    frozen[-1] ^= 1
    corrupted = _ascii_b64(bytes(frozen))
    imported["frozen_verify_request_body_base64"] = corrupted
    imported["frozen_settle_request_body_base64"] = corrupted

    with pytest.raises(CaptureError, match="frozen|request"):
        build_official_x402_artifact(bundle)


def test_capture_journal_snapshots_are_identical_and_root_bound() -> None:
    document = build_official_x402_artifact(_bundle())
    journal = document["fulfillment"]["upstream_settle_journal"]
    snapshots = journal["snapshots"]
    roots = {snap["journal_root_sha256"] for snap in snapshots.values()}
    images = {snap["sqlite_backup_base64"] for snap in snapshots.values()}
    assert len(roots) == 1 and len(images) == 1
    assert journal["migration_sql_sha256"] == (
        "c660abcce78e05edfebb475661dd8ee636a699e822956ac05a990cbe1fb51c5f"
    )


def _mutate_v3_proof(bundle: dict[str, Any]) -> None:
    raw = bytearray(base64.b64decode(bundle["v3_proof_bytes_base64"]))
    raw[-1] ^= 0x01
    bundle["v3_proof_bytes_base64"] = _ascii_b64(bytes(raw))


def _mutate_signature(bundle: dict[str, Any]) -> None:
    signature = bundle["imported_authorization"]["signature_hex"]
    replacement = "0" if signature[-1] != "0" else "1"
    bundle["imported_authorization"]["signature_hex"] = signature[:-1] + replacement


def _mutate_accepted_amount(bundle: dict[str, Any]) -> None:
    accepted = bundle["imported_authorization"]["signed_payment_payload"]["accepted"]
    accepted["amount"] = str(_REF["AMOUNT_ATOMIC"] + 1)


def _mutate_accepted_timeout(bundle: dict[str, Any]) -> None:
    accepted = bundle["imported_authorization"]["signed_payment_payload"]["accepted"]
    accepted["maxTimeoutSeconds"] = _REF["MAX_TIMEOUT_SECONDS"] + 1


def _mutate_resource_description(bundle: dict[str, Any]) -> None:
    resource = bundle["imported_authorization"]["signed_payment_payload"]["resource"]
    resource["description"] = "a divergent configured resource"


def _mutate_report(bundle: dict[str, Any]) -> None:
    bundle["report_bytes_base64"] = _reencode(
        bundle["report_bytes_base64"],
        lambda document: document.__setitem__("result", "tampered result"),
    )


def _mutate_verify_is_valid(bundle: dict[str, Any]) -> None:
    bundle["facilitator"]["verify"]["response_body_base64"] = _reencode(
        bundle["facilitator"]["verify"]["response_body_base64"],
        lambda document: document.__setitem__("isValid", False),
    )


def _mutate_supported_kind(bundle: dict[str, Any]) -> None:
    bundle["facilitator"]["supported"]["response_body_base64"] = _reencode(
        bundle["facilitator"]["supported"]["response_body_base64"],
        lambda document: document.__setitem__(
            "kinds", [{"x402Version": 2, "scheme": "upto", "network": _NETWORK}]
        ),
    )


def _mutate_settle_success(bundle: dict[str, Any]) -> None:
    bundle["facilitator"]["settle"]["response_body_base64"] = _reencode(
        bundle["facilitator"]["settle"]["response_body_base64"],
        lambda document: document.__setitem__("success", False),
    )


def _mutate_settle_status(bundle: dict[str, Any]) -> None:
    bundle["facilitator"]["settle"]["response_status"] = 502


def _mutate_settle_transaction(bundle: dict[str, Any]) -> None:
    bundle["facilitator"]["settle"]["response_body_base64"] = _reencode(
        bundle["facilitator"]["settle"]["response_body_base64"],
        lambda document: document.__setitem__("transaction", "fe" * 32),
    )


def _mutate_provider_execution_error(bundle: dict[str, Any]) -> None:
    provider = bundle["settlement_providers"][0]
    provider["info_get_transaction"]["response_body_base64"] = _reencode(
        provider["info_get_transaction"]["response_body_base64"],
        lambda document: document["result"]["execution_info"]["execution_result"][
            "Version2"
        ].__setitem__("error_message", "User error: 99"),
    )


def _break_chainspec(bundle: dict[str, Any], phase: str) -> None:
    readback = bundle["wcspr_readbacks"][phase]["rpc_transcript"]
    readback["response_body_base64"] = _reencode(
        readback["response_body_base64"],
        lambda responses: responses[0]["result"].__setitem__(
            "chainspec_name", "casper-main"
        ),
    )


def _mutate_pre_verify_readback(bundle: dict[str, Any]) -> None:
    _break_chainspec(bundle, "pre_verify")


def _mutate_pre_settle_readback(bundle: dict[str, Any]) -> None:
    _break_chainspec(bundle, "pre_settle")


def _mutate_post_settle_readback(bundle: dict[str, Any]) -> None:
    _break_chainspec(bundle, "post_settle")


def _mutate_report_release_early(bundle: dict[str, Any]) -> None:
    bundle["fulfillment"]["first_release"]["observed_at"] = (
        "2026-07-22T20:23:59Z"
    )


def _mutate_cross_url_equals_resource(bundle: dict[str, Any]) -> None:
    bundle["fulfillment"]["cross_binding_reuse"]["url"] = _REF[
        "RESOURCE_URL"
    ]


def _mutate_restart_same_instance(bundle: dict[str, Any]) -> None:
    bundle["fulfillment"]["post_restart_row"]["service_instance_id"] = (
        "x402-official-a"
    )


def _mutate_retry_before_release(bundle: dict[str, Any]) -> None:
    bundle["fulfillment"]["exact_retry"]["observed_at"] = (
        "2026-07-22T20:25:05Z"
    )


def _mutate_journal_snapshot_instance(bundle: dict[str, Any]) -> None:
    snapshots = bundle["fulfillment"]["journal"]["snapshots"]
    snapshots["after_exact_retry"]["service_instance_id"] = "x402-official-a"


def _mutate_service_url(bundle: dict[str, Any]) -> None:
    bundle["service_url"] = "https://impostor.example/x402"


# (id, mutation, expected substring in the fail-closed refusal message)
_CAPTURE_MUTATIONS = (
    ("v3-proof", _mutate_v3_proof, "v3 proof"),
    ("signature", _mutate_signature, "imported signature"),
    (
        "accepted-amount",
        _mutate_accepted_amount,
        "imported frozen request",
    ),
    (
        "accepted-timeout",
        _mutate_accepted_timeout,
        "imported frozen request",
    ),
    (
        "resource-description",
        _mutate_resource_description,
        "imported frozen request",
    ),
    ("report", _mutate_report, "report_hash_matches_envelope"),
    (
        "verify-is-valid",
        _mutate_verify_is_valid,
        "self-verification",
    ),
    (
        "supported-kind",
        _mutate_supported_kind,
        "facilitator_verify_returned_is_valid_true",
    ),
    (
        "settle-success",
        _mutate_settle_success,
        "self-verification",
    ),
    ("settle-status", _mutate_settle_status, "did not return HTTP 200"),
    (
        "settle-transaction",
        _mutate_settle_transaction,
        "settlement_transaction_finalized_without_execution_error",
    ),
    (
        "provider-execution-error",
        _mutate_provider_execution_error,
        "self-verification",
    ),
    (
        "pre-verify-readback",
        _mutate_pre_verify_readback,
        "active_wcspr_v8_pre_verify_drift_guard_passed",
    ),
    (
        "pre-settle-readback",
        _mutate_pre_settle_readback,
        "active_wcspr_v8_pre_settle_drift_guard_passed",
    ),
    (
        "post-settle-readback",
        _mutate_post_settle_readback,
        "active_wcspr_v8_post_settle_target_and_args_readback_passed",
    ),
    (
        "report-release-early",
        _mutate_report_release_early,
        "protected_report_released_only_after_finalized_state",
    ),
    (
        "cross-binding-url",
        _mutate_cross_url_equals_resource,
        "payment-signature",
    ),
    (
        "restart-instance",
        _mutate_restart_same_instance,
        "fulfillment_restart_reconciliation_passed",
    ),
    (
        "retry-before-release",
        _mutate_retry_before_release,
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
    ),
    (
        "journal-instance",
        _mutate_journal_snapshot_instance,
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
    ),
    ("capture-identity", _mutate_service_url, "capture identity"),
)


@pytest.mark.parametrize(
    ("_case_id", "mutate", "fragment"),
    _CAPTURE_MUTATIONS,
    ids=[case[0] for case in _CAPTURE_MUTATIONS],
)
def test_capture_refuses_every_mutated_raw_input(
    _case_id: str,
    mutate: Callable[[dict[str, Any]], None],
    fragment: str,
) -> None:
    bundle = _bundle()
    mutate(bundle)
    with pytest.raises(CaptureError) as exc:
        build_official_x402_artifact(bundle)
    assert fragment in str(exc.value)


def test_capture_output_is_canonical_and_writeonce(tmp_path: Path) -> None:
    from scripts.official_x402_capture import _emit

    document = build_official_x402_artifact(_bundle())
    out = tmp_path / "official-x402-settlement-v1.json"
    _emit(document, str(out))
    assert out.read_bytes() == _canonical(document)
    with pytest.raises(Exception):
        _emit(document, str(out))


def test_capture_requires_absolute_output_and_never_dumps_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts.official_x402_capture import _emit

    document = build_official_x402_artifact(_bundle())
    with pytest.raises(CaptureError, match="absolute|output"):
        _emit(document, None)
    with pytest.raises(CaptureError, match="absolute|output"):
        _emit(document, "relative.json")
    assert "protected_report" not in capsys.readouterr().out

    out = tmp_path / "artifact.json"
    _emit(document, str(out))
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    stdout = capsys.readouterr().out
    assert "protected_report" not in stdout
    assert '"sha256"' in stdout


def test_capture_refuses_missing_raw_paid_exchange() -> None:
    bundle = _bundle()
    del bundle["fulfillment"]["exact_retry"]
    with pytest.raises(CaptureError):
        build_official_x402_artifact(bundle)


def test_capture_refuses_tampered_raw_paid_response() -> None:
    bundle = _bundle()
    body = bytearray(
        base64.b64decode(
            bundle["fulfillment"]["first_release"][
                "response_body_base64"
            ]
        )
    )
    body[-1] ^= 1
    bundle["fulfillment"]["first_release"]["response_body_base64"] = (
        _ascii_b64(bytes(body))
    )
    with pytest.raises(CaptureError):
        build_official_x402_artifact(bundle)


def test_capture_refuses_tampered_raw_fulfillment_row() -> None:
    bundle = _bundle()
    row = bytearray(
        base64.b64decode(
            bundle["fulfillment"]["first_row"][
                "row_canonical_json_base64"
            ]
        )
    )
    row[-1] ^= 1
    bundle["fulfillment"]["first_row"]["row_canonical_json_base64"] = (
        _ascii_b64(bytes(row))
    )
    with pytest.raises(CaptureError):
        build_official_x402_artifact(bundle)


def test_capture_refuses_tampered_raw_journal_backup() -> None:
    bundle = _bundle()
    slot = bundle["fulfillment"]["journal"]["snapshots"][
        "after_exact_retry"
    ]
    raw = bytearray(base64.b64decode(slot["sqlite_backup_base64"]))
    raw[-1] ^= 1
    slot["sqlite_backup_base64"] = _ascii_b64(bytes(raw))
    with pytest.raises(CaptureError):
        build_official_x402_artifact(bundle)
