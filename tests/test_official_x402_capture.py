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
import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from scripts.official_x402_capture import (
    PREPARE_REQUEST_SCHEMA,
    CaptureError,
    build_imported_authorization,
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
