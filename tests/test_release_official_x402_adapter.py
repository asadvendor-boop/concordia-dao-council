from __future__ import annotations

import base64
import copy
import hashlib
import json
import runpy
import sqlite3
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jsonschema import Draft202012Validator

from scripts.verify_v3_proof import verify_v3_proof_document
from shared.actions_v3 import X402_CORE_SCHEMA, _derive_action_id, _encode_projection
from shared.release_proof_adapters import (
    ReleaseProofAdapterError,
    verify_official_x402_artifact,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_SCHEMA = (
    ROOT / "handoff" / "schemas" / "official-x402-live-artifact.schema.json"
)
RESULT_SCHEMA = (
    ROOT / "handoff" / "schemas" / "official-x402-adapter-result.schema.json"
)
ADAPTER_CONTRACT = ROOT / "handoff" / "RELEASE_REGISTRY_ADAPTER_SCHEMAS.json"

CAPTURED_AT = "2026-07-23T01:02:03Z"
SOURCE_COMMIT = "11" * 20
DEPLOYMENT_COMMIT = "22" * 20
NETWORK = "casper:casper-test"
CASPER_CHAIN_NAME = "casper-test"
WCSPR_PACKAGE = "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e"
WCSPR_CONTRACT = "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a"
WCSPR_VERSION = 8
TOKEN_NAME = "Wrapped CSPR"
TOKEN_SYMBOL = "WCSPR"
TOKEN_DECIMALS = 9
TOKEN_DOMAIN_VERSION = "1"
RESOURCE_URL = "https://x402.concordiadao.xyz/resource/finals-report-001"
RESOURCE_DESCRIPTION = "Concordia finals protected report"
RESOURCE_MIME = "application/json"
RESOURCE_ID = "finals-report-001"
AMOUNT_ATOMIC = 1_000_000_000
PAYEE_ACCOUNT_HASH = bytes.fromhex("ab" * 32)
NONCE = bytes.fromhex("99" * 32)
VALID_AFTER = 1_784_750_400
VALID_BEFORE = 1_784_754_000
MAX_TIMEOUT_SECONDS = 600

SETTLEMENT_TRANSACTION = "cc" * 32
SETTLEMENT_BLOCK_HASH = "dd" * 32
SETTLEMENT_STATE_ROOT = "ee" * 32
SETTLEMENT_BLOCK_HEIGHT = 8_600_001
SETTLEMENT_BLOCK_TIMESTAMP = "2026-07-22T20:24:00Z"
SETTLEMENT_FINALIZED_AT = "2026-07-22T20:25:00Z"
REPORT_RELEASED_AT = "2026-07-22T20:25:10Z"

ED25519_PRIVATE_SEED = bytes(range(1, 33))
EIP712_DOMAIN_FIELDS = (
    ("name", "string"),
    ("version", "string"),
    ("chain_name", "string"),
    ("contract_package_hash", "bytes32"),
)
EIP712_AUTHORIZATION_FIELDS = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)

MASK_64 = (1 << 64) - 1
KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

UPSTREAM_SETTLE_JOURNAL_MIGRATION = b"""\
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS x402_upstream_settle_calls (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL CHECK (event_type IN ('request_started','response_observed','request_failed')),
  call_id TEXT NOT NULL CHECK (length(call_id) = 64 AND call_id NOT GLOB '*[^0-9a-f]*'),
  network TEXT NOT NULL CHECK (network = 'casper:casper-test'),
  wcspr_contract TEXT NOT NULL CHECK (length(wcspr_contract) = 64 AND wcspr_contract NOT GLOB '*[^0-9a-f]*'),
  signed_payment_payload_hash TEXT NOT NULL CHECK (length(signed_payment_payload_hash) = 64 AND signed_payment_payload_hash NOT GLOB '*[^0-9a-f]*'),
  payer_account_hash TEXT NOT NULL CHECK (length(payer_account_hash) = 64 AND payer_account_hash NOT GLOB '*[^0-9a-f]*'),
  authorization_nonce TEXT NOT NULL CHECK (length(authorization_nonce) = 64 AND authorization_nonce NOT GLOB '*[^0-9a-f]*'),
  resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 128),
  action_id TEXT NOT NULL CHECK (length(action_id) = 64 AND action_id NOT GLOB '*[^0-9a-f]*'),
  envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64 AND envelope_hash NOT GLOB '*[^0-9a-f]*'),
  request_method TEXT,
  request_url TEXT,
  request_headers_canonical_json BLOB,
  request_body BLOB,
  request_body_sha256 TEXT,
  response_status INTEGER,
  response_headers_canonical_json BLOB,
  response_body BLOB,
  response_body_sha256 TEXT,
  failure_code TEXT,
  observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 20 AND 32),
  CHECK (
    (event_type = 'request_started'
      AND request_method = 'POST'
      AND request_url = 'https://x402-facilitator.cspr.cloud/settle'
      AND typeof(request_headers_canonical_json) = 'blob'
      AND length(request_headers_canonical_json) BETWEEN 2 AND 4096
      AND typeof(request_body) = 'blob'
      AND length(request_body) BETWEEN 2 AND 65536
      AND length(request_body_sha256) = 64
      AND request_body_sha256 NOT GLOB '*[^0-9a-f]*'
      AND response_status IS NULL
      AND response_headers_canonical_json IS NULL
      AND response_body IS NULL
      AND response_body_sha256 IS NULL
      AND failure_code IS NULL)
    OR
    (event_type = 'response_observed'
      AND request_method IS NULL
      AND request_url IS NULL
      AND request_headers_canonical_json IS NULL
      AND request_body IS NULL
      AND request_body_sha256 IS NULL
      AND response_status = 200
      AND typeof(response_headers_canonical_json) = 'blob'
      AND length(response_headers_canonical_json) BETWEEN 2 AND 4096
      AND typeof(response_body) = 'blob'
      AND length(response_body) BETWEEN 2 AND 65536
      AND length(response_body_sha256) = 64
      AND response_body_sha256 NOT GLOB '*[^0-9a-f]*'
      AND failure_code IS NULL)
    OR
    (event_type = 'request_failed'
      AND request_method IS NULL
      AND request_url IS NULL
      AND request_headers_canonical_json IS NULL
      AND request_body IS NULL
      AND request_body_sha256 IS NULL
      AND (response_status IS NULL OR response_status BETWEEN 400 AND 599)
      AND response_headers_canonical_json IS NULL
      AND response_body IS NULL
      AND response_body_sha256 IS NULL
      AND length(failure_code) BETWEEN 1 AND 64)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_one_start
  ON x402_upstream_settle_calls(call_id) WHERE event_type = 'request_started';
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_one_terminal
  ON x402_upstream_settle_calls(call_id) WHERE event_type IN ('response_observed','request_failed');
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_authorization_once
  ON x402_upstream_settle_calls(network,wcspr_contract,payer_account_hash,authorization_nonce)
  WHERE event_type = 'request_started';
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_payload_once
  ON x402_upstream_settle_calls(network,signed_payment_payload_hash)
  WHERE event_type = 'request_started';
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_terminal_binding
BEFORE INSERT ON x402_upstream_settle_calls
WHEN NEW.event_type IN ('response_observed','request_failed')
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_journal_orphan_or_binding_mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM x402_upstream_settle_calls AS started
    WHERE started.event_type = 'request_started'
      AND started.call_id = NEW.call_id
      AND started.network = NEW.network
      AND started.wcspr_contract = NEW.wcspr_contract
      AND started.signed_payment_payload_hash = NEW.signed_payment_payload_hash
      AND started.payer_account_hash = NEW.payer_account_hash
      AND started.authorization_nonce = NEW.authorization_nonce
      AND started.resource_id = NEW.resource_id
      AND started.action_id = NEW.action_id
      AND started.envelope_hash = NEW.envelope_hash
  );
END;
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_no_update
BEFORE UPDATE ON x402_upstream_settle_calls
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_journal_append_only');
END;
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_no_delete
BEFORE DELETE ON x402_upstream_settle_calls
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_journal_append_only');
END;
COMMIT;
"""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _blake2b256(value: bytes) -> bytes:
    return hashlib.blake2b(value, digest_size=32).digest()


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _u256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _rotate_left_64(value: int, shift: int) -> int:
    if shift == 0:
        return value & MASK_64
    return ((value << shift) | (value >> (64 - shift))) & MASK_64


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in KECCAK_ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [
            columns[(x - 1) % 5] ^ _rotate_left_64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]

        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate_left_64(
                    state[x + 5 * y],
                    KECCAK_ROTATIONS[x][y],
                )
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    rotated[x + 5 * y]
                    ^ (
                        (~rotated[(x + 1) % 5 + 5 * y])
                        & rotated[(x + 2) % 5 + 5 * y]
                    )
                ) & MASK_64
        state[0] ^= round_constant


def _keccak256(value: bytes) -> bytes:
    rate = 136
    padded = bytearray(value)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _keccak_f1600(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def _eip712_type(name: str, fields: tuple[tuple[str, str], ...]) -> bytes:
    rendered = f"{name}(" + ",".join(f"{kind} {field}" for field, kind in fields) + ")"
    return _keccak256(rendered.encode("ascii"))


def _eip712_address(value: bytes) -> bytes:
    assert len(value) == 33
    return _keccak256(value)


def _eip712_digest(
    *,
    payer_account_hash: bytes,
    payee_account_hash: bytes,
    value_atomic: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> bytes:
    domain_hash = _keccak256(
        b"".join(
            (
                _eip712_type("EIP712Domain", EIP712_DOMAIN_FIELDS),
                _keccak256(TOKEN_NAME.encode("utf-8")),
                _keccak256(TOKEN_DOMAIN_VERSION.encode("utf-8")),
                _keccak256(NETWORK.encode("utf-8")),
                bytes.fromhex(WCSPR_PACKAGE),
            )
        )
    )
    struct_hash = _keccak256(
        b"".join(
            (
                _eip712_type(
                    "TransferWithAuthorization",
                    EIP712_AUTHORIZATION_FIELDS,
                ),
                _eip712_address(b"\x00" + payer_account_hash),
                _eip712_address(b"\x00" + payee_account_hash),
                _u256(value_atomic),
                _u256(valid_after),
                _u256(valid_before),
                nonce,
            )
        )
    )
    return _keccak256(b"\x19\x01" + domain_hash + struct_hash)


def _resource_url_hash() -> bytes:
    return _blake2b256(
        b"CONCORDIA_RESOURCE_URL_V1\x00" + _lp(RESOURCE_URL.encode("ascii"))
    )


def _report_hash(report_bytes: bytes) -> bytes:
    return _blake2b256(
        b"CONCORDIA_X402_REPORT_V1\x00" + _lp(report_bytes)
    )


def _payment_requirements_hash() -> bytes:
    return _blake2b256(
        b"".join(
            (
                b"CONCORDIA_PAYMENT_REQUIREMENTS_V1\x00",
                _lp(b"exact"),
                _lp(NETWORK.encode("ascii")),
                bytes.fromhex(WCSPR_PACKAGE),
                _u256(AMOUNT_ATOMIC),
                PAYEE_ACCOUNT_HASH,
                _u32(MAX_TIMEOUT_SECONDS),
                _lp(TOKEN_NAME.encode("ascii")),
                _lp(TOKEN_DOMAIN_VERSION.encode("ascii")),
                bytes([TOKEN_DECIMALS]),
                _lp(TOKEN_SYMBOL.encode("ascii")),
            )
        )
    )


def _signed_payload_hash(
    *,
    signature: bytes,
    public_key: bytes,
    payer_account_hash: bytes,
    payment_requirements_hash: bytes,
) -> bytes:
    return _blake2b256(
        b"".join(
            (
                b"CONCORDIA_SIGNED_PAYMENT_PAYLOAD_V1\x00",
                _u32(2),
                _lp(RESOURCE_URL.encode("ascii")),
                _lp(RESOURCE_DESCRIPTION.encode("ascii")),
                _lp(RESOURCE_MIME.encode("ascii")),
                payment_requirements_hash,
                _lp(signature),
                public_key,
                payer_account_hash,
                PAYEE_ACCOUNT_HASH,
                _u256(AMOUNT_ATOMIC),
                _u64(VALID_AFTER),
                _u64(VALID_BEFORE),
                NONCE,
                _u32(0),
            )
        )
    )


def _exchange(
    *,
    method: str,
    url: str,
    request_bytes: bytes,
    response: object,
    status: int = 200,
    observed_at: str = "2026-07-22T20:20:00Z",
) -> dict[str, object]:
    response_bytes = _canonical(response)
    return {
        "method": method,
        "url": url,
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": _sha256(request_bytes),
        "response_status": status,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": _sha256(response_bytes),
        "observed_at": observed_at,
    }


def _paid_resource_exchange(
    *,
    url: str,
    payment_payload: dict[str, object],
    response_body: bytes,
    status: int,
    observed_at: str,
    payment_response: dict[str, object] | None,
) -> dict[str, object]:
    decoded_payment_payload = _canonical(payment_payload)
    payment_signature_raw = _b64(decoded_payment_payload).encode("ascii")
    request_headers = _canonical(
        {"payment-signature": payment_signature_raw.decode("ascii")}
    )
    if payment_response is None:
        response_headers_object: dict[str, str] = {}
    else:
        decoded_payment_response = _canonical(payment_response)
        payment_response_raw = _b64(decoded_payment_response).encode("ascii")
        response_headers_object = {
            "payment-response": payment_response_raw.decode("ascii")
        }
    response_headers = _canonical(response_headers_object)
    exchange: dict[str, object] = {
        "method": "GET",
        "url": url,
        "request_headers_canonical_json_base64": _b64(request_headers),
        "request_headers_canonical_json_sha256": _sha256(request_headers),
        "request_body_base64": "",
        "request_body_sha256": _sha256(b""),
        "payment_signature_raw_value_base64": _b64(payment_signature_raw),
        "payment_signature_raw_value_sha256": _sha256(payment_signature_raw),
        "payment_signature_decoded_payload_base64": _b64(
            decoded_payment_payload
        ),
        "payment_signature_decoded_payload_sha256": _sha256(
            decoded_payment_payload
        ),
        "response_status": status,
        "response_headers_canonical_json_base64": _b64(response_headers),
        "response_headers_canonical_json_sha256": _sha256(response_headers),
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_body),
        "response_body_sha256": _sha256(response_body),
        "observed_at": observed_at,
    }
    if payment_response is not None:
        exchange.update(
            {
                "payment_response_raw_value_base64": _b64(
                    payment_response_raw
                ),
                "payment_response_raw_value_sha256": _sha256(
                    payment_response_raw
                ),
                "payment_response_decoded_settlement_base64": _b64(
                    decoded_payment_response
                ),
                "payment_response_decoded_settlement_sha256": _sha256(
                    decoded_payment_response
                ),
            }
        )
    return exchange


def _rpc_exchange(
    request: object,
    response: object,
    *,
    url: str,
    observed_at: str,
) -> dict[str, object]:
    request_bytes = _canonical(request)
    response_bytes = _canonical(response)
    return {
        "url": url,
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": _sha256(request_bytes),
        "response_status": 200,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": _sha256(response_bytes),
        "observed_at": observed_at,
    }


def _runtime_args(
    *,
    payer_account_hash: bytes,
    public_key: bytes,
    signature: bytes,
) -> list[dict[str, str]]:
    def u256_bytes(value: int) -> bytes:
        width = (value.bit_length() + 7) // 8
        return bytes((width,)) + value.to_bytes(width, "little")

    def list_u8_bytes(value: bytes) -> bytes:
        return len(value).to_bytes(4, "little") + value

    values = (
        ("from", "Key", b"\x00" + payer_account_hash),
        ("to", "Key", b"\x00" + PAYEE_ACCOUNT_HASH),
        ("value", "U256", u256_bytes(AMOUNT_ATOMIC)),
        ("valid_after", "U64", VALID_AFTER.to_bytes(8, "little")),
        ("valid_before", "U64", VALID_BEFORE.to_bytes(8, "little")),
        ("nonce", "List<U8>", list_u8_bytes(NONCE)),
        ("public_key", "PublicKey", public_key),
        ("signature", "List<U8>", list_u8_bytes(signature)),
    )
    return [
        {
            "name": name,
            "cl_type": cl_type,
            "canonical_value_base64": _b64(value),
        }
        for name, cl_type, value in values
    ]


def _cl_args(runtime_args: list[dict[str, str]]) -> list[list[object]]:
    return [
        [
            item["name"],
            {
                "cl_type": (
                    {"List": "U8"}
                    if item["cl_type"] == "List<U8>"
                    else item["cl_type"]
                ),
                "bytes": base64.b64decode(item["canonical_value_base64"]).hex(),
            },
        ]
        for item in runtime_args
    ]


def _wcspr_readback(
    runtime_args: list[dict[str, str]],
    *,
    phase: str,
    observed_at: str,
) -> dict[str, object]:
    tip_values = {
        "pre-verify": (
            SETTLEMENT_BLOCK_HEIGHT - 11,
            "a1" * 32,
            "b1" * 32,
            "2026-07-22T20:18:30Z",
        ),
        "pre-settle": (
            SETTLEMENT_BLOCK_HEIGHT - 6,
            "a2" * 32,
            "b2" * 32,
            "2026-07-22T20:20:00Z",
        ),
        "post-settle": (
            SETTLEMENT_BLOCK_HEIGHT + 8,
            "a3" * 32,
            "b3" * 32,
            "2026-07-22T20:24:30Z",
        ),
    }
    tip_height, tip_hash, tip_state_root, tip_timestamp = tip_values[phase]
    status_request = {
        "jsonrpc": "2.0",
        "id": f"{phase}-status",
        "method": "info_get_status",
        "params": [],
    }
    status_response = {
        "jsonrpc": "2.0",
        "id": f"{phase}-status",
        "result": {
            "chainspec_name": CASPER_CHAIN_NAME,
            "our_public_signing_key": "01" + "71" * 32,
            "last_added_block_info": {
                "hash": tip_hash,
                "height": tip_height,
                "state_root_hash": tip_state_root,
                "timestamp": tip_timestamp,
            },
        },
    }
    package_request = {
        "jsonrpc": "2.0",
        "id": f"{phase}-package",
        "method": "state_get_package",
        "params": {
            "package_identifier": {
                "ContractPackageHash": f"contract-package-{WCSPR_PACKAGE}"
            },
            "block_identifier": {"Hash": tip_hash},
        },
    }
    package_response = {
        "jsonrpc": "2.0",
        "id": f"{phase}-package",
        "result": {
            "api_version": "2.0.0",
            "package": {
                "ContractPackage": {
                    "versions": [
                        {
                            "protocol_version_major": 2,
                            "contract_version": 7,
                            "contract_hash": f"contract-{'03' * 32}",
                        },
                        {
                            "protocol_version_major": 2,
                            "contract_version": WCSPR_VERSION,
                            "contract_hash": f"contract-{WCSPR_CONTRACT}",
                        },
                    ],
                    "disabled_versions": [[2, 7]],
                    "groups": [],
                    "lock_status": "Unlocked",
                }
            },
            "merkle_proof": "package-proof",
        },
    }
    contract_request = {
        "jsonrpc": "2.0",
        "id": f"{phase}-contract",
        "method": "query_global_state",
        "params": {
            "state_identifier": {"StateRootHash": tip_state_root},
            "key": f"hash-{WCSPR_CONTRACT}",
            "path": [],
        },
    }
    contract_response = {
        "jsonrpc": "2.0",
        "id": f"{phase}-contract",
        "result": {
            "api_version": "2.0.0",
            "stored_value": {
                "Contract": {
                    "contract_package_hash": f"contract-package-{WCSPR_PACKAGE}",
                    "entry_points": [
                        {
                            "name": "transfer_with_authorization",
                            "args": [
                                {
                                    "name": item["name"],
                                    "cl_type": (
                                        {"List": "U8"}
                                        if item["cl_type"] == "List<U8>"
                                        else item["cl_type"]
                                    ),
                                }
                                for item in runtime_args
                            ],
                        }
                    ],
                }
            },
            "merkle_proof": "contract-proof",
        },
    }
    return {
        "package_hash": WCSPR_PACKAGE,
        "contract_hash": WCSPR_CONTRACT,
        "contract_version": WCSPR_VERSION,
        "lock_status": "Unlocked",
        "entry_point": "transfer_with_authorization",
        "runtime_args": copy.deepcopy(runtime_args),
        "observed_at": observed_at,
        "rpc_transcript": _rpc_exchange(
            [status_request, package_request, contract_request],
            [status_response, package_response, contract_response],
            url="https://node.testnet.casper.network/rpc",
            observed_at=observed_at,
        ),
    }


def _settlement_provider(
    endpoint_id: str,
    origin: str,
    runtime_args: list[dict[str, str]],
) -> dict[str, object]:
    transaction_request = {
        "jsonrpc": "2.0",
        "id": f"{endpoint_id}-transaction",
        "method": "info_get_transaction",
        "params": {
            "transaction_hash": {"Version1": SETTLEMENT_TRANSACTION},
            "finalized_approvals": True,
        },
    }
    transaction_response = {
        "jsonrpc": "2.0",
        "id": f"{endpoint_id}-transaction",
        "result": {
            "api_version": "2.0.0",
            "transaction": {
                "Version1": {
                    "hash": SETTLEMENT_TRANSACTION,
                    "payload": {
                        "initiator_addr": {"PublicKey": "01" + "77" * 32},
                        "timestamp": "2026-07-22T20:20:00Z",
                        "ttl": "30m",
                        "chain_name": CASPER_CHAIN_NAME,
                        "pricing_mode": {
                            "PaymentLimited": {
                                "gas_price_tolerance": 1,
                                "payment_amount": 2_500_000_000,
                                "standard_payment": True,
                            }
                        },
                        "fields": {
                            "args": {"Named": _cl_args(runtime_args)},
                            "target": {
                                "Stored": {
                                    "id": {
                                        "ByPackageHash": {
                                            "addr": WCSPR_PACKAGE,
                                        }
                                    },
                                    "runtime": "VmCasperV1",
                                }
                            },
                            "entry_point": {
                                "Custom": "transfer_with_authorization"
                            },
                            "scheduling": "Standard",
                        },
                        "approvals": [],
                    },
                }
            },
            "execution_info": {
                "block_hash": SETTLEMENT_BLOCK_HASH,
                "block_height": SETTLEMENT_BLOCK_HEIGHT,
                "execution_result": {
                    "Version2": {
                        "error_message": None,
                    }
                },
            },
        },
    }
    block_request = {
        "jsonrpc": "2.0",
        "id": f"{endpoint_id}-block",
        "method": "chain_get_block",
        "params": {
            "block_identifier": {"Hash": SETTLEMENT_BLOCK_HASH},
        },
    }
    block_response = {
        "jsonrpc": "2.0",
        "id": f"{endpoint_id}-block",
        "result": {
            "api_version": "2.0.0",
            "block_with_signatures": {
                "block": {
                    "Version2": {
                        "hash": SETTLEMENT_BLOCK_HASH,
                        "header": {
                            "state_root_hash": SETTLEMENT_STATE_ROOT,
                            "height": SETTLEMENT_BLOCK_HEIGHT,
                            "timestamp": SETTLEMENT_BLOCK_TIMESTAMP,
                        },
                        "body": {
                            "transactions": {
                                "4": [{"Version1": SETTLEMENT_TRANSACTION}]
                            },
                            "rewarded_signatures": [],
                        },
                    }
                },
                "proofs": [
                    {
                        "public_key": "01" + "88" * 32,
                        "signature": "01" + "89" * 64,
                    }
                ],
            },
        },
    }
    node_key_byte = "81" if endpoint_id == "casper-testnet-rpc" else "82"
    status_request = {
        "jsonrpc": "2.0",
        "id": f"{endpoint_id}-status",
        "method": "info_get_status",
        "params": [],
    }
    status_response = {
        "jsonrpc": "2.0",
        "id": f"{endpoint_id}-status",
        "result": {
            "chainspec_name": CASPER_CHAIN_NAME,
            "our_public_signing_key": "01" + node_key_byte * 32,
            "last_added_block_info": {
                "hash": "f1" * 32,
                "height": SETTLEMENT_BLOCK_HEIGHT + 8,
                "state_root_hash": "f2" * 32,
                "timestamp": "2026-07-22T20:24:30Z",
            },
        },
    }
    return {
        "endpoint_id": endpoint_id,
        "origin": origin,
        "info_get_transaction": _rpc_exchange(
            transaction_request,
            transaction_response,
            url=origin,
            observed_at=SETTLEMENT_FINALIZED_AT,
        ),
        "chain_get_block": _rpc_exchange(
            block_request,
            block_response,
            url=origin,
            observed_at=SETTLEMENT_FINALIZED_AT,
        ),
        "info_get_status": _rpc_exchange(
            status_request,
            status_response,
            url=origin,
            observed_at=SETTLEMENT_FINALIZED_AT,
        ),
    }


def _row_observation(
    row: dict[str, object],
    *,
    observed_at: str,
    instance_id: str,
) -> dict[str, object]:
    row_bytes = _canonical(row)
    return {
        "row_canonical_json_base64": _b64(row_bytes),
        "row_canonical_json_sha256": _sha256(row_bytes),
        "observed_at": observed_at,
        "service_instance_id": instance_id,
    }


def _upstream_settle_journal(
    *,
    row: dict[str, object],
    request_bytes: bytes,
    response_bytes: bytes,
) -> dict[str, object]:
    columns = (
        "sequence",
        "event_type",
        "call_id",
        "network",
        "wcspr_contract",
        "signed_payment_payload_hash",
        "payer_account_hash",
        "authorization_nonce",
        "resource_id",
        "action_id",
        "envelope_hash",
        "request_method",
        "request_url",
        "request_headers_canonical_json",
        "request_body",
        "request_body_sha256",
        "response_status",
        "response_headers_canonical_json",
        "response_body",
        "response_body_sha256",
        "failure_code",
        "observed_at",
    )
    insert_columns = columns[1:]
    call_id = _sha256(
        b"".join(
            (
                b"CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\x00",
                bytes.fromhex(str(row["signedPaymentPayloadHash"])),
                bytes.fromhex(str(row["authorizationNonce"])),
            )
        )
    )
    bindings = (
        call_id,
        row["network"],
        row["wcsprContract"],
        row["signedPaymentPayloadHash"],
        row["payerAccountHash"],
        row["authorizationNonce"],
        row["resourceId"],
        row["actionId"],
        row["envelopeHash"],
    )
    request_headers = _canonical({"content-type": "application/json"})
    response_headers = _canonical({"content-type": "application/json"})
    started_values = (
        "request_started",
        *bindings,
        "POST",
        "https://x402-facilitator.cspr.cloud/settle",
        request_headers,
        request_bytes,
        _sha256(request_bytes),
        None,
        None,
        None,
        None,
        None,
        "2026-07-22T20:20:59Z",
    )
    response_values = (
        "response_observed",
        *bindings,
        None,
        None,
        None,
        None,
        None,
        200,
        response_headers,
        response_bytes,
        _sha256(response_bytes),
        None,
        "2026-07-22T20:21:00Z",
    )

    with TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)
        source = sqlite3.connect(directory / "journal.sqlite3")
        try:
            source.executescript(UPSTREAM_SETTLE_JOURNAL_MIGRATION.decode("utf-8"))
            placeholders = ",".join("?" for _ in insert_columns)
            insert_statement = (
                "INSERT INTO x402_upstream_settle_calls ("
                + ",".join(insert_columns)
                + f") VALUES ({placeholders})"
            )
            source.execute(insert_statement, started_values)
            source.execute(insert_statement, response_values)
            source.commit()
            selected = source.execute(
                "SELECT " + ",".join(columns)
                + " FROM x402_upstream_settle_calls ORDER BY sequence"
            ).fetchall()
            canonical_rows: list[dict[str, object]] = []
            blob_columns = {
                "request_headers_canonical_json",
                "request_body",
                "response_headers_canonical_json",
                "response_body",
            }
            for selected_row in selected:
                canonical_row: dict[str, object] = {}
                for key, value in zip(columns, selected_row, strict=True):
                    if key in blob_columns:
                        canonical_row[f"{key}_base64"] = (
                            None if value is None else _b64(value)
                        )
                    else:
                        canonical_row[key] = value
                canonical_rows.append(canonical_row)
            rows_bytes = _canonical(canonical_rows)
            journal_root = _sha256(
                b"".join(
                    (
                        b"CONCORDIA_X402_SETTLE_CALL_JOURNAL_V1\x00",
                        len(canonical_rows).to_bytes(8, "big"),
                        *(
                            hashlib.sha256(_canonical(canonical_row)).digest()
                            for canonical_row in canonical_rows
                        ),
                    )
                )
            )

            def snapshot(
                *,
                filename: str,
                observed_at: str,
                instance_id: str,
            ) -> dict[str, object]:
                path = directory / filename
                destination = sqlite3.connect(path)
                try:
                    source.backup(destination)
                finally:
                    destination.close()
                database_bytes = path.read_bytes()
                return {
                    "sqlite_backup_base64": _b64(database_bytes),
                    "sqlite_backup_sha256": _sha256(database_bytes),
                    "rows_canonical_json_base64": _b64(rows_bytes),
                    "rows_canonical_json_sha256": _sha256(rows_bytes),
                    "journal_root_sha256": journal_root,
                    "observed_at": observed_at,
                    "service_instance_id": instance_id,
                }

            snapshots = {
                "after_first_release": snapshot(
                    filename="after-first.sqlite3",
                    observed_at=REPORT_RELEASED_AT,
                    instance_id="x402-official-a",
                ),
                "after_exact_retry": snapshot(
                    filename="after-retry.sqlite3",
                    observed_at="2026-07-22T20:25:35Z",
                    instance_id="x402-official-b",
                ),
                "after_cross_binding_reuse": snapshot(
                    filename="after-cross-binding.sqlite3",
                    observed_at="2026-07-22T20:25:40Z",
                    instance_id="x402-official-b",
                ),
            }
        finally:
            source.close()

    return {
        "schema_id": "concordia.x402_upstream_settle_journal.v1",
        "authoritative_database_id": "x402-official-ledger",
        "migration_sql_base64": _b64(UPSTREAM_SETTLE_JOURNAL_MIGRATION),
        "migration_sql_sha256": _sha256(UPSTREAM_SETTLE_JOURNAL_MIGRATION),
        "snapshots": snapshots,
    }


def _customized_official_v3_proof(
    *,
    payer_account_hash: bytes,
    resource_url_hash: bytes,
    report_hash: bytes,
    payment_requirements_hash: bytes,
    signed_payment_payload_hash: bytes,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    namespace = runpy.run_path(str(ROOT / "tests" / "test_clvalue_roundtrip.py"))
    document = namespace["_x402_document"]()
    body = document["body"]
    body.update(
        {
            "payer": payer_account_hash.hex(),
            "payee": PAYEE_ACCOUNT_HASH.hex(),
            "value": str(AMOUNT_ATOMIC),
            "resource_url_hash": resource_url_hash.hex(),
            "report_hash": report_hash.hex(),
            "payment_requirements_hash": payment_requirements_hash.hex(),
            "signed_payment_payload_hash": signed_payment_payload_hash.hex(),
            "eip712_auth_nonce": NONCE.hex(),
            "valid_after": str(VALID_AFTER),
            "valid_before": str(VALID_BEFORE),
        }
    )
    document["header"]["action_id"] = _derive_action_id(
        2,
        body["action_nonce"],
        _encode_projection(body, X402_CORE_SCHEMA),
    ).hex()

    def document_factory() -> dict[str, Any]:
        return copy.deepcopy(document)

    bound_proof = namespace["_bound_v3_proof"]
    bound_proof.__globals__["_native_document"] = document_factory
    proof, prepared, identities = bound_proof()
    verification = verify_v3_proof_document(proof)
    assert verification["valid"] is True
    assert verification["proposal_id"] == document["header"]["proposal_id"]
    assert verification["action_id"] == prepared["action_id"]
    assert verification["envelope_hash"] == prepared["envelope_hash"]
    return proof, prepared, identities


@pytest.fixture(scope="module")
def official_x402_artifact() -> dict[str, Any]:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        ED25519_PRIVATE_SEED
    )
    public_key_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_key = b"\x01" + public_key_raw
    payer_account_hash = _blake2b256(b"ed25519\x00" + public_key_raw)
    eip712_digest = _eip712_digest(
        payer_account_hash=payer_account_hash,
        payee_account_hash=PAYEE_ACCOUNT_HASH,
        value_atomic=AMOUNT_ATOMIC,
        valid_after=VALID_AFTER,
        valid_before=VALID_BEFORE,
        nonce=NONCE,
    )
    # Pinned cross-language result from @casper-ecosystem/casper-eip-712 1.2.1.
    assert (
        eip712_digest.hex()
        == "51aeaf3aa87aeddde5ccbd96882501eb88b74519efb9d818beb28a4c2b7125dc"
    )
    signature = b"\x01" + private_key.sign(eip712_digest)
    private_key.public_key().verify(signature[1:], eip712_digest)

    report_bytes = _canonical(
        {
            "proposal_id": "DAO-PROP-V3-X402",
            "resource_id": RESOURCE_ID,
            "result": "official facilitator settlement finalized",
            "schema": "concordia-x402-report-v1",
        }
    )
    resource_hash = _resource_url_hash()
    report_digest = _report_hash(report_bytes)
    requirements_digest = _payment_requirements_hash()
    signed_payload_digest = _signed_payload_hash(
        signature=signature,
        public_key=public_key,
        payer_account_hash=payer_account_hash,
        payment_requirements_hash=requirements_digest,
    )

    resource = {
        "url": RESOURCE_URL,
        "description": RESOURCE_DESCRIPTION,
        "mimeType": RESOURCE_MIME,
    }
    requirements = {
        "scheme": "exact",
        "network": NETWORK,
        "asset": WCSPR_PACKAGE,
        "amount": str(AMOUNT_ATOMIC),
        "payTo": "00" + PAYEE_ACCOUNT_HASH.hex(),
        "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "extra": {
            "name": TOKEN_NAME,
            "version": TOKEN_DOMAIN_VERSION,
            "decimals": str(TOKEN_DECIMALS),
            "symbol": TOKEN_SYMBOL,
        },
    }
    domain = {
        "name": TOKEN_NAME,
        "version": TOKEN_DOMAIN_VERSION,
        "chain_name": NETWORK,
        "contract_package_hash": "0x" + WCSPR_PACKAGE,
    }
    authorization = {
        "from": "00" + payer_account_hash.hex(),
        "to": "00" + PAYEE_ACCOUNT_HASH.hex(),
        "value": str(AMOUNT_ATOMIC),
        "validAfter": str(VALID_AFTER),
        "validBefore": str(VALID_BEFORE),
        "nonce": NONCE.hex(),
    }
    payment_payload = {
        "x402Version": 2,
        "resource": resource,
        "accepted": copy.deepcopy(requirements),
        "payload": {
            "signature": signature.hex(),
            "publicKey": public_key.hex(),
            "authorization": authorization,
        },
    }
    facilitator_request = {
        "x402Version": 2,
        "paymentPayload": payment_payload,
        "paymentRequirements": copy.deepcopy(requirements),
    }
    resource_bytes = _canonical(resource)
    requirements_bytes = _canonical(requirements)
    payment_payload_bytes = _canonical(payment_payload)
    facilitator_request_bytes = _canonical(facilitator_request)
    runtime_args = _runtime_args(
        payer_account_hash=payer_account_hash,
        public_key=public_key,
        signature=signature,
    )

    v3_proof, prepared, identities = _customized_official_v3_proof(
        payer_account_hash=payer_account_hash,
        resource_url_hash=resource_hash,
        report_hash=report_digest,
        payment_requirements_hash=requirements_digest,
        signed_payment_payload_hash=signed_payload_digest,
    )
    v3_proof_bytes = _canonical(v3_proof)
    finalization_step = next(
        step for step in v3_proof["run"]["steps"] if step["name"] == "finalize_exact"
    )
    finalization_outcome = verify_v3_proof_document(v3_proof)[
        "contract_step_outcomes"
    ]["finalize_exact"]

    verify_response = {
        "isValid": True,
        "payer": "00" + payer_account_hash.hex(),
    }
    settle_response = {
        "success": True,
        "transaction": SETTLEMENT_TRANSACTION,
        "network": NETWORK,
        "payer": "00" + payer_account_hash.hex(),
    }
    settle_response_bytes = _canonical(settle_response)
    settlement_response_hash = _sha256(settle_response_bytes)
    row = {
        "network": NETWORK,
        "signedPaymentPayloadHash": signed_payload_digest.hex(),
        "resourceId": RESOURCE_ID,
        "actionId": prepared["action_id"],
        "envelopeHash": prepared["envelope_hash"],
        "resourceUrlHash": resource_hash.hex(),
        "reportHash": report_digest.hex(),
        "paymentRequirementsHash": requirements_digest.hex(),
        "payerAccountHash": payer_account_hash.hex(),
        "payeeAccountHash": PAYEE_ACCOUNT_HASH.hex(),
        "valueAtomic": str(AMOUNT_ATOMIC),
        "validAfter": str(VALID_AFTER),
        "validBefore": str(VALID_BEFORE),
        "authorizationNonce": NONCE.hex(),
        "publicKey": public_key.hex(),
        "signature": signature.hex(),
        "wcsprContract": WCSPR_CONTRACT,
        "state": "finalized",
        "settlementTransactionHash": SETTLEMENT_TRANSACTION,
        "settlementResponseHash": settlement_response_hash,
        "responseJson": settle_response_bytes.decode("ascii"),
        "settledAt": SETTLEMENT_FINALIZED_AT,
        "failureReason": None,
        "recoveryLeaseId": None,
        "recoveryLeaseExpiresAt": None,
        "createdAt": "2026-07-22T20:19:00Z",
        "updatedAt": SETTLEMENT_FINALIZED_AT,
    }
    cross_payment_payload = copy.deepcopy(payment_payload)
    cross_payment_payload["resource"]["url"] = (
        "https://x402.concordiadao.xyz/resource/other-report"
    )
    cross_response_bytes = _canonical({"error": "cross_binding_rejected"})

    artifact = {
        "schema_version": "concordia.official_x402_settlement.v2",
        "captured_at": CAPTURED_AT,
        "source_commit": SOURCE_COMMIT,
        "deployment_commit": DEPLOYMENT_COMMIT,
        "capture_identity": {
            "service_url": "https://x402.concordiadao.xyz",
            "service_deployment_id": (
                f"official-x402-{DEPLOYMENT_COMMIT[:12]}"
            ),
            "service_image_digest": "sha256:" + "23" * 32,
            "capture_tool_commit": SOURCE_COMMIT,
        },
        "governance_binding": {
            "proposal_id": v3_proof["input"]["header"]["proposal_id"],
            "proposal_hash": v3_proof["input"]["header"]["proposal_hash"],
            "proposal_nonce": v3_proof["input"]["header"]["proposal_nonce"],
            "action_id": prepared["action_id"],
            "action_kind": "OfficialX402SettlementV1",
            "action_version": 1,
            "envelope_hash": prepared["envelope_hash"],
            "deployment_domain": v3_proof["input"]["header"][
                "deployment_domain"
            ],
            "network": NETWORK,
            "package_hash": identities["package"],
            "contract_hash": identities["contract"],
            "finalization_transaction": finalization_step["deploy_hash"],
            "finalized_at": finalization_outcome["finalized_at"],
            "observed_at": finalization_outcome["observed_at"],
            "resource_url_hash": resource_hash.hex(),
            "payment_requirements_hash": requirements_digest.hex(),
            "signed_payment_payload_hash": signed_payload_digest.hex(),
            "report_hash": report_digest.hex(),
            "v3_proof_sha256": _sha256(v3_proof_bytes),
            "v3_proof_bytes_base64": _b64(v3_proof_bytes),
        },
        "resource_and_payment": {
            "configured_resource_json_base64": _b64(resource_bytes),
            "configured_resource_sha256": _sha256(resource_bytes),
            "accepted_json_base64": _b64(requirements_bytes),
            "accepted_sha256": _sha256(requirements_bytes),
            "payment_requirements_argument_json_base64": _b64(
                requirements_bytes
            ),
            "payment_requirements_argument_sha256": _sha256(
                requirements_bytes
            ),
        },
        "authorization": {
            "eip712_domain_json_base64": _b64(_canonical(domain)),
            "eip712_authorization_preimage_base64": _b64(eip712_digest),
            "signed_payment_payload_json_base64": _b64(payment_payload_bytes),
            "signature_hex": signature.hex(),
            "public_key_hex": public_key.hex(),
            "recovered_payer_account_hash": payer_account_hash.hex(),
            "payer_account_hash": payer_account_hash.hex(),
            "payee_account_hash": PAYEE_ACCOUNT_HASH.hex(),
            "value_atomic": str(AMOUNT_ATOMIC),
            "nonce_hex": NONCE.hex(),
            "valid_after": str(VALID_AFTER),
            "valid_before": str(VALID_BEFORE),
            "payment_requirements_hash": requirements_digest.hex(),
            "signed_payment_payload_hash": signed_payload_digest.hex(),
        },
        "facilitator": {
            "supported": _exchange(
                method="GET",
                url="https://x402-facilitator.cspr.cloud/supported",
                request_bytes=b"",
                response={
                    "kinds": [
                        {
                            "x402Version": 2,
                            "scheme": "exact",
                            "network": NETWORK,
                        }
                    ],
                    "extensions": {},
                    "signers": [],
                },
                observed_at="2026-07-22T20:18:00Z",
            ),
            "verify": _exchange(
                method="POST",
                url="https://x402-facilitator.cspr.cloud/verify",
                request_bytes=facilitator_request_bytes,
                response=verify_response,
                observed_at="2026-07-22T20:20:00Z",
            ),
            "settle": _exchange(
                method="POST",
                url="https://x402-facilitator.cspr.cloud/settle",
                request_bytes=facilitator_request_bytes,
                response=settle_response,
                observed_at="2026-07-22T20:21:00Z",
            ),
            "parsed_verify": {
                "is_valid": True,
                "payer_account_hash": payer_account_hash.hex(),
            },
            "parsed_settle": {
                "success": True,
                "transaction": SETTLEMENT_TRANSACTION,
                "network": NETWORK,
                "payer_account_hash": payer_account_hash.hex(),
            },
        },
        "wcspr_readbacks": {
            "pre_verify": _wcspr_readback(
                runtime_args,
                phase="pre-verify",
                observed_at="2026-07-22T20:19:00Z",
            ),
            "pre_settle": _wcspr_readback(
                runtime_args,
                phase="pre-settle",
                observed_at="2026-07-22T20:20:30Z",
            ),
            "post_settle": _wcspr_readback(
                runtime_args,
                phase="post-settle",
                observed_at=SETTLEMENT_FINALIZED_AT,
            ),
        },
        "settlement_chain_evidence": {
            "network": NETWORK,
            "settlement_transaction": SETTLEMENT_TRANSACTION,
            "providers": [
                _settlement_provider(
                    "casper-testnet-rpc",
                    "https://node.testnet.casper.network/rpc",
                    runtime_args,
                ),
                _settlement_provider(
                    "cspr-cloud-testnet",
                    "https://node.testnet.cspr.cloud/rpc",
                    runtime_args,
                ),
            ],
            "parsed_settlement": {
                "block_hash": SETTLEMENT_BLOCK_HASH,
                "block_height": SETTLEMENT_BLOCK_HEIGHT,
                "state_root_hash": SETTLEMENT_STATE_ROOT,
                "block_timestamp": SETTLEMENT_BLOCK_TIMESTAMP,
                "execution_success": True,
                "execution_error": None,
                "target_contract_hash": WCSPR_CONTRACT,
                "contract_version": WCSPR_VERSION,
                "entry_point": "transfer_with_authorization",
                "runtime_args": copy.deepcopy(runtime_args),
            },
        },
        "fulfillment": {
            "first_row": _row_observation(
                row,
                observed_at=SETTLEMENT_FINALIZED_AT,
                instance_id="x402-official-a",
            ),
            "post_restart_row": _row_observation(
                row,
                observed_at="2026-07-22T20:25:30Z",
                instance_id="x402-official-b",
            ),
            "first_release": _paid_resource_exchange(
                url="https://x402.concordiadao.xyz/resource/finals-report-001",
                payment_payload=payment_payload,
                response_body=report_bytes,
                status=200,
                payment_response=settle_response,
                observed_at=REPORT_RELEASED_AT,
            ),
            "exact_retry": _paid_resource_exchange(
                url="https://x402.concordiadao.xyz/resource/finals-report-001",
                payment_payload=payment_payload,
                response_body=report_bytes,
                status=200,
                payment_response=settle_response,
                observed_at="2026-07-22T20:25:35Z",
            ),
            "cross_binding_reuse": _paid_resource_exchange(
                url="https://x402.concordiadao.xyz/resource/other-report",
                payment_payload=cross_payment_payload,
                response_body=cross_response_bytes,
                status=409,
                payment_response=None,
                observed_at="2026-07-22T20:25:40Z",
            ),
            "upstream_settle_journal": _upstream_settle_journal(
                row=row,
                request_bytes=facilitator_request_bytes,
                response_bytes=settle_response_bytes,
            ),
        },
        "protected_report": {
            "media_type": "application/json",
            "content_base64": _b64(report_bytes),
            "decoded_length": len(report_bytes),
            "report_hash": report_digest.hex(),
            "response_hash": _sha256(report_bytes),
        },
        "release_order": {
            "v3_finalized_at": finalization_outcome["finalized_at"],
            "settlement_finalized_at": SETTLEMENT_FINALIZED_AT,
            "report_released_at": REPORT_RELEASED_AT,
        },
    }
    Draft202012Validator(json.loads(ARTIFACT_SCHEMA.read_text())).validate(
        artifact
    )
    return artifact


def _replace_b64_json(
    artifact: dict[str, Any],
    pointer: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    slot = _pointer_parent(artifact, pointer)
    key = pointer.rsplit("/", 1)[1]
    value = json.loads(base64.b64decode(slot[key]))
    mutate(value)
    slot[key] = _b64(_canonical(value))


def _pointer_parent(document: dict[str, Any], pointer: str) -> Any:
    value: Any = document
    for part in pointer.split("/")[1:-1]:
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _set_pointer(document: dict[str, Any], pointer: str, value: object) -> None:
    parent = _pointer_parent(document, pointer)
    key = pointer.rsplit("/", 1)[1]
    if isinstance(parent, list):
        parent[int(key)] = value
    else:
        parent[key] = value


def _flip_base64(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[-1] ^= 0x01
    return _b64(bytes(raw))


def _mutate_ox01(artifact: dict[str, Any]) -> None:
    pointer = "/governance_binding/v3_proof_bytes_base64"
    current = artifact["governance_binding"]["v3_proof_bytes_base64"]
    _set_pointer(artifact, pointer, _flip_base64(current))


def _mutate_ox02(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/resource_and_payment/configured_resource_json_base64",
        lambda value: value.__setitem__(
            "description", "a different configured resource"
        ),
    )


def _mutate_ox03(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/resource_and_payment/accepted_json_base64",
        lambda value: value.__setitem__("amount", str(AMOUNT_ATOMIC + 1)),
    )


def _mutate_ox04(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/resource_and_payment/payment_requirements_argument_json_base64",
        lambda value: value.__setitem__(
            "maxTimeoutSeconds", MAX_TIMEOUT_SECONDS + 1
        ),
    )


def _mutate_ox05(artifact: dict[str, Any]) -> None:
    signature = artifact["authorization"]["signature_hex"]
    replacement = "0" if signature[-1] != "0" else "1"
    artifact["authorization"]["signature_hex"] = signature[:-1] + replacement


def _mutate_ox06(artifact: dict[str, Any]) -> None:
    artifact["authorization"]["recovered_payer_account_hash"] = "ff" * 32


def _mutate_ox07(artifact: dict[str, Any]) -> None:
    artifact["authorization"]["value_atomic"] = str(AMOUNT_ATOMIC + 1)


def _mutate_ox08(artifact: dict[str, Any]) -> None:
    artifact["governance_binding"]["resource_url_hash"] = "ff" * 32


def _mutate_ox09(artifact: dict[str, Any]) -> None:
    content = artifact["protected_report"]["content_base64"]
    artifact["protected_report"]["content_base64"] = _flip_base64(content)


def _mutate_ox10(artifact: dict[str, Any]) -> None:
    artifact["authorization"]["payment_requirements_hash"] = "ff" * 32


def _mutate_ox11(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/authorization/signed_payment_payload_json_base64",
        lambda value: value["resource"].__setitem__(
            "description", "mutated signed resource"
        ),
    )


def _mutate_ox12(artifact: dict[str, Any]) -> None:
    artifact["wcspr_readbacks"]["pre_verify"]["contract_hash"] = "ff" * 32


def _mutate_ox13(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/facilitator/verify/response_body_base64",
        lambda value: value.__setitem__("isValid", False),
    )


def _mutate_ox14(artifact: dict[str, Any]) -> None:
    artifact["wcspr_readbacks"]["pre_settle"]["contract_version"] = 7


def _mutate_ox15(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/facilitator/settle/response_body_base64",
        lambda value: value.__setitem__("success", False),
    )


def _mutate_ox16(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/settlement_chain_evidence/providers/0/info_get_transaction/response_body_base64",
        lambda value: value["result"]["execution_info"][
            "execution_result"
        ]["Version2"].__setitem__("error_message", "User error: 99"),
    )


def _mutate_ox17(artifact: dict[str, Any]) -> None:
    artifact["wcspr_readbacks"]["post_settle"]["runtime_args"][2][
        "canonical_value_base64"
    ] = _b64(str(AMOUNT_ATOMIC + 1).encode("ascii"))


def _mutate_ox18(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/fulfillment/first_row/row_canonical_json_base64",
        lambda value: value.__setitem__("actionId", "ff" * 32),
    )


def _mutate_ox19(artifact: dict[str, Any]) -> None:
    _replace_b64_json(
        artifact,
        "/fulfillment/post_restart_row/row_canonical_json_base64",
        lambda value: value.__setitem__("state", "transaction_observed"),
    )


def _mutate_ox20(artifact: dict[str, Any]) -> None:
    current = artifact["fulfillment"]["exact_retry"][
        "payment_response_raw_value_base64"
    ]
    artifact["fulfillment"]["exact_retry"][
        "payment_response_raw_value_base64"
    ] = _flip_base64(current)


def _mutate_ox21(artifact: dict[str, Any]) -> None:
    artifact["fulfillment"]["cross_binding_reuse"]["response_status"] = 200


def _mutate_ox22(artifact: dict[str, Any]) -> None:
    artifact["fulfillment"]["first_release"]["observed_at"] = (
        "2026-07-22T20:23:59Z"
    )


def _replace_encoded_bytes(
    artifact: dict[str, Any],
    *,
    pointer: str,
    sha_pointer: str,
    replacement: bytes,
) -> None:
    _set_pointer(artifact, pointer, _b64(replacement))
    _set_pointer(artifact, sha_pointer, _sha256(replacement))


def _mutate_journal_sqlite_image(artifact: dict[str, Any]) -> None:
    snapshot = artifact["fulfillment"]["upstream_settle_journal"]["snapshots"][
        "after_exact_retry"
    ]
    image = bytearray(base64.b64decode(snapshot["sqlite_backup_base64"]))
    image[-1] ^= 0x01
    replacement = bytes(image)
    snapshot["sqlite_backup_base64"] = _b64(replacement)
    snapshot["sqlite_backup_sha256"] = _sha256(replacement)


def _mutate_journal_rows_projection(artifact: dict[str, Any]) -> None:
    snapshot = artifact["fulfillment"]["upstream_settle_journal"]["snapshots"][
        "after_exact_retry"
    ]
    rows = json.loads(base64.b64decode(snapshot["rows_canonical_json_base64"]))
    rows[1]["response_body_sha256"] = "ff" * 32
    replacement = _canonical(rows)
    snapshot["rows_canonical_json_base64"] = _b64(replacement)
    snapshot["rows_canonical_json_sha256"] = _sha256(replacement)


def _mutate_journal_root(artifact: dict[str, Any]) -> None:
    artifact["fulfillment"]["upstream_settle_journal"]["snapshots"][
        "after_exact_retry"
    ]["journal_root_sha256"] = "ff" * 32


def _mutate_first_release_payment_header_map(
    artifact: dict[str, Any],
) -> None:
    exchange = artifact["fulfillment"]["first_release"]
    replacement = _canonical({"payment-signature": "wrong"})
    exchange["request_headers_canonical_json_base64"] = _b64(replacement)
    exchange["request_headers_canonical_json_sha256"] = _sha256(replacement)


def _mutate_retry_decoded_payment_response(
    artifact: dict[str, Any],
) -> None:
    exchange = artifact["fulfillment"]["exact_retry"]
    decoded = json.loads(
        base64.b64decode(
            exchange["payment_response_decoded_settlement_base64"]
        )
    )
    decoded["transaction"] = "fe" * 32
    replacement = _canonical(decoded)
    exchange["payment_response_decoded_settlement_base64"] = _b64(replacement)
    exchange["payment_response_decoded_settlement_sha256"] = _sha256(
        replacement
    )


def _mutate_cross_binding_response_headers(
    artifact: dict[str, Any],
) -> None:
    exchange = artifact["fulfillment"]["cross_binding_reuse"]
    replacement = _canonical({"payment-response": "forbidden"})
    exchange["response_headers_canonical_json_base64"] = _b64(replacement)
    exchange["response_headers_canonical_json_sha256"] = _sha256(replacement)


MUTATION_CASES = (
    (
        "OX-ADAPTER-01",
        "exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
        "/governance_binding/v3_proof_bytes_base64",
        _mutate_ox01,
    ),
    (
        "OX-ADAPTER-02",
        "resource_object_equals_configured_resource",
        "/resource_and_payment/configured_resource_json_base64",
        _mutate_ox02,
    ),
    (
        "OX-ADAPTER-03",
        "accepted_equals_current_payment_requirements",
        "/resource_and_payment/accepted_json_base64",
        _mutate_ox03,
    ),
    (
        "OX-ADAPTER-04",
        "payment_requirements_argument_equals_accepted",
        "/resource_and_payment/payment_requirements_argument_json_base64",
        _mutate_ox04,
    ),
    (
        "OX-ADAPTER-05",
        "eip712_signature_verified",
        "/authorization/signature_hex",
        _mutate_ox05,
    ),
    (
        "OX-ADAPTER-06",
        "public_key_account_hash_equals_payer",
        "/authorization/recovered_payer_account_hash",
        _mutate_ox06,
    ),
    (
        "OX-ADAPTER-07",
        "authorization_equals_envelope_payer_payee_value_nonce_and_window",
        "/authorization/value_atomic",
        _mutate_ox07,
    ),
    (
        "OX-ADAPTER-08",
        "resource_url_hash_matches_envelope",
        "/governance_binding/resource_url_hash",
        _mutate_ox08,
    ),
    (
        "OX-ADAPTER-09",
        "report_hash_matches_envelope",
        "/protected_report/content_base64",
        _mutate_ox09,
    ),
    (
        "OX-ADAPTER-10",
        "payment_requirements_hash_matches_envelope",
        "/authorization/payment_requirements_hash",
        _mutate_ox10,
    ),
    (
        "OX-ADAPTER-11",
        "signed_payment_payload_hash_matches_envelope",
        "/authorization/signed_payment_payload_json_base64",
        _mutate_ox11,
    ),
    (
        "OX-ADAPTER-12",
        "active_wcspr_v8_pre_verify_drift_guard_passed",
        "/wcspr_readbacks/pre_verify/contract_hash",
        _mutate_ox12,
    ),
    (
        "OX-ADAPTER-13",
        "facilitator_verify_returned_is_valid_true",
        "/facilitator/verify/response_body_base64",
        _mutate_ox13,
    ),
    (
        "OX-ADAPTER-14",
        "active_wcspr_v8_pre_settle_drift_guard_passed",
        "/wcspr_readbacks/pre_settle/contract_version",
        _mutate_ox14,
    ),
    (
        "OX-ADAPTER-15",
        "facilitator_settlement_response_success_true",
        "/facilitator/settle/response_body_base64",
        _mutate_ox15,
    ),
    (
        "OX-ADAPTER-16",
        "settlement_transaction_finalized_without_execution_error",
        "/settlement_chain_evidence/providers/0/info_get_transaction/response_body_base64",
        _mutate_ox16,
    ),
    (
        "OX-ADAPTER-17",
        "active_wcspr_v8_post_settle_target_and_args_readback_passed",
        "/wcspr_readbacks/post_settle/runtime_args/2/canonical_value_base64",
        _mutate_ox17,
    ),
    (
        "OX-ADAPTER-18",
        "fulfillment_authorization_nonce_unique_binding_matches",
        "/fulfillment/first_row/row_canonical_json_base64",
        _mutate_ox18,
    ),
    (
        "OX-ADAPTER-19",
        "fulfillment_restart_reconciliation_passed",
        "/fulfillment/post_restart_row/row_canonical_json_base64",
        _mutate_ox19,
    ),
    (
        "OX-ADAPTER-20",
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
        "/fulfillment/exact_retry/payment_response_raw_value_base64",
        _mutate_ox20,
    ),
    (
        "OX-ADAPTER-21",
        "cross_binding_or_authorization_reuse_returned_terminal_409_before_submission",
        "/fulfillment/cross_binding_reuse/response_status",
        _mutate_ox21,
    ),
    (
        "OX-ADAPTER-22",
        "protected_report_released_only_after_finalized_state",
        "/fulfillment/first_release/observed_at",
        _mutate_ox22,
    ),
)

AUXILIARY_EVIDENCE_CASES = (
    (
        "OX-EVIDENCE-SQLITE",
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
        _mutate_journal_sqlite_image,
    ),
    (
        "OX-EVIDENCE-ROWS",
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
        _mutate_journal_rows_projection,
    ),
    (
        "OX-EVIDENCE-ROOT",
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
        _mutate_journal_root,
    ),
    (
        "OX-EVIDENCE-FIRST-HEADER",
        "protected_report_released_only_after_finalized_state",
        _mutate_first_release_payment_header_map,
    ),
    (
        "OX-EVIDENCE-RETRY-RESPONSE",
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
        _mutate_retry_decoded_payment_response,
    ),
    (
        "OX-EVIDENCE-409-HEADER",
        "cross_binding_or_authorization_reuse_returned_terminal_409_before_submission",
        _mutate_cross_binding_response_headers,
    ),
)


def test_official_x402_positive_artifact_returns_schema_valid_adapter_result(
    official_x402_artifact: dict[str, Any],
) -> None:
    contract = json.loads(ADAPTER_CONTRACT.read_text())
    required = contract["official_x402_settlement_v1"]
    assert [
        {"id": test_id, "check": check, "mutation": pointer}
        for test_id, check, pointer, _ in MUTATION_CASES
    ] == required["required_mutation_tests"]

    raw_bytes = _canonical(official_x402_artifact)
    result = verify_official_x402_artifact(
        copy.deepcopy(official_x402_artifact),
        raw_bytes,
    )

    Draft202012Validator(json.loads(RESULT_SCHEMA.read_text())).validate(result)
    assert result["artifact_sha256"] == _sha256(raw_bytes)
    assert result["proof_type"] == "official_x402_settlement_v1"
    assert [check["name"] for check in result["checks"]] == required[
        "required_checks"
    ]
    assert all(check["passed"] is True for check in result["checks"])
    assert result["derived_facts"]["action_kind"] == "OfficialX402SettlementV1"
    assert result["derived_facts"]["v3_finalized_exact"] is True
    assert result["internal_record"]["verification_status"] == "verified"


@pytest.mark.parametrize(
    ("test_id", "check", "_pointer", "mutate"),
    MUTATION_CASES,
    ids=[case[0] for case in MUTATION_CASES],
)
def test_official_x402_required_mutation_fails_closed_for_named_check(
    official_x402_artifact: dict[str, Any],
    test_id: str,
    check: str,
    _pointer: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    broken = copy.deepcopy(official_x402_artifact)
    mutate(broken)

    with pytest.raises(ReleaseProofAdapterError, match=f"^{check}:"):
        verify_official_x402_artifact(broken, _canonical(broken))


@pytest.mark.parametrize(
    ("_case_id", "check", "mutate"),
    AUXILIARY_EVIDENCE_CASES,
    ids=[case[0] for case in AUXILIARY_EVIDENCE_CASES],
)
def test_official_x402_raw_evidence_mutation_fails_closed(
    official_x402_artifact: dict[str, Any],
    _case_id: str,
    check: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    broken = copy.deepcopy(official_x402_artifact)
    mutate(broken)
    Draft202012Validator(json.loads(ARTIFACT_SCHEMA.read_text())).validate(
        broken
    )

    with pytest.raises(ReleaseProofAdapterError, match=f"^{check}:"):
        verify_official_x402_artifact(broken, _canonical(broken))
