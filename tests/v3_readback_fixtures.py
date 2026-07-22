"""Raw transcript fixtures for parser-sealed v3 authorization tests."""

from __future__ import annotations

import hashlib
import json

from scripts.read_v3_state import (
    VerifiedV3Readback,
    build_readback_artifact_from_transcripts,
    state_dictionary_key,
    verify_and_seal_readback_artifact,
)


def _cl_bytes(inner: bytes) -> dict[str, object]:
    return {
        "CLValue": {
            "cl_type": {"List": "U8"},
            "bytes": (len(inner).to_bytes(4, "little") + inner).hex(),
            "parsed": list(inner),
        }
    }


def _rpc(
    method: str,
    params: dict[str, object],
    result: dict[str, object],
    sequence: int,
) -> dict[str, object]:
    request_id = f"fixture-{sequence}"
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }
    response = {"jsonrpc": "2.0", "id": request_id, "result": result}
    return {
        "rpc_url_identity_or_node_id": "node.testnet.casper.network",
        "method": method,
        "params": params,
        "request": request,
        "response": response,
        "canonical_sha256": hashlib.sha256(
            json.dumps(
                {"request": request, "response": response},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest(),
    }


def sealed_v3_readback(
    *,
    package_hash: bytes,
    contract_hash: bytes,
    deployment_domain: bytes,
    proposal_id: str,
    envelope_hash: bytes,
    action_id: bytes,
    observed_block_hash: bytes,
    observed_block_height: int,
    observed_state_root_hash: bytes,
) -> VerifiedV3Readback:
    transcripts: list[dict[str, object]] = [
        _rpc(
            "chain_get_block",
            {"block_identifier": {"Hash": observed_block_hash.hex()}},
            {
                "api_version": "2.0.0",
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": observed_block_hash.hex(),
                            "header": {
                                "height": observed_block_height,
                                "state_root_hash": observed_state_root_hash.hex(),
                            },
                            "body": {},
                        }
                    },
                    "proofs": [],
                },
            },
            0,
        ),
        _rpc(
            "query_global_state",
            {
                "state_identifier": {
                    "StateRootHash": observed_state_root_hash.hex()
                },
                "key": "hash-" + contract_hash.hex(),
                "path": [],
            },
            {
                "stored_value": {
                    "Contract": {
                        "contract_package_hash": "contract-package-"
                        + package_hash.hex()
                    }
                }
            },
            1,
        ),
    ]

    def dictionary(index: int, mapping_key: bytes, inner: bytes) -> None:
        sequence = len(transcripts)
        transcripts.append(
            _rpc(
                "state_get_dictionary_item",
                {
                    "state_root_hash": observed_state_root_hash.hex(),
                    "dictionary_identifier": {
                        "ContractNamedKey": {
                            "key": "hash-" + contract_hash.hex(),
                            "dictionary_name": "state",
                        }
                    },
                    "dictionary_item_key": state_dictionary_key(index, mapping_key),
                },
                {"stored_value": _cl_bytes(inner)},
                sequence,
            )
        )

    proposal_key = len(proposal_id.encode("ascii")).to_bytes(4, "little") + proposal_id.encode("ascii")
    dictionary(1, b"", (3).to_bytes(4, "little"))
    dictionary(2, b"", deployment_domain)
    dictionary(3, b"", len(b"casper-test").to_bytes(4, "little") + b"casper-test")
    dictionary(4, b"", bytes.fromhex("01" * 32))
    dictionary(5, b"", bytes.fromhex("02" * 32))
    dictionary(6, b"", bytes.fromhex("03" * 32))
    dictionary(7, b"", bytes.fromhex("04" * 32))
    dictionary(8, b"", bytes.fromhex("05" * 32))
    dictionary(9, b"", b"\x02")
    dictionary(11, proposal_key, envelope_hash)
    dictionary(12, proposal_key, b"\x02")
    dictionary(14, proposal_key, b"\x01")
    dictionary(15, proposal_key, envelope_hash)
    dictionary(16, action_id, b"\x01")
    artifact = build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=package_hash.hex(),
        expected_contract_hash=contract_hash.hex(),
        proposal_id=proposal_id,
        action_id=action_id.hex(),
    )
    return verify_and_seal_readback_artifact(artifact)
