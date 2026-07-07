#!/usr/bin/env python3
"""Verify a Concordia proof pack or live hosted proof endpoints.

Examples:
  python scripts/verify_concordia_receipt.py artifacts/live/casper-final-receipt-proof.json
  python scripts/verify_concordia_receipt.py --proof-pack artifacts/live/concordia-governance-archive.json
  python scripts/verify_concordia_receipt.py --base-url https://concordia.example.com --proposal-id DAO-PROP-6CB25C
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen


HASH64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CONTRACT_RE = re.compile(r"^hash-[0-9a-fA-F]{64}$")


def _load_json(path_or_url: str) -> dict:
    if path_or_url.startswith(("http://", "https://")):
        with urlopen(path_or_url, timeout=30) as response:  # noqa: S310 - reviewer-provided URL
            return json.loads(response.read().decode("utf-8"))
    return json.loads(Path(path_or_url).read_text())


def _load_url_json(url: str, *, payload: dict | None = None) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method="POST" if payload is not None else "GET")
    with urlopen(request, timeout=30) as response:  # noqa: S310 - reviewer-provided URL
        return json.loads(response.read().decode("utf-8"))


def _walk_dicts(value: object):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk_dicts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_dicts(item)


def _as_contract_hash(value: object) -> str:
    text = str(value or "")
    if HASH64_RE.match(text):
        return f"hash-{text}"
    return text


def _runtime_arg_value(args: dict, name: str) -> object:
    value = (args or {}).get(name)
    if isinstance(value, dict):
        if "value" in value:
            return value["value"]
        if "parsed" in value:
            return value["parsed"]
        if "bytes" in value:
            return value["bytes"]
    return value


def _runtime_arg_type(args: dict, name: str) -> object:
    value = (args or {}).get(name)
    if isinstance(value, dict):
        return value.get("cl_type") or value.get("type")
    if value in {"String", "U32", "U64", "U512"} or isinstance(value, dict):
        return value
    return None


def _strip_hash(value: object) -> str:
    return str(value or "").removeprefix("hash-").lower()


def _typed_arg_parsed(args: dict, name: str) -> object:
    value = (args or {}).get(name)
    if isinstance(value, dict):
        return value.get("parsed", value.get("value", value.get("bytes")))
    return value


def _cspr_live_deploy(deploy_hash: str, api_base: str) -> dict:
    return _load_url_json(f"{api_base.rstrip('/')}/deploys/{deploy_hash}")


def _node_rpc_deploy(deploy_hash: str, rpc_url: str) -> dict:
    candidates = [
        ("info_get_deploy", {"deploy_hash": deploy_hash}),
        ("info_get_transaction", {"transaction_identifier": {"Deploy": deploy_hash}}),
        ("info_get_transaction", {"transaction_identifier": {"Version1": deploy_hash}}),
        ("info_get_transaction", {"transaction_hash": deploy_hash}),
    ]
    last_error: str | None = None
    for method, params in candidates:
        try:
            payload = _load_url_json(
                rpc_url,
                payload={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
            if not payload.get("error"):
                payload["_concordia_rpc_method"] = method
                return payload
            last_error = json.dumps(payload.get("error"))
        except Exception as exc:  # noqa: BLE001 - report all transport failures to reviewer
            last_error = f"{method}: {type(exc).__name__}: {exc}"
    raise RuntimeError(last_error or "Casper node RPC did not return deploy data")


def _rpc_finality_summary(payload: dict) -> dict:
    result = payload.get("result") or payload
    execution_info = result.get("execution_info") or result.get("executionInfo") or {}
    execution_result = execution_info.get("execution_result") or execution_info.get("executionResult")
    block_hash = execution_info.get("block_hash") or execution_info.get("blockHash")
    block_height = execution_info.get("block_height") or execution_info.get("blockHeight")
    if not block_hash or not block_height:
        for item in _walk_dicts(result):
            block_hash = block_hash or item.get("block_hash") or item.get("blockHash")
            block_height = block_height or item.get("block_height") or item.get("blockHeight")
            execution_result = execution_result or item.get("execution_result") or item.get("executionResult")
    error_message = None
    success = bool(execution_result)
    for item in _walk_dicts(execution_result or {}):
        error_message = error_message or item.get("error_message") or item.get("errorMessage")
        if item.get("Failure") or item.get("failure"):
            error_message = error_message or str(item.get("Failure") or item.get("failure"))
    if error_message:
        success = False
    return {
        "rpc_method": payload.get("_concordia_rpc_method"),
        "success": success,
        "block_hash": block_hash,
        "block_height": block_height,
        "error_message": error_message,
    }


def _live_chain_failures(packet: dict, *, rpc_url: str, cspr_live_api: str) -> tuple[list[str], dict]:
    receipt, _, _ = _normalise_receipt(packet)
    failures: list[str] = []
    deploy_hash = str(receipt.get("deploy_hash") or receipt.get("transaction_hash") or "")
    if not HASH64_RE.match(deploy_hash):
        return ["Live-chain check requires a valid local deploy hash."], {}

    try:
        rpc_payload = _node_rpc_deploy(deploy_hash, rpc_url)
        rpc_summary = _rpc_finality_summary(rpc_payload)
    except Exception as exc:  # noqa: BLE001 - live CSPR.live diff can still be useful
        rpc_summary = {
            "rpc_method": None,
            "success": None,
            "block_hash": None,
            "block_height": None,
            "error_message": f"{type(exc).__name__}: {exc}",
            "status": "unavailable",
        }
    try:
        live_payload = _cspr_live_deploy(deploy_hash, cspr_live_api)
    except Exception as exc:  # noqa: BLE001 - reviewer needs a clean verifier failure
        return [f"CSPR.live deploy lookup failed: {type(exc).__name__}: {exc}"], {
            "deploy_hash": deploy_hash,
            "rpc": rpc_summary,
            "cspr_live": {"status": "unavailable"},
        }
    live_data = live_payload.get("data") or live_payload
    live_args = live_data.get("args") or {}

    if rpc_summary.get("success") is False:
        failures.append(f"Casper node RPC does not show successful execution: {rpc_summary.get('error_message')}")
    live_hash = str(live_data.get("deploy_hash") or live_data.get("hash") or deploy_hash)
    if live_hash and live_hash != deploy_hash:
        failures.append(f"CSPR.live deploy hash mismatch: {live_hash} != {deploy_hash}")

    local_contract = _strip_hash(receipt.get("contract_hash"))
    live_contract = _strip_hash(live_data.get("contract_hash") or (live_data.get("contract") or {}).get("contract_hash"))
    if local_contract and live_contract and local_contract != live_contract:
        failures.append(f"Contract hash mismatch: CSPR.live {live_contract} != local {local_contract}")

    live_entry = (
        (live_data.get("contract_entrypoint") or {}).get("name")
        or live_data.get("entry_point")
        or live_data.get("entrypoint")
    )
    local_entry = receipt.get("entry_point") or "store_governance_receipt"
    if live_entry and live_entry != local_entry:
        failures.append(f"Entry point mismatch: CSPR.live {live_entry} != local {local_entry}")

    local_args = receipt.get("typed_args") or {}
    keys_to_compare = [
        "proposal_id",
        "proposal_type",
        "policy_hash",
        "dissent_hash",
        "final_card_hash",
        "plan_hash",
        "approved_allocation_bps",
        "risk_score",
        "casper_network",
        "decision",
    ]
    for key in keys_to_compare:
        expected = _typed_arg_parsed(local_args, key) if key in local_args else receipt.get(key)
        actual = _typed_arg_parsed(live_args, key)
        if expected in (None, "") or actual in (None, ""):
            continue
        if str(expected).lower() != str(actual).lower():
            failures.append(f"Runtime arg {key} mismatch: CSPR.live {actual!r} != local {expected!r}")

    dictionary_status = {
        "status": "skipped",
        "reason": "Odra Mapping dictionary URef is not exposed in the public proof pack; deploy/runtime-arg diff is authoritative for this verifier mode.",
    }
    summary = {
        "deploy_hash": deploy_hash,
        "rpc": rpc_summary,
        "cspr_live": {
            "block_hash": live_data.get("block_hash"),
            "block_height": live_data.get("block_height"),
            "contract_hash": live_contract,
            "entry_point": live_entry,
            "args_checked": [key for key in keys_to_compare if key in live_args],
        },
        "contract_receipts_dictionary": dictionary_status,
    }
    return failures, summary


def _normalise_receipt(packet: dict) -> tuple[dict, dict, bool]:
    """Return receipt, proof, requires_full_proof.

    Supported inputs:
    - /proof-pack/{proposal_id}
    - /evidence/{proposal_id}
    - flat artifacts/live/casper-final-receipt-proof.json
    - CSPR.live deploy API response
    - /cspr-click/unsigned-receipt/{proposal_id}?signer_public_key=...
    """
    packet = packet.get("data") if isinstance(packet.get("data"), dict) else packet
    proof = packet.get("proof_center") or {}
    evidence = packet.get("evidence") or packet if packet.get("cards") else packet.get("evidence") or {}
    receipt = proof.get("casper_receipt") or evidence.get("casper_receipt") or {}
    requires_full_proof = bool(packet.get("proof_center"))

    if not receipt and (packet.get("deploy_hash") or packet.get("transaction_hash")):
        receipt = packet
    if not receipt and packet.get("wallet_payload"):
        receipt = packet
    if not receipt and packet.get("args"):
        receipt = packet

    receipt = dict(receipt or {})
    args = (
        receipt.get("typed_args")
        or receipt.get("typed_runtime_args")
        or packet.get("typed_runtime_args")
        or packet.get("args")
        or {}
    )
    if args:
        receipt.setdefault("typed_args", args)

    if not receipt.get("deploy_hash"):
        receipt["deploy_hash"] = packet.get("deploy_hash") or packet.get("transaction_hash") or packet.get("hash")
    if not receipt.get("transaction_hash"):
        receipt["transaction_hash"] = packet.get("transaction_hash") or receipt.get("deploy_hash")
    if not receipt.get("contract_hash"):
        receipt["contract_hash"] = _as_contract_hash(packet.get("contract_hash") or receipt.get("contract_hash"))
    else:
        receipt["contract_hash"] = _as_contract_hash(receipt.get("contract_hash"))
    if not receipt.get("entry_point"):
        receipt["entry_point"] = packet.get("entry_point") or packet.get("contract_entrypoint") or (
            "store_governance_receipt" if args else ""
        )

    if args:
        mapping = {
            "policy_hash": "policy_hash",
            "dissent_hash": "dissent_hash",
            "final_card_hash": "final_card_hash",
            "plan_hash": "plan_hash",
            "approved_allocation_bps": "approved_allocation_bps",
            "risk_score": "risk_score",
        }
        for source, target in mapping.items():
            if not receipt.get(target):
                value = _runtime_arg_value(args, source)
                if value not in (None, ""):
                    receipt[target] = value
    return receipt, proof, requires_full_proof


def _failures_for_packet(packet: dict) -> list[str]:
    failures: list[str] = []
    proof = packet.get("proof_center") or {}
    evidence = packet.get("evidence") or packet if packet.get("cards") else packet.get("evidence") or {}
    receipt, proof, requires_full_proof = _normalise_receipt(packet)
    compact = proof.get("compact_proof_table") or []
    firewall = proof.get("locke_execution_firewall") or {}

    if evidence and evidence.get("chain_valid") is False:
        failures.append("Evidence chain is not valid.")
    if requires_full_proof and not compact:
        failures.append("Compact proof table is missing.")
    elif compact and not any(row.get("claim") == "Approved receipt anchored on Casper Testnet" and row.get("status") == "verified" for row in compact):
        failures.append("Approved Casper receipt claim is not verified.")

    deploy_hash = receipt.get("deploy_hash") or receipt.get("transaction_hash")
    if not deploy_hash or not HASH64_RE.match(str(deploy_hash)):
        failures.append("Casper deploy/transaction hash is missing or not a 64-character hash.")
    contract_hash = receipt.get("contract_hash")
    if not contract_hash or not CONTRACT_RE.match(str(contract_hash)):
        failures.append("Contract hash is missing or malformed.")
    if (receipt.get("entry_point") or "") != "store_governance_receipt":
        failures.append("Entry point is not store_governance_receipt.")

    required_roots = ["policy_hash", "dissent_hash", "final_card_hash", "plan_hash"]
    for key in required_roots:
        value = str(receipt.get(key) or "").removeprefix("sha256:").removeprefix("hash-")
        if not HASH64_RE.match(value):
            failures.append(f"{key} is missing or not a 32-byte root.")

    typed_args = receipt.get("typed_args") or {}
    typed_text = json.dumps(typed_args, sort_keys=True)
    if typed_args and "ByteArray" not in typed_text:
        failures.append("Typed Casper args do not show ByteArray roots.")
    if typed_args and "U32" not in typed_text:
        failures.append("Typed Casper args do not show U32 numeric fields.")

    if firewall and firewall.get("llm_can_execute_unapproved_action") is not False:
        failures.append("Execution firewall does not clearly block unapproved LLM actions.")
    if requires_full_proof and proof.get("adversarial_safety_demo", {}).get("status") != "blocked":
        failures.append("Adversarial safety demo is missing or not blocked.")
    failures.extend(_quorum_failures_for_packet(packet))
    return failures


def _quorum_failures_for_packet(packet: dict) -> list[str]:
    """Validate the optional live Odra quorum exercise if the proof pack includes it."""
    quorum = packet.get("odra_quorum_exercise") or (packet.get("proof_center") or {}).get("odra_quorum_exercise") or {}
    if not quorum:
        return []

    failures: list[str] = []
    summary = quorum.get("summary") or {}
    live_deploys = quorum.get("live_deploys") or {}
    option1 = quorum.get("option1_backend_signed_receipt") or {}
    option1_finality = option1.get("finality") or {}

    required_flags = {
        "pre_quorum_blocked": "Pre-quorum execution was not recorded as blocked.",
        "two_signers_approved": "Two quorum approvals were not recorded.",
        "final_receipt_after_threshold": "Wallet final receipt after threshold is not recorded.",
        "backend_signed_final_receipt_after_quorum": "Backend-signed final receipt after quorum is not recorded.",
    }
    for key, message in required_flags.items():
        if summary.get(key) is not True:
            failures.append(message)

    required_hashes = {
        "configure_quorum": "configure_quorum deploy hash is missing.",
        "propose_envelope": "propose_envelope deploy hash is missing.",
        "pre_quorum_expected_failure": "pre-quorum expected-failure deploy hash is missing.",
        "approve_envelope_server": "server approval deploy hash is missing.",
        "approve_envelope_browser_wallet": "browser-wallet approval deploy hash is missing.",
        "final_store_governance_receipt": "browser-wallet final receipt deploy hash is missing.",
        "backend_final_store_governance_receipt": "backend-signed final receipt deploy hash is missing.",
    }
    for key, message in required_hashes.items():
        if not HASH64_RE.match(str(live_deploys.get(key) or "")):
            failures.append(message)

    backend_hash = str(summary.get("backend_signed_final_receipt") or option1.get("deploy_hash") or "")
    if not HASH64_RE.match(backend_hash):
        failures.append("Backend-signed final receipt is missing or malformed.")
    elif live_deploys.get("backend_final_store_governance_receipt") and backend_hash != live_deploys.get(
        "backend_final_store_governance_receipt"
    ):
        failures.append("Backend-signed final receipt hash does not match live_deploys.")

    if option1 and option1.get("entry_point") != "store_governance_receipt":
        failures.append("Backend-signed quorum receipt entry point is not store_governance_receipt.")
    if option1 and option1_finality.get("success") is not True:
        failures.append("Backend-signed quorum receipt finality is not successful.")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof_pack_path", nargs="?", help="Path or URL to a Concordia proof/evidence JSON file.")
    parser.add_argument("--proof-pack", help="Path or URL to /proof-pack/{proposal_id}.")
    parser.add_argument("--base-url", help="Hosted Concordia base URL, e.g. https://concordia.example.com.")
    parser.add_argument("--proposal-id", default="DAO-PROP-6CB25C")
    parser.add_argument("--live-chain", action="store_true", help="Also verify the deploy and typed args against live Casper/CSPR.live data.")
    parser.add_argument("--node-rpc-url", default="https://node.testnet.casper.network/rpc")
    parser.add_argument("--cspr-live-api", default="https://api.testnet.cspr.live")
    args = parser.parse_args()

    proof_pack = args.proof_pack or args.proof_pack_path
    if proof_pack:
        packet = _load_json(proof_pack)
    elif args.base_url:
        base = args.base_url.rstrip("/")
        packet = _load_json(f"{base}/proof-pack/{args.proposal_id}")
    else:
        parser.error("Provide --proof-pack or --base-url")

    failures = _failures_for_packet(packet)
    live_summary = None
    if args.live_chain:
        live_failures, live_summary = _live_chain_failures(
            packet,
            rpc_url=args.node_rpc_url,
            cspr_live_api=args.cspr_live_api,
        )
        failures.extend(live_failures)
    if failures:
        print("Concordia receipt verification failed:")
        for failure in failures:
            print(f"- {failure}")
        if live_summary:
            print("live_chain_summary:")
            print(json.dumps(live_summary, indent=2, sort_keys=True))
        return 1
    receipt, _, _ = _normalise_receipt(packet)
    print("Concordia receipt verification passed.")
    print(f"proposal_id: {packet.get('proposal_id') or args.proposal_id}")
    print(f"deploy_hash: {receipt.get('deploy_hash') or receipt.get('transaction_hash')}")
    print(f"contract_hash: {receipt.get('contract_hash')}")
    print(f"entry_point: {receipt.get('entry_point')}")
    if live_summary:
        print("live_chain: passed")
        print(f"live_rpc_method: {live_summary.get('rpc', {}).get('rpc_method')}")
        print(f"live_block_height: {live_summary.get('rpc', {}).get('block_height') or live_summary.get('cspr_live', {}).get('block_height')}")
        print(f"contract_receipts_dictionary: {live_summary.get('contract_receipts_dictionary', {}).get('status')}")
    quorum = packet.get("odra_quorum_exercise") or (packet.get("proof_center") or {}).get("odra_quorum_exercise") or {}
    if quorum:
        summary = quorum.get("summary") or {}
        live_deploys = quorum.get("live_deploys") or {}
        print("quorum_threshold:", summary.get("quorum_threshold"))
        print("quorum_wallet_final_receipt:", live_deploys.get("final_store_governance_receipt"))
        print("quorum_backend_final_receipt:", live_deploys.get("backend_final_store_governance_receipt"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
