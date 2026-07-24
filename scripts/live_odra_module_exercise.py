#!/usr/bin/env python3
"""Run Concordia's separate Odra module exercise on Casper Testnet.

This is intentionally separate from the canonical receipt flow. It installs
each Odra module as its own package, broadcasts one real module call per module,
and then starts the 2-of-3 quorum flow. The VM can complete the server-signed
steps; the second quorum approval must be signed by a distinct browser wallet.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key
from pycspr.factory.deploys import create_deploy, create_deploy_parameters, create_standard_payment
from pycspr.types.cl import CLV_Bool, CLV_String, CLV_U32
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import DeployOfModuleBytes

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.prepare_odra_quorum_exercise import call_specs, envelope, receipt_args, sha256_hex  # noqa: E402
from shared.casper_executor import await_casper_finality, submit_odra_call_deploy  # noqa: E402
from shared.exact_casper_deploy_json import exact_deploy_rpc_json  # noqa: E402

DEPLOY_HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
HASH_RE = re.compile(r"^(?:hash|package)-[0-9a-fA-F]{64}$")
DEFAULT_MODULES = ("CouncilRegistry", "TreasuryPolicy", "CardIndexLedger", "GovernanceReceipt")
DAO_CONSTITUTION = ROOT / "config" / "dao_constitution.cas.json"
PUBLIC_EVIDENCE = ROOT / "artifacts" / "live" / "public-evidence-reconciled.json"


class LiveExerciseError(RuntimeError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _rpc_url(node_address: str) -> str:
    return node_address if node_address.endswith("/rpc") else node_address.rstrip("/") + "/rpc"


async def _rpc_call(node_address: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": f"concordia-odra-live-{int(time.time() * 1000)}",
        "method": method,
        "params": params,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(_rpc_url(node_address), json=payload)
    response.raise_for_status()
    parsed = response.json()
    if parsed.get("error"):
        raise LiveExerciseError(f"{method} failed: {parsed['error']}")
    return parsed


def _extract_deploy_hash(payload: Any) -> str:
    if isinstance(payload, dict):
        result = payload.get("result")
        if isinstance(result, dict):
            for key in ("deploy_hash", "transaction_hash"):
                value = result.get(key)
                if isinstance(value, str) and DEPLOY_HASH_RE.fullmatch(value[-64:]):
                    return value[-64:]
    encoded = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
    match = DEPLOY_HASH_RE.search(encoded)
    if not match:
        raise LiveExerciseError("Could not extract Casper deploy hash")
    return match.group(0)


def _find_named_key(value: Any, name: str) -> str | None:
    if isinstance(value, dict):
        if value.get("name") == name and isinstance(value.get("key"), str):
            key = value["key"]
            if HASH_RE.fullmatch(key):
                return key
        for item in value.values():
            found = _find_named_key(item, name)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_named_key(item, name)
            if found:
                return found
    return None


def _load_private_key(path: Path, key_algorithm: str):
    if not path.exists():
        raise LiveExerciseError(f"Secret key not found: {path}")
    return parse_private_key(path, KeyAlgorithm[key_algorithm.strip().upper()])


def _public_key_hex(private_key: Any) -> str:
    return private_key.to_public_key().account_key.hex()


def _constitution_caps() -> dict[str, int]:
    constitution = _load_json(DAO_CONSTITUTION)
    return {
        "max_single_allocation_bps": int(constitution["max_single_allocation_bps"]),
        "max_high_risk_allocation_bps": int(constitution["max_high_risk_allocation_bps"]),
    }


def _card_index_root(final_card_hash: str) -> dict[str, Any]:
    evidence = _load_json(PUBLIC_EVIDENCE)
    for card in evidence.get("cards") or []:
        card_hash = str(card.get("hash") or card.get("card_hash") or "")
        if card_hash == final_card_hash:
            return {
                "label": "receipt_final_card_hash",
                "sequence": int(card["sequence"]),
                "card_root_hex": final_card_hash,
                "card_type": card.get("card_type"),
            }
    raise LiveExerciseError(f"receipt final_card_hash {final_card_hash} was not found in public evidence")


async def _account_info(node_address: str, public_key_hex: str) -> dict[str, Any]:
    response = await _rpc_call(node_address, "state_get_account_info", {"public_key": public_key_hex})
    account = (response.get("result") or {}).get("account")
    if not isinstance(account, dict):
        raise LiveExerciseError("Funded Casper Testnet account was not found")
    return account


async def _wait_named_key(
    *,
    node_address: str,
    public_key_hex: str,
    named_key: str,
    attempts: int,
    sleep_seconds: float,
) -> str:
    for attempt in range(1, attempts + 1):
        account = await _account_info(node_address, public_key_hex)
        found = _find_named_key(account, named_key)
        if found:
            return found
        if attempt < attempts:
            await asyncio.sleep(sleep_seconds)
    raise LiveExerciseError(f"Named key {named_key!r} was not visible after install")


def _install_payload(
    *,
    private_key: Any,
    chain_name: str,
    payment_amount: int,
    ttl: str,
    wasm: bytes,
    package_key_name: str,
    install_upgradable: bool,
    constructor_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    params = create_deploy_parameters(private_key, chain_name, ttl=ttl)
    payment = create_standard_payment(payment_amount)
    session_args = {
        "odra_cfg_package_hash_key_name": CLV_String(package_key_name),
        "odra_cfg_allow_key_override": CLV_Bool(True),
        "odra_cfg_is_upgradable": CLV_Bool(install_upgradable),
        "odra_cfg_is_upgrade": CLV_Bool(False),
    }
    session_args.update(constructor_args or {})
    session = DeployOfModuleBytes(
        module_bytes=wasm,
        args=session_args,
    )
    deploy = create_deploy(params, payment, session)
    deploy.approve(private_key)
    return {
        "jsonrpc": "2.0",
        "id": f"concordia-odra-install-{int(time.time() * 1000)}",
        "method": "account_put_deploy",
        "params": {"deploy": exact_deploy_rpc_json(deploy)},
    }


async def _broadcast_install(
    *,
    module: str,
    wasm_path: Path,
    package_key_name: str,
    private_key: Any,
    public_key_hex: str,
    node_address: str,
    chain_name: str,
    payment_amount: int,
    ttl: str,
    install_upgradable: bool,
    constructor_args: dict[str, Any] | None,
    wait_attempts: int,
    wait_seconds: float,
) -> dict[str, Any]:
    if not wasm_path.exists():
        raise LiveExerciseError(f"{module} Wasm missing: {wasm_path}")
    payload = _install_payload(
        private_key=private_key,
        chain_name=chain_name,
        payment_amount=payment_amount,
        ttl=ttl,
        wasm=wasm_path.read_bytes(),
        package_key_name=package_key_name,
        install_upgradable=install_upgradable,
        constructor_args=constructor_args,
    )
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(_rpc_url(node_address), json=payload)
    response.raise_for_status()
    parsed = response.json()
    if parsed.get("error"):
        raise LiveExerciseError(f"{module} install failed: {parsed['error']}")
    deploy_hash = _extract_deploy_hash(parsed)
    finality = await await_casper_finality(
        deploy_hash,
        rpc_url=_rpc_url(node_address),
        max_attempts=wait_attempts,
        poll_interval_seconds=wait_seconds,
    )
    if finality.get("success") is False:
        raise LiveExerciseError(
            f"{module} install deploy {deploy_hash} failed on-chain: "
            f"{finality.get('error_message') or finality}"
        )
    package_hash = await _wait_named_key(
        node_address=node_address,
        public_key_hex=public_key_hex,
        named_key=package_key_name,
        attempts=wait_attempts,
        sleep_seconds=wait_seconds,
    )
    return {
        "module": module,
        "package_key_name": package_key_name,
        "package_hash": package_hash,
        "install_deploy_hash": deploy_hash,
        "install_finality": finality,
        "install_upgradable": install_upgradable,
        "constructor_args": {
            name: {"cl_type": "U32", "value": value.value}
            for name, value in (constructor_args or {}).items()
            if isinstance(value, CLV_U32)
        },
        "wasm": {
            "path": str(wasm_path),
            "size_bytes": wasm_path.stat().st_size,
        },
    }


def _call_success(result: dict[str, Any], *, expected_failure: bool = False) -> bool:
    if expected_failure:
        return result.get("status") == "failed" and (result.get("finality") or {}).get("success") is False
    return result.get("status") == "success" and (result.get("finality") or {}).get("success") is not False


async def _server_call(
    *,
    package_hash: str,
    entry_point: str,
    argument_specs: dict[str, Any],
    payment_amount: int,
    expected_failure: bool = False,
) -> dict[str, Any]:
    result = await submit_odra_call_deploy(
        contract_hash=package_hash,
        entry_point=entry_point,
        argument_specs=argument_specs,
        call_target="package",
        contract_version=1,
        payment_amount=payment_amount,
    )
    result["acceptance_passed"] = _call_success(result, expected_failure=expected_failure)
    result["expected_failure"] = expected_failure
    return result


def _module_call_args(module: str, proposal_id: str, server_signer: str) -> tuple[str, dict[str, Any]]:
    roots = receipt_args(proposal_id)
    if module == "CouncilRegistry":
        return "register_agent", {
            "agent_id": {"cl_type": "String", "value": "Locke"},
            "public_key_hex": {"cl_type": "String", "value": server_signer},
        }
    if module == "TreasuryPolicy":
        return "validate_allocation", {
            "requested_bps": {"cl_type": "U32", "value": 800},
            "high_risk": {"cl_type": "Bool", "value": False},
        }
    if module == "CardIndexLedger":
        card_root = _card_index_root(roots["final_card_hash"]["value"])
        return "seal_card_root", {
            "proposal_id": {"cl_type": "String", "value": proposal_id},
            "sequence": {"cl_type": "U32", "value": card_root["sequence"]},
            "card_root_hex": {"cl_type": "String", "value": card_root["card_root_hex"]},
        }
    raise LiveExerciseError(f"No standalone call configured for {module}")


async def run(args: argparse.Namespace) -> dict[str, Any]:
    secret_key = Path(args.secret_key_path or os.getenv("CASPER_SECRET_KEY_PATH", ""))
    private_key = _load_private_key(secret_key, args.key_algorithm)
    server_signer = _public_key_hex(private_key)
    chrome_signer = args.chrome_signer.strip()
    web_signer = args.web_signer.strip()
    if not chrome_signer or not web_signer:
        raise LiveExerciseError("Both --chrome-signer and --web-signer are required for 2-of-3 quorum")

    prefix = args.key_prefix or f"concordia_live_{int(time.time())}"
    requested_modules = tuple(
        module.strip() for module in args.modules.split(",") if module.strip()
    )
    unknown_modules = sorted(set(requested_modules) - set(DEFAULT_MODULES))
    if unknown_modules:
        raise LiveExerciseError(f"Unknown Odra modules requested: {', '.join(unknown_modules)}")
    modules = requested_modules or DEFAULT_MODULES
    out: dict[str, Any] = {
        "schema": "concordia.live-odra-module-exercise.v1",
        "status": "running",
        "generated_at": _utc_now(),
        "proposal_id": args.proposal_id,
        "server_signer": server_signer,
        "chrome_signer": chrome_signer,
        "web_signer": web_signer,
        "node_address": args.node_address,
        "requested_modules": modules,
        "install_upgradable": args.install_upgradable,
        "modules": {},
        "standalone_calls": {},
        "quorum": {
            "threshold": 2,
            "status": "not_started",
            "steps": {},
        },
    }

    for module in modules:
        package_key = f"{prefix}_{module.lower()}_package_hash"
        constructor_args = None
        if module == "TreasuryPolicy":
            caps = _constitution_caps()
            constructor_args = {
                "max_single_allocation_bps": CLV_U32(caps["max_single_allocation_bps"]),
                "max_high_risk_allocation_bps": CLV_U32(caps["max_high_risk_allocation_bps"]),
            }
        install = await _broadcast_install(
            module=module,
            wasm_path=args.wasm_dir / f"{module}.wasm",
            package_key_name=package_key,
            private_key=private_key,
            public_key_hex=server_signer,
            node_address=args.node_address,
            chain_name=args.chain_name,
            payment_amount=args.install_payment,
            ttl=args.ttl,
            install_upgradable=args.install_upgradable,
            constructor_args=constructor_args,
            wait_attempts=args.wait_attempts,
            wait_seconds=args.wait_seconds,
        )
        out["modules"][module] = install

        if module != "GovernanceReceipt":
            entry_point, call_args = _module_call_args(module, args.proposal_id, server_signer)
            call_result = await _server_call(
                package_hash=install["package_hash"],
                entry_point=entry_point,
                argument_specs=call_args,
                payment_amount=args.call_payment,
            )
            out["standalone_calls"][module] = {
                "entry_point": entry_point,
                "result": call_result,
            }

    if "GovernanceReceipt" not in out["modules"]:
        out["quorum"]["status"] = "skipped_governance_receipt_not_requested"
        out["status"] = "module_calls_complete"
        return out

    governance_package = out["modules"]["GovernanceReceipt"]["package_hash"]
    quorum_steps = call_specs(args.proposal_id, server_signer, chrome_signer, web_signer)
    step_map = {step["step"]: step for step in quorum_steps}
    out["quorum"]["package_hash"] = governance_package
    out["quorum"]["package_version"] = 1
    out["quorum"]["envelope_hash"] = sha256_hex(envelope(args.proposal_id))

    for step_name in (
        "configure_quorum",
        "propose_envelope",
        "pre_quorum_store_governance_receipt",
        "approve_envelope_server",
    ):
        step = step_map[step_name]
        result = await _server_call(
            package_hash=governance_package,
            entry_point=step["entry_point"],
            argument_specs=step["args"],
            payment_amount=args.call_payment,
            expected_failure=bool(step.get("expected_failure")),
        )
        out["quorum"]["steps"][step_name] = {
            "entry_point": step["entry_point"],
            "expected": step.get("expected"),
            "expected_failure": bool(step.get("expected_failure")),
            "result": result,
        }

    out["quorum"]["status"] = "waiting_for_second_signer"
    out["quorum"]["second_signer_endpoint"] = (
        f"/cspr-click/quorum-approval/{args.proposal_id}"
        f"?signer_public_key={chrome_signer}"
    )
    out["quorum"]["acceptance"] = {
        "pre_quorum_blocked": out["quorum"]["steps"]["pre_quorum_store_governance_receipt"]["result"]["acceptance_passed"],
        "server_approval_processed": out["quorum"]["steps"]["approve_envelope_server"]["result"]["acceptance_passed"],
        "second_signer_required": True,
        "final_receipt_after_threshold": "pending_browser_wallet_signature",
    }
    out["status"] = "waiting_for_browser_wallet_quorum_approval"
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal-id", default="DAO-PROP-6CB25C")
    parser.add_argument("--wasm-dir", type=Path, default=ROOT / "contracts/odra-governance-receipt/wasm")
    parser.add_argument("--node-address", default=os.getenv("CASPER_NODE_ADDRESS", "https://node.testnet.casper.network"))
    parser.add_argument("--chain-name", default=os.getenv("CASPER_CHAIN_NAME", "casper-test"))
    parser.add_argument("--secret-key-path", default=os.getenv("CASPER_SECRET_KEY_PATH", ""))
    parser.add_argument("--key-algorithm", default=os.getenv("CASPER_KEY_ALGORITHM", "ED25519"))
    parser.add_argument("--chrome-signer", default=os.getenv("CONCORDIA_CHROME_SIGNER_PUBLIC_KEY", ""))
    parser.add_argument("--web-signer", default=os.getenv("CONCORDIA_WEB_SIGNER_PUBLIC_KEY", ""))
    parser.add_argument("--key-prefix", default="")
    parser.add_argument("--install-payment", type=int, default=int(os.getenv("CASPER_ODRA_INSTALL_PAYMENT_AMOUNT", "10000000000")))
    parser.add_argument("--call-payment", type=int, default=int(os.getenv("CASPER_ODRA_CALL_PAYMENT_AMOUNT", "5000000000")))
    parser.add_argument(
        "--modules",
        default=os.getenv("CONCORDIA_ODRA_MODULES", ",".join(DEFAULT_MODULES)),
        help="Comma-separated subset of CouncilRegistry,TreasuryPolicy,CardIndexLedger,GovernanceReceipt.",
    )
    parser.add_argument(
        "--install-upgradable",
        action=argparse.BooleanOptionalAction,
        default=os.getenv("CONCORDIA_ODRA_INSTALL_UPGRADABLE", "true").lower() not in {"0", "false", "no"},
        help="Whether Odra installs should create upgradable packages. --no-install-upgradable may reduce install gas.",
    )
    parser.add_argument("--ttl", default=os.getenv("CASPER_DEPLOY_TTL", "30minutes"))
    parser.add_argument("--wait-attempts", type=int, default=int(os.getenv("CASPER_FINALITY_MAX_ATTEMPTS", "30")))
    parser.add_argument("--wait-seconds", type=float, default=float(os.getenv("CASPER_FINALITY_POLL_SECONDS", "6")))
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/live/odra-module-exercise-live.json")
    args = parser.parse_args()

    try:
        result = asyncio.run(run(args))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"status": result["status"], "artifact": str(args.out), "quorum": result["quorum"]["status"]}, indent=2))
        return 0
    except Exception as exc:
        error = {
            "schema": "concordia.live-odra-module-exercise.v1",
            "status": "failed",
            "generated_at": _utc_now(),
            "error": f"{type(exc).__name__}: {exc}",
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(error, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(error, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
