"""Finalize Concordia's shared-host Casper Testnet contract setup.

Run this on the ECS host after the dedicated Testnet account has been funded.
It installs the governance receipt Wasm through Python-native Casper deploy
assembly (`pycspr`), broadcasts through JSON-RPC, resolves the stored contract
hash from the account named keys, patches the shared-host environment, restarts
Concordia, and reruns preflight.

This script intentionally does not submit the final governance receipt. Locke
must still execute the approved proposal flow after this setup succeeds.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key
from pycspr.factory.deploys import create_deploy, create_deploy_parameters, create_standard_payment
from pycspr.types.cl import CLV_Bool, CLV_String
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.crypto.complex import PrivateKey
from pycspr.types.node.rpc import DeployOfModuleBytes

ROOT = Path(__file__).resolve().parents[1]
HOST_ROOT = Path("/opt/apps/concordia/src")
HOST_ENV = Path("/opt/apps/concordia/shared-host/concordia.env")
HOST_COMPOSE_DIR = HOST_ROOT / "deploy/shared-host"
HOST_WASM = HOST_ROOT / "contracts/governance-receipt/target/wasm32-unknown-unknown/release/concordia_governance_receipt.wasm"
LOCAL_WASM = ROOT / "contracts/governance-receipt/target/wasm32-unknown-unknown/release/concordia_governance_receipt.wasm"
LOCAL_COMPOSE_DIR = ROOT / "deploy/shared-host"
CONTRACT_HASH_RE = re.compile(r"(?:hash|package)-[0-9a-fA-F]{64}")
DEPLOY_HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
CONTRACT_NAMED_KEY = "concordia_governance_receipt"
ODRA_PACKAGE_KEY = "concordia_governance_receipt_package_hash"
DEFAULT_HOST_SECRET_KEY = Path("/opt/apps/concordia/secrets/casper_secret_key.pem")


class ProofSetupError(RuntimeError):
    pass


def _default(path: Path, fallback: Path) -> Path:
    return path if path.exists() else fallback


def _run(command: list[str], *, dry_run: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    print(f"$ {printable}")
    if dry_run:
        return subprocess.CompletedProcess(command, 0, "", "")
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.stdout.strip():
        print(proc.stdout.strip())
    if proc.stderr.strip():
        print(proc.stderr.strip(), file=sys.stderr)
    if check and proc.returncode != 0:
        raise ProofSetupError(f"command failed with exit {proc.returncode}: {printable}")
    return proc


def _json_from_output(output: str) -> dict[str, Any]:
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ProofSetupError(f"expected JSON output: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProofSetupError("expected JSON object")
    return parsed


def _docker_python(container: str, args: list[str], *, dry_run: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["docker", "exec", container, "python", *args], dry_run=dry_run, check=check)


def _extract_hash(payload: Any) -> str:
    parsed = payload
    if isinstance(parsed, dict):
        result = parsed.get("result")
        if isinstance(result, dict):
            for key in ("deploy_hash", "transaction_hash"):
                value = result.get(key)
                if isinstance(value, str) and DEPLOY_HASH_RE.fullmatch(value[-64:]):
                    return value[-64:]
    output = json.dumps(payload) if not isinstance(payload, str) else payload
    match = DEPLOY_HASH_RE.search(output)
    if not match:
        raise ProofSetupError("could not extract a deploy hash from JSON-RPC output")
    return match.group(0)


def _find_named_key(value: Any, name: str) -> str | None:
    if isinstance(value, dict):
        if value.get("name") == name and isinstance(value.get("key"), str):
            key = value["key"]
            if CONTRACT_HASH_RE.fullmatch(key):
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


def _rpc_url(node_address: str) -> str:
    return node_address if node_address.endswith("/rpc") else node_address.rstrip("/") + "/rpc"


def _rpc_call(node_address: str, method: str, params: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    if dry_run:
        return {"jsonrpc": "2.0", "id": "dry-run", "result": {}}
    payload = {
        "jsonrpc": "2.0",
        "id": f"concordia-setup-{int(time.time() * 1000)}",
        "method": method,
        "params": params,
    }
    response = httpx.post(_rpc_url(node_address), json=payload, timeout=60.0)
    response.raise_for_status()
    parsed = response.json()
    if parsed.get("error"):
        raise ProofSetupError(f"Casper JSON-RPC {method} failed: {parsed['error']}")
    return parsed


def _load_private_key(path: Path, key_algorithm: str) -> PrivateKey:
    if not path.exists():
        raise ProofSetupError(f"Testnet secret key not found: {path}")
    try:
        algorithm = KeyAlgorithm[key_algorithm.strip().upper()]
    except KeyError as exc:
        raise ProofSetupError(f"unsupported CASPER_KEY_ALGORITHM: {key_algorithm}") from exc
    return parse_private_key(path, algorithm)


def _public_key_hex(private_key: PrivateKey) -> str:
    return private_key.to_public_key().account_key.hex()


def _account_info(node_address: str, public_key_hex: str, *, dry_run: bool = False, named_key: str = CONTRACT_NAMED_KEY) -> dict[str, Any]:
    if dry_run:
        return {"account": {"named_keys": [{"name": named_key, "key": "hash-" + ("1" * 64)}]}}
    response = _rpc_call(
        node_address,
        "state_get_account_info",
        {"public_key": public_key_hex},
        dry_run=dry_run,
    )
    account = (response.get("result") or {}).get("account")
    if not isinstance(account, dict):
        raise ProofSetupError(
            "Funded Testnet account was not found. Fund the public key through the Casper Testnet faucet first."
        )
    return account


def _account_contract_hash(node_address: str, public_key_hex: str, *, named_key: str, dry_run: bool = False) -> str | None:
    account = _account_info(node_address, public_key_hex, dry_run=dry_run, named_key=named_key)
    return _find_named_key(account, named_key)


def _build_contract_install_rpc_payload(
    *,
    private_key: PrivateKey,
    chain_name: str,
    payment_amount: int,
    wasm: bytes,
    ttl: str,
    odra_package_key_name: str | None = None,
) -> dict[str, Any]:
    params = create_deploy_parameters(private_key, chain_name, ttl=ttl)
    payment = create_standard_payment(payment_amount)
    session_args = {}
    if odra_package_key_name:
        session_args = {
            "odra_cfg_package_hash_key_name": CLV_String(odra_package_key_name),
            "odra_cfg_allow_key_override": CLV_Bool(True),
            "odra_cfg_is_upgradable": CLV_Bool(True),
            "odra_cfg_is_upgrade": CLV_Bool(False),
        }
    session = DeployOfModuleBytes(module_bytes=wasm, args=session_args)
    deploy = create_deploy(params, payment, session)
    deploy.approve(private_key)
    return {
        "jsonrpc": "2.0",
        "id": f"concordia-install-{int(time.time() * 1000)}",
        "method": "account_put_deploy",
        "params": {"deploy": serializer.to_json(deploy)},
    }


def _broadcast_payload(node_address: str, payload: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    if dry_run:
        return {
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": {"deploy_hash": (payload["params"]["deploy"]["hash"] or "0" * 64)},
        }
    response = httpx.post(_rpc_url(node_address), json=payload, timeout=60.0)
    response.raise_for_status()
    parsed = response.json()
    if parsed.get("error"):
        raise ProofSetupError(f"Casper contract install broadcast failed: {parsed['error']}")
    return parsed


def _wait_for_contract_hash(
    *,
    node_address: str,
    public_key_hex: str,
    named_key: str,
    attempts: int,
    sleep_seconds: int,
    dry_run: bool,
) -> str:
    for attempt in range(1, attempts + 1):
        contract_hash = _account_contract_hash(
            node_address,
            public_key_hex,
            named_key=named_key,
            dry_run=dry_run,
        )
        if contract_hash:
            return contract_hash
        print(f"Contract named key not visible yet ({attempt}/{attempts}); waiting {sleep_seconds}s")
        if not dry_run:
            time.sleep(sleep_seconds)
    raise ProofSetupError(f"{named_key!r} named key was not found after contract install")


def _set_env_values(path: Path, values: dict[str, str], *, dry_run: bool = False) -> None:
    if not path.exists():
        raise ProofSetupError(f"env file not found: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    updated: list[str] = []
    for line in lines:
        if not line or line.lstrip().startswith("#") or "=" not in line:
            updated.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in values:
            updated.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            updated.append(line)
    for key, value in values.items():
        if key not in seen:
            updated.append(f"{key}={value}")
    print(f"Patch env file: {path}")
    if not dry_run:
        path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def _compose_up(compose_dir: Path, env_file: Path, *, dry_run: bool = False) -> None:
    _run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_dir / "compose.prod.yml"),
            "--env-file",
            str(env_file),
            "up",
            "-d",
        ],
        dry_run=dry_run,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default="concordia-gateway-1")
    parser.add_argument("--env-file", type=Path, default=_default(HOST_ENV, ROOT / "deploy/shared-host/concordia.env"))
    parser.add_argument("--compose-dir", type=Path, default=_default(HOST_COMPOSE_DIR, LOCAL_COMPOSE_DIR))
    parser.add_argument("--wasm", type=Path, default=_default(HOST_WASM, LOCAL_WASM))
    parser.add_argument("--node-address", default="https://node.testnet.casper.network")
    parser.add_argument("--chain-name", default="casper-test")
    parser.add_argument("--key-algorithm", default=os.getenv("CASPER_KEY_ALGORITHM", "ED25519"))
    parser.add_argument("--deploy-ttl", default="30minutes")
    parser.add_argument("--install-payment", default="10000000000")
    parser.add_argument("--receipt-payment", default="5000000000")
    parser.add_argument("--contract-named-key", default=CONTRACT_NAMED_KEY)
    parser.add_argument("--odra", action="store_true", help="Install an Odra package and configure Concordia to call it by package hash.")
    parser.add_argument("--odra-package-key-name", default=ODRA_PACKAGE_KEY)
    parser.add_argument("--contract-version", default="1")
    parser.add_argument(
        "--secret-key-path",
        type=Path,
        default=Path(os.getenv("CASPER_SECRET_KEY_FILE") or DEFAULT_HOST_SECRET_KEY),
    )
    parser.add_argument("--wait-attempts", type=int, default=30)
    parser.add_argument("--wait-seconds", type=int, default=10)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/casper-contract-setup.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    if not args.wasm.exists():
        raise ProofSetupError(f"receipt contract Wasm not found: {args.wasm}")
    if not args.compose_dir.exists():
        raise ProofSetupError(f"compose directory not found: {args.compose_dir}")

    private_key = _load_private_key(args.secret_key_path, args.key_algorithm)
    public_key_hex = _public_key_hex(private_key)

    print("Checking funded Casper Testnet account")
    named_key = args.odra_package_key_name if args.odra else args.contract_named_key
    _account_info(args.node_address, public_key_hex, dry_run=args.dry_run, named_key=named_key)

    install_payload = _build_contract_install_rpc_payload(
        private_key=private_key,
        chain_name=args.chain_name,
        payment_amount=int(args.install_payment),
        wasm=args.wasm.read_bytes(),
        ttl=args.deploy_ttl,
        odra_package_key_name=named_key if args.odra else None,
    )
    install_result = _broadcast_payload(args.node_address, install_payload, dry_run=args.dry_run)
    install_hash = _extract_hash(install_result)
    print(f"Install deploy hash: {install_hash}")

    contract_hash = _wait_for_contract_hash(
        node_address=args.node_address,
        public_key_hex=public_key_hex,
        named_key=named_key,
        attempts=args.wait_attempts,
        sleep_seconds=args.wait_seconds,
        dry_run=args.dry_run,
    )
    print(f"{'Odra package' if args.odra else 'Contract'} hash: {contract_hash}")

    env_values = {
        "CASPER_EXECUTION_MODE": "real",
        "CASPER_EXECUTION_DRIVER": "pycspr",
        "CONCORDIA_PYCSPR_DRY_RUN": "0",
        "CASPER_RECEIPT_CONTRACT_HASH": contract_hash,
        "CASPER_NODE_ADDRESS": args.node_address,
        "CSPR_NODE_RPC_URL": f"{args.node_address.rstrip('/')}/rpc",
        "CASPER_CHAIN_NAME": args.chain_name,
        "CASPER_PAYMENT_AMOUNT": args.receipt_payment,
        "CASPER_ENTRY_POINT": "store_governance_receipt",
        "CASPER_CALL_TARGET": "package" if args.odra else "contract",
    }
    if args.odra:
        env_values["CASPER_CONTRACT_VERSION"] = str(args.contract_version)
    else:
        env_values["CASPER_CONTRACT_VERSION"] = ""

    _set_env_values(
        args.env_file,
        env_values,
        dry_run=args.dry_run,
    )

    preflight: dict[str, Any] | None = None
    if not args.no_restart:
        _compose_up(args.compose_dir, args.env_file, dry_run=args.dry_run)
        if not args.dry_run:
            time.sleep(5)
        preflight_proc = _docker_python(
            args.container,
            ["scripts/casper_preflight.py", "--network"],
            dry_run=args.dry_run,
            check=False,
        )
        if args.dry_run:
            preflight = {"dry_run": True}
        else:
            try:
                preflight = _json_from_output(preflight_proc.stdout)
            except ProofSetupError:
                preflight = {"ok": False, "raw_stdout": preflight_proc.stdout[-2000:]}
            if preflight_proc.returncode != 0 or not preflight.get("ok"):
                raise ProofSetupError("post-restart Casper preflight did not pass")

    result = {
        "schema": "concordia.casper-contract-setup.v1",
        "contract_runtime": "odra-package" if args.odra else "raw-contract",
        "install_deploy_hash": install_hash,
        "contract_hash": contract_hash,
        "named_key": named_key,
        "call_target": env_values["CASPER_CALL_TARGET"],
        "contract_version": env_values.get("CASPER_CONTRACT_VERSION") or None,
        "entry_point": "store_governance_receipt",
        "node_address": args.node_address,
        "public_key_hex": public_key_hex,
        "env_file": str(args.env_file),
        "preflight": preflight,
        "next_required_step": "Run the approved Concordia proposal flow so Locke submits the governance receipt transaction.",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if not args.dry_run:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofSetupError as exc:
        print(f"Casper setup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
