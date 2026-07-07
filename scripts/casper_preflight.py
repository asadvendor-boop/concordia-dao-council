"""Preflight check for Concordia's real Casper Testnet execution path."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.casper_executor import casper_execution_preflight  # noqa: E402
from shared.cspr_cloud import get_node_status, get_public_testnet_probe  # noqa: E402


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", action="store_true", help="also probe configured Casper node/public Testnet read boundary")
    args = parser.parse_args()

    result = casper_execution_preflight()
    if args.network:
        result["node_status"] = await get_node_status()
        result["public_status"] = await get_public_testnet_probe()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
