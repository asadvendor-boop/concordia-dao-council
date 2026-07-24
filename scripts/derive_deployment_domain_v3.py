#!/usr/bin/env python3
"""Derive Concordia v3's immutable deployment domain."""

from __future__ import annotations

import argparse
import json
from typing import Any

from shared.envelope_v3 import derive_deployment_domain


PACKAGE_KEY_NAME = "concordia_governance_receipt_v3"
CHAIN_NAME = "casper-test"


def deployment_domain_record(
    installation_nonce_hex: str,
    *,
    chain_name: str = CHAIN_NAME,
    package_key_name: str = PACKAGE_KEY_NAME,
) -> dict[str, Any]:
    try:
        nonce = bytes.fromhex(installation_nonce_hex)
    except ValueError as exc:
        raise ValueError("installation nonce must be lowercase hexadecimal") from exc
    if installation_nonce_hex != installation_nonce_hex.lower() or len(nonce) != 32:
        raise ValueError("installation nonce must be exactly 64 lowercase hex characters")
    domain = derive_deployment_domain(
        chain_name=chain_name,
        package_name=package_key_name,
        installation_nonce=nonce,
    )
    return {
        "schema_id": "concordia.v3-deployment-domain.v1",
        "casper_chain_name": chain_name,
        "package_key_name": package_key_name,
        "installation_nonce": installation_nonce_hex,
        "deployment_domain": domain.hex(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--installation-nonce", required=True)
    parser.add_argument("--chain-name", default=CHAIN_NAME)
    parser.add_argument("--package-key-name", default=PACKAGE_KEY_NAME)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                deployment_domain_record(
                    args.installation_nonce,
                    chain_name=args.chain_name,
                    package_key_name=args.package_key_name,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except ValueError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
