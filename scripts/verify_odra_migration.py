#!/usr/bin/env python3
"""Verify Concordia's Odra multi-contract migration package.

This is intentionally static and fast: it proves the repository contains the
four Odra contract domains, their expected entrypoints, the Odra build harness,
and the machine-readable migration manifest that judges can inspect without
running a Casper node.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ODRA_DIR = ROOT / "contracts" / "odra-governance-receipt"
LIB_RS = ODRA_DIR / "src" / "lib.rs"
MANIFEST = ODRA_DIR / "migration.manifest.json"
ODRA_TOML = ODRA_DIR / "Odra.toml"
CARGO_TOML = ODRA_DIR / "Cargo.toml"
BUILD_CONTRACT = ODRA_DIR / "bin" / "build_contract.rs"
BUILD_SCHEMA = ODRA_DIR / "bin" / "build_schema.rs"

EXPECTED_MODULES = {
    "CouncilRegistry": ["register_agent", "get_agent_key"],
    "CardIndexLedger": ["seal_card_root", "get_card_root"],
    "TreasuryPolicy": ["init", "validate_allocation", "current_caps"],
    "GovernanceReceipt": [
        "configure_quorum",
        "propose_envelope",
        "approve_envelope",
        "quorum_status",
        "store_governance_receipt",
        "get_receipt",
    ],
}


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def main() -> int:
    if not LIB_RS.exists():
        return fail(f"missing {LIB_RS}")
    if not MANIFEST.exists():
        return fail(f"missing {MANIFEST}")
    for required_file in (ODRA_TOML, CARGO_TOML, BUILD_CONTRACT, BUILD_SCHEMA):
        if not required_file.exists():
            return fail(f"missing Odra build harness file {required_file}")

    source = LIB_RS.read_text(encoding="utf-8")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    odra_toml = ODRA_TOML.read_text(encoding="utf-8")
    manifest_modules = [item["module"] for item in manifest.get("contracts", [])]

    for module, entrypoints in EXPECTED_MODULES.items():
        if not re.search(rf"pub struct\s+{module}\b", source):
            return fail(f"missing Odra module {module}")
        if module not in manifest_modules:
            return fail(f"manifest missing module {module}")
        if f"::{module}" not in odra_toml:
            return fail(f"Odra.toml missing module {module}")
        for entrypoint in entrypoints:
            if not re.search(rf"pub fn\s+{entrypoint}\b", source):
                return fail(f"missing {module}.{entrypoint}")

    required_typed_args = {
        "risk_score: u32",
        "approved_allocation_bps: u32",
        "sequence: u32",
        "requested_bps: u32",
        "high_risk: bool",
    }
    for needle in required_typed_args:
        if needle not in source:
            return fail(f"missing typed Odra argument {needle}")

    allowed_statuses = {
        "wasm_build_checked_migration_package",
        "live_governance_receipt_deployed_with_multi_contract_topology",
        "quorum_enabled_migration_package",
    }
    if manifest.get("status") not in allowed_statuses:
        return fail(f"manifest status must be one of {sorted(allowed_statuses)}")
    if manifest.get("deployment_order") != list(EXPECTED_MODULES):
        return fail("deployment_order must match CouncilRegistry -> CardIndexLedger -> TreasuryPolicy -> GovernanceReceipt")

    wasm_artifacts = []
    for item in manifest.get("wasm_build", {}).get("artifacts", []):
        path = ODRA_DIR / item["path"]
        if path.exists():
            wasm_artifacts.append({"path": item["path"], "sha256": item.get("sha256"), "present": True})

    print(
        json.dumps(
            {
                "status": "ok",
                "package": str(ODRA_DIR.relative_to(ROOT)),
                "modules": manifest_modules,
                "entrypoint_count": sum(len(v) for v in EXPECTED_MODULES.values()),
                "typed_governance_args": sorted(required_typed_args),
                "build_harness": [
                    str(ODRA_TOML.relative_to(ROOT)),
                    str(BUILD_CONTRACT.relative_to(ROOT)),
                    str(BUILD_SCHEMA.relative_to(ROOT)),
                ],
                "wasm_artifacts_present": wasm_artifacts,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
