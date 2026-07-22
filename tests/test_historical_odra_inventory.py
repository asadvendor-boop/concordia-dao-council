from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "handoff" / "HISTORICAL_ODRA_RECEIPTS_V1.json"
SOURCE_MANIFEST = ROOT / "handoff" / "HISTORICAL_ODRA_SHA256.txt"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
GIT40 = re.compile(r"^[0-9a-f]{40}$")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def _load() -> dict[str, object]:
    value = json.loads(INVENTORY.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    assert isinstance(value, dict)
    return value


def test_historical_odra_inventory_separates_chain_identity_from_source_preservation() -> None:
    inventory = _load()

    assert set(inventory) == {
        "schema_version",
        "network",
        "chain_identity",
        "preserved_repo_source",
    }
    assert inventory["schema_version"] == "concordia.historical_odra_inventory.v1"
    assert inventory["network"] == "casper-test"
    preserved = inventory["preserved_repo_source"]
    assert preserved["source_deployment_equivalence"] == "unproven"
    assert preserved["manifest_path"] == "handoff/HISTORICAL_ODRA_SHA256.txt"
    assert GIT40.fullmatch(preserved["baseline_commit"])
    assert HEX32.fullmatch(preserved["manifest_sha256"])
    assert hashlib.sha256(SOURCE_MANIFEST.read_bytes()).hexdigest() == preserved["manifest_sha256"]
    assert preserved["governance_receipt_wasm_path"] == (
        "contracts/odra-governance-receipt/wasm/GovernanceReceipt.wasm"
    )
    wasm = ROOT / preserved["governance_receipt_wasm_path"]
    assert hashlib.sha256(wasm.read_bytes()).hexdigest() == preserved["governance_receipt_wasm_sha256"]


def test_historical_odra_inventory_pins_exact_v1_and_v2_chain_identities() -> None:
    chain_identity = _load()["chain_identity"]

    assert set(chain_identity) == {"v1", "v2"}
    expected = {
        "v1": {
            "package_hash": "992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a",
            "contract_hash": "a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1",
            "contract_wasm_state_hash": "242f2621c5f1d276da98a9019626e811518a2955798bbd5849c7a2461fbfface",
            "install_deploy_hash": "d319157b2638ed8fa7c1dfc639be16e1455530cd568c3cde35bb40c1bd20ba32",
            "receipt_deploys": {
                "canonical_accepted": "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852"
            },
        },
        "v2": {
            "package_hash": "1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96",
            "contract_hash": "fda5618813b629d2a69f71e1d2dfc497b16ab8a09713dcd6c47ac8eb7e0c735f",
            "contract_wasm_state_hash": "42848a133bee46d6c704bb9bcff88156bc363473e06641ae41c0661077338ec4",
            "install_deploy_hash": "6282b437c4d79de98537cf593ddbbd79f6d95fbf2a79b7a96c35d81f76ecdc6a",
            "receipt_deploys": {
                "pre_quorum_expected_rejection": "6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431",
                "post_quorum_accepted": "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928",
            },
        },
    }
    for generation, identity in chain_identity.items():
        assert set(identity) == {
            "package_hash",
            "contract_hash",
            "contract_wasm_state_hash",
            "contract_version",
            "protocol_version_major",
            "install_deploy_hash",
            "install_block_height",
            "entry_point",
            "receipt_deploys",
        }
        assert identity["contract_version"] == 1
        assert identity["protocol_version_major"] == 2
        assert identity["entry_point"] == "store_governance_receipt"
        assert identity["install_block_height"] > 0
        for field in (
            "package_hash",
            "contract_hash",
            "contract_wasm_state_hash",
            "install_deploy_hash",
        ):
            assert HEX32.fullmatch(identity[field])
        assert identity["package_hash"] == expected[generation]["package_hash"]
        assert identity["contract_hash"] == expected[generation]["contract_hash"]
        assert identity["contract_wasm_state_hash"] == expected[generation]["contract_wasm_state_hash"]
        assert identity["install_deploy_hash"] == expected[generation]["install_deploy_hash"]
        assert identity["receipt_deploys"] == expected[generation]["receipt_deploys"]


def test_preserved_source_manifest_still_matches_every_historical_file() -> None:
    for line in SOURCE_MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        expected_sha256, relative_path = line.split("  ", 1)
        path = ROOT / relative_path
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256
