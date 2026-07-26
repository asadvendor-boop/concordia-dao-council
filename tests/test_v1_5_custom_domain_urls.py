from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CURRENT_APEX = "https://concordiadao.xyz"
RETIRED_HOST = "concordia.47.84.232.193.sslip.io"
ACTIVE_URL_FILES = (
    ROOT / "shared" / "proof_runtime.py",
    ROOT / "shared" / "ipfs_client.py",
    ROOT / "scripts" / "generate_dynamic_proposal.py",
    ROOT / "scripts" / "planb_quorum_live_run.py",
    ROOT / "deploy" / "shared-host" / "concordia.env.example",
    ROOT / "deploy" / "shared-host" / "README.md",
)

URL_PROBE = """
import json

from scripts import generate_dynamic_proposal
from scripts import planb_quorum_live_run
from shared import proof_runtime
from shared.ipfs_client import default_gateway_base

proposal_id = "DAO-PROP-URL-TEST"
wallet_url = getattr(planb_quorum_live_run, "wallet_approval_url", lambda _: None)(proposal_id)
print(json.dumps({
    "proof_base": proof_runtime.PUBLIC_BASE_URL,
    "dashboard": proof_runtime.canonical_manifest()["public_urls"]["dashboard"],
    "generator_base": generate_dynamic_proposal.PUBLIC_BASE_URL,
    "wallet_approval": wallet_url,
    "ipfs_gateway": default_gateway_base(),
}))
"""


def _probe_urls(**overrides: str) -> dict[str, str | None]:
    env = os.environ.copy()
    for name in (
        "PUBLIC_BASE_URL",
        "IPFS_GATEWAY_BASE",
        "CONCORDIA_PUBLIC_BASE_URL",
        "CONCORDIA_HOSTNAME",
    ):
        env.pop(name, None)
    env.update(overrides)
    completed = subprocess.run(
        [sys.executable, "-c", URL_PROBE],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_generated_urls_default_to_current_apex() -> None:
    assert _probe_urls() == {
        "proof_base": CURRENT_APEX,
        "dashboard": f"{CURRENT_APEX}/dashboard",
        "generator_base": CURRENT_APEX,
        "wallet_approval": (
            f"{CURRENT_APEX}/dashboard/proof?proposal=DAO-PROP-URL-TEST&quorum_demo=1"
        ),
        "ipfs_gateway": f"{CURRENT_APEX}/api/ipfs",
    }


def test_generated_urls_share_configurable_normalized_base() -> None:
    custom_base = "https://preview.concordia.example/current/"
    expected_base = custom_base.rstrip("/")

    assert _probe_urls(PUBLIC_BASE_URL=custom_base) == {
        "proof_base": expected_base,
        "dashboard": f"{expected_base}/dashboard",
        "generator_base": expected_base,
        "wallet_approval": (
            f"{expected_base}/dashboard/proof?proposal=DAO-PROP-URL-TEST&quorum_demo=1"
        ),
        "ipfs_gateway": f"{expected_base}/api/ipfs",
    }


def test_public_base_url_precedence_preserves_legacy_configuration() -> None:
    assert _probe_urls(
        PUBLIC_BASE_URL="https://preferred.concordia.example/",
        CONCORDIA_PUBLIC_BASE_URL="https://legacy-base.concordia.example/",
        CONCORDIA_HOSTNAME="legacy-host.concordia.example",
    )["proof_base"] == "https://preferred.concordia.example"

    assert _probe_urls(
        CONCORDIA_PUBLIC_BASE_URL="https://legacy-base.concordia.example/",
        CONCORDIA_HOSTNAME="legacy-host.concordia.example",
    )["proof_base"] == "https://legacy-base.concordia.example"

    hostname_urls = _probe_urls(CONCORDIA_HOSTNAME="legacy-host.concordia.example/")
    assert hostname_urls["proof_base"] == "https://legacy-host.concordia.example"
    assert hostname_urls["ipfs_gateway"] == (
        "https://legacy-host.concordia.example/api/ipfs"
    )


def test_active_url_sources_do_not_reference_retired_sslip_host() -> None:
    residues = [
        path.relative_to(ROOT).as_posix()
        for path in ACTIVE_URL_FILES
        if RETIRED_HOST in path.read_text(encoding="utf-8")
    ]

    assert residues == []


def test_shared_host_examples_use_current_apex() -> None:
    env_example = (ROOT / "deploy" / "shared-host" / "concordia.env.example").read_text(
        encoding="utf-8"
    )
    runbook = (ROOT / "deploy" / "shared-host" / "README.md").read_text(
        encoding="utf-8"
    )

    assert "CONCORDIA_HOSTNAME=concordiadao.xyz" in env_example
    assert CURRENT_APEX in runbook
