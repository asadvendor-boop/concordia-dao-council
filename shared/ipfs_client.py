"""Optional IPFS evidence upload helpers for Concordia.

The live submission can publish public evidence through the hosted dashboard.
When a pinning token or local Kubo node is configured, the same evidence bundle
can also be pinned to IPFS and its CID stored in the audit packet.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

from shared.telemetry import span

CID_RE = re.compile(r"^(?:b[a-z2-7]{20,}|Qm[1-9A-HJ-NP-Za-km-z]{44})$")


def default_gateway_base() -> str:
    """Return the hosted Concordia gateway used for judge-facing IPFS links."""

    configured = os.getenv("IPFS_GATEWAY_BASE", "").strip()
    if configured:
        return configured.rstrip("/")
    public_base = os.getenv("CONCORDIA_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if not public_base:
        hostname = os.getenv("CONCORDIA_HOSTNAME", "concordiadao.xyz").strip().rstrip("/")
        public_base = hostname if hostname.startswith(("http://", "https://")) else f"https://{hostname}"
    return f"{public_base}/api/ipfs"


def ipfs_status() -> dict[str, Any]:
    pinata_jwt = os.getenv("PINATA_JWT", "").strip()
    pinata_key = os.getenv("PINATA_API_KEY", "").strip()
    kubo_api = os.getenv("IPFS_API_URL", "").strip().rstrip("/")
    provider = "not_configured"
    legacy_provider = ""
    if kubo_api:
        provider = "kubo"
    elif pinata_jwt or pinata_key:
        provider = "pinata"
    elif os.getenv("WEB3_STORAGE_TOKEN", "").strip():
        legacy_provider = "web3_storage"
    elif os.getenv("NFT_STORAGE_TOKEN", "").strip():
        legacy_provider = "nft_storage"
    return {
        "provider": provider,
        "configured": provider != "not_configured",
        "legacy_provider_token_present": legacy_provider or None,
        "legacy_provider_supported": False if legacy_provider else None,
        "gateway_base": default_gateway_base(),
        "api_url_configured": bool(kubo_api) if provider == "kubo" else None,
    }


async def upload_json_to_ipfs(payload: dict[str, Any], *, name: str) -> dict[str, Any]:
    status = ipfs_status()
    if not status["configured"]:
        if status.get("legacy_provider_token_present"):
            return {
                "status": "not_configured",
                "provider": status["legacy_provider_token_present"],
                "message": (
                    "Pinata is the supported live IPFS provider. The configured "
                    "legacy Web3.Storage/NFT.Storage token path is disabled "
                    "because current providers require updated auth flows."
                ),
            }
        return {
            "status": "not_configured",
            "message": "Set PINATA_JWT or PINATA_API_KEY/PINATA_API_SECRET to pin evidence to IPFS.",
        }

    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    provider = status["provider"]
    async with httpx.AsyncClient(timeout=45.0) as client:
        if provider == "kubo":
            api_url = os.getenv("IPFS_API_URL", "").strip().rstrip("/")
            files = {
                "file": (f"{name}.json", body, "application/json"),
            }
            with span("ipfs.add_json", provider=provider, object_name=name, bytes=len(body)):
                response = await client.post(
                    f"{api_url}/api/v0/add",
                    params={"pin": "true", "cid-version": "1"},
                    files=files,
                )
            response.raise_for_status()
            result = response.json()
            cid = result.get("Hash")
        elif provider == "pinata":
            headers: dict[str, str]
            jwt = os.getenv("PINATA_JWT", "").strip()
            if jwt:
                headers = {"Authorization": f"Bearer {jwt}"}
            else:
                headers = {
                    "pinata_api_key": os.getenv("PINATA_API_KEY", "").strip(),
                    "pinata_secret_api_key": os.getenv("PINATA_API_SECRET", "").strip(),
                }
            files = {
                "file": (f"{name}.json", body, "application/json"),
            }
            metadata = {"name": name, "keyvalues": {"app": "concordia-dao-council"}}
            with span("ipfs.pin_json", provider=provider, object_name=name, bytes=len(body)):
                response = await client.post(
                    "https://api.pinata.cloud/pinning/pinFileToIPFS",
                    headers=headers,
                    files=files,
                    data={"pinataMetadata": json.dumps(metadata)},
                )
            response.raise_for_status()
            result = response.json()
            cid = result.get("IpfsHash")
        else:
            return {
                "status": "failed",
                "provider": provider,
                "error": "Unsupported IPFS provider selected.",
            }

    if not cid:
        return {
            "status": "failed",
            "provider": provider,
            "error": "Provider response did not contain a CID.",
            "response": result,
        }
    gateway_url = f"{status['gateway_base']}/{cid}"
    return {
        "status": "uploaded",
        "provider": provider,
        "cid": cid,
        "ipfs_uri": f"ipfs://{cid}",
        "gateway_url": gateway_url,
        "response": result,
    }


async def fetch_ipfs_cid(cid: str) -> tuple[bytes, str]:
    """Fetch a pinned CID through the configured local Kubo API or gateway."""
    if not CID_RE.match(cid):
        raise ValueError("Invalid IPFS CID format")
    api_url = os.getenv("IPFS_API_URL", "").strip().rstrip("/")
    if api_url:
        async with httpx.AsyncClient(timeout=30.0) as client:
            with span("ipfs.cat", provider="kubo", cid=cid):
                response = await client.post(f"{api_url}/api/v0/cat", params={"arg": cid})
            response.raise_for_status()
            return response.content, response.headers.get("content-type", "application/json")
    gateway_base = default_gateway_base()
    async with httpx.AsyncClient(timeout=30.0) as client:
        with span("ipfs.gateway_get", cid=cid):
            response = await client.get(f"{gateway_base}/{cid}")
        response.raise_for_status()
        return response.content, response.headers.get("content-type", "application/json")
