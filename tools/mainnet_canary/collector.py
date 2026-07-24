"""Live, read-only dual-node observation collector (blocker 2).

The collector is the sanctioned producer of v3 step observations and of
Testnet harness receipt observations: it performs the bounded, credential-
free read calls (``info_get_deploy``, ``chain_get_block``,
``info_get_status``) against TWO caller-pinned, disjoint RPC endpoints
through an injected transport, embeds the exact canonical request/response
bodies as raw evidence, computes every digest itself, and DERIVES the
recorded observation fields from those bodies — so the observation is
consistent with its own raw evidence by construction, and any later editor
trips ``RAW_EVIDENCE_MISMATCH``.

Secret safety: every emitted body is scanned by the secret guard before the
observation is returned; the transport itself is the repo's pinned
credential-redacting client when run live (tests inject fakes).  Nothing
here signs, submits, or mutates anything.
"""

from __future__ import annotations

import json
from typing import Callable

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.finality_v2 import OBSERVATION_V3_SCHEMA_ID
from tools.mainnet_canary.raw_evidence import (
    RAW_EXCHANGE_METHODS,
    digest_of_bodies,
    derive_execution_from_result,
    _derive_block_facts,
    _derive_deploy_facts,
    _derive_status_facts,
)
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

# One read call: (method, params) -> normalized JSON-RPC response dict.
ReadCall = Callable[[str, dict[str, object]], dict[str, object]]


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def _canonical(document: dict[str, object]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _perform_exchanges(
    call: ReadCall, *, deploy_hash: str, block_hash_hint: str | None
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, object]]]:
    exchanges: dict[str, dict[str, str]] = {}
    parsed: dict[str, dict[str, object]] = {}
    deploy_response = None
    for method in RAW_EXCHANGE_METHODS:
        if method == "info_get_deploy":
            params: dict[str, object] = {"deploy_hash": deploy_hash}
        elif method == "chain_get_block":
            block_hash = block_hash_hint
            if block_hash is None and deploy_response is not None:
                executions = deploy_response.get("result", {}).get(
                    "execution_results"
                )
                if isinstance(executions, list) and executions:
                    entry = executions[0]
                    if isinstance(entry, dict) and isinstance(
                        entry.get("block_hash"), str
                    ):
                        block_hash = entry["block_hash"]
            if block_hash is None:
                raise _refuse(
                    RefusalCode.RAW_EVIDENCE_ABSENT,
                    "no finalized block hash is derivable for the block "
                    "lookup; the deploy may not be executed yet",
                )
            params = {"block_identifier": {"Hash": block_hash}}
        else:
            params = {}
        request = {
            "jsonrpc": "2.0",
            "id": f"canary-{method}",
            "method": method,
            "params": params,
        }
        try:
            response = call(method, params)
        except CanaryRefusal:
            raise
        except Exception:
            raise _refuse(
                RefusalCode.SUBMISSION_TRANSPORT_INVALID,
                f"read call {method} failed; the observation cannot be "
                "collected",
            ) from None
        if not isinstance(response, dict):
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_MISMATCH,
                f"{method}: transport returned a non-object response",
            )
        request_body = _canonical(request)
        response_body = _canonical(response)
        refuse_if_secret_material(request_body, context=f"collector.{method}")
        refuse_if_secret_material(response_body, context=f"collector.{method}")
        exchanges[method] = {
            "request_body": request_body,
            "response_body": response_body,
        }
        parsed[method] = response
        if method == "info_get_deploy":
            deploy_response = response
    return exchanges, parsed


def collect_provider_observation(
    call: ReadCall,
    *,
    provider_id: str,
    endpoint_host: str,
    step_id: str,
    deploy_hash: str,
    retrieved_at_unix: int,
    target: dict[str, object],
    state_readback: object,
    block_hash_hint: str | None = None,
) -> dict[str, object]:
    """One provider's v3 observation, derived from its own raw exchanges."""

    if not provider_id or not endpoint_host:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "provider identity must be pinned before collection",
        )
    exchanges, parsed = _perform_exchanges(
        call, deploy_hash=deploy_hash, block_hash_hint=block_hash_hint
    )
    deploy_facts = _derive_deploy_facts(
        parsed["info_get_deploy"], label=f"collector[{provider_id}].deploy"
    )
    block_facts = _derive_block_facts(
        parsed["chain_get_block"], label=f"collector[{provider_id}].block"
    )
    status_facts = _derive_status_facts(
        parsed["info_get_status"], label=f"collector[{provider_id}].status"
    )
    if deploy_facts["deploy_hash"] != deploy_hash.lower():
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            "provider returned evidence for a different deploy hash",
        )
    request_bodies = [
        exchanges[method]["request_body"] for method in RAW_EXCHANGE_METHODS
    ]
    response_bodies = [
        exchanges[method]["response_body"] for method in RAW_EXCHANGE_METHODS
    ]
    provider_evidence = {
        "provider_id": provider_id,
        "endpoint_host": endpoint_host,
        "method": "info_get_deploy",
        "request_sha256": digest_of_bodies(request_bodies),
        "response_sha256": digest_of_bodies(response_bodies),
        "retrieved_at_unix": retrieved_at_unix,
        "api_version": status_facts["api_version"],
        "chainspec_name": status_facts["chainspec_name"],
        "chain_tip_height": status_facts["chain_tip_height"],
        "raw_exchanges": exchanges,
    }
    return {
        "schema_id": OBSERVATION_V3_SCHEMA_ID,
        "step_id": step_id,
        "deploy_hash": deploy_facts["deploy_hash"],
        "chain_name_observed": status_facts["chainspec_name"],
        "block": {
            "status": "finalized",
            "block_hash": block_facts["block_hash"],
            "block_height": block_facts["block_height"],
            "state_root_hash": block_facts["state_root_hash"],
            "era_id": block_facts["era_id"],
            "block_proofs_present": bool(block_facts["proofs_present"]),
            "deploy_is_member": deploy_facts["deploy_hash"]
            in block_facts["member_hashes"],
        },
        "execution": {
            "success": deploy_facts["success"],
            "error_message": deploy_facts["error_message"],
            "cost_motes": None,
        },
        "target": target,
        "provider": provider_evidence,
        "state_readback": state_readback,
    }


def collect_dual_observations(
    calls: dict[str, ReadCall],
    *,
    hosts: dict[str, str],
    step_id: str,
    deploy_hash: str,
    retrieved_at_unix: int,
    target: dict[str, object],
    state_readback: object,
) -> list[dict[str, object]]:
    """Two disjoint providers' observations for one step, or refuse."""

    if len(calls) != 2 or set(calls) != set(hosts):
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "exactly two pinned providers are required for collection",
        )
    if len(set(hosts.values())) != 2:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "the two pinned providers do not resolve to disjoint hosts",
        )
    # SEC4: two labels wrapped around ONE callable/source are not two
    # providers.  If both provider ids map to the same underlying callable
    # object (identity), the "disjoint" evidence is a single source in
    # disguise and is refused.
    call_objects = list(calls.values())
    if call_objects[0] is call_objects[1]:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "the two provider labels wrap the same callable; a single source "
            "behind two names is not disjoint evidence",
        )
    bound_source = getattr(call_objects[0], "__self__", None)
    if bound_source is not None and bound_source is getattr(
        call_objects[1], "__self__", None
    ):
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "the two provider callables are bound to the same transport "
            "instance; that is one source, not two",
        )
    observations = []
    for provider_id in sorted(calls):
        observations.append(
            collect_provider_observation(
                calls[provider_id],
                provider_id=provider_id,
                endpoint_host=hosts[provider_id],
                step_id=step_id,
                deploy_hash=deploy_hash,
                retrieved_at_unix=retrieved_at_unix,
                target=target,
                state_readback=state_readback,
            )
        )
    return observations


class PinnedRpcReadTransport:
    """A read-only provider that OWNS a validated PinnedHttpsJsonRpc (SEC4).

    The collector never receives a bare lambda for the live lane: it binds a
    `shared.casper_rpc_transport.PinnedHttpsJsonRpc` validated over exactly
    one canonical endpoint, records that endpoint's resolved network identity
    (pinned IP + chainspec), and exposes a `read` callable whose identity is
    the transport instance — so two labels wrapping the same transport are
    caught by the disjointness guard above.
    """

    def __init__(self, endpoint: str, *, resolver: object | None = None):
        from shared.casper_rpc_transport import (
            PinnedHttpsJsonRpc,
            validate_public_rpc_endpoints,
        )

        validated = validate_public_rpc_endpoints(
            [endpoint], resolver=resolver
        )
        self.endpoint = validated[0].url
        self.pinned_ip = validated[0].pinned_ip
        self._rpc = PinnedHttpsJsonRpc([endpoint], resolver=resolver)

    def read(self, method: str, params: dict[str, object]) -> dict[str, object]:
        # Reads only; the underlying transport refuses the write method
        # unless explicit submit authority is passed (never here).
        return self._rpc.call(
            self.endpoint, method, params, f"canary-collect-{method}"
        )


def bind_dual_read_calls(
    transports: list[PinnedRpcReadTransport],
) -> tuple[dict[str, ReadCall], dict[str, str]]:
    """Build the (calls, hosts) maps from two owned, distinct transports."""

    if len(transports) != 2:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "exactly two owned read transports are required",
        )
    if transports[0] is transports[1] or (
        transports[0].endpoint == transports[1].endpoint
    ):
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "the two read transports must be distinct instances on distinct "
            "canonical endpoints",
        )
    if transports[0].pinned_ip == transports[1].pinned_ip:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "the two read transports resolve to the same pinned network "
            "identity; that is one source",
        )
    calls: dict[str, ReadCall] = {}
    hosts: dict[str, str] = {}
    for index, transport in enumerate(transports):
        provider_id = f"provider-{index}"
        calls[provider_id] = transport.read
        hosts[provider_id] = transport.endpoint
    return calls, hosts


__all__ = [
    "ReadCall",
    "PinnedRpcReadTransport",
    "bind_dual_read_calls",
    "collect_dual_observations",
    "collect_provider_observation",
    "derive_execution_from_result",
]
