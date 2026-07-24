"""Raw, bounded RPC evidence — recomputed, never transcribed (blocker 2).

A provider label plus a caller-supplied response digest proves nothing: the
digest could describe bytes nobody ever received.  Correction-round provider
evidence therefore embeds the BOUNDED raw JSON-RPC exchanges themselves
(``info_get_deploy``, ``chain_get_block``, ``info_get_status`` — normalized
by :mod:`shared.casper_rpc_transport`), and this module:

- recomputes ``request_sha256``/``response_sha256`` from the embedded bodies;
- independently re-derives the deploy hash, block identity, membership,
  execution result, and confirmation depth FROM the raw response bodies and
  refuses on any disagreement with the recorded observation fields;
- bounds every body (size cap) and scans it for secret material.

Every nested structure is validated BEFORE indexing (blocker 5): malformed
``block``/``execution``/provider/finality fields return stable refusal codes,
never ``KeyError`` tracebacks.
"""

from __future__ import annotations

import hashlib
import json
import re

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

RAW_EXCHANGE_METHODS = ("info_get_deploy", "chain_get_block", "info_get_status")
_EXCHANGE_FIELDS = {"request_body", "response_body"}
MAX_RAW_BODY_CHARS = 800_000
_DIGEST_SEPARATOR = b"\x00"

_VERSION_WRAPPERS = ("Version1", "Version2")


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def digest_of_bodies(bodies: list[str]) -> str:
    """Order-preserving digest over the exact embedded body strings."""

    digest = hashlib.sha256()
    for index, body in enumerate(bodies):
        if index:
            digest.update(_DIGEST_SEPARATOR)
        digest.update(body.encode("utf-8"))
    return digest.hexdigest()


def _parse_body(body: object, *, label: str) -> dict[str, object]:
    if not isinstance(body, str) or not body:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_ABSENT,
            f"{label}: raw body is absent; a digest without its bytes is a "
            "transcription, not evidence",
        )
    if len(body) > MAX_RAW_BODY_CHARS:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_OVERSIZED,
            f"{label}: raw body exceeds the {MAX_RAW_BODY_CHARS}-character "
            "bound",
        )
    refuse_if_secret_material(body, context=label)
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: raw body is not valid JSON",
        ) from exc
    if not isinstance(parsed, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: raw body must be a JSON-RPC object",
        )
    return parsed


def _result_of(parsed: dict[str, object], *, label: str) -> dict[str, object]:
    result = parsed.get("result")
    if not isinstance(result, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: raw response carries no result object",
        )
    return result


def _unwrap_versioned(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH, f"{label}: expected an object"
        )
    if len(value) == 1:
        (key,) = value
        if key in _VERSION_WRAPPERS:
            inner = value[key]
            if not isinstance(inner, dict):
                raise _refuse(
                    RefusalCode.RAW_EVIDENCE_MISMATCH,
                    f"{label}: versioned wrapper is not an object",
                )
            return inner
    return value


def _lower_hex64(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH, f"{label}: hash field malformed"
        )
    lowered = value.lower()
    if _HEX64.match(lowered) is None:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH, f"{label}: hash field malformed"
        )
    return lowered


def derive_execution_from_result(
    execution_result: object, *, label: str
) -> tuple[bool, str | None]:
    """(success, error_message) re-derived from a raw execution result."""

    record = _unwrap_versioned(execution_result, label=label)
    if "Success" in record and len(record) == 1:
        return True, None
    if "Failure" in record and len(record) == 1:
        failure = record["Failure"]
        message = failure.get("error_message") if isinstance(failure, dict) else None
        if message is not None and not isinstance(message, str):
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_MISMATCH,
                f"{label}: failure error_message malformed",
            )
        return False, message
    if "error_message" in record:
        message = record["error_message"]
        if message is None:
            return True, None
        if not isinstance(message, str):
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_MISMATCH,
                f"{label}: error_message malformed",
            )
        return False, message
    raise _refuse(
        RefusalCode.RAW_EVIDENCE_MISMATCH,
        f"{label}: execution result carries no recognizable outcome",
    )


def _derive_deploy_facts(
    parsed: dict[str, object], *, label: str
) -> dict[str, object]:
    result = _result_of(parsed, label=label)
    deploy = result.get("deploy")
    if not isinstance(deploy, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: deploy response carries no deploy object",
        )
    deploy_hash = _lower_hex64(deploy.get("hash"), label=f"{label}.deploy.hash")
    executions = result.get("execution_results")
    if not isinstance(executions, list) or not executions:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: deploy response carries no finalized execution results",
        )
    entry = executions[0]
    if not isinstance(entry, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: execution entry malformed",
        )
    block_hash = _lower_hex64(
        entry.get("block_hash"), label=f"{label}.execution.block_hash"
    )
    success, error_message = derive_execution_from_result(
        entry.get("result"), label=f"{label}.execution.result"
    )
    # SEC3: the target/entry-point/typed-args/transfer are DERIVED from the
    # raw deploy session when present, never copied from observation metadata.
    session = deploy.get("session") if isinstance(deploy.get("session"), dict) else None
    target: dict[str, object] | None = None
    if session is not None:
        target = _derive_target_from_session(session, label=f"{label}.session")
    return {
        "deploy_hash": deploy_hash,
        "block_hash": block_hash,
        "success": success,
        "error_message": error_message,
        "derived_target": target,
    }


def _derive_target_from_session(
    session: dict[str, object], *, label: str
) -> dict[str, object]:
    """Pull entry point, typed args, and any transfer from a raw session."""

    entry_point = session.get("entry_point")
    raw_args = session.get("args")
    typed_args: dict[str, object] = {}
    if isinstance(raw_args, list):
        for pair in raw_args:
            # Casper args serialize as [name, {cl_type, parsed, ...}].
            if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str):
                clvalue = pair[1]
                parsed = (
                    clvalue.get("parsed") if isinstance(clvalue, dict) else None
                )
                typed_args[pair[0]] = parsed
    transfer = session.get("transfer")
    return {
        "entry_point": entry_point,
        "typed_args": typed_args,
        "transfer": transfer if isinstance(transfer, dict) else None,
    }


def _derive_block_facts(
    parsed: dict[str, object], *, label: str
) -> dict[str, object]:
    result = _result_of(parsed, label=label)
    proofs_present = False
    container = result.get("block_with_signatures")
    if isinstance(container, dict):
        block_value = container.get("block")
        proofs = container.get("proofs")
        proofs_present = isinstance(proofs, list) and len(proofs) > 0
    else:
        block_value = result.get("block")
        if isinstance(block_value, dict):
            proofs = block_value.get("proofs")
            proofs_present = isinstance(proofs, list) and len(proofs) > 0
    if block_value is None:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: block response carries no block",
        )
    block = _unwrap_versioned(block_value, label=f"{label}.block")
    block_hash = _lower_hex64(block.get("hash"), label=f"{label}.block.hash")
    header = block.get("header")
    if not isinstance(header, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: block header malformed",
        )
    height = header.get("height")
    era_id = header.get("era_id")
    if not isinstance(height, int) or height < 0 or not isinstance(era_id, int):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: block height/era malformed",
        )
    state_root = _lower_hex64(
        header.get("state_root_hash"), label=f"{label}.block.state_root_hash"
    )
    member_hashes: set[str] = set()
    body = block.get("body")
    if isinstance(body, dict):
        for field in ("deploy_hashes", "transfer_hashes"):
            hashes = body.get(field)
            if isinstance(hashes, list):
                for item in hashes:
                    if isinstance(item, str):
                        member_hashes.add(item.lower())
        transactions = body.get("transactions")
        if isinstance(transactions, dict):
            for group in transactions.values():
                if isinstance(group, list):
                    for item in group:
                        if isinstance(item, dict):
                            candidate = item.get("hash") or item.get("Deploy")
                            if isinstance(candidate, str):
                                member_hashes.add(candidate.lower())
                        elif isinstance(item, str):
                            member_hashes.add(item.lower())
    return {
        "block_hash": block_hash,
        "block_height": height,
        "era_id": era_id,
        "state_root_hash": state_root,
        "proofs_present": proofs_present,
        "member_hashes": member_hashes,
    }


def _derive_status_facts(
    parsed: dict[str, object], *, label: str
) -> dict[str, object]:
    result = _result_of(parsed, label=label)
    chainspec = result.get("chainspec_name")
    api_version = result.get("api_version")
    tip_info = result.get("last_added_block_info")
    if not isinstance(tip_info, dict):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: status response carries no last-added block info",
        )
    tip_height = tip_info.get("height")
    if (
        not isinstance(chainspec, str)
        or not chainspec
        or not isinstance(api_version, str)
        or not api_version
        or not isinstance(tip_height, int)
        or tip_height < 0
    ):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: status fields malformed",
        )
    return {
        "chainspec_name": chainspec,
        "api_version": api_version,
        "chain_tip_height": tip_height,
    }


def validate_raw_exchanges(provider: dict[str, object], *, label: str) -> dict[str, object]:
    """Structural validation of the embedded exchanges; returns parsed bodies."""

    exchanges = provider.get("raw_exchanges")
    if not isinstance(exchanges, dict) or set(exchanges) != set(
        RAW_EXCHANGE_METHODS
    ):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_ABSENT,
            f"{label}: provider evidence must embed exactly the raw "
            f"{list(RAW_EXCHANGE_METHODS)} exchanges; labels and digests "
            "without raw bodies are insufficient",
        )
    request_bodies: list[str] = []
    response_bodies: list[str] = []
    parsed: dict[str, dict[str, object]] = {}
    for method in RAW_EXCHANGE_METHODS:
        exchange = exchanges[method]
        if not isinstance(exchange, dict) or set(exchange) != _EXCHANGE_FIELDS:
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_ABSENT,
                f"{label}.{method}: exchange must contain exactly "
                f"{sorted(_EXCHANGE_FIELDS)}",
            )
        request_body = exchange["request_body"]
        if not isinstance(request_body, str) or not request_body:
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_ABSENT,
                f"{label}.{method}: raw request body is absent",
            )
        if len(request_body) > MAX_RAW_BODY_CHARS:
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_OVERSIZED,
                f"{label}.{method}: raw request body exceeds the bound",
            )
        refuse_if_secret_material(request_body, context=f"{label}.{method}")
        request_parsed = _parse_body(request_body, label=f"{label}.{method}.request")
        if request_parsed.get("method") != method:
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_MISMATCH,
                f"{label}.{method}: raw request names a different method",
            )
        parsed[method] = _parse_body(
            exchange["response_body"], label=f"{label}.{method}.response"
        )
        request_bodies.append(request_body)
        response_bodies.append(str(exchange["response_body"]))

    if provider.get("request_sha256") != digest_of_bodies(request_bodies):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: request_sha256 does not recompute from the embedded "
            "raw request bodies",
        )
    if provider.get("response_sha256") != digest_of_bodies(response_bodies):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: response_sha256 does not recompute from the embedded "
            "raw response bodies",
        )
    return parsed


def require_rederived_agreement(
    provider: dict[str, object],
    *,
    label: str,
    expected_chain_name: str,
    deploy_hash: str,
    block_hash: str,
    block_height: int,
    execution_success: object,
    execution_error_message: object,
    era_id: int | None = None,
    state_root_hash: str | None = None,
    require_proofs: bool = False,
    require_membership: bool = False,
    observed_target: dict[str, object] | None = None,
) -> None:
    """Re-derive every recorded binding from the raw bodies; refuse drift.

    The recorded observation fields are treated as CLAIMS; the embedded raw
    responses are the evidence.  Any disagreement between claim and evidence
    refuses with ``RAW_EVIDENCE_MISMATCH``.
    """

    parsed = validate_raw_exchanges(provider, label=label)
    deploy_facts = _derive_deploy_facts(
        parsed["info_get_deploy"], label=f"{label}.info_get_deploy"
    )
    # SEC3: when the raw deploy carries a session, the observation's target
    # metadata (entry point, typed args, transfer) must equal the values
    # DERIVED from that raw session — a metadata target that disagrees with
    # the on-chain deploy is refused rather than trusted.
    derived_target = deploy_facts.get("derived_target")
    if derived_target is not None and observed_target is not None:
        for field in ("entry_point", "typed_args", "transfer"):
            if observed_target.get(field) != derived_target.get(field):
                raise _refuse(
                    RefusalCode.RAW_EVIDENCE_MISMATCH,
                    f"{label}: observation target.{field} does not equal the "
                    "value derived from the raw deploy session",
                )
    block_facts = _derive_block_facts(
        parsed["chain_get_block"], label=f"{label}.chain_get_block"
    )
    status_facts = _derive_status_facts(
        parsed["info_get_status"], label=f"{label}.info_get_status"
    )

    if deploy_facts["deploy_hash"] != deploy_hash:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded deploy hash does not re-derive from the raw "
            "deploy response",
        )
    if (
        deploy_facts["block_hash"] != block_hash
        or block_facts["block_hash"] != block_hash
    ):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded block hash does not re-derive from the raw "
            "responses",
        )
    if block_facts["block_height"] != block_height:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded block height does not re-derive from the raw "
            "block response",
        )
    if (
        deploy_facts["success"] != execution_success
        or deploy_facts["error_message"] != execution_error_message
    ):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded execution result does not re-derive from the "
            "raw deploy response",
        )
    if era_id is not None and block_facts["era_id"] != era_id:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded era does not re-derive from the raw block "
            "response",
        )
    if (
        state_root_hash is not None
        and block_facts["state_root_hash"] != state_root_hash
    ):
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded state root does not re-derive from the raw "
            "block response",
        )
    if require_proofs and not block_facts["proofs_present"]:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: raw block response carries no finality proofs",
        )
    if require_membership and deploy_hash not in block_facts["member_hashes"]:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: deploy is not a member of the raw block body",
        )
    if status_facts["chainspec_name"] != expected_chain_name:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH,
            f"{label}: raw status response reports chainspec "
            f"{status_facts['chainspec_name']!r}, not "
            f"{expected_chain_name!r}",
        )
    if provider.get("chainspec_name") != status_facts["chainspec_name"]:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded chainspec does not re-derive from the raw "
            "status response",
        )
    if provider.get("api_version") != status_facts["api_version"]:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded api_version does not re-derive from the raw "
            "status response",
        )
    if provider.get("chain_tip_height") != status_facts["chain_tip_height"]:
        raise _refuse(
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            f"{label}: recorded chain tip does not re-derive from the raw "
            "status response",
        )
