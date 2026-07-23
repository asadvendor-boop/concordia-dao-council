#!/usr/bin/env python3
"""Build the only release-approved, permanently non-upgradable v3 install."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from pycspr import crypto, serializer
from pycspr.factory.accounts import parse_private_key
from pycspr.factory.deploys import (
    create_deploy,
    create_deploy_parameters,
    create_standard_payment,
)
from pycspr.factory.digests import create_digest_of_deploy, create_digest_of_deploy_body
from pycspr.types.cl import CLV_Bool, CLV_ByteArray, CLV_String, CLV_U512, CLV_U8
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import Deploy, DeployOfModuleBytes

from scripts.derive_deployment_domain_v3 import deployment_domain_record
from shared.casper_rpc_transport import (
    PinnedHttpsJsonRpc,
    RpcEndpointPolicyError,
    RpcRemoteError,
    RpcTransportError,
    parse_rpc_authorization_file_args,
    validate_public_rpc_endpoints as _validate_shared_rpc_endpoints,
)


PACKAGE_KEY_NAME = "concordia_governance_receipt_v3"
CHAIN_NAME = "casper-test"
ROOT = Path(__file__).resolve().parents[1]
RELEASE_IDENTITY_PATHS = (
    "contracts/odra-governance-receipt-v3/src/lib.rs",
    "contracts/odra-governance-receipt-v3/src/encoding.rs",
    "contracts/odra-governance-receipt-v3/Cargo.lock",
    "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm",
    "contracts/odra-governance-receipt-v3/resources/casper_contract_schemas/governance_receiptv3_schema.json",
    "contracts/odra-governance-receipt-v3/deployment.manifest.json",
)


class InstallValidationError(ValueError):
    pass


JOURNAL_SCHEMA_ID = "concordia.wp10-deploy-journal.v1"
JOURNAL_STATES = {
    "prepared",
    "broadcast_inflight",
    "submitted",
    "broadcast_ambiguous",
    "terminal_rejected",
    "finalized",
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sealed_journal(value: Mapping[str, Any]) -> dict[str, Any]:
    sealed = dict(value)
    sealed.pop("journal_sha256", None)
    sealed["journal_sha256"] = hashlib.sha256(_canonical_json(sealed)).hexdigest()
    return sealed


class DurableDeployJournal:
    """Crash-durable exact-deploy state used before every WP10 network write."""

    def __init__(self, path: Path, value: Mapping[str, Any]):
        self.path = path
        self._value = self._validate(value)

    @property
    def state(self) -> str:
        return str(self._value["state"])

    @property
    def deploy_hash(self) -> str:
        return str(self._value["deploy_hash"])

    @property
    def signed_deploy(self) -> dict[str, Any]:
        return dict(self._value["signed_deploy"])

    @property
    def intent(self) -> dict[str, Any]:
        return dict(self._value["intent"])

    @property
    def evidence(self) -> object:
        return self._value["evidence"]

    @staticmethod
    def _validate(value: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "schema_id",
            "state",
            "intent",
            "signed_deploy",
            "signed_deploy_json_bytes_hex",
            "signed_deploy_sha256",
            "signed_deploy_casper_bytes_hex",
            "signed_deploy_casper_sha256",
            "deploy_hash",
            "evidence",
            "last_detail_code",
            "revision",
            "journal_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise InstallValidationError("deploy journal field set is invalid")
        if (
            value["schema_id"] != JOURNAL_SCHEMA_ID
            or value["state"] not in JOURNAL_STATES
        ):
            raise InstallValidationError("deploy journal schema/state is invalid")
        if not isinstance(value["intent"], Mapping) or not isinstance(
            value["signed_deploy"], Mapping
        ):
            raise InstallValidationError("deploy journal intent/deploy is invalid")
        deploy_hash = _strip_hash(value["deploy_hash"], "journal deploy hash")
        if str(value["signed_deploy"].get("hash", "")).lower() != deploy_hash:
            raise InstallValidationError("deploy journal signed deploy hash mismatch")
        canonical = _canonical_json(value["signed_deploy"])
        try:
            persisted = bytes.fromhex(str(value["signed_deploy_json_bytes_hex"]))
        except ValueError as exc:
            raise InstallValidationError(
                "deploy journal signed bytes are invalid"
            ) from exc
        if (
            persisted != canonical
            or hashlib.sha256(canonical).hexdigest() != value["signed_deploy_sha256"]
        ):
            raise InstallValidationError("deploy journal signed bytes digest mismatch")
        try:
            parsed_deploy = serializer.from_json(dict(value["signed_deploy"]), Deploy)
            canonical_deploy = serializer.to_json(parsed_deploy)
            casper_bytes = serializer.to_bytes(parsed_deploy)
            body_hash = create_digest_of_deploy_body(
                parsed_deploy.payment, parsed_deploy.session
            )
            recomputed_hash = create_digest_of_deploy(parsed_deploy.header)
        except Exception as exc:
            raise InstallValidationError(
                "deploy journal is not canonical Casper deploy data"
            ) from exc
        if _normalize_deploy_json(canonical_deploy) != _normalize_deploy_json(
            value["signed_deploy"]
        ):
            raise InstallValidationError(
                "deploy journal is not canonical Casper deploy data"
            )
        if (
            parsed_deploy.header.body_hash != body_hash
            or parsed_deploy.hash != recomputed_hash
            or recomputed_hash.hex() != deploy_hash
            or parsed_deploy.header.chain_name != CHAIN_NAME
            or len(parsed_deploy.approvals) != 1
        ):
            raise InstallValidationError(
                "deploy journal is not canonical Casper deploy data"
            )
        approval = parsed_deploy.approvals[0]
        signer = getattr(approval.signer, "account_key", None)
        if (
            not isinstance(signer, bytes)
            or signer != parsed_deploy.header.account.account_key
            or not crypto.verify_deploy_approval_signature(
                recomputed_hash, approval.signature, signer
            )
        ):
            raise InstallValidationError(
                "deploy journal is not canonical Casper deploy data"
            )
        try:
            persisted_casper = bytes.fromhex(
                str(value["signed_deploy_casper_bytes_hex"])
            )
        except ValueError as exc:
            raise InstallValidationError(
                "deploy journal canonical Casper bytes are invalid"
            ) from exc
        if (
            persisted_casper != casper_bytes
            or hashlib.sha256(casper_bytes).hexdigest()
            != value["signed_deploy_casper_sha256"]
        ):
            raise InstallValidationError(
                "deploy journal canonical Casper bytes digest mismatch"
            )
        if value["intent"].get("kind") == "v3_install":
            manifest = value["intent"].get("manifest")
            if not isinstance(manifest, Mapping):
                raise InstallValidationError(
                    "install journal immutable intent is invalid"
                )
            try:
                validate_finalized_install_deploy(value["signed_deploy"], manifest)
            except InstallValidationError as exc:
                raise InstallValidationError(
                    "install journal deploy differs from immutable intent"
                ) from exc
        if type(value["revision"]) is not int or value["revision"] < 0:
            raise InstallValidationError("deploy journal revision is invalid")
        sealed = _sealed_journal(value)
        if not hmac.compare_digest(
            str(value["journal_sha256"]), sealed["journal_sha256"]
        ):
            raise InstallValidationError("deploy journal checksum mismatch")
        return dict(value)

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        intent: Mapping[str, Any],
        signed_deploy: Mapping[str, Any],
        deploy_hash: str,
    ) -> "DurableDeployJournal":
        path.parent.mkdir(parents=True, exist_ok=True)
        canonical = _canonical_json(signed_deploy)
        try:
            casper_deploy = serializer.from_json(dict(signed_deploy), Deploy)
            casper_bytes = serializer.to_bytes(casper_deploy)
        except Exception as exc:
            raise InstallValidationError(
                "signed deploy is not canonical Casper deploy data"
            ) from exc
        value = _sealed_journal(
            {
                "schema_id": JOURNAL_SCHEMA_ID,
                "state": "prepared",
                "intent": dict(intent),
                "signed_deploy": dict(signed_deploy),
                "signed_deploy_json_bytes_hex": canonical.hex(),
                "signed_deploy_sha256": hashlib.sha256(canonical).hexdigest(),
                "signed_deploy_casper_bytes_hex": casper_bytes.hex(),
                "signed_deploy_casper_sha256": hashlib.sha256(casper_bytes).hexdigest(),
                "deploy_hash": _strip_hash(deploy_hash, "journal deploy hash"),
                "evidence": None,
                "last_detail_code": None,
                "revision": 0,
            }
        )
        rendered = json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise InstallValidationError(
                "deploy journal already exists; resume it"
            ) from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(path.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                path.unlink()
            raise
        return cls(path, value)

    @classmethod
    def open(cls, path: Path) -> "DurableDeployJournal":
        try:
            value = json.loads(path.read_text(encoding="ascii"))
        except (OSError, ValueError) as exc:
            raise InstallValidationError("deploy journal cannot be loaded") from exc
        return cls(path, value)

    @contextlib.contextmanager
    def locked(self):
        lock_path = self.path.with_name(self.path.name + ".lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            current = self.open(self.path)
            self._value = current._value
            yield self
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def transition(
        self,
        expected_state: str,
        state: str,
        *,
        evidence: object = None,
        detail_code: str | None = None,
    ) -> "DurableDeployJournal":
        if self.state != expected_state:
            raise InstallValidationError(
                f"journal transition expected {expected_state}, found {self.state}"
            )
        if state not in JOURNAL_STATES:
            raise InstallValidationError("journal target state is invalid")
        updated = dict(self._value)
        updated.update(
            {
                "state": state,
                "evidence": evidence,
                "last_detail_code": detail_code,
                "revision": int(updated["revision"]) + 1,
            }
        )
        updated = _sealed_journal(updated)
        rendered = json.dumps(updated, indent=2, sort_keys=True).encode("ascii") + b"\n"
        descriptor, name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            _fsync_directory(self.path.parent)
        finally:
            with contextlib.suppress(OSError):
                temporary.unlink()
        self._value = self._validate(updated)
        return self


def execute_journaled_submission(
    journal: DurableDeployJournal,
    *,
    broadcast: Any,
    reconcile: Any,
) -> DurableDeployJournal:
    """Advance one exact deploy without rebuilding or ambiguous rebroadcast."""

    with journal.locked():
        if journal.state in {"finalized", "terminal_rejected"}:
            return journal
        if journal.state == "broadcast_inflight":
            journal.transition(
                "broadcast_inflight",
                "broadcast_ambiguous",
                detail_code="recovered_inflight_after_restart",
            )
        if journal.state == "prepared":
            journal.transition(
                "prepared", "broadcast_inflight", detail_code="broadcast_inflight"
            )
            try:
                result = broadcast(journal.signed_deploy, journal.deploy_hash)
            except Exception:
                journal.transition(
                    "broadcast_inflight",
                    "broadcast_ambiguous",
                    detail_code="broadcast_result_unknown",
                )
                result = None
            if result is None:
                pass
            elif not isinstance(result, Mapping) or result.get("deploy_hash") not in {
                None,
                journal.deploy_hash,
            }:
                journal.transition(
                    "broadcast_inflight",
                    "broadcast_ambiguous",
                    detail_code="broadcast_response_unverified",
                )
            elif result.get("status") == "terminal_rejected":
                return journal.transition(
                    "broadcast_inflight",
                    "terminal_rejected",
                    evidence=dict(result),
                    detail_code="broadcast_terminal_rejected",
                )
            elif result.get("status") == "submitted":
                journal.transition(
                    "broadcast_inflight",
                    "submitted",
                    evidence=dict(result),
                    detail_code="broadcast_submitted",
                )
            else:
                journal.transition(
                    "broadcast_inflight",
                    "broadcast_ambiguous",
                    evidence=dict(result),
                    detail_code="broadcast_result_unknown",
                )
        result = reconcile(journal.deploy_hash)
        if not isinstance(result, Mapping) or result.get("deploy_hash") not in {
            None,
            journal.deploy_hash,
        }:
            return journal
        if result.get("status") == "finalized":
            prior_evidence = journal.evidence
            return journal.transition(
                journal.state,
                "finalized",
                evidence={
                    "broadcast": prior_evidence,
                    "reconciliation": dict(result),
                },
                detail_code="deploy_finalized",
            )
        if result.get("status") == "terminal_rejected":
            return journal.transition(
                journal.state,
                "terminal_rejected",
                evidence=dict(result),
                detail_code="deploy_terminal_rejected",
            )
        return journal


def validate_public_rpc_endpoints(
    urls: Sequence[str], *, resolver: Any | None = None
) -> tuple[str, str]:
    try:
        endpoints = _validate_shared_rpc_endpoints(urls, resolver=resolver)
    except RpcEndpointPolicyError as exc:
        raise InstallValidationError(
            "RPC endpoints must be two distinct public credential-free HTTPS /rpc URLs"
        ) from exc
    return endpoints[0].url, endpoints[1].url


def build_public_rpc_transport(
    urls: Sequence[str],
    *,
    resolver: Any | None = None,
    authorization_files: Mapping[str, Path] | None = None,
) -> PinnedHttpsJsonRpc:
    try:
        return PinnedHttpsJsonRpc(
            urls,
            resolver=resolver,
            authorization_files=authorization_files,
        )
    except RpcEndpointPolicyError as exc:
        raise InstallValidationError(
            "RPC endpoints must be two distinct public credential-free HTTPS /rpc URLs"
        ) from exc


def deploy_expiry_epoch(signed_deploy: Mapping[str, Any]) -> float:
    try:
        deploy = serializer.from_json(dict(signed_deploy), Deploy)
        return deploy.header.timestamp.value + deploy.header.ttl.as_milliseconds / 1000
    except Exception as exc:
        raise InstallValidationError("signed deploy expiry cannot be decoded") from exc


def verify_git_release_identity(
    repository_root: Path,
    *,
    source_commit: str,
    deployment_commit: str,
    release_paths: Sequence[str],
) -> dict[str, str]:
    source = _commit_hash(source_commit, "source_commit")
    deployment = _commit_hash(deployment_commit, "deployment_commit")

    def git(*arguments: str) -> str:
        try:
            return subprocess.check_output(
                ["git", *arguments],
                cwd=repository_root,
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise InstallValidationError(
                "release Git identity cannot be verified"
            ) from exc

    head = git("rev-parse", "HEAD").lower()
    if deployment != head:
        raise InstallValidationError("deployment_commit must equal actual Git HEAD")
    if git("status", "--porcelain"):
        raise InstallValidationError("release Git tree must be clean")
    git("cat-file", "-e", source + "^{commit}")
    for relative in release_paths:
        current = (repository_root / relative).read_bytes()
        try:
            historical = subprocess.check_output(
                ["git", "show", f"{source}:{relative}"],
                cwd=repository_root,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise InstallValidationError(
                "source_commit does not contain the exact release files"
            ) from exc
        if not hmac.compare_digest(current, historical):
            raise InstallValidationError(
                "source_commit does not contain the exact release files"
            )
    return {"source_commit": source, "deployment_commit": deployment}


def _block_inclusion(
    block_response: Mapping[str, Any], deploy_hash: str
) -> dict[str, Any]:
    try:
        result = block_response["result"]
        wrapped = result["block_with_signatures"]
        versioned = wrapped["block"]
        if len(versioned) != 1:
            raise KeyError("version")
        version, block = next(iter(versioned.items()))
        block_hash = _strip_hash(block["hash"], "canonical block hash")
        height = block["header"]["height"]
        state_root = _strip_hash(block["header"]["state_root_hash"], "state root")
        block_timestamp = block["header"]["timestamp"]
        body = block["body"]
    except (KeyError, TypeError, ValueError) as exc:
        raise InstallValidationError("canonical block response is invalid") from exc
    if type(height) is not int or height < 0:
        raise InstallValidationError("canonical block height is invalid")
    if not isinstance(block_timestamp, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z",
        block_timestamp,
    ):
        raise InstallValidationError("canonical block timestamp is invalid")
    try:
        parsed_timestamp = datetime.fromisoformat(block_timestamp[:-1] + "+00:00")
    except ValueError as exc:
        raise InstallValidationError("canonical block timestamp is invalid") from exc
    if parsed_timestamp.tzinfo != timezone.utc:
        raise InstallValidationError("canonical block timestamp is invalid")
    matches = 0
    if version in {"Version1", "Legacy"}:
        for name in ("deploy_hashes", "transfer_hashes"):
            matches += sum(
                str(item).lower() == deploy_hash for item in body.get(name, [])
            )
    elif version == "Version2":
        transactions = body.get("transactions")
        if not isinstance(transactions, Mapping):
            raise InstallValidationError("canonical block response is invalid")
        for items in transactions.values():
            if not isinstance(items, list):
                raise InstallValidationError("canonical block response is invalid")
            for item in items:
                if isinstance(item, Mapping) and len(item) == 1:
                    matches += int(
                        str(next(iter(item.values()))).lower() == deploy_hash
                    )
    else:
        raise InstallValidationError("canonical block response is invalid")
    if matches == 0:
        raise InstallValidationError("deploy is absent from canonical block")
    if matches != 1:
        raise InstallValidationError("deploy appears multiple times in canonical block")
    return {
        "block_hash": block_hash,
        "block_height": height,
        "state_root_hash": state_root,
        "block_timestamp": block_timestamp,
    }


def verify_two_node_deploy_finality(
    observations: Sequence[Mapping[str, Any]],
    *,
    deploy_hash: str,
    expected_user_error: int | None = None,
) -> dict[str, Any]:
    expected_hash = _strip_hash(deploy_hash, "deploy hash")
    if len(observations) != 2:
        raise InstallValidationError("exactly two node observations are required")
    facts: list[dict[str, Any]] = []
    outcomes: list[tuple[bool, int | None]] = []
    node_ids: set[str] = set()
    endpoint_identities: list[str] = []
    for observation in observations:
        node_id = observation.get("node_id")
        node_url = observation.get("node_url")
        parsed_url = urlsplit(str(node_url))
        if (
            not isinstance(node_id, str)
            or not node_id
            or node_id in node_ids
            or parsed_url.scheme != "https"
            or parsed_url.hostname != node_id
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise InstallValidationError("node observations must be distinct")
        node_ids.add(node_id)
        endpoint_identities.append(str(node_url))
        deploy_request = observation.get("deploy_request")
        deploy_response = observation.get("deploy_response")
        if (
            not isinstance(deploy_request, Mapping)
            or set(deploy_request) != {"jsonrpc", "id", "method", "params"}
            or deploy_request["jsonrpc"] != "2.0"
            or deploy_request["method"] != "info_get_deploy"
            or deploy_request["params"] != {"deploy_hash": expected_hash}
            or not isinstance(deploy_response, Mapping)
            or set(deploy_response) != {"jsonrpc", "id", "result"}
            or deploy_response["jsonrpc"] != "2.0"
            or deploy_response["id"] != deploy_request["id"]
        ):
            raise InstallValidationError("deploy finality request/response is invalid")
        try:
            result = deploy_response["result"]
            returned_deploy = result["deploy"]
            execution_info = result["execution_info"]
            returned_hash = _strip_hash(returned_deploy["hash"], "returned deploy hash")
            execution_block = _strip_hash(
                execution_info["block_hash"], "execution block hash"
            )
            execution_height = execution_info["block_height"]
            versioned = execution_info["execution_result"]["Version2"]
        except (KeyError, TypeError, ValueError) as exc:
            raise InstallValidationError("deploy finality response is invalid") from exc
        if returned_hash != expected_hash:
            raise InstallValidationError("node returned another deploy")
        error_message = versioned.get("error_message")
        if error_message is None:
            outcome = (True, None)
        elif isinstance(error_message, str):
            match = re.search(
                r"(?:User error|ApiError::User)[:( ]+(\d+)", error_message
            )
            outcome = (False, int(match.group(1)) if match else None)
        else:
            raise InstallValidationError("deploy execution outcome is invalid")
        if expected_user_error is None and outcome != (True, None):
            raise InstallValidationError("deploy did not finalize successfully")
        if expected_user_error is not None and outcome != (False, expected_user_error):
            raise InstallValidationError(
                "deploy did not finalize with expected user error"
            )
        outcomes.append(outcome)
        block_request = observation.get("block_request")
        block_response = observation.get("block_response")
        if (
            not isinstance(block_request, Mapping)
            or set(block_request) != {"jsonrpc", "id", "method", "params"}
            or block_request["jsonrpc"] != "2.0"
            or block_request["method"] != "chain_get_block"
            or block_request["params"]
            != {"block_identifier": {"Hash": execution_block}}
            or not isinstance(block_response, Mapping)
            or set(block_response) != {"jsonrpc", "id", "result"}
            or block_response["jsonrpc"] != "2.0"
            or block_response["id"] != block_request["id"]
        ):
            raise InstallValidationError("canonical block request/response is invalid")
        block = _block_inclusion(block_response, expected_hash)
        if (
            block["block_hash"] != execution_block
            or block["block_height"] != execution_height
        ):
            raise InstallValidationError("deploy finality and canonical block disagree")
        facts.append(block)
    if facts[0] != facts[1] or outcomes[0] != outcomes[1]:
        raise InstallValidationError("public RPC nodes disagree on deploy finality")
    return {
        **facts[0],
        "finalized_at": facts[0]["block_timestamp"],
        "deploy_hash": expected_hash,
        "corroboration_count": 2,
        "success": outcomes[0][0],
        "user_error": outcomes[0][1],
        "node_observations": [dict(item) for item in observations],
        "endpoint_identities": endpoint_identities,
    }


def _safe_rpc_payload(
    transport: PinnedHttpsJsonRpc,
    url: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        method = payload["method"]
        params = payload["params"]
        request_id = payload["id"]
        if (
            payload.get("jsonrpc") != "2.0"
            or not isinstance(method, str)
            or not isinstance(params, Mapping)
        ):
            raise InstallValidationError("public RPC request is invalid")
        return transport.call(
            url,
            method,
            dict(params),
            request_id,
            allow_submit=method == "account_put_deploy",
        )
    except (KeyError, RpcEndpointPolicyError, RpcTransportError) as exc:
        raise InstallValidationError("public RPC request failed") from exc


def reconcile_two_node_deploy(
    transport: PinnedHttpsJsonRpc,
    *,
    deploy_hash: str,
    expected_user_error: int | None = None,
    deploy_expires_at: float | None = None,
) -> dict[str, Any]:
    expected_hash = _strip_hash(deploy_hash, "deploy hash")
    observations: list[dict[str, Any]] = []
    absence_observations: list[dict[str, Any]] = []
    pending = False
    for index, url in enumerate(transport.endpoints):
        request = {
            "jsonrpc": "2.0",
            "id": f"concordia-wp10-finality-{index}",
            "method": "info_get_deploy",
            "params": {"deploy_hash": expected_hash},
        }
        try:
            response = transport.call(
                url,
                "info_get_deploy",
                {"deploy_hash": expected_hash},
                request["id"],
            )
        except RpcRemoteError as exc:
            if exc.code != -32001:
                raise InstallValidationError(
                    "public RPC deploy lookup returned an unexpected error"
                ) from exc
            absence_observations.append(
                {
                    "node_id": urlsplit(url).hostname,
                    "node_url": str(url),
                    "deploy_request": request,
                    "deploy_error_code": exc.code,
                }
            )
            continue
        except (RpcEndpointPolicyError, RpcTransportError) as exc:
            raise InstallValidationError("public RPC request failed") from exc
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise InstallValidationError("public RPC finality response is invalid")
        execution = result.get("execution_info")
        if execution is None:
            pending = True
            continue
        if not isinstance(execution, Mapping):
            raise InstallValidationError("public RPC finality response is invalid")
        block_hash = _strip_hash(execution.get("block_hash"), "execution block hash")
        block_request = {
            "jsonrpc": "2.0",
            "id": f"concordia-wp10-block-{index}",
            "method": "chain_get_block",
            "params": {"block_identifier": {"Hash": block_hash}},
        }
        block_response = _safe_rpc_payload(transport, url, block_request)
        observations.append(
            {
                "node_id": urlsplit(url).hostname,
                "node_url": str(url),
                "deploy_request": request,
                "deploy_response": response,
                "block_request": block_request,
                "block_response": block_response,
            }
        )
    if len(absence_observations) == 2:
        if (
            isinstance(deploy_expires_at, (int, float))
            and not isinstance(deploy_expires_at, bool)
            and datetime.now(timezone.utc).timestamp() >= float(deploy_expires_at)
        ):
            return {
                "status": "terminal_rejected",
                "deploy_hash": expected_hash,
                "detail_code": "ttl_expired_and_two_nodes_report_absent",
                "absence_observations": absence_observations,
            }
        return {"status": "pending", "deploy_hash": expected_hash}
    if absence_observations or pending or len(observations) != 2:
        return {"status": "pending", "deploy_hash": expected_hash}
    proof = verify_two_node_deploy_finality(
        observations,
        deploy_hash=expected_hash,
        expected_user_error=expected_user_error,
    )
    observed_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    finalized = datetime.fromisoformat(proof["finalized_at"][:-1] + "+00:00")
    observed = datetime.fromisoformat(observed_at[:-1] + "+00:00")
    if observed < finalized:
        raise InstallValidationError("canonical block timestamp is in the future")
    return {"status": "finalized", **proof, "observed_at": observed_at}


def _commit_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 40 or value != value.lower():
        raise InstallValidationError(f"{field}: exact lowercase 40-hex commit required")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise InstallValidationError(
            f"{field}: exact lowercase 40-hex commit required"
        ) from exc
    return value


def _hash32(value: object, field: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise InstallValidationError(f"{field}: 64 lowercase hex characters required")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise InstallValidationError(f"{field}: invalid hexadecimal") from exc
    if result == bytes(32):
        raise InstallValidationError(f"{field}: zero account is forbidden")
    return result


def _role_account(role: object, field: str) -> bytes:
    if not isinstance(role, Mapping) or set(role) != {"kind", "account_hash"}:
        raise InstallValidationError(f"{field}: typed account-only identity required")
    if role["kind"] != "Account":
        raise InstallValidationError(f"{field}: account-only identity required")
    return _hash32(role["account_hash"], field)


def build_locked_install_args(
    *,
    installer_account_hash: str,
    roles: Mapping[str, object],
    threshold: int,
    casper_chain_name: str,
    installation_nonce: str,
) -> dict[str, object]:
    expected_roles = {"proposer", "finalizer", "signer_a", "signer_b", "signer_c"}
    if set(roles) != expected_roles:
        raise InstallValidationError(
            "roles must contain exactly proposer, finalizer and signer_a/b/c"
        )
    installer = _hash32(installer_account_hash, "installer_account_hash")
    role_values = {
        name: _role_account(roles[name], name) for name in sorted(expected_roles)
    }
    proposer = role_values["proposer"]
    finalizer = role_values["finalizer"]
    signers = [role_values[name] for name in ("signer_a", "signer_b", "signer_c")]
    if installer in role_values.values():
        raise InstallValidationError(
            "installer must be distinct from every governance role"
        )
    if proposer == finalizer or any(
        value in (proposer, finalizer) for value in signers
    ):
        raise InstallValidationError(
            "proposer, finalizer and signers must be pairwise distinct"
        )
    if len(set(signers)) != 3:
        raise InstallValidationError("three pairwise-distinct signers are required")
    if type(threshold) is not int or threshold != 2:
        raise InstallValidationError(
            "threshold must be exactly 2 for the frozen seven-step finals proof"
        )
    try:
        nonce = _hash32(installation_nonce, "installation_nonce")
        deployment_domain_record(
            installation_nonce,
            chain_name=casper_chain_name,
            package_key_name=PACKAGE_KEY_NAME,
        )
    except ValueError as exc:
        raise InstallValidationError(str(exc)) from exc

    return {
        "odra_cfg_package_hash_key_name": CLV_String(PACKAGE_KEY_NAME),
        "odra_cfg_allow_key_override": CLV_Bool(False),
        "odra_cfg_is_upgradable": CLV_Bool(False),
        "odra_cfg_is_upgrade": CLV_Bool(False),
        "proposer": CLV_ByteArray(proposer),
        "finalizer": CLV_ByteArray(finalizer),
        "signer_a": CLV_ByteArray(signers[0]),
        "signer_b": CLV_ByteArray(signers[1]),
        "signer_c": CLV_ByteArray(signers[2]),
        "threshold": CLV_U8(threshold),
        "casper_chain_name": CLV_String(casper_chain_name),
        "installation_nonce": CLV_ByteArray(nonce),
    }


def _normalize_schema_type(value: object) -> object:
    if isinstance(value, dict):
        return {key: _normalize_schema_type(item) for key, item in value.items()}
    return value


def diff_entry_point_args_against_schema(
    schema: Mapping[str, Any],
    entry_point: str,
    runtime_args: Sequence[Mapping[str, Any]],
) -> list[str]:
    matches = [
        item
        for item in schema.get("entry_points", [])
        if item.get("name") == entry_point
    ]
    if len(matches) != 1:
        return [f"schema entry point {entry_point!r} missing or duplicated"]
    expected = [
        (arg["name"], _normalize_schema_type(arg["ty"]))
        for arg in matches[0]["arguments"]
    ]
    actual = [
        (arg.get("name"), _normalize_schema_type(arg.get("cl_type")))
        for arg in runtime_args
    ]
    failures: list[str] = []
    if [name for name, _ in actual] != [name for name, _ in expected]:
        failures.append("runtime argument names/order differ from generated schema")
    for position, (expected_item, actual_item) in enumerate(
        zip(expected, actual, strict=False)
    ):
        if expected_item != actual_item:
            failures.append(
                f"argument {position}: expected {expected_item!r}, got {actual_item!r}"
            )
    if len(expected) != len(actual):
        failures.append(f"argument count: expected {len(expected)}, got {len(actual)}")
    return failures


def build_signed_install_payload(
    *,
    secret_key_path: Path,
    key_algorithm: str,
    roles: Mapping[str, object],
    threshold: int,
    installation_nonce: str,
    wasm_path: Path,
    schema_path: Path,
    payment_amount_motes: int,
    ttl: str,
    source_commit: str,
    deployment_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_commit = _commit_hash(source_commit, "source_commit")
    deployment_commit = _commit_hash(deployment_commit, "deployment_commit")
    if not wasm_path.is_file() or not wasm_path.read_bytes().startswith(b"\x00asm"):
        raise InstallValidationError(
            "release Wasm is missing or not a WebAssembly module"
        )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    expected_wasm_name = schema.get("call", {}).get("wasm_file_name")
    if wasm_path.name != expected_wasm_name:
        raise InstallValidationError(
            f"Wasm filename must be generated-schema authority {expected_wasm_name!r}"
        )
    try:
        algorithm = KeyAlgorithm[key_algorithm.strip().upper()]
        private_key = parse_private_key(secret_key_path, algorithm)
    except (KeyError, OSError, ValueError) as exc:
        raise InstallValidationError("installer key could not be loaded") from exc
    public_key = private_key.to_public_key()
    installer_hash = public_key.to_account_hash().hex()
    session_args = build_locked_install_args(
        installer_account_hash=installer_hash,
        roles=roles,
        threshold=threshold,
        casper_chain_name=CHAIN_NAME,
        installation_nonce=installation_nonce,
    )
    call_args = [
        {"name": name, **serializer.to_json(value)}
        for name, value in session_args.items()
    ]
    expected_call = [(item["name"], item["ty"]) for item in schema["call"]["arguments"]]
    actual_call = [(item["name"], item["cl_type"]) for item in call_args]
    if expected_call != actual_call:
        raise InstallValidationError(
            "locked installer args differ from generated Odra call schema"
        )

    params = create_deploy_parameters(private_key, CHAIN_NAME, ttl=ttl)
    payment = create_standard_payment(payment_amount_motes)
    session = DeployOfModuleBytes(
        module_bytes=wasm_path.read_bytes(), args=session_args
    )
    deploy = create_deploy(params, payment, session)
    deploy.approve(private_key)
    deploy_json = serializer.to_json(deploy)
    payload = {
        "jsonrpc": "2.0",
        "id": "concordia-v3-install",
        "method": "account_put_deploy",
        "params": {"deploy": deploy_json},
    }
    template_path = wasm_path.parent.parent / "deployment.manifest.json"
    if not template_path.is_file():
        raise InstallValidationError(
            "versioned deployment.manifest.json template is missing"
        )
    manifest = json.loads(template_path.read_text(encoding="utf-8"))
    actual_wasm_hash = hashlib.sha256(wasm_path.read_bytes()).hexdigest()
    actual_schema_hash = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    if manifest.get("build", {}).get("wasm_sha256") != actual_wasm_hash:
        raise InstallValidationError("release Wasm differs from deployment manifest")
    if manifest.get("build", {}).get("schema_sha256") != actual_schema_hash:
        raise InstallValidationError(
            "generated schema differs from deployment manifest"
        )
    manifest.update(
        {
            "status": "prepared",
            "installer_public_key": public_key.account_key.hex(),
            "installer_account_hash": installer_hash,
            "deployment_domain": deployment_domain_record(installation_nonce)[
                "deployment_domain"
            ],
            "installation_nonce": installation_nonce,
            "threshold": threshold,
            "roles": roles,
            "install_deploy_hash": str(deploy_json["hash"]),
            "install_payment_motes": payment_amount_motes,
            "install_ttl": ttl,
            "source_commit": source_commit,
            "deployment_commit": deployment_commit,
        }
    )
    return payload, manifest


def _rpc(
    transport: PinnedHttpsJsonRpc,
    rpc_url: str,
    method: str,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    request = {
        "jsonrpc": "2.0",
        "id": "concordia-v3-install-" + method,
        "method": method,
        "params": dict(params),
    }
    parsed = _safe_rpc_payload(transport, rpc_url, request)
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"jsonrpc", "id", "result"}
        or parsed.get("jsonrpc") != "2.0"
        or parsed.get("id") != request["id"]
    ):
        raise InstallValidationError(f"Casper RPC {method} failed")
    return {"request": request, "response": parsed}


def _strip_hash(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise InstallValidationError(f"{field} is missing")
    for prefix in ("contract-package-", "contract-", "package-", "hash-"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    if len(value) != 64:
        raise InstallValidationError(f"{field} is not a 32-byte hash")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise InstallValidationError(f"{field} is not hexadecimal") from exc
    return value.lower()


def _find_named_key(value: object, name: str) -> str | None:
    if isinstance(value, Mapping):
        if value.get("name") == name and isinstance(value.get("key"), str):
            return str(value["key"])
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


def _normalize_deploy_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _normalize_deploy_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_deploy_json(item) for item in value]
    if isinstance(value, str) and len(value) % 2 == 0:
        try:
            bytes.fromhex(value)
        except ValueError:
            return value
        return value.lower()
    return value


def validate_finalized_install_deploy(
    value: object,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "approvals",
        "hash",
        "header",
        "payment",
        "session",
    }:
        raise InstallValidationError("install deploy JSON field set is invalid")
    try:
        deploy = serializer.from_json(dict(value), Deploy)
        canonical_json = serializer.to_json(deploy)
        body_hash = create_digest_of_deploy_body(deploy.payment, deploy.session)
        deploy_hash = create_digest_of_deploy(deploy.header)
    except Exception as exc:
        raise InstallValidationError(
            "install deploy cannot be decoded canonically"
        ) from exc
    if _normalize_deploy_json(canonical_json) != _normalize_deploy_json(value):
        raise InstallValidationError(
            "install deploy parsed fields disagree with canonical bytes"
        )
    if deploy.header.body_hash != body_hash or deploy.hash != deploy_hash:
        raise InstallValidationError("install deploy body/deploy hash mismatch")
    if deploy_hash.hex() != _strip_hash(
        manifest.get("install_deploy_hash"), "install deploy hash"
    ):
        raise InstallValidationError(
            "finalized install deploy hash differs from prepared deploy"
        )
    if deploy.header.chain_name != CHAIN_NAME:
        raise InstallValidationError("install deploy is not on casper-test")
    installer_public_key = manifest.get("installer_public_key")
    if (
        not isinstance(installer_public_key, str)
        or deploy.header.account.account_key.hex() != installer_public_key.lower()
    ):
        raise InstallValidationError("install deploy initiator differs from installer")
    if len(deploy.approvals) != 1:
        raise InstallValidationError(
            "install deploy must carry exactly one installer approval"
        )
    approval = deploy.approvals[0]
    signer = getattr(approval.signer, "account_key", None)
    if not isinstance(signer, bytes) or signer.hex() != installer_public_key.lower():
        raise InstallValidationError("install approval signer differs from installer")
    try:
        signature_valid = crypto.verify_deploy_approval_signature(
            deploy_hash,
            approval.signature,
            signer,
        )
    except Exception as exc:
        raise InstallValidationError("install approval signature is invalid") from exc
    if not signature_valid:
        raise InstallValidationError("install approval signature is invalid")

    if (
        type(deploy.payment) is not DeployOfModuleBytes
        or deploy.payment.module_bytes != b""
    ):
        raise InstallValidationError("install payment must be standard ModuleBytes")
    expected_payment = manifest.get("install_payment_motes")
    if type(expected_payment) is not int or expected_payment <= 0:
        raise InstallValidationError("install manifest payment amount is invalid")
    payment_json = serializer.to_json(deploy.payment)["ModuleBytes"]
    if _normalize_deploy_json(payment_json) != _normalize_deploy_json(
        {
            "module_bytes": "",
            "args": [("amount", serializer.to_json(CLV_U512(expected_payment)))],
        }
    ):
        raise InstallValidationError("install payment differs from prepared amount")

    if type(deploy.session) is not DeployOfModuleBytes:
        raise InstallValidationError("install session must be ModuleBytes")
    wasm_sha256 = hashlib.sha256(deploy.session.module_bytes).hexdigest()
    if wasm_sha256 != manifest.get("build", {}).get("wasm_sha256"):
        raise InstallValidationError(
            "finalized install Wasm differs from release manifest"
        )
    roles = manifest.get("roles")
    if not isinstance(roles, Mapping):
        raise InstallValidationError("install manifest roles are invalid")
    expected_args = build_locked_install_args(
        installer_account_hash=str(manifest.get("installer_account_hash")),
        roles=roles,
        threshold=manifest.get("threshold"),
        casper_chain_name=CHAIN_NAME,
        installation_nonce=str(manifest.get("installation_nonce")),
    )
    actual_args = [
        (argument.name, serializer.to_json(argument.value))
        for argument in deploy.session.arguments
    ]
    frozen_args = [
        (name, serializer.to_json(clv)) for name, clv in expected_args.items()
    ]
    if _normalize_deploy_json(actual_args) != _normalize_deploy_json(frozen_args):
        raise InstallValidationError(
            "finalized install arguments differ from locked constructor"
        )
    return {
        "deploy_hash": deploy_hash.hex(),
        "body_hash": body_hash.hex(),
        "wasm_sha256": wasm_sha256,
        "installer_public_key": installer_public_key.lower(),
        "locked_argument_names": [name for name, _ in frozen_args],
    }


def _validate_successful_install_rpc(
    transcript: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    response = transcript.get("response")
    result = response.get("result") if isinstance(response, Mapping) else None
    if not isinstance(result, Mapping) or set(result) != {
        "api_version",
        "deploy",
        "execution_info",
    }:
        raise InstallValidationError(
            "install finality is not the exact Casper v2 deploy shape"
        )
    if not isinstance(result["api_version"], str) or not result["api_version"]:
        raise InstallValidationError("install finality lacks api_version")
    deploy_facts = validate_finalized_install_deploy(result["deploy"], manifest)
    execution_info = result["execution_info"]
    if not isinstance(execution_info, Mapping) or set(execution_info) != {
        "block_hash",
        "block_height",
        "execution_result",
    }:
        raise InstallValidationError("install execution_info field set is invalid")
    versioned = execution_info["execution_result"]
    if not isinstance(versioned, Mapping) or set(versioned) != {"Version2"}:
        raise InstallValidationError("install execution result is not Version2")
    outcome = versioned["Version2"]
    if not isinstance(outcome, Mapping) or set(outcome) != {
        "initiator",
        "error_message",
        "current_price",
        "limit",
        "consumed",
        "cost",
        "refund",
        "transfers",
        "size_estimate",
        "effects",
    }:
        raise InstallValidationError("install execution outcome is invalid")
    initiator = outcome["initiator"]
    if (
        not isinstance(initiator, Mapping)
        or set(initiator) != {"PublicKey"}
        or not isinstance(initiator["PublicKey"], str)
        or initiator["PublicKey"].lower()
        != str(manifest.get("installer_public_key", "")).lower()
    ):
        raise InstallValidationError(
            "install execution initiator differs from installer"
        )
    if outcome["error_message"] is not None:
        raise InstallValidationError("v3 install execution failed")
    block_hash = _strip_hash(
        execution_info["block_hash"], "install execution block hash"
    )
    block_height = execution_info["block_height"]
    if type(block_height) is not int or block_height < 0:
        raise InstallValidationError("install execution block height is invalid")
    return {**deploy_facts, "block_hash": block_hash, "block_height": block_height}


def _resolve_locked_contract(package_value: object) -> tuple[int, str]:
    if not isinstance(package_value, Mapping):
        raise InstallValidationError("package state is missing")
    package = package_value.get("ContractPackage")
    if not isinstance(package, Mapping) or set(package) != {
        "access_key",
        "versions",
        "disabled_versions",
        "groups",
        "lock_status",
    }:
        raise InstallValidationError("package query did not return ContractPackage")
    if package["lock_status"] != "Locked":
        raise InstallValidationError("v3 package is not permanently locked")
    versions = package.get("versions")
    if not isinstance(versions, list) or len(versions) != 1:
        raise InstallValidationError(
            "v3 package must contain exactly one contract version"
        )
    version_record = versions[0]
    if not isinstance(version_record, Mapping) or set(version_record) != {
        "protocol_version_major",
        "contract_version",
        "contract_hash",
    }:
        raise InstallValidationError("v3 contract version record is invalid")
    if (
        version_record["protocol_version_major"] != 2
        or version_record["contract_version"] != 1
    ):
        raise InstallValidationError(
            "v3 package must install exactly protocol-2 contract version 1"
        )
    if package["disabled_versions"] != []:
        raise InstallValidationError(
            "v3 package contains disabled or historical versions"
        )
    groups = package["groups"]
    if not isinstance(groups, list):
        raise InstallValidationError("v3 package groups are invalid")
    for group in groups:
        if (
            not isinstance(group, Mapping)
            or set(group) != {"group_name", "group_users"}
            or not isinstance(group["group_name"], str)
            or group["group_users"] != []
        ):
            raise InstallValidationError("v3 package exposes an upgrade-capable group")
    access_key = package["access_key"]
    if not isinstance(access_key, str):
        raise InstallValidationError("v3 package access key is invalid")
    parts = access_key.split("-")
    try:
        canonical_address = bytes.fromhex(parts[1]).hex()
    except (IndexError, ValueError) as exc:
        raise InstallValidationError("v3 package access key is invalid") from exc
    if (
        len(parts) != 3
        or parts[0] != "uref"
        or len(parts[1]) != 64
        or parts[1] != canonical_address
        or parts[2] not in {f"{rights:03d}" for rights in range(8)}
    ):
        raise InstallValidationError("v3 package access key is invalid")
    return 1, _strip_hash(version_record["contract_hash"], "contract_hash")


def finalize_deployment_manifest(
    *,
    rpc_transport: PinnedHttpsJsonRpc,
    rpc_url: str,
    manifest: dict[str, Any],
    broadcast_response: Mapping[str, Any],
    two_node_finality: Mapping[str, Any],
) -> dict[str, Any]:
    deploy_hash = str(
        (broadcast_response.get("result") or {}).get("deploy_hash")
        or broadcast_response.get("deploy_hash")
        or ""
    )
    if deploy_hash.lower() != str(manifest["install_deploy_hash"]).lower():
        raise InstallValidationError("node returned a different install deploy hash")
    if two_node_finality.get("status") != "finalized":
        raise InstallValidationError("two-node install finality is not complete")
    block_hash = str(two_node_finality.get("block_hash") or "")
    block_height = two_node_finality.get("block_height")
    observations = two_node_finality.get("node_observations")
    if not isinstance(observations, list) or len(observations) != 2:
        raise InstallValidationError("two-node install finality evidence is invalid")
    primary = observations[0]
    install_rpc = {
        "request": primary["deploy_request"],
        "response": primary["deploy_response"],
    }
    finality = {
        "success": True,
        "block_hash": block_hash,
        "block_height": block_height,
    }
    install_facts = _validate_successful_install_rpc(install_rpc, manifest)
    if install_facts["block_hash"] != _strip_hash(block_hash, "install block hash"):
        raise InstallValidationError(
            "install finality summary disagrees with raw node response"
        )
    root_rpc = _rpc(
        rpc_transport,
        rpc_url,
        "chain_get_state_root_hash",
        {"block_identifier": {"Hash": _strip_hash(block_hash, "install block hash")}},
    )
    state_root = (root_rpc["response"].get("result") or {}).get("state_root_hash")
    state_root = _strip_hash(state_root, "install state root")
    account_rpc = _rpc(
        rpc_transport,
        rpc_url,
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "account-hash-" + manifest["installer_account_hash"],
            "path": [],
        },
    )
    account_value = (account_rpc["response"].get("result") or {}).get("stored_value")
    package_key = _find_named_key(account_value, PACKAGE_KEY_NAME)
    package_hash = _strip_hash(package_key, "v3 package named key")
    package_rpc = _rpc(
        rpc_transport,
        rpc_url,
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "hash-" + package_hash,
            "path": [],
        },
    )
    package_value = (package_rpc["response"].get("result") or {}).get("stored_value")
    version, contract_hash = _resolve_locked_contract(package_value)
    contract_rpc = _rpc(
        rpc_transport,
        rpc_url,
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "hash-" + contract_hash,
            "path": [],
        },
    )
    contract_value = (contract_rpc["response"].get("result") or {}).get("stored_value")
    contract = (
        contract_value.get("Contract") if isinstance(contract_value, Mapping) else None
    )
    if (
        not isinstance(contract, Mapping)
        or _strip_hash(
            contract.get("contract_package_hash"), "contract package ownership"
        )
        != package_hash
    ):
        raise InstallValidationError(
            "exact contract does not belong to the installed package"
        )
    result = dict(manifest)
    canonical_finality = {
        "status": "finalized",
        "success": True,
        "block_hash": install_facts["block_hash"],
        "block_height": install_facts["block_height"],
        "deploy_hash": install_facts["deploy_hash"],
    }
    result.update(
        {
            "status": "finalized",
            "package_hash": package_hash,
            "contract_hash": contract_hash,
            "contract_version": version,
            "install_block_hash": _strip_hash(block_hash, "install block hash"),
            "install_block_height": finality.get("block_height"),
            "install_state_root_hash": state_root,
            "finality": canonical_finality,
            "verified_install_deploy": install_facts,
            "raw_rpc": {
                "broadcast_response": dict(broadcast_response),
                "install_deploy": install_rpc,
                "state_root": root_rpc,
                "installer_account": account_rpc,
                "package": package_rpc,
                "contract": contract_rpc,
            },
        }
    )
    if two_node_finality is not None:
        result["two_node_finality"] = dict(two_node_finality)
    return result


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True).encode("utf-8"))
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def build_install_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-key", type=Path, required=True)
    parser.add_argument("--key-algorithm", default="ED25519")
    parser.add_argument("--roles", type=Path, required=True)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--installation-nonce", required=True)
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--payment-motes", type=int, default=30_000_000_000)
    parser.add_argument("--ttl", default="30m")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--deployment-commit", required=True)
    parser.add_argument(
        "--rpc-url",
        dest="rpc_urls",
        action="append",
        default=[],
        help="repeat exactly twice when --submit is used",
    )
    parser.add_argument(
        "--rpc-authorization-file",
        action="append",
        default=[],
        help="repeat URL=/absolute/token-file; token values are never accepted",
    )
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_install_parser()
    args = parser.parse_args()
    try:
        if args.journal.exists():
            journal = DurableDeployJournal.open(args.journal)
            intent = journal.intent
            if intent.get("kind") != "v3_install" or not isinstance(
                intent.get("manifest"), Mapping
            ):
                raise InstallValidationError("install journal intent is invalid")
            manifest = dict(intent["manifest"])
            payload = {
                "jsonrpc": "2.0",
                "id": "concordia-v3-install",
                "method": "account_put_deploy",
                "params": {"deploy": journal.signed_deploy},
            }
        else:
            identity = verify_git_release_identity(
                ROOT,
                source_commit=args.source_commit,
                deployment_commit=args.deployment_commit,
                release_paths=RELEASE_IDENTITY_PATHS,
            )
            roles = json.loads(args.roles.read_text(encoding="utf-8"))
            payload, manifest = build_signed_install_payload(
                secret_key_path=args.secret_key,
                key_algorithm=args.key_algorithm,
                roles=roles,
                threshold=args.threshold,
                installation_nonce=args.installation_nonce,
                wasm_path=args.wasm,
                schema_path=args.schema,
                payment_amount_motes=args.payment_motes,
                ttl=args.ttl,
                source_commit=identity["source_commit"],
                deployment_commit=identity["deployment_commit"],
            )
            journal = DurableDeployJournal.create(
                args.journal,
                intent={"kind": "v3_install", "manifest": manifest},
                signed_deploy=payload["params"]["deploy"],
                deploy_hash=str(manifest["install_deploy_hash"]),
            )
        if args.submit:
            verify_git_release_identity(
                ROOT,
                source_commit=str(manifest.get("source_commit", "")),
                deployment_commit=str(manifest.get("deployment_commit", "")),
                release_paths=RELEASE_IDENTITY_PATHS,
            )
            authorization_files = parse_rpc_authorization_file_args(
                args.rpc_authorization_file,
                args.rpc_urls,
            )
            rpc_transport = (
                build_public_rpc_transport(
                    args.rpc_urls,
                    authorization_files=authorization_files,
                )
                if authorization_files
                else build_public_rpc_transport(args.rpc_urls)
            )
            rpc_urls = rpc_transport.endpoints

            def broadcast(
                signed_deploy: Mapping[str, Any], deploy_hash: str
            ) -> dict[str, Any]:
                exact_payload = {
                    "jsonrpc": "2.0",
                    "id": "concordia-v3-install",
                    "method": "account_put_deploy",
                    "params": {"deploy": dict(signed_deploy)},
                }
                parsed = _safe_rpc_payload(rpc_transport, rpc_urls[0], exact_payload)
                result = parsed.get("result")
                if (
                    not isinstance(result, Mapping)
                    or str(result.get("deploy_hash", "")).lower() != deploy_hash
                ):
                    return {
                        "status": "ambiguous",
                        "deploy_hash": deploy_hash,
                    }
                return {
                    "status": "submitted",
                    "deploy_hash": deploy_hash,
                    "raw_response": parsed,
                }

            journal = execute_journaled_submission(
                journal,
                broadcast=broadcast,
                reconcile=lambda deploy_hash: reconcile_two_node_deploy(
                    rpc_transport,
                    deploy_hash=deploy_hash,
                    deploy_expires_at=deploy_expiry_epoch(journal.signed_deploy),
                ),
            )
            if journal.state != "finalized":
                print(
                    json.dumps(
                        {
                            "status": journal.state,
                            "manifest": None,
                            "journal": str(args.journal),
                        }
                    )
                )
                return 3
            journal_evidence = journal.evidence
            reconciliation = journal_evidence["reconciliation"]
            broadcast_evidence = journal_evidence.get("broadcast")
            raw_broadcast = (
                broadcast_evidence.get("raw_response")
                if isinstance(broadcast_evidence, Mapping)
                else None
            )
            if not isinstance(raw_broadcast, Mapping):
                raw_broadcast = {
                    "status": "response_lost_reconciled_by_hash",
                    "deploy_hash": journal.deploy_hash,
                }
            manifest = finalize_deployment_manifest(
                rpc_transport=rpc_transport,
                rpc_url=rpc_urls[0],
                manifest=manifest,
                broadcast_response=raw_broadcast,
                two_node_finality=reconciliation,
            )
            _atomic_write_json(args.manifest_out, manifest)
        print(
            json.dumps(
                {
                    "status": "finalized" if args.submit else "prepared",
                    "manifest": str(args.manifest_out) if args.submit else None,
                    "journal": str(args.journal),
                }
            )
        )
        return 0
    except (InstallValidationError, OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
