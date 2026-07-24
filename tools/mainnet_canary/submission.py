"""Live submission boundary — imported signed bytes, exactly-once (blocker 3).

This module gives the canary a real, bounded broadcast path WITHOUT adding
any private-key handling to the package:

- the deploy is signed EXTERNALLY (wallet/operator tooling); this module only
  IMPORTS the signed bytes from a file that must not sit under a secret mount;
- the authoritative deploy hash is RECOMPUTED from the imported bytes
  (``create_digest_of_deploy`` over the decoded header — never a value the
  caller typed) and persisted to the durable journal at ``SIGNED`` BEFORE any
  broadcast, together with the canonical signed-bytes SHA-256;
- submission happens EXACTLY ONCE: the journal transitions to ``SUBMITTED``
  under the exclusive lock before the RPC call, so a crash at any point
  leaves the step in flight and only reconciliation by the ORIGINAL deploy
  hash can continue — re-signing, re-staging, or submitting different bytes
  refuses (``DUPLICATE_ECONOMIC_ACTION`` / ``SIGNED_BYTES_MISMATCH``);
- reconciliation queries the chain for the original deploy hash through the
  injected read-only transport and finalizes the journal state from evidence.

The RPC transport is injected (tests use fakes; the live lane uses
``shared.casper_rpc_transport.PinnedHttpsJsonRpc`` with its explicit
``allow_submit`` authority).  Spend-plan binding: the imported deploy's
payment must sit within the calibrated maximum for its step and the deploy
must match the plan step exactly.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable, Protocol

from pycspr import crypto, serializer
from pycspr.factory.digests import (
    create_digest_of_deploy,
    create_digest_of_deploy_body,
)
from pycspr.types.node.rpc import (
    Deploy,
    DeployOfModuleBytes,
    DeployOfStoredContractByHash,
    DeployOfStoredContractByHashVersioned,
    DeployOfTransfer,
)

from tools.mainnet_canary.constants import MAINNET_CHAIN_NAME
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.secret_guard import refuse_secret_path

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

MAX_SIGNED_DEPLOY_BYTES = 1_048_576

SubmitCall = Callable[[str, bytes], str]


class SubmissionTransport(Protocol):
    """Injected transport surface; the live lane binds PinnedHttpsJsonRpc."""

    def submit_deploy(self, signed_bytes: bytes) -> str:
        """Broadcast once; return the node-reported deploy hash (hex)."""

    def fetch_deploy_status(self, deploy_hash_hex: str) -> dict[str, object]:
        """Read-only lookup used exclusively for reconciliation."""


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def load_signed_deploy_bytes(path: Path) -> bytes:
    """Import externally signed bytes; bounded, never from a secret mount."""

    refuse_secret_path(path, context="signed-deploy-import")
    if not path.is_file():
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "signed deploy file does not exist; the wallet-signed bytes must "
            "be exported before submission",
        )
    size = path.stat().st_size
    if size <= 0 or size > MAX_SIGNED_DEPLOY_BYTES:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "signed deploy file is empty or exceeds the size bound",
        )
    return path.read_bytes()


def _decode_canonical(raw: bytes) -> Deploy:
    if type(raw) is not bytes or not raw:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID, "signed bytes must be non-empty"
        )
    try:
        remainder, deploy = serializer.from_bytes(raw, Deploy)
    except Exception as exc:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "signed deploy bytes could not be decoded",
        ) from exc
    if remainder:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID, "signed deploy carries trailing bytes"
        )
    try:
        canonical = serializer.to_bytes(deploy)
    except Exception as exc:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "decoded deploy could not be re-encoded",
        ) from exc
    if canonical != raw:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "signed deploy is not canonically encoded",
        )
    return deploy


def validate_signed_step_deploy(
    raw: bytes,
    *,
    step: dict[str, object],
    max_payment_motes: int,
    expected_chain_name: str = MAINNET_CHAIN_NAME,
) -> dict[str, object]:
    """Fail closed unless ``raw`` is the one expected step deploy.

    Reuses the accepted pycspr primitives (serializer, deploy digests,
    approval-signature verification) — no crypto is reimplemented.  The
    returned deploy hash is RECOMPUTED from the decoded header; nothing the
    caller asserts about the bytes is trusted.
    """

    deploy = _decode_canonical(raw)

    computed_body_hash = create_digest_of_deploy_body(
        deploy.payment, deploy.session
    )
    if deploy.header.body_hash != computed_body_hash:
        raise _refuse(RefusalCode.SIGNED_BYTES_INVALID, "body hash mismatch")
    computed_deploy_hash = create_digest_of_deploy(deploy.header)
    if deploy.hash != computed_deploy_hash:
        raise _refuse(RefusalCode.SIGNED_BYTES_INVALID, "deploy hash mismatch")

    if not deploy.approvals:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "signed deploy carries no approvals",
        )
    seen: set[bytes] = set()
    for approval in deploy.approvals:
        signer = (
            approval.signer.account_key
            if hasattr(approval.signer, "account_key")
            else approval.signer
        )
        if type(signer) is not bytes:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID, "approval signer malformed"
            )
        if signer in seen:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID, "duplicate approval signer"
            )
        seen.add(signer)
        try:
            valid = crypto.verify_deploy_approval_signature(
                computed_deploy_hash, approval.signature, signer
            )
        except Exception as exc:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "approval signature could not be verified",
            ) from exc
        if not valid:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID, "invalid approval signature"
            )

    if deploy.header.chain_name != expected_chain_name:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH,
            f"signed deploy targets chain {deploy.header.chain_name!r}, not "
            f"{expected_chain_name!r}",
        )
    signing_account_hash = deploy.header.account.account_hash.hex()
    if signing_account_hash != str(step.get("signing_account_hash")):
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "signed deploy source account does not equal the plan step's "
            "signing account",
        )

    if type(deploy.payment) is not DeployOfModuleBytes:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "payment must be standard ModuleBytes",
        )
    payment_args = deploy.payment.arguments
    if [argument.name for argument in payment_args] != ["amount"]:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID,
            "payment arguments must be exactly [amount]",
        )
    payment_amount = getattr(payment_args[0].value, "value", None)
    if not isinstance(payment_amount, int) or payment_amount <= 0:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID, "payment amount malformed"
        )
    if payment_amount > max_payment_motes:
        raise _refuse(
            RefusalCode.COST_CEILING_EXCEEDED,
            "signed deploy payment exceeds the calibrated maximum for this "
            "step; the spend plan is binding",
        )

    kind = str(step.get("kind"))
    session = deploy.session
    if kind == "native_transfer":
        if type(session) is not DeployOfTransfer:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "native-transfer step requires a Transfer session",
            )
        names = [argument.name for argument in session.arguments]
        if names != ["target", "amount", "id"]:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "transfer session arguments must be exactly ordered "
                "target, amount, id",
            )
        expected = step.get("expected_outcome", {})
        target_value = session.arguments[0].value
        recipient = getattr(target_value, "identifier", None)
        if (
            type(recipient) is not bytes
            or recipient.hex() != str(expected.get("recipient_account"))
        ):
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "transfer recipient does not equal the plan's bound recipient",
            )
        amount = getattr(session.arguments[1].value, "value", None)
        if str(amount) != str(expected.get("amount_motes")):
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "transfer amount does not equal the plan's bound amount",
            )
    else:
        if type(session) not in (
            DeployOfStoredContractByHash,
            DeployOfStoredContractByHashVersioned,
        ):
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "contract step requires a stored-contract-by-hash session",
            )
        if session.entry_point != step.get("entry_point"):
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "session entry point does not equal the plan step's",
            )
        session_names = [argument.name for argument in session.arguments]
        plan_args = step.get("typed_args") or []
        plan_names = [str(argument.get("name")) for argument in plan_args]
        if session_names != plan_names:
            raise _refuse(
                RefusalCode.SIGNED_BYTES_INVALID,
                "session argument names/order do not equal the plan step's "
                "typed arguments",
            )

    return {
        "deploy_hash_hex": computed_deploy_hash.hex(),
        "signed_bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "chain_name": deploy.header.chain_name,
        "payment_amount_motes": str(payment_amount),
    }


def submit_step_exactly_once(
    *,
    journal_path: Path,
    plan_hash: str,
    step: dict[str, object],
    signed_bytes: bytes,
    facts: dict[str, object],
    transport: SubmissionTransport,
) -> dict[str, object]:
    """SIGNED → SUBMITTED under one lock; the RPC fires at most once.

    Ordering is the whole control: the durable ``SUBMITTED`` record is
    fsynced BEFORE the network call, so a crash between journal and network
    (or between network and return) leaves the step in flight, where the
    journal refuses every path except reconciliation by the original hash.
    A pre-existing SIGNED record with a different signed-bytes digest
    refuses: different bytes would be a second economic action.
    """

    step_id = str(step.get("step_id"))
    deploy_hash_hex = str(facts["deploy_hash_hex"])
    signed_digest = str(facts["signed_bytes_sha256"])
    if _HEX64.match(deploy_hash_hex) is None or _HEX64.match(signed_digest) is None:
        raise _refuse(
            RefusalCode.SIGNED_BYTES_INVALID, "recomputed digests malformed"
        )

    journal = CanaryJournal.load(journal_path)
    try:
        if journal.plan_hash != plan_hash:
            raise _refuse(
                RefusalCode.PLAN_HASH_MISMATCH,
                "journal is bound to a different plan",
            )
        status = journal.step_status(step_id)
        if status is None:
            raise _refuse(
                RefusalCode.JOURNAL_CONFLICT,
                f"step {step_id} was never staged; staging precedes signing",
            )
        if status.state == "AUTHORIZATION_VALIDATED":
            journal.transition(
                step_id,
                "SIGNED",
                plan_hash=plan_hash,
                deploy_hash=deploy_hash_hex,
                signed_bytes_sha256=signed_digest,
            )
        elif status.state == "SIGNED":
            # Crash-resume path: the ONLY bytes that may proceed are the
            # exact bytes whose digests were persisted at SIGNED.
            if (
                status.deploy_hash != deploy_hash_hex
                or status.signed_bytes_sha256 != signed_digest
            ):
                raise _refuse(
                    RefusalCode.SIGNED_BYTES_MISMATCH,
                    f"step {step_id} already persisted different signed "
                    "bytes; broadcasting these would be a second economic "
                    "action",
                )
        else:
            raise _refuse(
                RefusalCode.DUPLICATE_ECONOMIC_ACTION,
                f"step {step_id} is {status.state}; a new submission is not "
                "a legal continuation",
            )

        # Durable intent BEFORE the network call.
        journal.transition(
            step_id,
            "SUBMITTED",
            plan_hash=plan_hash,
            deploy_hash=deploy_hash_hex,
        )
        try:
            reported = transport.submit_deploy(signed_bytes)
        except Exception:
            journal.transition(
                step_id,
                "SUBMISSION_UNKNOWN",
                plan_hash=plan_hash,
                deploy_hash=deploy_hash_hex,
                detail="transport error during the single broadcast attempt",
            )
            raise _refuse(
                RefusalCode.SUBMISSION_TRANSPORT_INVALID,
                f"step {step_id}: the single broadcast attempt errored; the "
                "step is in flight and must be reconciled by its original "
                "deploy hash",
            ) from None
        if reported != deploy_hash_hex:
            journal.transition(
                step_id,
                "SUBMISSION_UNKNOWN",
                plan_hash=plan_hash,
                deploy_hash=deploy_hash_hex,
                detail="node-reported hash differs from the recomputed hash",
            )
            raise _refuse(
                RefusalCode.SUBMISSION_RESULT_MISMATCH,
                f"step {step_id}: the node reported a different deploy hash "
                "than the locally recomputed one; reconcile by the original "
                "hash before anything else",
            )
    finally:
        journal.close()

    return {
        "step_id": step_id,
        "deploy_hash": deploy_hash_hex,
        "signed_bytes_sha256": signed_digest,
        "state": "SUBMITTED",
    }


def reconcile_step(
    *,
    journal_path: Path,
    plan_hash: str,
    step_id: str,
    transport: SubmissionTransport,
) -> dict[str, object]:
    """Reconcile an in-flight step by its ORIGINAL deploy hash only."""

    journal = CanaryJournal.load(journal_path)
    try:
        if journal.plan_hash != plan_hash:
            raise _refuse(
                RefusalCode.PLAN_HASH_MISMATCH,
                "journal is bound to a different plan",
            )
        status = journal.step_status(step_id)
        if status is None or status.deploy_hash is None:
            raise _refuse(
                RefusalCode.RECONCILIATION_REQUIRED,
                f"step {step_id} has no persisted original deploy hash to "
                "reconcile against",
            )
        original = status.deploy_hash
        if status.state not in ("SUBMITTED", "SUBMISSION_UNKNOWN"):
            raise _refuse(
                RefusalCode.JOURNAL_CONFLICT,
                f"step {step_id} is {status.state}; reconciliation applies "
                "only to in-flight submissions",
            )
        try:
            evidence = transport.fetch_deploy_status(original)
        except Exception:
            raise _refuse(
                RefusalCode.SUBMISSION_TRANSPORT_INVALID,
                f"step {step_id}: reconciliation lookup failed; the step "
                "stays in flight",
            ) from None
        if not isinstance(evidence, dict) or "finalized" not in evidence or (
            "success" not in evidence
        ):
            raise _refuse(
                RefusalCode.OBSERVATION_MALFORMED,
                f"step {step_id}: reconciliation evidence malformed",
            )
        if evidence["finalized"] is not True:
            raise _refuse(
                RefusalCode.PROOF_PENDING,
                f"step {step_id}: the original deploy is not finalized yet; "
                "the step stays in flight",
            )
        if status.state == "SUBMITTED":
            outcome = (
                "CONFIRMED_FINALIZED"
                if evidence["success"] is True
                else "FAILED_FINALIZED"
            )
        else:
            outcome = (
                "RECONCILED_CONFIRMED"
                if evidence["success"] is True
                else "RECONCILED_FAILED"
            )
        journal.transition(
            step_id, outcome, plan_hash=plan_hash, deploy_hash=original
        )
    finally:
        journal.close()
    return {"step_id": step_id, "deploy_hash": original, "state": outcome}


class PinnedRpcSubmissionTransport:
    """Adapter binding the accepted repo transport to this boundary.

    Uses ``shared.casper_rpc_transport.PinnedHttpsJsonRpc`` — the write
    method requires that transport's own explicit ``allow_submit`` authority,
    and reads stay on the primary endpoint.  Constructed only by the live
    lane; tests inject fakes.
    """

    def __init__(self, rpc: object, endpoint: str):
        self._rpc = rpc
        self._endpoint = endpoint

    def submit_deploy(self, signed_bytes: bytes) -> str:
        from pycspr import serializer as _serializer
        from pycspr.types.node.rpc import Deploy as _Deploy

        _, deploy = _serializer.from_bytes(signed_bytes, _Deploy)
        response = self._rpc.call(
            self._endpoint,
            "account_put_deploy",
            {"deploy": _serializer.to_json(deploy)},
            "canary-submit-1",
            allow_submit=True,
        )
        result = response.get("result") if isinstance(response, dict) else None
        reported = result.get("deploy_hash") if isinstance(result, dict) else None
        if not isinstance(reported, str):
            raise _refuse(
                RefusalCode.SUBMISSION_RESULT_MISMATCH,
                "node response carries no deploy hash",
            )
        return reported.lower()

    def fetch_deploy_status(self, deploy_hash_hex: str) -> dict[str, object]:
        response = self._rpc.call(
            self._endpoint,
            "info_get_deploy",
            {"deploy_hash": deploy_hash_hex},
            "canary-reconcile-1",
        )
        result = response.get("result") if isinstance(response, dict) else None
        executions = (
            result.get("execution_results") if isinstance(result, dict) else None
        )
        if not isinstance(executions, list) or not executions:
            return {"finalized": False, "success": None}
        from tools.mainnet_canary.raw_evidence import (
            derive_execution_from_result,
        )

        entry = executions[0] if isinstance(executions[0], dict) else {}
        success, _ = derive_execution_from_result(
            entry.get("result"), label="reconciliation"
        )
        return {"finalized": True, "success": success}
