"""Complete raw v3 proof fixtures for treasury execution tests."""

from __future__ import annotations

import copy
import hashlib
import json
from unittest.mock import patch

import scripts.run_v3_live_proof as live_proof_runner
from scripts.prepare_v3_envelope import prepare_v3_envelope
from scripts.read_v3_state import (
    build_readback_artifact_from_transcripts,
    state_dictionary_key,
)
from shared.actions_v3 import build_native_material
from tests.test_clvalue_roundtrip import (
    _cl_bytes,
    _deployment_evidence,
    _live_run,
    _native_document,
    _readback_fixture,
    _role_private_keys,
)


def treasury_v3_proof(
    *,
    source_account: bytes,
    recipient_account: bytes,
    proposal_id: str = "DAO-PROP-V3-TREASURY",
    action_nonce: bytes = bytes.fromhex("44" * 32),
    snapshot_block_height: int = 8_999,
) -> dict[str, object]:
    """Build one fully signed/raw v3 proof with snapshot before finalization."""

    document = _native_document()
    header = copy.deepcopy(document["header"])
    body = copy.deepcopy(document["body"])
    header["proposal_id"] = proposal_id
    header["action_id"] = "00" * 32
    body["source_account"] = source_account.hex()
    body["recipient_account"] = recipient_account.hex()
    body["action_nonce"] = action_nonce.hex()
    body["transfer_id"] = "0"
    # The synthetic contract sequence finalizes at heights 9002..9008 and its
    # state readback is at 9010, so 8999 is the exact pre-authorization snapshot.
    body["snapshot_block_height"] = str(snapshot_block_height)
    header, body, _ = build_native_material(header, body)
    document["header"] = header
    document["body"] = body
    prepared = prepare_v3_envelope(document)

    transcripts, ids = _readback_fixture()
    old_proposal = ids["proposal"]
    old_proposal_key = (
        len(old_proposal.encode()).to_bytes(4, "little") + old_proposal.encode()
    )
    new_proposal_key = (
        len(proposal_id.encode()).to_bytes(4, "little") + proposal_id.encode()
    )
    role_accounts = {
        name: private.to_public_key().to_account_hash().hex()
        for name, private in _role_private_keys().items()
    }
    role_indexes = {
        4: "proposer",
        5: "finalizer",
        6: "signer_a",
        7: "signer_b",
        8: "signer_c",
    }
    replacements = {
        state_dictionary_key(11, old_proposal_key): state_dictionary_key(
            11, new_proposal_key
        ),
        state_dictionary_key(12, old_proposal_key): state_dictionary_key(
            12, new_proposal_key
        ),
        state_dictionary_key(14, old_proposal_key): state_dictionary_key(
            14, new_proposal_key
        ),
        state_dictionary_key(15, old_proposal_key): state_dictionary_key(
            15, new_proposal_key
        ),
        state_dictionary_key(16, bytes.fromhex(ids["action"])): (
            state_dictionary_key(16, bytes.fromhex(str(prepared["action_id"])))
        ),
    }
    for transcript in transcripts:
        params = transcript["params"]
        item_key = params.get("dictionary_item_key")
        if item_key == state_dictionary_key(2):
            transcript["response"]["result"]["stored_value"] = _cl_bytes(
                bytes.fromhex(str(header["deployment_domain"]))
            )
        for index, role in role_indexes.items():
            if item_key == state_dictionary_key(index):
                transcript["response"]["result"]["stored_value"] = _cl_bytes(
                    bytes.fromhex(role_accounts[role])
                )
        if item_key in replacements:
            params["dictionary_item_key"] = replacements[item_key]
        if item_key in (
            state_dictionary_key(11, old_proposal_key),
            state_dictionary_key(15, old_proposal_key),
        ):
            transcript["response"]["result"]["stored_value"] = _cl_bytes(
                bytes.fromhex(str(prepared["envelope_hash"]))
            )
        transcript["request"]["params"] = params
        transcript["canonical_sha256"] = hashlib.sha256(
            json.dumps(
                {
                    "request": transcript["request"],
                    "response": transcript["response"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()

    readback = build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=ids["package"],
        expected_contract_hash=ids["contract"],
        proposal_id=proposal_id,
        action_id=str(prepared["action_id"]),
    )
    original_parameters = live_proof_runner.create_deploy_parameters
    # pycspr's JSON form is minute-precision; use minute-aligned instants so
    # serialization round-trips without changing the header digest.
    timestamp = iter(range(1_784_750_400, 1_784_751_000, 60))

    def deterministic_parameters(
        signer: object,
        chain_name: str,
        **kwargs: object,
    ) -> object:
        return original_parameters(
            signer,
            chain_name,
            timestamp=next(timestamp),
            **kwargs,
        )

    with patch.object(
        live_proof_runner,
        "create_deploy_parameters",
        deterministic_parameters,
    ):
        run = _live_run(prepared, readback, ids)
    return {
        "schema_id": "concordia.v3-proof.v1",
        "deployment": _deployment_evidence(
            run,
            ids,
            str(header["deployment_domain"]),
        ),
        "input": document,
        "prepared": prepared,
        "run": run,
        "readback": readback,
    }


__all__ = ["treasury_v3_proof"]
