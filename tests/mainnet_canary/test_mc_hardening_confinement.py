"""Path confinement, the redacting /supported probe, and the proof bundle.

Requirements under test:
- one centralized policy confines every output write: canonical/live/secret
  namespaces refuse, traversal and symlink escapes refuse, evidence is never
  overwritten, in-repo capture requires the supplemental namespace AND an
  explicit live-capture authorization that the preparation lane never sets;
- staging routes its unsigned-intent writes through the policy;
- the CSPR.cloud probe helper sends ``Authorization: <token>`` (NEVER
  ``Bearer``), and never emits response-body text from failed authenticated
  probes — hashes and allowlisted scalar fields only;
- the proof bundle carries lineage ``concordia-mainnet-canary-v1`` and the
  exact required statement, and refuses every forbidden claim.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.path_policy import CanaryPathPolicy
from tools.mainnet_canary.proof_bundle import (
    BUNDLE_LINEAGE,
    REQUIRED_STATEMENT,
    build_proof_bundle_document,
    scan_forbidden_claims,
    validate_bundle_document,
)
from tools.mainnet_canary.supported_probe import (
    build_authorization_header,
    redact_probe_observation,
)


@pytest.fixture()
def policy(hermetic_repo: Path, tmp_path: Path) -> CanaryPathPolicy:
    return CanaryPathPolicy(
        hermetic_repo, tmp_path / "out", canary_id="canary-test-01"
    )


class TestPathPolicy:
    def test_in_repo_root_requires_authorization(self, hermetic_repo: Path) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            CanaryPathPolicy(
                hermetic_repo,
                hermetic_repo / "artifacts" / "mainnet-canary" / "canary-test-01",
                canary_id="canary-test-01",
            )
        assert refusal.value.code == RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP

    @pytest.mark.parametrize(
        "namespace", ["artifacts/live/x", "artifacts/rwa/x", "handoff/HISTORICAL_x"]
    )
    def test_canonical_namespaces_refuse_even_when_authorized(
        self, hermetic_repo: Path, namespace: str
    ) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            CanaryPathPolicy(
                hermetic_repo,
                hermetic_repo / namespace,
                canary_id="canary-test-01",
                live_capture_authorized=True,
            )
        assert refusal.value.code in (
            RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
            RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP,
        )

    @pytest.mark.parametrize("relpath", ["/etc/target", "../escape", "a/../../b", ".hidden"])
    def test_traversal_and_bad_components_refuse(
        self, policy: CanaryPathPolicy, relpath: str
    ) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            policy.resolve(relpath)
        assert refusal.value.code == RefusalCode.CANONICAL_NAMESPACE_PROTECTED

    def test_symlinked_ancestor_refuses(
        self, policy: CanaryPathPolicy, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (tmp_path / "out").mkdir(exist_ok=True)
        os.symlink(outside, tmp_path / "out" / "leak")
        with pytest.raises(CanaryRefusal) as refusal:
            policy.resolve("leak/receipt.json")
        assert refusal.value.code == RefusalCode.CANONICAL_NAMESPACE_PROTECTED

    def test_exclusive_write_never_overwrites_different_evidence(
        self, policy: CanaryPathPolicy
    ) -> None:
        target = policy.exclusive_write_bytes("receipts/step.json", b"{\"a\":1}")
        assert target.read_bytes() == b"{\"a\":1}"
        # Identical bytes are an idempotent no-op (content-addressed restage)…
        policy.exclusive_write_bytes("receipts/step.json", b"{\"a\":1}")
        # …but different bytes at the same path can never replace evidence.
        with pytest.raises(CanaryRefusal) as refusal:
            policy.exclusive_write_bytes("receipts/step.json", b"{\"a\":2}")
        assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT
        assert target.read_bytes() == b"{\"a\":1}"

    def test_stage_routes_intent_writes_through_the_policy(
        self, plan_inputs: dict[str, Path], tmp_path: Path
    ) -> None:
        from tools.mainnet_canary.stage import run_stage

        plan = mc_support.build_valid_plan(plan_inputs)
        report = run_stage(
            plan_inputs["repo"],
            plan_document=plan,
            rc_declaration_path=plan_inputs["rc"],
            snapshot_path=plan_inputs["snapshot"],
            status_path=plan_inputs["status"],
            ceiling_path=plan_inputs["ceiling"],
            measured_costs_path=plan_inputs["measured"],
            journal_path=tmp_path / "stage-out" / "journal.jsonl",
            output_dir=tmp_path / "stage-out" / "intents",
        )
        assert report["path_policy"] == {
            "canary_id": plan["canary_plan_sha256"][:24] + "-prep",
            "live_capture_authorized": False,
            "output_root_in_repo": False,
        }
        for entry in report["staged_steps"]:
            assert Path(entry["unsigned_intent_path"]).is_file()


class TestSupportedProbe:
    def test_header_is_raw_token_never_bearer(self) -> None:
        headers = build_authorization_header("cspr-cloud-token-value")
        assert headers == {"Authorization": "cspr-cloud-token-value"}
        for poisoned in ("Bearer cspr-cloud-token", "bearer x", "Bearer  "):
            with pytest.raises(CanaryRefusal) as refusal:
                build_authorization_header(poisoned)
            assert refusal.value.code == RefusalCode.PROBE_HEADER_INVALID

    def test_empty_or_multiline_token_refuses(self) -> None:
        for bad in ("", "line1\nline2", "tab\tted", " padded "):
            with pytest.raises(CanaryRefusal) as refusal:
                build_authorization_header(bad)
            assert refusal.value.code == RefusalCode.PROBE_HEADER_INVALID

    def test_failed_authenticated_probe_body_is_never_reflected(self) -> None:
        body = json.dumps(
            {"error": "invalid authorization: cspr-cloud-token-value"}
        ).encode("utf-8")
        record = redact_probe_observation(
            url="https://api.cspr.cloud/supported",
            status_code=401,
            body_bytes=body,
            authenticated=True,
        )
        serialized = json.dumps(record)
        assert "cspr-cloud-token-value" not in serialized
        assert "invalid authorization" not in serialized
        assert record["body_disposition"] == "REDACTED_FAILED_AUTHENTICATED_PROBE"
        assert record["body_sha256"] is None
        assert record["endpoint_host"] == "api.cspr.cloud"

    def test_successful_probe_reports_hashes_and_allowlisted_scalars_only(self) -> None:
        body = json.dumps(
            {
                "supported": True,
                "network": "casper:casper",
                "asset_contract": "hash-" + "ab" * 32,
                "free_text_note": "ATTACKER CONTROLLED <script>",
            }
        ).encode("utf-8")
        record = redact_probe_observation(
            url="https://api.cspr.cloud/supported",
            status_code=200,
            body_bytes=body,
            authenticated=True,
        )
        serialized = json.dumps(record)
        assert "ATTACKER" not in serialized
        assert "free_text_note" not in record["sanitized_fields"]
        assert record["sanitized_fields"]["supported"] is True
        assert record["sanitized_fields"]["network"] == "casper:casper"
        assert len(record["body_sha256"]) == 64


class TestProofBundle:
    def _bundle(self) -> dict[str, object]:
        return build_proof_bundle_document(
            plan_hash="ab" * 32,
            rc_tag="rc-tag-v1",
            economic_manifest_sha256="cd" * 32,
            attestations={"testnet_wasm_sha256": "11" * 32, "mainnet_wasm_sha256": "22" * 32},
            step_verifications={"G-finalize-exact-envelope": {"consensus_block_hash": "6f" * 32}},
            journal_head_hash="ee" * 32,
            narrative=REQUIRED_STATEMENT,
        )

    def test_bundle_pins_lineage_and_required_statement(self) -> None:
        bundle = self._bundle()
        assert bundle["lineage"] == BUNDLE_LINEAGE == "concordia-mainnet-canary-v1"
        assert bundle["required_statement"] == REQUIRED_STATEMENT
        assert "off-chain bounded executor" in REQUIRED_STATEMENT
        validate_bundle_document(bundle)

    @pytest.mark.parametrize(
        "claim",
        [
            "The contract custodied the treasury funds during the canary.",
            "The contract disbursed funds to the recipient.",
            "Testnet and Mainnet Wasm artifacts are byte-identical.",
            "Official x402 settlement is supported on Casper Mainnet.",
            "A wallet transfer proves governance authorization.",
            "Historical evidence was rewritten to reflect the Mainnet run.",
        ],
    )
    def test_forbidden_claims_refuse(self, claim: str) -> None:
        assert scan_forbidden_claims(claim), claim
        bundle = self._bundle()
        bundle["notes"] = claim
        with pytest.raises(CanaryRefusal) as refusal:
            validate_bundle_document(bundle)
        assert refusal.value.code == RefusalCode.FORBIDDEN_CLAIM

    def test_required_statement_itself_is_not_forbidden(self) -> None:
        assert scan_forbidden_claims(REQUIRED_STATEMENT) == []

    def test_tampered_statement_refuses(self) -> None:
        bundle = self._bundle()
        bundle["required_statement"] = REQUIRED_STATEMENT.replace(
            "off-chain bounded executor", "on-chain contract"
        )
        with pytest.raises(CanaryRefusal) as refusal:
            validate_bundle_document(bundle)
        assert refusal.value.code == RefusalCode.FORBIDDEN_CLAIM
