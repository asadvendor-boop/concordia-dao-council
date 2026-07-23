"""Custody disclosure: declared twice, strictly validated, never inferred.

- the parameters schema (v2) REQUIRES custody_model; a v1-shaped document
  without it refuses (PLAN_INPUT_INVALID — exact field-set equality);
- only the frozen enum values are expressible (CUSTODY_MODEL_INVALID);
- the CLI/builder confirmation must equal the parameters declaration;
- independent_custodians refuses outright: this release carries no separate
  custody evidence, and distinct accounts or key mounts are not
  independence (CUSTODY_EVIDENCE_ABSENT);
- the plan (v2) and the proof bundle (v2) both carry the disclosure, and
  the bundle's copy must equal the plan's (BUNDLE_CROSS_BINDING_INVALID).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.proof_bundle import (
    REQUIRED_STATEMENT,
    build_proof_bundle_document,
    require_cross_binding,
)


def _rewrite_parameters(plan_inputs: dict[str, Path], **changes: object) -> None:
    path = plan_inputs["parameters"]
    document = json.loads(path.read_text(encoding="utf-8"))
    for key, value in changes.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    path.write_text(json.dumps(document), encoding="utf-8")


def _expect_plan_refusal(
    plan_inputs: dict[str, Path], code: str, **plan_kwargs: object
) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        mc_support.build_valid_plan({**plan_inputs, **plan_kwargs})
    assert refusal.value.code == code


class TestCustodyDeclaration:
    def test_plan_and_parameters_are_v2_and_disclose_custody(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        plan = mc_support.build_valid_plan(plan_inputs)
        assert plan["schema_id"] == "concordia.mainnet-canary.plan.v2"
        assert plan["custody_model"] == "single_operator"

    def test_missing_custody_model_refuses(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        # A v1-shaped parameters file (no custody_model) must fail closed,
        # never default: exact field-set equality catches the absence.
        _rewrite_parameters(
            plan_inputs,
            custody_model=None,
            schema_id="concordia.mainnet-canary.parameters.v1",
        )
        _expect_plan_refusal(plan_inputs, RefusalCode.PLAN_INPUT_INVALID)

    def test_unknown_custody_model_refuses(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        _rewrite_parameters(plan_inputs, custody_model="multi_sig")
        _expect_plan_refusal(
            plan_inputs,
            RefusalCode.CUSTODY_MODEL_INVALID,
            custody_model="multi_sig",
        )

    def test_confirmation_mismatch_refuses(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        _expect_plan_refusal(
            plan_inputs,
            RefusalCode.CUSTODY_MODEL_INVALID,
            custody_model="independent_custodians",
        )

    def test_independent_custodians_refuses_without_evidence(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        # Even when BOTH declarations agree: distinct accounts and key
        # mounts do not establish independence, and no separate custody
        # evidence mechanism exists in this release.
        _rewrite_parameters(
            plan_inputs, custody_model="independent_custodians"
        )
        _expect_plan_refusal(
            plan_inputs,
            RefusalCode.CUSTODY_EVIDENCE_ABSENT,
            custody_model="independent_custodians",
        )


def _bundle(custody_model: object) -> dict[str, object]:
    return build_proof_bundle_document(
        plan_hash="ab" * 32,
        rc_tag="rc-tag-v1",
        custody_model=custody_model,
        economic_manifest_sha256="cd" * 32,
        attestations={
            "testnet_wasm_sha256": "11" * 32,
            "mainnet_wasm_sha256": "22" * 32,
        },
        step_verifications={},
        journal_head_hash="ee" * 32,
        narrative=REQUIRED_STATEMENT,
    )


class TestBundleDisclosure:
    def test_bundle_requires_a_valid_custody_model(self) -> None:
        for invalid in (None, "", "multi_sig", 7):
            with pytest.raises(CanaryRefusal) as refusal:
                _bundle(invalid)
            assert refusal.value.code == RefusalCode.CUSTODY_MODEL_INVALID

    def test_bundle_custody_must_equal_the_plans(self) -> None:
        document = _bundle("single_operator")
        with pytest.raises(CanaryRefusal) as refusal:
            require_cross_binding(
                document,
                journal_plan_hash="ab" * 32,
                manifest_plan_hash="ab" * 32,
                verification_plan_hash="ab" * 32,
                journal_head_hash="ee" * 32,
                plan_custody_model="independent_custodians",
            )
        assert refusal.value.code == RefusalCode.BUNDLE_CROSS_BINDING_INVALID

    def test_matching_disclosure_binds(self) -> None:
        document = _bundle("single_operator")
        require_cross_binding(
            document,
            journal_plan_hash="ab" * 32,
            manifest_plan_hash="ab" * 32,
            verification_plan_hash="ab" * 32,
            journal_head_hash="ee" * 32,
            plan_custody_model="single_operator",
        )
        assert document["custody_model"] == "single_operator"
        assert document["schema_id"] == (
            "concordia.mainnet-canary.proof-bundle.v2"
        )
