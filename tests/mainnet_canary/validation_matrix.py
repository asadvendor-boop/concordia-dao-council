"""Reproducible control-behaviour matrix for the Mainnet canary CLI.

Purpose: let a reviewer obtain the evidence WITHOUT authoring adversarial
prose. Every row states a precondition, runs the real CLI, and records the
refusal code AND process exit code the tool actually produced. The output is
a factual table plus machine-readable JSON — there is no narrative to write.

WHAT THIS COMMAND DOES, STATED EXACTLY
--------------------------------------
It builds hermetic fixtures in a temporary directory, and one of those
fixtures is a **signed human authorization**: `mc_support.sign_authorization`
performs an ed25519 `private.sign(...)` over canonical bytes using a fixed,
test-only seed committed in the test support module. That signature
authorizes nothing outside these fixtures and cannot produce a transaction.

An earlier version of this docstring claimed the command "never signs".
That was false and a reviewer was right to reject it. The accurate claim is:

  * the PREPARATION PACKAGE (tools/mainnet_canary) has no live-key,
    deploy-signing, or submission path — a test scans its sources for the
    banned tokens, and that scan is deliberately scoped to the package;
  * THIS COMMAND generates exactly one hermetic test-authorization
    signature, from a fixed seed, inside a temp directory.

This module lives under tests/ precisely because of the above: it is
verification tooling that depends on test fixtures and signs them. Keeping it
out of tools/mainnet_canary keeps the shipped package free of both the
tests/ import inversion and any signing call.

It reads the repository, writes only inside a temporary directory, performs
no network I/O, and never submits anything.

STATUS OF THIS EVIDENCE
-----------------------
Self-verification evidence produced by the lane that wrote the code — NOT a
verdict. A reviewer should run it against their own immutable checkout, read
this script, and reach their own GO / NO-GO. Its value is that the harness
already exists and the results reproduce, not that the author vouches.

    python3 tests/mainnet_canary/validation_matrix.py [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_support():
    """Import the hermetic fixture builders used by the test suite."""

    sys.path.insert(0, str(REPO_ROOT))
    sys.path.insert(0, str(REPO_ROOT / "tests" / "mainnet_canary"))
    import mc_support  # noqa: PLC0415

    return mc_support


def _run_cli(argv: list[str]) -> tuple[int, dict]:
    from tools.mainnet_canary.cli import main  # noqa: PLC0415

    buffer = StringIO()
    with redirect_stdout(buffer):
        code = main(argv)
    try:
        return code, json.loads(buffer.getvalue())
    except json.JSONDecodeError:
        return code, {}


def build_matrix() -> list[dict[str, object]]:
    """Execute every control and record what the CLI actually did."""

    mc = _load_support()
    tmp = Path(tempfile.mkdtemp(prefix="canary-matrix-"))
    repo = mc.build_hermetic_repo(tmp)
    inputs = mc.build_plan_inputs(repo, tmp)
    plan = mc.build_valid_plan(inputs)
    plan_path = tmp / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    gates = mc.stage_gate_kwargs(inputs, tmp)
    key = mc.test_authorizer_public_key_hex()

    def stage_argv(label: str, **swap: str) -> list[str]:
        argv = {
            "--attestation": str(gates["attestation_path"]),
            "--calibration": str(gates["calibration_path"]),
            "--authorization": str(gates["authorization_path"]),
            "--clock-unix": str(gates["clock_unix"]),
            "--snapshot-corroboration": str(gates["snapshot_corroboration_path"]),
            "--authorizer-key": key,
        }
        argv.update(swap)
        flat: list[str] = [
            "--repo-root", str(repo), "stage",
            "--plan", str(plan_path),
            "--rc-declaration", str(inputs["rc"]),
            "--snapshot", str(inputs["snapshot"]),
            "--status", str(inputs["status"]),
            "--journal", str(tmp / f"journal-{label}.jsonl"),
            "--out-dir", str(tmp / f"staged-{label}"),
        ]
        for flag, value in argv.items():
            flat += [flag, value]
        return flat

    authorization = json.loads(
        Path(gates["authorization_path"]).read_text(encoding="utf-8")
    )

    # An authorization whose ceiling was raised AFTER it was signed. NOTE:
    # this trips the manifest-binding check, so it does NOT by itself prove
    # the signature is verified — hence the two cases after it.
    forged = dict(authorization)
    forged["max_total_outlay_motes"] = str(
        int(forged["max_total_outlay_motes"]) * 10
    )
    forged_path = tmp / "authorization-edited-after-signing.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")

    # Signature bytes corrupted, every bound field left INTACT. Binding
    # passes, so only the ed25519 verification can reject this — the case
    # that actually exercises the crypto path end to end.
    bad_signature = dict(authorization)
    flipped = "0" if authorization["signature_hex"][0] != "0" else "1"
    bad_signature["signature_hex"] = flipped + authorization["signature_hex"][1:]
    bad_signature_path = tmp / "authorization-signature-corrupted.json"
    bad_signature_path.write_text(json.dumps(bad_signature), encoding="utf-8")

    unsigned = dict(authorization)
    unsigned["signature_hex"] = ""
    unsigned_path = tmp / "authorization-unsigned.json"
    unsigned_path.write_text(json.dumps(unsigned), encoding="utf-8")

    # Bundle inputs: a real journal bound to this plan, plus a manifest and
    # a verification report. A second verification report claims a DIFFERENT
    # plan, to exercise the cross-binding check.
    from tools.mainnet_canary.economic_manifest import (  # noqa: PLC0415
        build_economic_manifest,
    )
    from tools.mainnet_canary.journal import CanaryJournal  # noqa: PLC0415

    journal_path = mc.terminal_journal_for(plan, tmp / "bundle-journal.jsonl")
    bundle_calibration = mc.make_calibration(plan)
    bundle_calibration_path = tmp / "bundle-calibration.json"
    bundle_calibration_path.write_text(
        json.dumps(bundle_calibration), encoding="utf-8"
    )
    manifest_path = tmp / "bundle-manifest.json"
    manifest_path.write_text(
        json.dumps(
            build_economic_manifest(
                plan,
                calibration=bundle_calibration,
                operator_ceilings={},
            )
        ),
        encoding="utf-8",
    )
    verification_path = tmp / "bundle-verification.json"
    verification_path.write_text(
        json.dumps(mc.full_verification_report(plan)), encoding="utf-8"
    )
    mismatched_report = mc.full_verification_report(plan)
    mismatched_report["plan_hash"] = "0" * 64
    mismatched_path = tmp / "bundle-verification-other-plan.json"
    mismatched_path.write_text(json.dumps(mismatched_report), encoding="utf-8")
    empty_report = mc.full_verification_report(plan)
    empty_report["steps"] = []
    empty_steps_path = tmp / "bundle-verification-empty-steps.json"
    empty_steps_path.write_text(json.dumps(empty_report), encoding="utf-8")

    def bundle_argv(label: str, verification: Path, out_dir: Path) -> list[str]:
        return [
            "--repo-root", str(repo), "bundle",
            "--plan", str(plan_path),
            "--verification", str(verification),
            "--economic-manifest", str(manifest_path),
            "--attestation", str(gates["attestation_path"]),
            "--calibration", str(bundle_calibration_path),
            "--authorization", str(gates["authorization_path"]),
            "--clock-unix", str(gates["clock_unix"]),
            "--authorizer-key", key,
            "--journal", str(journal_path),
            "--out-dir", str(out_dir),
        ]

    def observations(count: int, **provider_swap: object) -> Path:
        bundle: list[dict] = []
        for step in plan["steps"]:
            if not step["economic"]:
                continue
            pair = mc.make_v2_pair(str(step["step_id"]))
            for entry in pair[:count]:
                entry["provider"].update(provider_swap)
            bundle.extend(pair[:count])
        path = tmp / f"observations-{count}-{len(provider_swap)}.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    def satisfied_observations() -> Path:
        """A bundle that SATISFIES every economic step's expectation."""

        bundle: list[dict] = []
        for step in plan["steps"]:
            if not step["economic"]:
                continue
            expected = step["expected_outcome"]
            overrides: dict = {}
            if expected.get("execution") == "failure":
                overrides["execution"] = {
                    "success": False,
                    "error_message": expected["exact_error_message"],
                    "cost_motes": "100000000",
                }
            if step["kind"] == "native_transfer":
                overrides["target"] = {
                    "transfer": {
                        "source_account": expected["source_account"],
                        "recipient_account": expected["recipient_account"],
                        "amount_motes": expected["amount_motes"],
                        "transfer_id": str(
                            plan["envelope"]["derived"]["transfer_id"]
                        ),
                    }
                }
            bundle.extend(mc.make_v2_pair(str(step["step_id"]), **overrides))
        path = tmp / "observations-satisfied.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    def legacy_observations() -> Path:
        """v1-shaped bundle: no provider evidence at all."""

        bundle = [
            mc.make_observation(str(step["step_id"]))
            for step in plan["steps"]
            if step["economic"]
            for _ in (0, 1)
        ]
        path = tmp / "observations-legacy-v1.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    # Calibration-discipline fixtures: an operator-ceiling file (which the
    # finals policy refuses outright), a calibration with one line removed,
    # and a calibration rebound to a different plan hash.
    ceilings_path = tmp / "operator-ceilings.json"
    ceilings_path.write_text(
        json.dumps(
            {
                "B-install-rc-wasm": {
                    "conservative_ceiling_motes": "400000000000",
                    "declared_by": "asad-public-approval",
                }
            }
        ),
        encoding="utf-8",
    )
    full_calibration = mc.make_calibration(plan)
    short_calibration = json.loads(json.dumps(full_calibration))
    del short_calibration["lines"]["I-executor-native-transfer"]
    short_calibration_path = tmp / "calibration-missing-line.json"
    short_calibration_path.write_text(
        json.dumps(short_calibration), encoding="utf-8"
    )
    rebound_calibration = json.loads(json.dumps(full_calibration))
    rebound_calibration["mainnet_plan_hash"] = "0" * 64
    rebound_calibration_path = tmp / "calibration-other-plan.json"
    rebound_calibration_path.write_text(
        json.dumps(rebound_calibration), encoding="utf-8"
    )

    # Correction-round fixtures: a caller-authored attestation summary whose
    # recorded tag object does not recompute from the repository, and a
    # calibration whose embedded raw response bytes were edited after the
    # digests were recorded.
    fake_attestation = mc.make_attestation(repo)
    from tools.mainnet_canary.attestation import (  # noqa: PLC0415
        attestation_entry_digest,
    )
    for profile_entry in fake_attestation["network_artifacts"].values():
        profile_entry["tag_object_sha"] = "9" * 40
    fake_attestation["entry_digests"] = {
        profile: attestation_entry_digest(entry)
        for profile, entry in fake_attestation["network_artifacts"].items()
    }
    fake_attestation_path = tmp / "attestation-caller-authored.json"
    fake_attestation_path.write_text(
        json.dumps(fake_attestation), encoding="utf-8"
    )

    tampered_raw = json.loads(json.dumps(full_calibration))
    first_line = next(iter(tampered_raw["lines"].values()))
    first_obs = first_line["receipt"]["observations"][0]
    first_obs["raw_exchanges"]["info_get_status"]["response_body"] = (
        first_obs["raw_exchanges"]["info_get_status"]["response_body"].replace(
            "casper-test", "casper-fake"
        )
    )
    tampered_raw_path = tmp / "calibration-tampered-raw.json"
    tampered_raw_path.write_text(json.dumps(tampered_raw), encoding="utf-8")

    rows: list[tuple[str, str, list[str]]] = [
        ("build attestation absent", "ATTESTATION_NOT_EXECUTED",
         stage_argv("a", **{"--attestation": str(tmp / "absent.json")})),
        ("caller-authored attestation summary refuses",
         "ATTESTATION_NOT_EXECUTED",
         stage_argv("a2", **{"--attestation": str(fake_attestation_path)})),
        ("stale legacy ceiling input refuses as unsupported",
         "LEGACY_COST_INPUT_UNSUPPORTED",
         stage_argv("a3") + ["--ceiling", str(inputs["ceiling"])]),
        ("calibration raw evidence does not recompute",
         "RAW_EVIDENCE_MISMATCH",
         stage_argv("a4", **{"--calibration": str(tampered_raw_path)})),
        ("bundle with empty step verifications refuses",
         "PROOF_STEP_SET_MISMATCH",
         bundle_argv("e1", empty_steps_path, tmp / "bundle-empty")),
        ("authorization expired vs trusted clock", "AUTHORIZATION_EXPIRED",
         stage_argv("b", **{"--clock-unix": str(int(gates["clock_unix"]) + 999_999)})),
        ("authorizer outside the pinned set", "AUTHORIZER_NOT_PINNED",
         stage_argv("c", **{"--authorizer-key": "01" + "ff" * 32})),
        ("ceiling edited after signing", "AUTHORIZATION_INVALID",
         stage_argv("d", **{"--authorization": str(forged_path)})),
        ("treasury snapshot uncorroborated", "SNAPSHOT_NOT_CORROBORATED",
         stage_argv("e", **{"--snapshot-corroboration": str(tmp / "absent.json")})),
        ("single-source observations", "NODE_SET_INVALID",
         ["verify", "--plan", str(plan_path),
          "--observations", str(observations(1))]),
        ("block shallower than the required depth", "INSUFFICIENT_CONFIRMATIONS",
         ["verify", "--plan", str(plan_path),
          "--observations", str(observations(2, chain_tip_height=121))]),
        # These two isolate the ed25519 path. The ceiling-edit case above
        # trips manifest binding first, so without them nothing in this
        # matrix would prove the signature is actually verified.
        ("signature corrupted, bound fields intact",
         "AUTHORIZATION_SIGNATURE_INVALID",
         stage_argv("f", **{"--authorization": str(bad_signature_path)})),
        ("authorization carries no signature", "AUTHORIZATION_UNSIGNED",
         stage_argv("g", **{"--authorization": str(unsigned_path)})),
        ("calibration receipts absent", "CALIBRATION_RECEIPT_ABSENT",
         stage_argv("h", **{"--calibration": str(tmp / "absent.json")})),
        ("operator ceilings supplied (finals: receipts only)",
         "OPERATOR_CEILING_NOT_PERMITTED",
         stage_argv("i", **{"--operator-ceilings": str(ceilings_path)})),
        ("calibration missing one economic line",
         "CALIBRATION_LINE_SET_MISMATCH",
         stage_argv("j", **{"--calibration": str(short_calibration_path)})),
        ("calibration bound to a different plan",
         "CALIBRATION_BINDING_INVALID",
         stage_argv("k", **{"--calibration": str(rebound_calibration_path)})),
        ("custody confirmation disagrees with parameters",
         "CUSTODY_MODEL_INVALID",
         ["--repo-root", str(repo), "plan",
          "--rc-declaration", str(inputs["rc"]),
          "--key-inventory", str(inputs["inventory"]),
          "--parameters", str(inputs["parameters"]),
          "--snapshot", str(inputs["snapshot"]),
          "--status", str(inputs["status"]),
          "--custody-model", "independent_custodians"]),
        ("observations without provider evidence (v1)", "OBSERVATION_MALFORMED",
         ["verify", "--plan", str(plan_path),
          "--observations", str(legacy_observations())]),
        ("bundle constituents disagree on plan hash",
         "BUNDLE_CROSS_BINDING_INVALID",
         bundle_argv("x", mismatched_path, tmp / "bundle-mismatch")),
        ("bundle written into a protected namespace",
         "CANONICAL_NAMESPACE_PROTECTED",
         bundle_argv("y", verification_path, repo / "artifacts" / "live" / "x")),
        # The guard refuses at the FIRST unmet gate, which here is the absent
        # live-authorization mount — it never reaches the
        # not-implemented refusal. Recorded as the code actually produced
        # rather than the one I first assumed.
        ("broadcast is disabled (no authorization mount)",
         "BROADCAST_DISABLED_AUTHORIZATION_ABSENT",
         ["--repo-root", str(repo), "broadcast", "--plan", str(plan_path),
          "--journal", str(journal_path)]),
        ("all gates satisfied (positive control)", "<accepted>",
         stage_argv("ok")),
        ("bundle fully bound (positive control)", "<accepted>",
         bundle_argv("z", verification_path, tmp / "bundle-ok")),
        ("verify fully satisfied (positive control)", "<accepted>",
         ["verify", "--plan", str(plan_path),
          "--observations", str(satisfied_observations())]),
    ]

    results: list[dict[str, object]] = []
    for control, expected, argv in rows:
        code, document = _run_cli(argv)
        refusal = document.get("refusal")
        observed = refusal["code"] if refusal else "<accepted>"
        # The exit code is part of the contract, not decoration: a control
        # that printed the right refusal while exiting 0 would be a REAL
        # defect, and an oracle that only compared the code string would
        # score it PASS. Both must agree.
        expected_exit = 0 if expected == "<accepted>" else 2
        results.append(
            {
                "control": control,
                "expected": expected,
                "observed": observed,
                "expected_exit": expected_exit,
                "exit_code": code,
                "pass": observed == expected and code == expected_exit,
            }
        )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Record how each Mainnet canary control behaves."
    )
    parser.add_argument("--json", action="store_true", help="machine-readable")
    args = parser.parse_args(argv)

    results = build_matrix()
    failed = [row for row in results if not row["pass"]]
    if args.json:
        # ONLY JSON on stdout, so the output actually parses. The human
        # summary would otherwise trail the document as extra data.
        print(json.dumps({"results": results, "failed": len(failed)}, indent=2))
        return 1 if failed else 0
    width = max(len(str(row["control"])) for row in results)
    for row in results:
        mark = "PASS" if row["pass"] else "FAIL"
        print(
            f"  {mark}  {str(row['control']):<{width}}  "
            f"exit={row['exit_code']}  {row['observed']}"
        )
    print(f"\n{len(results) - len(failed)}/{len(results)} controls behaved as recorded")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
