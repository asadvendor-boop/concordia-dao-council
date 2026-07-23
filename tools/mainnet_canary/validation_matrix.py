"""Reproducible control-behaviour matrix for the Mainnet canary CLI.

Purpose: let a reviewer obtain the evidence WITHOUT authoring adversarial
prose. Every row states a precondition, runs the real CLI, and records the
refusal code the tool actually produced. The output is a factual table plus
machine-readable JSON — there is no narrative to write.

This is SELF-verification evidence produced by the lane that wrote the code.
It is deliberately not a validation verdict: a reviewer should run this
against their own immutable checkout, read the script, and reach their own
GO / NO-GO. Its value is that the harness is already built and the results
are reproducible, not that the author vouches for them.

Safety: reads the repository, writes only inside a temporary directory, and
never signs, submits, or touches live artifacts. Run:

    python3 -m tools.mainnet_canary.validation_matrix [--json]
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
            "--ceiling", str(inputs["ceiling"]),
            "--measured-costs", str(inputs["measured"]),
            "--journal", str(tmp / f"journal-{label}.jsonl"),
            "--out-dir", str(tmp / f"staged-{label}"),
        ]
        for flag, value in argv.items():
            flat += [flag, value]
        return flat

    # An authorization whose ceiling was raised AFTER it was signed.
    forged = json.loads(Path(gates["authorization_path"]).read_text(encoding="utf-8"))
    forged["max_total_outlay_motes"] = str(
        int(forged["max_total_outlay_motes"]) * 10
    )
    forged_path = tmp / "authorization-edited-after-signing.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")

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

    rows: list[tuple[str, str, list[str]]] = [
        ("build attestation absent", "ARTIFACT_HASH_UNBACKED",
         stage_argv("a", **{"--attestation": str(tmp / "absent.json")})),
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
        ("all gates satisfied (positive control)", "<accepted>",
         stage_argv("ok")),
    ]

    results: list[dict[str, object]] = []
    for control, expected, argv in rows:
        code, document = _run_cli(argv)
        refusal = document.get("refusal")
        observed = refusal["code"] if refusal else "<accepted>"
        results.append(
            {
                "control": control,
                "expected": expected,
                "observed": observed,
                "exit_code": code,
                "pass": observed == expected,
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
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        width = max(len(str(row["control"])) for row in results)
        for row in results:
            mark = "PASS" if row["pass"] else "FAIL"
            print(
                f"  {mark}  {str(row['control']):<{width}}  "
                f"exit={row['exit_code']}  {row['observed']}"
            )
    failed = [row for row in results if not row["pass"]]
    print(f"\n{len(results) - len(failed)}/{len(results)} controls behaved as recorded")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
