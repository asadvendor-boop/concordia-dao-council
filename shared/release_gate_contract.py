"""Immutable command-gate contract shared by collectors and gate runners."""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Final

COMMAND_GATE_RECEIPT_SCHEMA_VERSION: Final = "concordia.command_gate_receipt.v3"
COMMAND_GATE_PUBLIC_BUILD_PROFILE_SCHEMA_VERSION: Final = (
    "concordia.dashboard_public_build_profile.v2"
)
COMMAND_GATE_G9_PUBLIC_BUILD_PROFILE = MappingProxyType(
    {
        "NEXT_PUBLIC_GATEWAY_URL": "",
        "NEXT_PUBLIC_CONCORDIA_MODE": "reviewer",
        "NEXT_PUBLIC_CSPR_CLICK_APP_ID": "0f892487-0a8c-45b5-8cea-bbe95c64",
    }
)
COMMAND_GATE_G9_LIVE_TEST_BUILD_PROFILE = MappingProxyType(
    {
        "NEXT_PUBLIC_GATEWAY_URL": "",
        "NEXT_PUBLIC_CONCORDIA_MODE": "live",
        "NEXT_PUBLIC_CSPR_CLICK_APP_ID": "0f892487-0a8c-45b5-8cea-bbe95c64",
    }
)
COMMAND_LOG_NORMALIZATION_SCHEMA_VERSION: Final = (
    "concordia.command_log_normalization.v1"
)
BOUND_COMMAND_SCHEMA_VERSION: Final = "concordia.bound_command.v1"
BOUND_TOOL_IDENTITY_SCHEMA_VERSION: Final = "concordia.bound_tool_identity.v1"
BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION: Final = (
    "concordia.bound_host_toolchain_receipt.v1"
)
BOUND_HOST_TOOLCHAIN_RECEIPT_PATH: Final = "release/receipts/HOST_TOOLCHAIN.json"
BOUND_HOST_TOOLCHAIN_RUNNER_PATH: Final = "scripts/build_release_manifest.py"
BOUND_HOST_AUTHORITY_DESCENDANT_PREFIXES: Final = (
    "release/receipts/",
    "release/captures/",
    "release/g13/",
)
BOUND_HOST_AUTHORITY_DESCENDANT_PATHS: Final = (
    "release/organizer/G12_RENDERED_LINK_AUDIT.json",
    "release/organizer/G12_RENDERED_LINK_INVOCATION.json",
    "release/RELEASE_MANIFEST.json",
    "release/G13_SUBMISSION_RECEIPT.json",
)
BOUND_GIT_CONFIG_OVERRIDES: Final = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "diff.external=",
    "-c",
    "core.pager=cat",
    "-c",
    "interactive.diffFilter=",
)
BOUND_HOST_ID_DOMAIN: Final = "CONCORDIA_BOUND_HOST_ID_V1\0"
BOUND_HOST_ID_POLICY = MappingProxyType(
    {
        "raw_identity_in_receipt": False,
        "darwin_source": "/usr/sbin/ioreg",
        "darwin_argv": (
            "ioreg",
            "-a",
            "-r",
            "-d",
            "1",
            "-c",
            "IOPlatformExpertDevice",
        ),
        "linux_sources": (
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
        ),
        "source_commit_binding": ("receipt_only_authority_commit_parent_source_commit"),
        "runner_sha256_binding": "exact_frozen_runner_bytes_at_source_commit",
        "authority_descendants": "closed_release_output_allowlist_only",
    }
)
G1_FREEZE_TAG: Final = "concordia-g1-freeze-v2.0-a"
G1_FREEZE_COMMIT: Final = "b24c0409023e6c4b56287d4fddc17bdb42d9b1ac"
G1_FREEZE_TAG_OBJECT: Final = "65772a09bf73e50f061a2e7728fa5d48538cdc61"
G11_CLAIM_POLICY_AUTHORITY_PATH: Final = "shared/g11_claim_policy_authority.py"
G11_CLAIM_POLICY_AUTHORITY_SCHEMA_VERSION: Final = (
    "concordia.g11_claim_policy_authority.v1"
)
G11_CLAIM_POLICY_PATH: Final = "handoff/G11_CLAIM_POLICY.json"
COMMAND_GATE_SECRET_COMPOSE_PATH: Final = "deploy/shared-host/compose.prod.yml"
COMMAND_GATE_SECRET_DIRECTORIES: Final = (
    "/run/secrets",
    "/opt/apps/concordia/secrets",
)
COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION: Final = "concordia.executable_chain.v1"
COMMAND_GATE_UV_PYTHON: Final = "python3.12"
COMMAND_GATE_EXECUTABLE_CHAIN_POLICY = MappingProxyType(
    {
        "maximum_shebang_depth": 8,
        "bind_shebang_interpreter": True,
        "bind_env_shebang_target": True,
        "uv_python": COMMAND_GATE_UV_PYTHON,
        "uv_python_preference": "only-system",
        "cargo_odra_subcommand": "cargo-odra",
        "cargo_compiler": "rustc",
        "cargo_compiler_commands": ("build", "test"),
        "locked_odra_wrapper": "scripts/run_locked_odra_build.py",
        "locked_odra_dependencies": ("cargo", "cargo-odra", "rustc"),
    }
)
COMMAND_GATE_EXECUTION_POLICY = MappingProxyType(
    {
        "trusted_git_path": "/usr/bin/git",
        "trusted_git_owner_uid": 0,
        "trusted_git_reject_group_or_other_write": True,
        "working_directory_descriptor_walk": "validation_only_not_execution_binding",
        "working_directory_execution_binding": (
            "path_revalidated_before_and_after_execution"
        ),
        "working_directory_reject_symlink_ancestors": True,
        "bind_resolved_entrypoint_once": True,
        "revalidate_executable_chain_before_and_after": True,
        "output_capture": "bounded_temporary_files",
        "maximum_output_stream_bytes": 64 * 1024 * 1024,
        "darwin_rosetta_native_architecture_detection": True,
        "credential_reversible_encodings": (
            "raw",
            "base64_standard_padded",
            "base64_standard_unpadded",
            "base64_urlsafe_padded",
            "base64_urlsafe_unpadded",
            "hex_lower",
            "hex_upper",
            "percent_upper",
        ),
        "arbitrary_encryption_detection": False,
        "post_receipt_link_full_revalidation": True,
        "receipt_account_home_path_redaction": "tokenized_without_username",
    }
)
COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS = MappingProxyType(
    {
        "cargo": "cargo 1.86.0-nightly (cecde95c1 2025-01-24)",
        "node": "v22.12.0",
        "npm": "11.6.2",
        "odra": "cargo-odra 0.1.7",
        "pytest": "pytest 9.0.3",
        "python": "Python 3.12.11",
        "rustc": (
            "rustc 1.86.0-nightly (854f22563 2025-01-31)\n"
            "binary: rustc\n"
            "commit-hash: 854f22563c8daf92709fae18ee6aed52953835cd\n"
            "commit-date: 2025-01-31\n"
            "host: aarch64-apple-darwin\n"
            "release: 1.86.0-nightly\n"
            "LLVM version: 19.1.7"
        ),
        "uv": "uv 0.10.12 (00d72dac7 2026-03-19 aarch64-apple-darwin)",
        "next": "Next.js v16.2.11",
        "playwright": "Version 1.58.2",
    }
)
BOUND_TOOL_POLICY = MappingProxyType(
    {
        "caller_path": "ignored",
        "resolution": "contract_absolute_candidates_or_sys_executable",
        "sys_executable_resolution": "resolved_runtime_binary",
        "symlink_chain_max_depth": 16,
        "mutable_tool_execution": "private_fsync_snapshot",
        "private_directory_mode": 0o700,
        "private_executable_mode": 0o500,
        "source_revalidation": "before_and_after",
        "snapshot_revalidation": "before_and_after",
        "node_command_asset_execution": ("explicit_closed_tree_private_fsync_snapshot"),
        "python_command_asset_execution": (
            "explicit_closed_tree_private_fsync_snapshot"
        ),
        "bound_data_input_execution": (
            "explicit_exact_regular_file_private_fsync_snapshot"
        ),
        "command_asset_revalidation": "source_and_snapshot_before_and_after",
        "version_policy": "exact_contract_or_accepted_host_receipt",
        "non_system_manifest_required": True,
        "system_tool_policy": "root_owned_nonwritable_ancestors",
        "stdout_stderr_capture": "separate_live_capped_files",
        "process_group_kill_on_limit_or_timeout": True,
        "process_group_kill_after_leader_exit": True,
        "process_launch_barrier": (
            "trusted_runtime_parent_release_pipe_before_target_exec"
        ),
        "process_launch_isolation": "isolated_no_site",
        "process_exec_status": "ready_then_cloexec_eof_or_fixed_failure",
        "process_signal_restoration": ("SIGPIPE", "SIGXFZ", "SIGXFSZ"),
        "process_launcher_environment": {
            "LANG": "C",
            "LC_ALL": "C",
        },
        "target_environment": "exact_parent_frame_not_launcher_environment",
        "process_exit_observation": ("nonreaping_darwin_kqueue_linux_waitid_or_pidfd"),
        "leader_reap_order": "after_group_and_detached_descendant_containment",
        "detached_descendant_containment": (
            "inherited_descriptor_scan_plus_darwin_active_tree_or_linux_nonce_sweep"
        ),
        "malicious_descendant_evasion_sandbox": False,
        "execution_trust_boundary": "exact_bound_trusted_code_not_hostile_code_sandbox",
        "tree_scan_binding": "path_pre_post_stat_and_content_revalidation_not_openat",
        "minimum_timeout_seconds": 5,
        "maximum_timeout_seconds": 180,
        "maximum_source_bytes": 512 * 1024 * 1024,
        "maximum_stream_bytes": 256 * 1024 * 1024,
        "allowed_environment_keys": (
            "CI",
            "DOCKER_CONFIG",
            "DOCKER_HOST",
            "GH_CONFIG_DIR",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_OPTIONAL_LOCKS",
            "GIT_TERMINAL_PROMPT",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "NPM_CONFIG_CACHE",
            "NPM_CONFIG_GLOBALCONFIG",
            "NPM_CONFIG_REGISTRY",
            "NPM_CONFIG_USERCONFIG",
            "NEXT_PUBLIC_CSPR_CLICK_APP_ID",
            "NEXT_PUBLIC_CONCORDIA_MODE",
            "NEXT_PUBLIC_GATEWAY_URL",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
        ),
        "fixed_path": "/usr/bin:/bin:/usr/sbin:/sbin",
        "accepted_identity_fields": (
            "schema_version",
            "tool_id",
            "resolution",
            "resolved_path_sha256",
            "symlink_chain_sha256",
            "source_sha256",
            "source_size",
            "source_mode",
            "source_owner_uid",
            "version",
            "dependencies",
        ),
        "accepted_receipt_reuse": "same_host_source_and_tool_identity_across_gates",
    }
)
BOUND_TOOL_SPECS = MappingProxyType(
    {
        "dig": MappingProxyType(
            {
                "absolute_candidates": ("/usr/bin/dig",),
                "use_sys_executable": False,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": None,
                "version_argv": ("dig", "-v"),
                "exact_version": None,
                "script_policy": "binary",
            }
        ),
        "docker": MappingProxyType(
            {
                "absolute_candidates": (
                    "/usr/bin/docker",
                    "/opt/homebrew/bin/docker",
                    "/usr/local/bin/docker",
                ),
                "use_sys_executable": False,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": None,
                "version_argv": ("docker", "--version"),
                "exact_version": None,
                "script_policy": "binary",
            }
        ),
        "gh": MappingProxyType(
            {
                "absolute_candidates": (
                    "/usr/bin/gh",
                    "/opt/homebrew/bin/gh",
                    "/usr/local/bin/gh",
                ),
                "use_sys_executable": False,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": None,
                "version_argv": ("gh", "--version"),
                "exact_version": None,
                "script_policy": "binary",
            }
        ),
        "git": MappingProxyType(
            {
                "absolute_candidates": ("/usr/bin/git",),
                "use_sys_executable": False,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": None,
                "version_argv": ("git", "--version"),
                "exact_version": None,
                "script_policy": "binary",
            }
        ),
        "node": MappingProxyType(
            {
                "absolute_candidates": (
                    "/usr/bin/node",
                    "/opt/homebrew/bin/node",
                    "/usr/local/bin/node",
                ),
                "use_sys_executable": False,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": None,
                "version_argv": ("node", "--version"),
                "exact_version": "v22.12.0",
                "script_policy": "binary",
            }
        ),
        "npm": MappingProxyType(
            {
                "absolute_candidates": (
                    "/usr/bin/npm",
                    "/opt/homebrew/bin/npm",
                    "/usr/local/bin/npm",
                ),
                "use_sys_executable": False,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": "node",
                "version_argv": ("npm", "--version"),
                "exact_version": "11.6.2",
                "script_policy": "node_launcher",
            }
        ),
        "python": MappingProxyType(
            {
                "absolute_candidates": (),
                "use_sys_executable": True,
                "manifest_required_when_mutable": True,
                "launcher_tool_id": None,
                "version_argv": ("python", "--version"),
                "exact_version": "Python 3.12.11",
                "script_policy": "binary",
            }
        ),
    }
)

COMMAND_GATE_RECEIPT_PATHS = MappingProxyType(
    {
        "G2": "release/receipts/G2_COMPONENT_GATES.json",
        "G9": "release/receipts/G9_FRONTEND_GATES.json",
        "G11": "release/receipts/G11_CLAIM_AUDIT.json",
    }
)
COMMAND_GATE_RUNNER_PATHS = MappingProxyType(
    {
        "G2": "scripts/run_g2_component_gates.py",
        "G9": "scripts/run_g9_frontend_gates.py",
        "G11": "scripts/run_g11_claim_audit.py",
    }
)
COMMAND_GATE_COMMANDS = MappingProxyType(
    {
        "G2": (
            (
                "python_components",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "-m",
                    "pytest",
                    "-q",
                ),
            ),
            (
                "v3_rust",
                "contracts/odra-governance-receipt-v3",
                ("cargo", "test", "--locked"),
            ),
            (
                "v3_wasm",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "scripts/run_locked_odra_build.py",
                    "--verify-only",
                ),
            ),
            ("verifier_install", "packages/verify", ("npm", "ci")),
            ("verifier_test", "packages/verify", ("npm", "test")),
            ("verifier_lint", "packages/verify", ("npm", "run", "lint")),
            (
                "verifier_audit",
                "packages/verify",
                ("npm", "audit", "--audit-level=high"),
            ),
            ("official_x402_install", "services/x402-official", ("npm", "ci")),
            (
                "official_x402_build",
                "services/x402-official",
                ("npm", "run", "build"),
            ),
            (
                "official_x402_typecheck",
                "services/x402-official",
                ("npm", "run", "typecheck"),
            ),
            ("official_x402_test", "services/x402-official", ("npm", "test")),
            (
                "official_x402_audit",
                "services/x402-official",
                ("npm", "audit", "--audit-level=high"),
            ),
        ),
        "G9": (
            ("dashboard_install", "dashboard", ("npm", "ci")),
            ("dashboard_unit", "dashboard", ("npm", "run", "test:unit")),
            (
                "dashboard_live_build",
                "dashboard",
                ("npm", "run", "build:e2e:live"),
            ),
            (
                "dashboard_live_e2e",
                "dashboard",
                ("npm", "run", "test:e2e:live"),
            ),
            ("dashboard_build", "dashboard", ("npm", "run", "build")),
            (
                "dashboard_reviewer_e2e",
                "dashboard",
                ("npm", "run", "test:e2e:reviewer"),
            ),
            (
                "dashboard_audit",
                "dashboard",
                ("npm", "audit", "--audit-level=high"),
            ),
        ),
        "G11": (
            (
                "claim_audit",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "scripts/run_g11_claim_audit.py",
                    "--verify-only",
                ),
            ),
        ),
    }
)
COMMAND_GATE_REQUIRED_RUNTIMES = MappingProxyType(
    {
        "G2": ("cargo", "node", "npm", "odra", "pytest", "python", "rustc", "uv"),
        "G9": ("next", "node", "npm", "playwright"),
        "G11": ("python", "uv"),
    }
)

COMMAND_GATE_NORMALIZATION = MappingProxyType(
    {
        "schema_version": COMMAND_LOG_NORMALIZATION_SCHEMA_VERSION,
        "repository_root_token": "<REPOSITORY_ROOT>",
        "temporary_root_token": "<TEMP_ROOT>",
        "account_home_token": "<USER_HOME>",
        "encoding": "utf-8",
        "encoding_errors": "strict",
        "line_endings": "lf",
        "trailing_newline": "preserve",
        "path_aliases": (
            "literal",
            "resolved",
            "darwin-private-var",
            "darwin-private-tmp",
        ),
        "maximum_log_bytes": 64 * 1024 * 1024,
    }
)

# These are repository-tracked outputs whose bytes make each successful gate
# meaningful after its command logs have been normalized.
COMMAND_GATE_PRODUCED_ARTIFACT_PATHS = MappingProxyType(
    {
        "G2": (
            "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm",
            (
                "contracts/odra-governance-receipt-v3/resources/"
                "casper_contract_schemas/governance_receiptv3_schema.json"
            ),
        ),
        "G9": (
            "dashboard/.next/BUILD_ID",
            "dashboard/.next/build-manifest.json",
            "dashboard/.next/routes-manifest.json",
        ),
        "G11": (
            "README.md",
            "docs/POLICY_TEMPLATES.md",
            "docs/TECHNICAL_JURY_NOTE.md",
            "docs/DORAHACKS_SUBMISSION_TEXT.md",
            "docs/DEMO_SCRIPT.md",
            "docs/CLAIM_TO_ARTIFACT_MAP.json",
        ),
    }
)

COMMAND_GATE_INPUT_ARTIFACT_PATHS = MappingProxyType(
    {
        "G2": (),
        "G9": (),
        "G11": (
            "handoff/G11_CLAIM_POLICY.json",
            "artifacts/live/proof-registry/registry.json",
        ),
    }
)

COMMAND_GATE_FRESH_OUTPUT_PATHS = MappingProxyType(
    {
        "G2": (),
        "G9": ("dashboard/.next",),
        "G11": (),
    }
)

COMMAND_GATE_IDENTITY_PATHS = MappingProxyType(
    {
        "G2": (
            COMMAND_GATE_SECRET_COMPOSE_PATH,
            "scripts/run_g2_component_gates.py",
            "scripts/release_gate_runner.py",
            "shared/release_gate_contract.py",
            "shared/bound_command.py",
            "scripts/run_locked_odra_build.py",
        ),
        "G9": (
            COMMAND_GATE_SECRET_COMPOSE_PATH,
            "scripts/run_g9_frontend_gates.py",
            "scripts/release_gate_runner.py",
            "shared/release_gate_contract.py",
            "shared/bound_command.py",
        ),
        "G11": (
            COMMAND_GATE_SECRET_COMPOSE_PATH,
            "scripts/run_g11_claim_audit.py",
            "scripts/release_gate_runner.py",
            "shared/release_gate_contract.py",
            "shared/bound_command.py",
            "shared/proof_registry.py",
            "handoff/G11_CLAIM_POLICY.json",
            G11_CLAIM_POLICY_AUTHORITY_PATH,
        ),
    }
)

COMMAND_GATE_RUNTIME_PROBES = MappingProxyType(
    {
        "G2": (
            (
                "cargo",
                "contracts/odra-governance-receipt-v3",
                ("cargo", "--version"),
            ),
            ("node", ".", ("node", "--version")),
            ("npm", ".", ("npm", "--version")),
            (
                "odra",
                "contracts/odra-governance-receipt-v3",
                ("cargo", "odra", "--version"),
            ),
            (
                "pytest",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "-m",
                    "pytest",
                    "--version",
                ),
            ),
            (
                "python",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "--version",
                ),
            ),
            (
                "rustc",
                "contracts/odra-governance-receipt-v3",
                ("rustc", "-vV"),
            ),
            ("uv", ".", ("uv", "--version")),
        ),
        "G9": (
            ("next", "dashboard", ("node_modules/.bin/next", "--version")),
            ("node", "dashboard", ("node", "--version")),
            ("npm", "dashboard", ("npm", "--version")),
            (
                "playwright",
                "dashboard",
                ("node_modules/.bin/playwright", "--version"),
            ),
        ),
        "G11": (
            (
                "python",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "--version",
                ),
            ),
            ("uv", ".", ("uv", "--version")),
        ),
    }
)

COMMAND_GATE_TIMEOUT_SECONDS = MappingProxyType(
    {
        "G2": (1800, 1800, 1800, 900, 900, 900, 900, 900, 900, 900, 900, 900),
        "G9": (900, 900, 900, 1800, 900, 900, 900),
        "G11": (300,),
    }
)
COMMAND_GATE_RUNTIME_TIMEOUT_SECONDS: Final = 60

_FROZEN_COLLECTOR_CONTRACT_SHA256: Final = (
    "8a919b2ed38d11d08ca249a1801ab50aa5a51287335fbd577460fe6aa55367df"
)


def collector_contract_projection() -> dict[str, object]:
    """Return the exact value hashed by the collector-contract regression gate."""

    return {
        "receipt_schema": COMMAND_GATE_RECEIPT_SCHEMA_VERSION,
        "public_build_profile": {
            "schema_version": COMMAND_GATE_PUBLIC_BUILD_PROFILE_SCHEMA_VERSION,
            "g9_production_values": dict(COMMAND_GATE_G9_PUBLIC_BUILD_PROFILE),
            "g9_live_test_values": dict(
                COMMAND_GATE_G9_LIVE_TEST_BUILD_PROFILE
            ),
        },
        "g1_freeze_tag": G1_FREEZE_TAG,
        "g1_freeze_tag_object": G1_FREEZE_TAG_OBJECT,
        "g1_freeze_commit": G1_FREEZE_COMMIT,
        "g11_claim_policy_authority": {
            "path": G11_CLAIM_POLICY_AUTHORITY_PATH,
            "schema_version": G11_CLAIM_POLICY_AUTHORITY_SCHEMA_VERSION,
            "policy_path": G11_CLAIM_POLICY_PATH,
        },
        "secret_compose_path": COMMAND_GATE_SECRET_COMPOSE_PATH,
        "secret_directories": COMMAND_GATE_SECRET_DIRECTORIES,
        "executable_chain": {
            "schema_version": COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION,
            "policy": dict(COMMAND_GATE_EXECUTABLE_CHAIN_POLICY),
        },
        "execution_policy": dict(COMMAND_GATE_EXECUTION_POLICY),
        "bound_command": {
            "schema_version": BOUND_COMMAND_SCHEMA_VERSION,
            "tool_identity_schema_version": BOUND_TOOL_IDENTITY_SCHEMA_VERSION,
            "host_receipt_schema_version": (
                BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION
            ),
            "host_receipt_path": BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
            "host_receipt_runner_path": BOUND_HOST_TOOLCHAIN_RUNNER_PATH,
            "host_authority_descendant_prefixes": (
                BOUND_HOST_AUTHORITY_DESCENDANT_PREFIXES
            ),
            "host_authority_descendant_paths": (BOUND_HOST_AUTHORITY_DESCENDANT_PATHS),
            "git_config_overrides": BOUND_GIT_CONFIG_OVERRIDES,
            "host_id_domain": BOUND_HOST_ID_DOMAIN,
            "host_id_policy": dict(BOUND_HOST_ID_POLICY),
            "policy": dict(BOUND_TOOL_POLICY),
            "specs": {
                tool_id: dict(spec) for tool_id, spec in BOUND_TOOL_SPECS.items()
            },
        },
        "normalization": dict(COMMAND_GATE_NORMALIZATION),
        "receipt_paths": dict(COMMAND_GATE_RECEIPT_PATHS),
        "runner_paths": dict(COMMAND_GATE_RUNNER_PATHS),
        "commands": dict(COMMAND_GATE_COMMANDS),
        "required_runtimes": dict(COMMAND_GATE_REQUIRED_RUNTIMES),
        "runtime_probes": dict(COMMAND_GATE_RUNTIME_PROBES),
        "expected_runtime_versions": dict(COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS),
        "command_timeouts": dict(COMMAND_GATE_TIMEOUT_SECONDS),
        "runtime_timeout": COMMAND_GATE_RUNTIME_TIMEOUT_SECONDS,
        "produced_artifact_paths": dict(COMMAND_GATE_PRODUCED_ARTIFACT_PATHS),
        "input_artifact_paths": dict(COMMAND_GATE_INPUT_ARTIFACT_PATHS),
        "fresh_output_paths": dict(COMMAND_GATE_FRESH_OUTPUT_PATHS),
        "identity_paths": dict(COMMAND_GATE_IDENTITY_PATHS),
    }


def collector_contract_sha256() -> str:
    """Recompute the frozen collector constant-block digest."""

    raw = json.dumps(
        collector_contract_projection(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


if collector_contract_sha256() != _FROZEN_COLLECTOR_CONTRACT_SHA256:
    raise RuntimeError("release command-gate collector contract drifted")
