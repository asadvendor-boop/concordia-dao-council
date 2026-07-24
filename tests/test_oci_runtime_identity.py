from __future__ import annotations

import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/shared-host/compose.prod.yml"
VALIDATOR = ROOT / "scripts/validate_oci_image_identity.sh"
PIN_RECORD = ROOT / "deploy/shared-host/OCI_IMAGE_PINS.md"
SOURCE = "https://github.com/asadvendor-boop/concordia-dao-council"
D = "71" * 20

PROJECT_BUILDS = {
    "gateway": ROOT / "Dockerfile",
    "dashboard": ROOT / "dashboard/Dockerfile",
    "x402-official": ROOT / "services/x402-official/Dockerfile",
}
PINNED_IMAGES = {
    "ipfs": (
        "ipfs/kubo@sha256:"
        "7cc0e0de8f845d6c9fa1dce414c069974c34ed3cd3742e0d4f5bccda4adc376d"
    ),
    "otel-collector": (
        "otel/opentelemetry-collector-contrib@sha256:"
        "37fa87091cfaaec7234a27e4e395a40c31c2bfaea97a349a4afef6d9e9681197"
    ),
    "jaeger": (
        "jaegertracing/all-in-one@sha256:"
        "836e9b69c88afbedf7683ea7162e179de63b1f981662e83f5ebb68badadc710f"
    ),
}


def _validate(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", str(VALIDATOR), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_identity_validator_accepts_only_one_exact_deployment_identity() -> None:
    accepted = _validate(D, D, SOURCE)
    assert accepted.returncode == 0, accepted.stderr
    assert accepted.stdout == ""
    assert accepted.stderr == ""

    for values in (
        (),
        (D,),
        ("", D, SOURCE),
        ("A" * 40, "A" * 40, SOURCE),
        ("1" * 39, "1" * 39, SOURCE),
        ("1" * 41, "1" * 41, SOURCE),
        (D, "72" * 20, SOURCE),
        (D, D, "https://example.invalid/repository"),
        (D, D, SOURCE, "extra"),
    ):
        refused = _validate(*values)
        assert refused.returncode != 0, values
        assert refused.stdout == ""
        assert "OCI_IMAGE_IDENTITY_INVALID" in refused.stderr
        assert D not in refused.stderr


def test_compose_pins_external_images_and_one_required_build_identity() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose["services"]

    for service, expected in PINNED_IMAGES.items():
        assert services[service]["image"] == expected

    expected_args = {
        "CONCORDIA_IMAGE_REVISION": (
            "${CONCORDIA_DEPLOYMENT_COMMIT:?Set exact 40-hex "
            "CONCORDIA_DEPLOYMENT_COMMIT}"
        ),
        "CONCORDIA_IMAGE_DEPLOYMENT": (
            "${CONCORDIA_DEPLOYMENT_COMMIT:?Set exact 40-hex "
            "CONCORDIA_DEPLOYMENT_COMMIT}"
        ),
        "CONCORDIA_IMAGE_SOURCE": SOURCE,
    }
    for service in PROJECT_BUILDS:
        actual_args = services[service]["build"]["args"]
        assert {
            name: actual_args[name] for name in expected_args
        } == expected_args


def test_all_project_images_validate_and_label_the_exact_build_args() -> None:
    for service, path in PROJECT_BUILDS.items():
        dockerfile = path.read_text(encoding="utf-8")
        for name in (
            "CONCORDIA_IMAGE_REVISION",
            "CONCORDIA_IMAGE_DEPLOYMENT",
            "CONCORDIA_IMAGE_SOURCE",
        ):
            assert f"ARG {name}\n" in dockerfile, service
            assert f"ARG {name}=" not in dockerfile, service
        assert "scripts/validate_oci_image_identity.sh" in dockerfile, service
        assert (
            'org.opencontainers.image.revision="${CONCORDIA_IMAGE_REVISION}"'
            in dockerfile
        ), service
        assert (
            'io.concordia.deployment-commit="${CONCORDIA_IMAGE_DEPLOYMENT}"'
            in dockerfile
        ), service
        assert "org.opencontainers.image.deployment=" not in dockerfile, service
        assert (
            'org.opencontainers.image.source="${CONCORDIA_IMAGE_SOURCE}"'
            in dockerfile
        ), service


def test_official_image_copies_only_service_inputs_from_repo_root_context() -> None:
    dockerfile = PROJECT_BUILDS["x402-official"].read_text(encoding="utf-8")
    assert dockerfile.count(
        "RUN /bin/sh /usr/local/bin/validate-oci-image-identity"
    ) == 2
    for source in (
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "src",
        "migrations",
    ):
        assert f"services/x402-official/{source}" in dockerfile
    assert "\nCOPY package.json " not in dockerfile
    assert "\nCOPY package.json\n" not in dockerfile
    assert "\nCOPY src " not in dockerfile
    assert "\nCOPY migrations " not in dockerfile


def test_pin_record_binds_registry_indexes_and_linux_amd64_children() -> None:
    record = PIN_RECORD.read_text(encoding="utf-8")
    expected = {
        "ipfs/kubo:v0.32.1": (
            "7cc0e0de8f845d6c9fa1dce414c069974c34ed3cd3742e0d4f5bccda4adc376d",
            "5b55e60dbe79e047ccfa58d6ac6640b81e9fab60d5a3ee10e7a4ccd9a1f1239f",
        ),
        "otel/opentelemetry-collector-contrib:0.114.0": (
            "37fa87091cfaaec7234a27e4e395a40c31c2bfaea97a349a4afef6d9e9681197",
            "94ac10da6c15fdad4f8091c4292a8c6814b467cd3bcf575ba2279e9dc6346e63",
        ),
        "jaegertracing/all-in-one:1.62.0": (
            "836e9b69c88afbedf7683ea7162e179de63b1f981662e83f5ebb68badadc710f",
            "53d140774b407d5e2a1b4eed556f1852595fc39e14b24acbceaf7e36691f3a60",
        ),
    }
    for tag, (index_digest, amd64_digest) in expected.items():
        assert tag in record
        assert index_digest in record
        assert amd64_digest in record
    assert "docker buildx imagetools inspect --raw" in record
    assert "docker pull" not in record
    assert "docker run" not in record
    assert "linux/amd64" in record
