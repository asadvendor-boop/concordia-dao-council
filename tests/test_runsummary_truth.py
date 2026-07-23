from __future__ import annotations

from gateway.app import _approval_ui_is_configured, _run_receipt_is_verified


class _RecordingRepository:
    def __init__(self, result: dict | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls: list[tuple[str, str, str | None]] = []

    def unique_green_public_item(
        self,
        proposal_id: str,
        proof_type: str,
        *,
        temporal_scope: str | None = None,
    ) -> dict | None:
        self.calls.append((proposal_id, proof_type, temporal_scope))
        if self.error is not None:
            raise self.error
        return self.result


def test_run_receipt_verification_requires_exact_green_historical_registry_item() -> None:
    repository = _RecordingRepository(result={"proof_id": "historical-v2"})

    assert _run_receipt_is_verified(
        repository,
        proposal_id="DAO-PROP-TEST",
        receipt_card_present=True,
    )
    assert repository.calls == [
        ("DAO-PROP-TEST", "historical_odra_receipt_v2", "historical")
    ]


def test_run_receipt_verification_never_uses_card_presence_as_proof() -> None:
    missing = _RecordingRepository(result=None)
    unavailable = _RecordingRepository(error=ValueError("registry unavailable"))

    assert not _run_receipt_is_verified(
        missing,
        proposal_id="DAO-PROP-TEST",
        receipt_card_present=True,
    )
    assert not _run_receipt_is_verified(
        unavailable,
        proposal_id="DAO-PROP-TEST",
        receipt_card_present=True,
    )
    assert not _run_receipt_is_verified(
        _RecordingRepository(result={"proof_id": "historical-v2"}),
        proposal_id="DAO-PROP-TEST",
        receipt_card_present=False,
    )


def test_approval_ui_configuration_requires_all_five_file_secrets(
    monkeypatch,
    tmp_path,
) -> None:
    names = (
        "APPROVAL_PROXY_SECRET",
        "APPROVAL_UI_USER",
        "APPROVAL_UI_APPROVER_ID",
        "APPROVAL_UI_BCRYPT_HASH",
        "APPROVAL_UI_CSRF_SECRET",
    )
    for index, name in enumerate(names):
        path = tmp_path / f"secret-{index}"
        path.write_text(f"value-{index}", encoding="utf-8")
        monkeypatch.setenv(f"{name}_FILE", str(path))
        monkeypatch.setenv(name, "direct-env-must-not-decide-readiness")

    assert _approval_ui_is_configured()

    monkeypatch.delenv("APPROVAL_UI_CSRF_SECRET_FILE")
    assert not _approval_ui_is_configured()
