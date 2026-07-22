from __future__ import annotations

import hashlib
import importlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from gateway.database import init_db


NOW = "2026-07-23T00:00:00Z"
SOURCE_URL = "https://concordia.example/proof-artifacts/v1/DAO-PROP-CARDS/card-chain"


def _canonical_card(
    sequence_number: int,
    card_type: str,
    previous_card_hash: str | None,
    *,
    marker: str,
    proposal_id: str = "DAO-PROP-CARDS",
) -> str:
    # Deliberate whitespace and non-ASCII content prove that publication keeps
    # the stored UTF-8 preimage instead of parsing and reserializing it.
    identity = (
        {"signal_id": proposal_id}
        if card_type == "ProposalCard"
        else {"proposal_id": proposal_id}
    )
    return json.dumps(
        {
            "card_type": card_type,
            **identity,
            "marker": marker,
            "previous_card_hash": previous_card_hash,
            "sequence_number": sequence_number,
        },
        ensure_ascii=False,
        sort_keys=False,
        indent=1,
    )


def _insert_chain(db, proposal_id: str = "DAO-PROP-CARDS") -> list[tuple[str, str]]:
    db.execute(
        "INSERT INTO proposals (proposal_id, state, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (proposal_id, "RESOLVED", NOW, NOW),
    )
    first_json = _canonical_card(
        1,
        "ProposalCard",
        None,
        marker="café",
        proposal_id=proposal_id,
    )
    first_hash = hashlib.sha256(first_json.encode("utf-8")).hexdigest()
    second_json = _canonical_card(
        2,
        "Verdict",
        first_hash,
        marker="dissent",
        proposal_id=proposal_id,
    )
    second_hash = hashlib.sha256(second_json.encode("utf-8")).hexdigest()
    for sequence_number, card_type, card_hash, card_json, published_at in (
        (1, "ProposalCard", first_hash, first_json, NOW),
        (2, "Verdict", second_hash, second_json, None),
    ):
        db.execute(
            "INSERT INTO cards ("
            "proposal_id, sequence_number, card_type, card_hash, card_json, created_at, published_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                proposal_id,
                sequence_number,
                card_type,
                card_hash,
                card_json,
                NOW,
                published_at,
            ),
        )
    return [(first_json, first_hash), (second_json, second_hash)]


def test_card_chain_artifact_preserves_exact_stored_preimages_and_shape() -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    expected = _insert_chain(db)
    changes_before = db.total_changes

    artifact = module.build_card_chain_artifact(
        db,
        proposal_id="DAO-PROP-CARDS",
        captured_at=NOW,
        source_url=SOURCE_URL,
    )

    assert set(artifact) == {
        "schema_version",
        "proposal_id",
        "captured_at",
        "source_url",
        "cards",
    }
    assert artifact["schema_version"] == "concordia.card_chain.v1"
    assert artifact["proposal_id"] == "DAO-PROP-CARDS"
    assert artifact["captured_at"] == NOW
    assert artifact["source_url"] == SOURCE_URL
    assert len(artifact["cards"]) == 2
    for index, card in enumerate(artifact["cards"]):
        expected_json, expected_hash = expected[index]
        assert set(card) == {
            "sequence_number",
            "card_type",
            "card_hash",
            "canonical_card_json",
            "published_at",
        }
        assert card["canonical_card_json"].encode("utf-8") == expected_json.encode("utf-8")
        assert card["card_hash"] == expected_hash
    assert db.total_changes == changes_before


def test_card_chain_artifact_rejects_a_known_proposal_with_no_cards() -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    db.execute(
        "INSERT INTO proposals (proposal_id, state, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("DAO-PROP-EMPTY", "DETECTED", NOW, NOW),
    )

    with pytest.raises(module.CardChainArtifactError, match="non-empty"):
        module.build_card_chain_artifact(
            db,
            proposal_id="DAO-PROP-EMPTY",
            captured_at=NOW,
            source_url="https://concordia.example/proof-artifacts/v1/DAO-PROP-EMPTY/card-chain",
        )


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("hash", "hash"),
        ("sequence", "sequence"),
        ("card_type", "card_type"),
        ("linkage", "previous_card_hash"),
        ("embedded_hash", "card_hash"),
        ("missing_previous", "previous_card_hash"),
        ("duplicate_key", "duplicate"),
        ("invalid_json", "JSON"),
    ],
)
def test_card_chain_artifact_rejects_malformed_or_unlinked_rows(
    mutation: str,
    expected_error: str,
) -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    _insert_chain(db)

    if mutation == "hash":
        db.execute("UPDATE cards SET card_hash=? WHERE sequence_number=2", ("0" * 64,))
    elif mutation == "sequence":
        db.execute("UPDATE cards SET sequence_number=3 WHERE sequence_number=2")
    elif mutation == "card_type":
        db.execute("UPDATE cards SET card_type='Assessment' WHERE sequence_number=2")
    elif mutation == "missing_previous":
        raw = json.dumps(
            {
                "sequence_number": 1,
                "card_type": "ProposalCard",
                "signal_id": "DAO-PROP-CARDS",
            },
            separators=(",", ":"),
        )
        db.execute("DELETE FROM cards WHERE sequence_number=2")
        db.execute(
            "UPDATE cards SET card_json=?, card_hash=? WHERE sequence_number=1",
            (raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()),
        )
    else:
        first_hash = db.execute(
            "SELECT card_hash FROM cards WHERE sequence_number=1"
        ).fetchone()["card_hash"]
        if mutation == "linkage":
            raw = _canonical_card(2, "Verdict", "1" * 64, marker="dissent")
        elif mutation == "embedded_hash":
            raw = json.dumps(
                {
                    "sequence_number": 2,
                    "card_type": "Verdict",
                    "previous_card_hash": first_hash,
                    "card_hash": "2" * 64,
                    "proposal_id": "DAO-PROP-CARDS",
                },
                separators=(",", ":"),
            )
        elif mutation == "duplicate_key":
            raw = (
                '{"sequence_number":2,"sequence_number":2,"card_type":"Verdict",'
                f'"previous_card_hash":"{first_hash}","proposal_id":"DAO-PROP-CARDS"}}'
            )
        else:
            raw = "{not-json"
        db.execute(
            "UPDATE cards SET card_json=?, card_hash=? WHERE sequence_number=2",
            (raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()),
        )

    with pytest.raises(module.CardChainArtifactError, match=expected_error):
        module.build_card_chain_artifact(
            db,
            proposal_id="DAO-PROP-CARDS",
            captured_at=NOW,
            source_url=SOURCE_URL,
        )


def test_card_chain_artifact_uses_one_read_transaction_and_does_not_mutate() -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    _insert_chain(db)
    rows_before = list(db.iterdump())
    changes_before = db.total_changes
    statements: list[str] = []
    db.set_trace_callback(statements.append)

    module.build_card_chain_artifact(
        db,
        proposal_id="DAO-PROP-CARDS",
        captured_at=NOW,
        source_url=SOURCE_URL,
    )
    db.set_trace_callback(None)

    transaction_statements = [
        statement.strip().upper()
        for statement in statements
        if statement.strip().upper().startswith(("BEGIN", "COMMIT", "ROLLBACK"))
    ]
    reads = [statement for statement in statements if statement.lstrip().upper().startswith("SELECT")]
    mutations = [
        statement
        for statement in statements
        if statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE"))
    ]
    assert transaction_statements == ["BEGIN DEFERRED", "COMMIT"]
    assert len(reads) == 1
    assert mutations == []
    assert db.total_changes == changes_before
    assert list(db.iterdump()) == rows_before


def test_card_chain_artifact_rejects_secret_like_exact_preimage_without_rewriting_it() -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    _insert_chain(db)
    original = json.dumps(
        {
            "sequence_number": 1,
            "card_type": "ProposalCard",
            "previous_card_hash": None,
            "signal_id": "DAO-PROP-CARDS",
            "api_key": "sk-live-secret-that-must-never-leak",
        },
        separators=(",", ":"),
    )
    original_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()
    db.execute("DELETE FROM cards WHERE sequence_number=2")
    db.execute(
        "UPDATE cards SET card_json=?, card_hash=? WHERE sequence_number=1",
        (original, original_hash),
    )

    with pytest.raises(module.CardChainArtifactError, match="secret-like"):
        module.build_card_chain_artifact(
            db,
            proposal_id="DAO-PROP-CARDS",
            captured_at=NOW,
            source_url=SOURCE_URL,
        )

    stored = db.execute("SELECT card_json FROM cards WHERE sequence_number=1").fetchone()[0]
    assert stored == original


def test_card_chain_artifact_allows_public_authorization_ids_and_token_usage_counts() -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    _insert_chain(db)
    raw = json.dumps(
        {
            "sequence_number": 1,
            "card_type": "ProposalCard",
            "previous_card_hash": None,
            "signal_id": "DAO-PROP-CARDS",
            "authorization_id": "public-approval-id",
            "token_usage": {"prompt_tokens": 12},
        },
        separators=(",", ":"),
    )
    db.execute("DELETE FROM cards WHERE sequence_number=2")
    db.execute(
        "UPDATE cards SET card_json=?, card_hash=? WHERE sequence_number=1",
        (raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()),
    )

    artifact = module.build_card_chain_artifact(
        db,
        proposal_id="DAO-PROP-CARDS",
        captured_at=NOW,
        source_url=SOURCE_URL,
    )

    assert artifact["cards"][0]["canonical_card_json"] == raw


def test_card_chain_artifact_enforces_card_count_and_byte_bounds(monkeypatch) -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    _insert_chain(db)

    monkeypatch.setattr(module, "MAX_CARD_COUNT", 1)
    with pytest.raises(module.CardChainArtifactError, match="card-count"):
        module.build_card_chain_artifact(
            db,
            proposal_id="DAO-PROP-CARDS",
            captured_at=NOW,
            source_url=SOURCE_URL,
        )

    monkeypatch.setattr(module, "MAX_CARD_COUNT", 256)
    monkeypatch.setattr(module, "MAX_CARD_JSON_BYTES", 32)
    with pytest.raises(module.CardChainArtifactError, match="card_json size"):
        module.build_card_chain_artifact(
            db,
            proposal_id="DAO-PROP-CARDS",
            captured_at=NOW,
            source_url=SOURCE_URL,
        )


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        ("proposal_id", "../private", "proposal_id"),
        ("captured_at", "2026-07-23T05:00:00+05:00", "captured_at"),
        ("source_url", "http://attacker.example/card-chain", "source_url"),
    ],
)
def test_card_chain_artifact_rejects_invalid_public_metadata(
    field: str,
    value: str,
    expected_error: str,
) -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    _insert_chain(db)
    kwargs = {
        "proposal_id": "DAO-PROP-CARDS",
        "captured_at": NOW,
        "source_url": SOURCE_URL,
    }
    kwargs[field] = value

    with pytest.raises(module.CardChainArtifactError, match=expected_error):
        module.build_card_chain_artifact(db, **kwargs)


def test_public_card_chain_route_is_exact_read_only_and_never_cached(tmp_path, monkeypatch) -> None:
    from gateway.app import create_app

    db_path = tmp_path / "gateway.db"
    db = init_db(db_path)
    expected = _insert_chain(db)
    db.close()
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://proofs.concordia.example")

    with TestClient(create_app(db_path=str(db_path))) as client:
        response = client.get("/proof-artifacts/v1/DAO-PROP-CARDS/card-chain")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["source_url"] == (
        "https://proofs.concordia.example/proof-artifacts/v1/DAO-PROP-CARDS/card-chain"
    )
    assert re.fullmatch(
        r"2026-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
        payload["captured_at"],
    )
    assert [card["canonical_card_json"] for card in payload["cards"]] == [
        value[0] for value in expected
    ]
    reopened = init_db(db_path)
    assert reopened.execute("SELECT COUNT(*) FROM cards").fetchone()[0] == 2
    reopened.close()


def test_public_card_chain_route_404s_unknown_and_fails_closed_on_unsafe_rows(
    tmp_path,
    monkeypatch,
) -> None:
    from gateway.app import create_app

    db_path = tmp_path / "gateway.db"
    db = init_db(db_path)
    _insert_chain(db)
    unsafe = json.dumps(
        {
            "sequence_number": 1,
            "card_type": "ProposalCard",
            "previous_card_hash": None,
            "signal_id": "DAO-PROP-CARDS",
            "private_key": "-----BEGIN PRIVATE KEY-----never-publish",
        },
        separators=(",", ":"),
    )
    db.execute("DELETE FROM cards WHERE sequence_number=2")
    db.execute(
        "UPDATE cards SET card_json=?, card_hash=? WHERE sequence_number=1",
        (unsafe, hashlib.sha256(unsafe.encode("utf-8")).hexdigest()),
    )
    db.close()
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://proofs.concordia.example")

    with TestClient(create_app(db_path=str(db_path))) as client:
        unknown = client.get("/proof-artifacts/v1/DAO-PROP-UNKNOWN/card-chain")
        blocked = client.get("/proof-artifacts/v1/DAO-PROP-CARDS/card-chain")

    assert unknown.status_code == 404
    assert unknown.json() == {"error": "proposal_not_found"}
    assert unknown.headers["cache-control"] == "no-store"
    assert blocked.status_code == 503
    assert blocked.json() == {"error": "card_chain_artifact_unavailable"}
    assert blocked.headers["cache-control"] == "no-store"
    assert "PRIVATE KEY" not in blocked.text


def test_card_chain_artifact_rejects_cross_proposal_transplant_and_relabeling() -> None:
    module = importlib.import_module("shared.card_chain_artifact")
    db = init_db(":memory:")
    relabeled_proposal_id = "DAO-PROP-RELABELLED"
    db.execute(
        "INSERT INTO proposals (proposal_id, state, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (relabeled_proposal_id, "RESOLVED", NOW, NOW),
    )
    first_json = json.dumps(
        {
            "sequence_number": 1,
            "card_type": "ProposalCard",
            "previous_card_hash": None,
            "signal_id": "DAO-PROP-ORIGINAL",
        },
        separators=(",", ":"),
    )
    first_hash = hashlib.sha256(first_json.encode("utf-8")).hexdigest()
    second_json = json.dumps(
        {
            "sequence_number": 2,
            "card_type": "Verdict",
            "previous_card_hash": first_hash,
            "proposal_id": "DAO-PROP-ORIGINAL",
        },
        separators=(",", ":"),
    )
    second_hash = hashlib.sha256(second_json.encode("utf-8")).hexdigest()
    for sequence_number, card_type, card_hash, card_json in (
        (1, "ProposalCard", first_hash, first_json),
        (2, "Verdict", second_hash, second_json),
    ):
        db.execute(
            "INSERT INTO cards ("
            "proposal_id, sequence_number, card_type, card_hash, card_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (
                relabeled_proposal_id,
                sequence_number,
                card_type,
                card_hash,
                card_json,
                NOW,
            ),
        )

    with pytest.raises(module.CardChainArtifactError, match="proposal identity"):
        module.build_card_chain_artifact(
            db,
            proposal_id=relabeled_proposal_id,
            captured_at=NOW,
            source_url=(
                "https://concordia.example/proof-artifacts/v1/"
                f"{relabeled_proposal_id}/card-chain"
            ),
        )
