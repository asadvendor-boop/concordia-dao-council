from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_MARKDOWN = (
    (ROOT / "README.md",)
    + tuple(sorted((ROOT / "docs").rglob("*.md")))
    + tuple(sorted((ROOT / "docs-site").rglob("*.md")))
)


def test_public_finals_docs_do_not_reference_retired_sslip_domains() -> None:
    retired_references = [
        path.relative_to(ROOT).as_posix()
        for path in PUBLIC_MARKDOWN
        if "sslip" in path.read_text(encoding="utf-8").lower()
    ]

    assert not retired_references, (
        "finals-facing public docs must not publish retired sslip references: "
        + ", ".join(retired_references)
    )


def test_public_service_map_uses_the_owned_finals_domains() -> None:
    links = (ROOT / "docs-site" / "links.md").read_text(encoding="utf-8")
    expected = {
        "Main application": "https://concordiadao.xyz",
        "WWW redirect": "https://www.concordiadao.xyz",
        "SafePay v2 provider": "https://safepay.concordiadao.xyz",
        "Official WCSPR facilitator": "https://x402.concordiadao.xyz",
        "Documentation portal": "https://docs.concordiadao.xyz",
    }

    for service, url in expected.items():
        assert f"| {service} | <{url}> |" in links
