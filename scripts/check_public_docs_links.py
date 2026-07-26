#!/usr/bin/env python3
"""Fail on unresolved local links or forbidden public documentation origins."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
AUTOLINK = re.compile(r"<((?:https?|mailto):[^>]+)>")
FORBIDDEN = (
    "sslip.io",
    "x402.concordiadao.xyz",
    "safepay.concordiadao.xyz",
    "x402-provider.",
)


def _public_files() -> list[Path]:
    candidates = [
        ROOT / "README.md",
        ROOT / "buidl-page-FINALS-STABLE.md",
        ROOT / "packages" / "verify" / "README.md",
    ]
    candidates.extend(sorted((ROOT / "docs-site").rglob("*.md")))
    return [path for path in candidates if path.is_file()]


def _target(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<") and ">" in value:
        return value[1 : value.index(">")]
    return value.split(maxsplit=1)[0]


def _local_error(source: Path, target: str) -> str | None:
    parsed = urlsplit(target)
    if parsed.scheme or target.startswith(("#", "/")):
        return None
    relative = unquote(parsed.path)
    if not relative:
        return None
    resolved = (source.parent / relative).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return f"{source.relative_to(ROOT)}: link escapes repository: {target}"
    if not resolved.exists():
        return f"{source.relative_to(ROOT)}: unresolved link: {target}"
    return None


def main() -> int:
    errors: list[str] = []
    checked = 0
    for source in _public_files():
        text = source.read_text(encoding="utf-8")
        lowered = text.lower()
        for forbidden in FORBIDDEN:
            if forbidden in lowered:
                errors.append(
                    f"{source.relative_to(ROOT)}: forbidden public origin: {forbidden}"
                )
        raw_targets = MARKDOWN_LINK.findall(text) + AUTOLINK.findall(text)
        for raw in raw_targets:
            target = _target(raw)
            checked += 1
            error = _local_error(source, target)
            if error:
                errors.append(error)
    if errors:
        print("\n".join(sorted(set(errors))), file=sys.stderr)
        return 1
    print(f"checked {checked} links across {len(_public_files())} public Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
