"""Repository hygiene checks for Concordia DAO Council."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".next",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}
SKIP_FILES = {"uv.lock", "package-lock.json"}
SKIP_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".db",
    ".sqlite",
    ".zip",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".wasm",
    ".pem",
}

BLOCKED = [
    "YI" + "TING",
    "Q" + "wen",
    "q" + "wen",
    "Ali" + "baba",
    "Ali" + "Baba",
    "Dash" + "Scope",
    "DASH" + "SCOPE",
    "Ali" + "yun",
    "QUN" + "CE",
    "Agent" + " Room",
    "Lin" + " Xun",
    "Chen" + " Ming",
    "Zhou" + " Shen",
    "Han" + " Ce",
    "Lu" + " Xing",
    "auth" + "-service",
    "payment" + "-service",
    "github" + "_deploy",
    "sentry" + "_error",
    "hack" + "athon",
    "Hack" + "athon",
]


def should_skip(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if path.name in SKIP_FILES:
        return True
    if any(part in SKIP_DIRS for part in rel.parts):
        return True
    if path.suffix in SKIP_SUFFIXES:
        return True
    if path.name.endswith((".db-shm", ".db-wal")):
        return True
    return False


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if path.is_dir() or should_skip(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for term in BLOCKED:
            if term in text:
                findings.append(f"{path.relative_to(ROOT)}: contains deprecated marker")
                break
    if findings:
        print("Repository hygiene check failed:")
        print("\n".join(findings))
        return 1
    print("Repository hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
