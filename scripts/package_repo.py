"""Create a clean Concordia repository zip."""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".next",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "tmp",
}
SKIP_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite", ".zip", ".pem", ".key"}
def include(path: Path) -> bool:
    if path.parts and path.parts[0] == "artifacts":
        return len(path.parts) >= 2 and path.parts[1] in {"live", "rwa"}
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.suffix in SKIP_SUFFIXES:
        return False
    if path.name in {".env", ".DS_Store"}:
        return False
    if path.name.endswith((".db-shm", ".db-wal")):
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_dir() or not include(path.relative_to(root)):
                continue
            zf.write(path, Path(root.name) / path.relative_to(root))
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
