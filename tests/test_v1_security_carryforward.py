from __future__ import annotations

import ast
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_function(path: Path, name: str, globals_: dict[str, object]):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace = dict(globals_)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name], ast.get_source_segment(source, function) or ""


def test_gateway_path_guard_rejects_directory_control(tmp_path: Path) -> None:
    safe_data_path, _ = _load_function(
        ROOT / "gateway/app.py",
        "_safe_data_path",
        {"Path": Path, "os": os},
    )
    assert safe_data_path(tmp_path, "evidence.json") == tmp_path / "evidence.json"
    for unsafe in ("", ".", "..", "../evidence.json", "sub/evidence.json", r"sub\evidence.json"):
        try:
            safe_data_path(tmp_path, unsafe)
        except ValueError:
            continue
        raise AssertionError(f"unsafe filename accepted: {unsafe!r}")


def test_allocation_regex_has_bounded_input_and_quantifiers() -> None:
    allocation, source = _load_function(
        ROOT / "shared/proof_runtime.py",
        "_allocation_from_prompt",
        {"re": re},
    )
    assert allocation("allocate 12.5%") == 1250
    assert "[:4096]" in source
    assert r"\d{1,9}" in source
    assert r"\d{1,4}" in source
    assert r"\d+" not in source


def test_insecure_url_check_is_host_anchored() -> None:
    source = (ROOT / "shared/proof_runtime.py").read_text(encoding="utf-8")
    expected = r"http://concordia\.47\.84\.232\.193\.sslip\.io(?![\w.-])"
    assert expected in source
    pattern = re.compile(expected)
    assert pattern.search("http://concordia.47.84.232.193.sslip.io/path")
    assert not pattern.search("http://concordia.47.84.232.193.sslip.io.evil/path")
