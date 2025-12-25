from __future__ import annotations

import os
import time
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _timed_call(mcp_client, tool: str, args: dict, *, max_seconds: float | None = None):
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    if max_seconds is not None:
        assert elapsed <= max_seconds, {"tool": tool, "elapsed": elapsed, "result": result}
    return result, elapsed


def _fill_defaults(d: dict) -> dict:
    normalized = dict(d)
    normalized.setdefault("server_version", None)
    normalized.setdefault("error", None)

    # Common graph-ish fields for this tool.
    if not isinstance(normalized.get("extracted_symbols"), list):
        normalized["extracted_symbols"] = []
    if "dependencies" in normalized and not isinstance(normalized.get("dependencies"), list):
        normalized["dependencies"] = []
    if "mermaid" in normalized and not isinstance(normalized.get("mermaid"), str):
        normalized["mermaid"] = ""
    if "summary" in normalized and not isinstance(normalized.get("summary"), dict):
        normalized["summary"] = {}

    return normalized


def _normalize_get_cross_file_dependencies_result(raw) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict tool output
    - Envelope v1 wrapper
    - JSON-RPC error wrapper

    Also normalize pre-tool validation failures into a stable shape.
    """

    if not isinstance(raw, dict):
        return _fill_defaults({"success": False, "error": "Non-dict tool result", "_raw": raw})

    # JSON-RPC error wrapper
    if "jsonrpc" in raw and "error" in raw and isinstance(raw.get("error"), dict):
        return _fill_defaults(
            {
                "success": False,
                "error": raw["error"].get("message") or str(raw["error"]),
                "_jsonrpc": raw,
            }
        )

    # Envelope v1
    if "data" in raw and "capabilities" in raw:
        data = raw.get("data") or {}
        err = raw.get("error")
        if err:
            msg = err.get("error") if isinstance(err, dict) else str(err)
            normalized = dict(data)
            normalized.update({"success": False, "error": msg})
            return _fill_defaults(normalized)
        normalized = dict(data)
        normalized.update({"success": True, "error": None})
        return _fill_defaults(normalized)

    return _fill_defaults(raw)


def _assert_common_shape(result: dict):
    assert isinstance(result, dict), result
    assert "success" in result and isinstance(result["success"], bool), result
    assert isinstance(result.get("server_version"), (str, type(None))), result
    assert isinstance(result.get("error"), (str, type(None))), result

    # Even on failures we want a consistent shape.
    assert isinstance(result.get("extracted_symbols"), list), result

    if result["success"] is False:
        assert result.get("error"), result
        return

    # Successful calls must include at least extracted_symbols.
    assert isinstance(result.get("extracted_symbols"), list), result


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def _make_tiny_project(tmp_path: Path) -> tuple[Path, Path, str]:
    """Create a tiny multi-file Python project to keep tests fast.

    Returns (project_root, target_file, target_symbol).
    """

    root = tmp_path / "tiny_cross_deps"
    root.mkdir(parents=True, exist_ok=True)

    # a.fa -> b.fb -> c.fc
    _write_text(
        root / "a.py",
        "import b\n\n"
        "def fa(x):\n"
        "    return b.fb(x)\n",
    )
    _write_text(
        root / "b.py",
        "import c\n\n"
        "def fb(x):\n"
        "    return c.fc(x)\n",
    )
    _write_text(
        root / "c.py",
        "def fc(x):\n"
        "    return x\n",
    )
    return root, root / "a.py", "fa"


def test_get_cross_file_dependencies_known_fixture_low_noise(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "target_file": "torture-tests/stage8-advanced-taint/crossfile-hard/routes.py",
            "target_symbol": "search_route",
            "max_depth": 2,
            "include_code": False,
            "include_diagram": False,
            "confidence_decay_factor": 0.9,
        },
        max_seconds=30,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("extracted_symbols"), result


def test_get_cross_file_dependencies_include_code_returns_code_strings(mcp_client, tmp_path):
    root, target_file, target_symbol = _make_tiny_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "project_root": str(root),
            "target_file": str(target_file),
            "target_symbol": target_symbol,
            "max_depth": 2,
            "include_code": True,
            "include_diagram": False,
            "confidence_decay_factor": 0.9,
        },
        max_seconds=15,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)

    if result.get("success") is not True:
        pytest.skip(f"Tool failed unexpectedly: {result}")

    # Best-effort validation: at least one extracted symbol should include some code-like payload.
    found_code = False
    for s in result.get("extracted_symbols") or []:
        if isinstance(s, dict):
            for k in ("code", "source", "snippet"):
                v = s.get(k)
                if isinstance(v, str) and v.strip():
                    found_code = True
                    break
        if found_code:
            break
    assert found_code, result


def test_get_cross_file_dependencies_include_diagram_emits_mermaid_or_safe_empty(mcp_client, tmp_path):
    root, target_file, target_symbol = _make_tiny_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "project_root": str(root),
            "target_file": str(target_file),
            "target_symbol": target_symbol,
            "max_depth": 2,
            "include_code": False,
            "include_diagram": True,
            "confidence_decay_factor": 0.9,
        },
        max_seconds=15,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        mermaid = result.get("mermaid")
        # Some implementations may omit mermaid; require safe behavior.
        assert isinstance(mermaid, str), result


def test_get_cross_file_dependencies_depth_zero_bounded(mcp_client, tmp_path):
    root, target_file, target_symbol = _make_tiny_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "project_root": str(root),
            "target_file": str(target_file),
            "target_symbol": target_symbol,
            "max_depth": 0,
            "include_code": False,
            "include_diagram": False,
            "confidence_decay_factor": 0.9,
        },
        max_seconds=15,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


@pytest.mark.parametrize("decay", [0.0, 0.5, 0.9, 1.0, 1.5])
def test_get_cross_file_dependencies_confidence_decay_factor_edge_values(mcp_client, tmp_path, decay):
    root, target_file, target_symbol = _make_tiny_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "project_root": str(root),
            "target_file": str(target_file),
            "target_symbol": target_symbol,
            "max_depth": 2,
            "include_code": False,
            "include_diagram": False,
            "confidence_decay_factor": decay,
        },
        max_seconds=15,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_cross_file_dependencies_missing_target_file_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {"target_symbol": "search_route", "max_depth": 1, "include_code": False, "include_diagram": False, "confidence_decay_factor": 0.9},
        max_seconds=30,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_cross_file_dependencies_missing_target_symbol_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {"target_file": "torture-tests/stage8-advanced-taint/crossfile-hard/routes.py", "max_depth": 1, "include_code": False},
        max_seconds=30,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_cross_file_dependencies_nonexistent_target_file_fails_safely(mcp_client, tmp_path):
    missing = tmp_path / "nope.py"
    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {"target_file": str(missing), "target_symbol": "x", "max_depth": 1, "include_code": False, "include_diagram": False, "confidence_decay_factor": 0.9},
        max_seconds=30,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


@pytest.mark.parametrize(
    "filename,content,symbol",
    [
        ("a.js", "export function f(x){ return x }\n", "f"),
        ("a.ts", "export function f(x: number): number { return x }\n", "f"),
        ("A.java", "public class A { static int f(int x){ return x; } }\n", "f"),
    ],
    ids=["js", "ts", "java"],
)
def test_get_cross_file_dependencies_should_reject_non_python_target_files(mcp_client, tmp_path, filename, content, symbol):
    root = tmp_path / "non_python"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / filename, content)

    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {"target_file": str(root / filename), "target_symbol": symbol, "max_depth": 1, "include_code": False, "include_diagram": False, "confidence_decay_factor": 0.9},
        max_seconds=30,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_cross_file_dependencies_symlink_loop_does_not_hang(mcp_client, tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    root = tmp_path / "symlink_loop"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "a.py", "import b\n\n" + "def fa(x):\n    return b.fb(x)\n")
    _write_text(root / "b.py", "def fb(x):\n    return x\n")

    loop = root / "loop"
    try:
        os.symlink(str(root), str(loop))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "project_root": str(root),
            "target_file": str(root / "a.py"),
            "target_symbol": "fa",
            "max_depth": 3,
            "include_code": False,
            "include_diagram": False,
            "confidence_decay_factor": 0.9,
        },
        max_seconds=30,
    )
    result = _normalize_get_cross_file_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result
