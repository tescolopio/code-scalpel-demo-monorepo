from __future__ import annotations

import os
import stat
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
    normalized.setdefault("success", False)
    normalized.setdefault("server_version", None)
    normalized.setdefault("error", None)

    normalized.setdefault("symbol_name", None)
    normalized.setdefault("definition_file", None)
    normalized.setdefault("definition_line", None)
    normalized.setdefault("total_references", None)
    normalized.setdefault("references", [])

    if not isinstance(normalized.get("references"), list):
        normalized["references"] = []

    return normalized


def _normalize_get_symbol_references_result(raw) -> dict:
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

    # Envelope v1 wrapper
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
    assert isinstance(result.get("success"), bool), result
    assert isinstance(result.get("server_version"), (str, type(None))), result
    assert isinstance(result.get("error"), (str, type(None))), result

    assert isinstance(result.get("references"), list), result
    assert isinstance(result.get("definition_file"), (str, type(None))), result
    assert isinstance(result.get("definition_line"), (int, type(None))), result
    assert isinstance(result.get("total_references"), (int, type(None))), result

    if result.get("success") is False:
        assert result.get("error"), result


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def test_get_symbol_references_known_fixture_positive_control(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "search_users", "project_root": str(root)},
        max_seconds=25,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("references"), result


def test_get_symbol_references_missing_symbol_negative_control(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "definitely_not_a_real_symbol_12345", "project_root": str(root)},
        max_seconds=25,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)

    # Accept either (success True with 0 refs) or (success False with error).
    if result.get("success") is True:
        total = result.get("total_references")
        assert total in (0, None) or total == 0, result


def test_get_symbol_references_invalid_root_fails_safely(mcp_client, tmp_path):
    missing = tmp_path / "nope"
    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "search_users", "project_root": str(missing)},
        max_seconds=15,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_symbol_references_missing_symbol_name_fails_safely(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(mcp_client, "get_symbol_references", {"project_root": str(root)}, max_seconds=15)
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


@pytest.mark.parametrize(
    "symbol_name",
    ["", " ", "x" * 4096, chr(3), chr(0)],
    ids=["empty", "space", "very_long", "unicode_control", "nul"],
)
def test_get_symbol_references_weird_symbol_names_handled_safely(mcp_client, tmp_path, symbol_name):
    root = tmp_path / "tiny"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "a.py", "def ok():\n    return 1\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": symbol_name, "project_root": str(root)},
        max_seconds=15,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_symbol_references_tiny_project_finds_multiple_refs(mcp_client, tmp_path):
    root = tmp_path / "tiny_refs"
    root.mkdir(parents=True, exist_ok=True)

    _write_text(root / "a.py", "def target(x):\n    return x\n")
    _write_text(root / "b.py", "import a\n\n\ndef call():\n    return a.target(1)\n")
    _write_text(root / "c.py", "from a import target\n\n\ndef call2():\n    return target(2)\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "target", "project_root": str(root)},
        max_seconds=20,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    # Best-effort: should find at least one reference.
    assert result.get("references"), result


def test_get_symbol_references_mixed_language_root_does_not_crash(mcp_client, tmp_path):
    root = tmp_path / "mixed"
    root.mkdir(parents=True, exist_ok=True)

    _write_text(root / "a.py", "def only_py():\n    return 1\n")
    _write_text(root / "x.js", "export function only_py(){ return 1 }\n")
    _write_text(root / "x.ts", "export function only_py(): number { return 1 }\n")
    _write_text(root / "A.java", "public class A { static int only_py(){ return 1; } }\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "only_py", "project_root": str(root)},
        max_seconds=20,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_symbol_references_symlink_loop_does_not_hang(mcp_client, tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    root = tmp_path / "symlink_loop"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "a.py", "def t():\n    return 1\n")

    loop = root / "loop"
    try:
        os.symlink(str(root), str(loop))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "t", "project_root": str(root)},
        max_seconds=20,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_symbol_references_permission_denied_subdir_safe(mcp_client, tmp_path):
    root = tmp_path / "perm"
    root.mkdir(parents=True, exist_ok=True)

    _write_text(root / "a.py", "def t():\n    return 1\n")

    locked = root / "locked"
    locked.mkdir(parents=True, exist_ok=True)
    _write_text(locked / "b.py", "def t2():\n    return 2\n")

    try:
        locked.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "t", "project_root": str(root)},
        max_seconds=20,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result

    # Restore so tmp cleanup can succeed.
    try:
        locked.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError:
        pass


def test_get_symbol_references_large_project_bounded(mcp_client, tmp_path):
    root = tmp_path / "big"
    root.mkdir(parents=True, exist_ok=True)

    # Create many files with a shared symbol to exercise scanning.
    _write_text(root / "base.py", "def shared(x):\n    return x\n")
    for i in range(40):
        _write_text(root / f"m{i}.py", f"import base\n\n\ndef f{i}():\n    return base.shared({i})\n")

    raw, elapsed = _timed_call(
        mcp_client,
        "get_symbol_references",
        {"symbol_name": "shared", "project_root": str(root)},
        max_seconds=25,
    )
    result = _normalize_get_symbol_references_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, {"elapsed": elapsed, "result": result}
    # Best-effort: should find at least some references.
    assert result.get("references"), result
