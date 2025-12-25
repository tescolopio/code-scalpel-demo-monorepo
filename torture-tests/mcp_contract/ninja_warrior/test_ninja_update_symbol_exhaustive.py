from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest


def _fill_defaults(d: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(d)
    normalized.setdefault("success", False)
    normalized.setdefault("server_version", None)
    normalized.setdefault("error", None)
    # Common PatchResult-ish fields (best-effort; server may omit).
    normalized.setdefault("backup_path", None)
    normalized.setdefault("backup_file", None)
    normalized.setdefault("lines_changed", None)
    normalized.setdefault("line_changes", None)
    return normalized


def _normalize_update_symbol_result(raw: Any) -> dict[str, Any]:
    """Normalize output across server formats.

    Expected shapes observed across tools:
    - Flat dict: {success: bool, ...}
    - Envelope v1 wrapper: {capabilities: ['envelope-v1'], data: {...}, error: {...}|None, duration_ms: ...}
    - JSON-RPC error wrapper: {jsonrpc: '2.0', error: {...}}

    Also normalize pre-tool validation failures that may only include {success, error}.
    """
    if not isinstance(raw, dict):
        return _fill_defaults({"success": False, "error": f"non-dict result: {type(raw).__name__}", "_raw": raw})

    # JSON-RPC error wrapper
    if "jsonrpc" in raw and "error" in raw and isinstance(raw.get("error"), dict):
        err = raw.get("error") or {}
        msg = err.get("message") or str(err)
        return _fill_defaults({"success": False, "error": msg, "_jsonrpc": raw})

    # Envelope v1 wrapper
    if isinstance(raw.get("capabilities"), list) and "data" in raw:
        data = raw.get("data")
        if not isinstance(data, dict):
            msg = None
            if isinstance(raw.get("error"), dict):
                msg = raw["error"].get("message")
            return _fill_defaults({"success": False, "error": msg or "envelope missing data", "_envelope": raw})
        if raw.get("error"):
            err = raw.get("error")
            msg = err.get("message") if isinstance(err, dict) else str(err)
            normalized = dict(data)
            normalized.update({"success": False, "error": msg, "_envelope": raw})
            return _fill_defaults(normalized)
        normalized = dict(data)
        normalized.update({"success": True, "error": None, "_envelope": raw})
        return _fill_defaults(normalized)

    # Flat dict
    return _fill_defaults(raw)


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _call_update_symbol(mcp_client, args: dict[str, Any], max_seconds: float = 10.0) -> tuple[dict[str, Any], float]:
    start = time.monotonic()
    raw = mcp_client.tools_call("update_symbol", args)
    elapsed = time.monotonic() - start
    # Contract: tool call should not hang.
    assert elapsed < max_seconds, {"elapsed": elapsed, "raw": raw, "args": args}
    return _normalize_update_symbol_result(raw), elapsed


def _assert_safe_failure(result: dict[str, Any]) -> None:
    assert result.get("success") is False, result
    assert result.get("error") is None or isinstance(result.get("error"), str)


def test_update_symbol_function_success_backup_and_content(tmp_path, mcp_client):
    demo = tmp_path / "demo_update_symbol.py"
    _write_text(
        demo,
        """
# fixture

def greet():
    return 'hi'
""".lstrip(),
    )

    new_code = """

def greet():
    return 'hello'
""".lstrip("\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {
            "file_path": str(demo),
            "target_type": "function",
            "target_name": "greet",
            "new_code": new_code,
            "create_backup": True,
        },
    )
    assert result.get("success") is True, result

    bak = tmp_path / "demo_update_symbol.py.bak"
    assert bak.exists(), result
    assert "return 'hello'" in _read_text(demo)
    assert "return 'hi'" in _read_text(bak)

    if result.get("backup_path"):
        assert str(bak) in str(result.get("backup_path")), result


def test_update_symbol_default_backup_when_omitted(tmp_path, mcp_client):
    demo = tmp_path / "demo_default_backup.py"
    _write_text(demo, "def f():\n    return 1\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 2\n"},
    )
    assert result.get("success") is True, result
    assert (tmp_path / "demo_default_backup.py.bak").exists(), result


def test_update_symbol_create_backup_false_preferred_behavior(tmp_path, mcp_client):
    demo = tmp_path / "demo_no_backup.py"
    _write_text(demo, "def f():\n    return 'a'\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {
            "file_path": str(demo),
            "target_type": "function",
            "target_name": "f",
            "new_code": "def f():\n    return 'b'\n",
            "create_backup": False,
        },
    )
    assert result.get("success") is True, result
    # Contract preference: create_backup=False should avoid writing .bak.
    assert not (tmp_path / "demo_no_backup.py.bak").exists(), result


def test_update_symbol_invalid_python_syntax_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "bad_syntax.py"
    _write_text(demo, "def greet():\n    return 'hi'\n")

    bad_new_code = "def greet():\n    return\n      'oops'\n"  # invalid indent

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "greet", "new_code": bad_new_code, "create_backup": True},
    )
    _assert_safe_failure(result)


def test_update_symbol_missing_args_fails_safely(mcp_client):
    result, _ = _call_update_symbol(mcp_client, {})
    _assert_safe_failure(result)


def test_update_symbol_invalid_target_type_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "invalid_target_type.py"
    _write_text(demo, "def f():\n    return 1\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "fn", "target_name": "f", "new_code": "def f():\n    return 2\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_nonexistent_symbol_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "missing_symbol.py"
    _write_text(demo, "def exists():\n    return 1\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "does_not_exist_12345", "new_code": "def does_not_exist_12345():\n    return 0\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_missing_file_fails_safely(tmp_path, mcp_client):
    missing = tmp_path / "nope.py"

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(missing), "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 1\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_directory_path_fails_safely(tmp_path, mcp_client):
    d = tmp_path / "dir"
    d.mkdir()

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(d), "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 1\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_method_success(tmp_path, mcp_client):
    demo = tmp_path / "demo_method.py"
    _write_text(
        demo,
        """
class User:
    def greet(self):
        return 'hi'
""".lstrip(),
    )

    new_code = """

def greet(self):
    return 'hello'
""".lstrip("\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "method", "target_name": "User.greet", "new_code": new_code, "create_backup": True},
    )
    assert result.get("success") is True, result
    assert (tmp_path / "demo_method.py.bak").exists(), result
    assert "return 'hello'" in _read_text(demo)


def test_update_symbol_class_success(tmp_path, mcp_client):
    demo = tmp_path / "demo_class.py"
    _write_text(
        demo,
        """
class Thing:
    def value(self):
        return 1
""".lstrip(),
    )

    new_code = """
class Thing:
    def value(self):
        return 2
""".lstrip()

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "class", "target_name": "Thing", "new_code": new_code, "create_backup": True},
    )
    assert result.get("success") is True, result
    assert "return 2" in _read_text(demo)


def test_update_symbol_decorated_function_boundary_handling(tmp_path, mcp_client):
    demo = tmp_path / "demo_decorated.py"
    _write_text(
        demo,
        """

def deco(fn):
    def wrapper(*a, **k):
        return fn(*a, **k)
    return wrapper

@deco
def greet():
    return 'hi'
""".lstrip(),
    )

    new_code = """
@deco
def greet():
    return 'hello'
""".lstrip()

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "greet", "new_code": new_code, "create_backup": True},
    )
    assert result.get("success") is True, result
    txt = _read_text(demo)
    assert "@deco" in txt
    assert "return 'hello'" in txt


def test_update_symbol_unicode_identifier(tmp_path, mcp_client):
    demo = tmp_path / "demo_unicode.py"
    _write_text(demo, "def café():\n    return 1\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "café", "new_code": "def café():\n    return 2\n", "create_backup": True},
    )
    assert result.get("success") is True, result
    assert "return 2" in _read_text(demo)


def test_update_symbol_nul_bytes_in_arguments_fail_safely(tmp_path, mcp_client):
    demo = tmp_path / "demo_nul.py"
    _write_text(demo, "def f():\n    return 1\n")

    nul = chr(0)
    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo) + nul, "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 2\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_binary_file_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "binary.py"
    demo.write_bytes(b"\xff\xfe\x00\x00not python\x00\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "x", "new_code": "def x():\n    return 1\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_permission_denied_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "no_perms.py"
    _write_text(demo, "def f():\n    return 1\n")
    os.chmod(demo, 0)

    try:
        result, _ = _call_update_symbol(
            mcp_client,
            {"file_path": str(demo), "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 2\n"},
        )
        _assert_safe_failure(result)
    finally:
        try:
            os.chmod(demo, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass


def test_update_symbol_symlink_path_does_not_crash(tmp_path, mcp_client):
    target = tmp_path / "real.py"
    _write_text(target, "def f():\n    return 1\n")

    link = tmp_path / "link.py"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(link), "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 2\n", "create_backup": True},
    )

    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert "return 2" in _read_text(target) or "return 2" in _read_text(link)


def test_update_symbol_non_python_file_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "demo.js"
    _write_text(demo, "function f() { return 1 }\n")

    result, _ = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "f", "new_code": "def f():\n    return 2\n"},
    )
    _assert_safe_failure(result)


def test_update_symbol_large_file_perf_bound(tmp_path, mcp_client):
    demo = tmp_path / "big.py"
    filler = "\n".join(["x = 1" for _ in range(8000)])
    _write_text(demo, f"{filler}\n\ndef tail():\n    return 'a'\n")

    result, elapsed = _call_update_symbol(
        mcp_client,
        {"file_path": str(demo), "target_type": "function", "target_name": "tail", "new_code": "def tail():\n    return 'b'\n", "create_backup": True},
        max_seconds=20.0,
    )
    assert result.get("success") is True, result
    assert elapsed < 5.0, {"elapsed": elapsed, "result": result}
    assert "return 'b'" in _read_text(demo)
