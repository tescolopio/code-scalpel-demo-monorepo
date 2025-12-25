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
    normalized.setdefault("error", None)
    normalized.setdefault("server_version", None)

    # File context fields
    normalized.setdefault("file_path", None)
    normalized.setdefault("functions", [])
    normalized.setdefault("classes", [])
    normalized.setdefault("imports", [])
    normalized.setdefault("complexity_score", None)
    normalized.setdefault("line_count", None)
    normalized.setdefault("has_security_issues", False)
    normalized.setdefault("security_warnings", [])
    normalized.setdefault("docstring", None)

    # Type normalization
    for k in ("functions", "classes", "imports", "security_warnings"):
        if not isinstance(normalized.get(k), list):
            normalized[k] = []

    if not isinstance(normalized.get("has_security_issues"), bool):
        normalized["has_security_issues"] = False

    if not isinstance(normalized.get("docstring"), (str, type(None))):
        normalized["docstring"] = None

    return normalized


def _normalize_get_file_context_result(raw) -> dict:
    """Normalize output across server formats.

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

    assert isinstance(result.get("functions"), list), result
    assert isinstance(result.get("classes"), list), result
    assert isinstance(result.get("imports"), list), result
    assert isinstance(result.get("security_warnings"), list), result
    assert isinstance(result.get("has_security_issues"), bool), result


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_get_file_context_python_positive_control(mcp_client, tmp_path):
    f = tmp_path / "sample.py"
    _write_text(
        f,
        "\"\"\"Module docstring.\"\"\"\n"
        "import os\n"
        "\n"
        "class C:\n"
        "    def m(self):\n"
        "        return 1\n"
        "\n"
        "def f(x):\n"
        "    return x\n",
    )

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(f)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert any(isinstance(x, str) and x for x in result.get("functions") or []), result


@pytest.mark.parametrize(
    "filename,content",
    [
        ("a.js", "export function f(x){ return x }\nclass C { m(){ return 1 } }\n"),
        ("a.ts", "export function f(x: number): number { return x }\nexport class C { m(): number { return 1 } }\n"),
        ("A.java", "public class A { static int f(int x){ return x; } }\n"),
    ],
    ids=["js", "ts", "java"],
)
def test_get_file_context_cross_language_supported_extensions(mcp_client, tmp_path, filename, content):
    f = tmp_path / filename
    _write_text(f, content)

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(f)}, max_seconds=15)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)

    # Tool advertises support for these extensions; require success.
    assert result.get("success") is True, result


def test_get_file_context_missing_file_fails_safely(mcp_client, tmp_path):
    missing = tmp_path / "missing.py"
    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(missing)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_file_context_unsupported_extension_fails_safely(mcp_client, tmp_path):
    weird = tmp_path / "data.bin"
    _write_bytes(weird, b"\x00\x01\x02\x03")

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(weird)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_file_context_invalid_utf8_bytes_in_py_fails_or_succeeds_safely(mcp_client, tmp_path):
    f = tmp_path / "bad_utf8.py"
    _write_bytes(f, b"def f():\n    return 1\n\xff\xfe\xff")

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(f)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_file_context_binary_nul_bytes_py_fails_or_succeeds_safely(mcp_client, tmp_path):
    f = tmp_path / "nul_bytes.py"
    _write_bytes(f, b"def f():\n    return 1\n\x00\x00\x00")

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(f)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_file_context_permission_denied_fails_safely(mcp_client, tmp_path):
    f = tmp_path / "secret.py"
    _write_text(f, "def f():\n    return 1\n")

    try:
        f.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(f)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result

    # Restore permissions so tmp cleanup can succeed.
    try:
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def test_get_file_context_symlink_loop_fails_safely(mcp_client, tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    link = tmp_path / "loop.py"
    try:
        os.symlink(str(link), str(link))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(link)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_file_context_large_file_bounded(mcp_client, tmp_path):
    big = tmp_path / "big.py"
    big.write_text("\n".join(["def f%d():\n    return %d" % (i, i) for i in range(300)]), encoding="utf-8")

    raw, elapsed = _timed_call(mcp_client, "get_file_context", {"file_path": str(big)}, max_seconds=20)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert len(result.get("functions") or []) >= 200, {"elapsed": elapsed, "result": result}

    # Best-effort numeric fields if present.
    if result.get("line_count") is not None:
        assert isinstance(result.get("line_count"), int), result
    if result.get("complexity_score") is not None:
        assert isinstance(result.get("complexity_score"), int), result


def test_get_file_context_relative_path_from_repo_root(mcp_client, tmp_path):
    root = _repo_root()
    rel_dir = root / "torture-tests" / "mcp_contract" / "_tmp" / "file_context"
    f = rel_dir / "rel_example.py"
    _write_text(f, "def rel_f():\n    return 1\n")

    rel = str(f.relative_to(root))
    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": rel}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)

    # Some servers may only accept absolute paths; accept safe failure.
    assert result.get("success") in (True, False), result


def test_get_file_context_security_fields_are_type_safe(mcp_client, tmp_path):
    f = tmp_path / "danger.py"
    _write_text(
        f,
        "import os\n\n"
        "def run(cmd):\n"
        "    return os.system(cmd)\n",
    )

    raw, _ = _timed_call(mcp_client, "get_file_context", {"file_path": str(f)}, max_seconds=10)
    result = _normalize_get_file_context_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    # If the tool flags issues, require warnings to be list-of-str.
    if result.get("has_security_issues") is True:
        assert all(isinstance(w, str) for w in (result.get("security_warnings") or [])), result
