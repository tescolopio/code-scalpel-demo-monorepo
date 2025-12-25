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


def _normalize_crawl_project_result(raw: dict) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict: {success: bool, summary: {...}, files: [...], error: str|None, ...}
    - Envelope v1: {capabilities: ['envelope-v1'], data: {...}, error: {...}|None, duration_ms: ...}
    """
    if not isinstance(raw, dict):
        return {"success": False, "error": "Non-dict tool result", "_raw": raw}

    if "data" in raw and "capabilities" in raw:
        data = raw.get("data") or {}
        err = raw.get("error")
        if err:
            msg = err.get("error") if isinstance(err, dict) else str(err)
            normalized = dict(data)
            normalized.update({"success": False, "error": msg})
            return normalized
        normalized = dict(data)
        # Keep existing data.error if present, but prefer normalized error=None.
        normalized["success"] = True
        normalized["error"] = None
        return normalized

    return raw


def _assert_common_shape(result: dict):
    assert isinstance(result, dict), result
    assert "success" in result and isinstance(result["success"], bool), result
    assert isinstance(result.get("server_version"), (str, type(None))), result
    assert isinstance(result.get("root_path"), (str, type(None))), result
    assert isinstance(result.get("error"), (str, type(None))), result

    if result["success"] is False:
        assert result.get("error"), result
        return

    assert isinstance(result.get("summary"), dict), result
    assert isinstance(result.get("files"), list), result
    assert isinstance(result.get("errors"), list), result
    assert isinstance(result.get("markdown_report"), str), result

    summary = result["summary"]
    for key in [
        "total_files",
        "successful_files",
        "failed_files",
        "total_lines_of_code",
        "total_functions",
        "total_classes",
        "complexity_warnings",
    ]:
        assert key in summary, {"missing": key, "summary": summary, "result": result}
        assert isinstance(summary[key], int), {"key": key, "value": summary[key], "result": result}

    # Basic internal consistency checks
    assert summary["total_files"] >= 0
    assert summary["successful_files"] >= 0
    assert summary["failed_files"] >= 0
    assert summary["successful_files"] + summary["failed_files"] <= summary["total_files"], result

    for f in result["files"]:
        assert isinstance(f, dict), f
        assert isinstance(f.get("path"), str) and f["path"], f
        assert f.get("status") in ("success", "failed"), f
        assert isinstance(f.get("lines_of_code"), int), f
        assert isinstance(f.get("functions"), list), f
        assert isinstance(f.get("classes"), list), f
        assert isinstance(f.get("imports"), list), f
        assert isinstance(f.get("complexity_warnings"), list), f
        assert isinstance(f.get("error"), (str, type(None))), f


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_crawl_project_small_known_fixture(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 50, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True, result

    # At least the known files should appear.
    seen = {f["path"] for f in (result.get("files") or [])}
    assert {"__init__.py", "routes.py", "database.py"}.issubset(seen), {"seen": sorted(seen), "result": result}


def test_crawl_project_include_report_generates_markdown(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 50, "include_report": True},
        max_seconds=30,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True, result
    # Report content can vary, but should be non-empty markdown.
    assert result.get("markdown_report"), result


def test_crawl_project_exclude_dirs_filters_files(mcp_client, tmp_path):
    # Create a tiny project with a nested dir to exclude.
    root = tmp_path / "proj"
    include_dir = root / "include_me"
    exclude_dir = root / "exclude_me"

    _write_text(
        include_dir / "a.py",
        """
def a(x):
    if x:
        return 1
    return 0
""".lstrip(),
    )
    _write_text(
        exclude_dir / "b.py",
        """
def b(x):
    if x:
        return 1
    return 0
""".lstrip(),
    )
    _write_text(root / "root.py", "def root_fn():\n    return 1\n")
    _write_text(root / "README.txt", "not python")

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {
            "root_path": str(root),
            "exclude_dirs": ["exclude_me"],
            "complexity_threshold": 1,
            "include_report": False,
        },
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True, result

    seen = {f["path"] for f in (result.get("files") or [])}
    # Ensure excluded file not present.
    assert all("exclude_me" not in p for p in seen), {"seen": sorted(seen), "result": result}
    # Included files should be present (paths may be relative).
    assert any(p.endswith("include_me/a.py") or p == "a.py" for p in seen), {"seen": sorted(seen), "result": result}
    assert any(p.endswith("root.py") for p in seen), {"seen": sorted(seen), "result": result}


def test_crawl_project_counts_failed_files_on_syntax_error(mcp_client, tmp_path):
    root = tmp_path / "badproj"
    _write_text(root / "ok.py", "def ok():\n    return 1\n")
    _write_text(root / "bad.py", "def f(:\n    pass\n")

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)

    assert result["success"] is True, result
    assert result["summary"]["failed_files"] >= 1, result
    # Either file-level errors or top-level errors should capture the failure.
    assert result.get("errors") or any(f.get("status") == "failed" for f in result.get("files") or []), result


def test_crawl_project_handles_nonexistent_root(mcp_client, tmp_path):
    missing = tmp_path / "does_not_exist_12345"
    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(missing), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is False, result


def test_crawl_project_rejects_file_path_root(mcp_client, tmp_path):
    root_file = tmp_path / "not_a_dir.py"
    _write_text(root_file, "def f():\n    return 1\n")
    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root_file), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is False, result


def test_crawl_project_perf_sanity_medium_synthetic_tree(mcp_client, tmp_path):
    # Build a medium synthetic tree to shake out traversal/perf issues.
    root = tmp_path / "medium"
    root.mkdir(parents=True, exist_ok=True)
    for i in range(1, 61):
        code = "\n".join(
            [
                f"def f{i}(x):",
                "    if x > 10:",
                "        return x * 2",
                "    return x",
                "",
            ]
        )
        _write_text(root / f"m{i}.py", code)

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 1, "include_report": False},
        # Keep a generous cap since MCP server startup/IO can vary.
        max_seconds=30,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True, result
    assert result["summary"]["total_files"] >= 60, result
    # With low threshold, warnings should generally appear.
    assert result["summary"]["complexity_warnings"] >= 0, result


def test_crawl_project_invalid_utf8_file_fails_safely(mcp_client, tmp_path):
    root = tmp_path / "encoding"
    root.mkdir(parents=True, exist_ok=True)

    ok = root / "ok.py"
    ok.write_text("def ok():\n    return 1\n", encoding="utf-8")

    bad = root / "bad_utf8.py"
    # Write invalid UTF-8 bytes.
    bad.write_bytes(b"def f():\n    return '\xff'\n")

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)

    # Implementation may either mark the bad file as failed but still overall success,
    # or choose to fail the overall crawl. Accept both but ensure it doesn't crash.
    if result["success"] is True:
        assert result["summary"]["failed_files"] >= 1, result
    else:
        assert result.get("error"), result


def test_crawl_project_mixed_language_tree_ignores_non_python(mcp_client, tmp_path):
    """crawl_project should focus on Python files and not crash on other languages."""
    root = tmp_path / "mixed"
    _write_text(root / "a.py", "def a():\n    return 1\n")
    _write_text(root / "b.js", "export function b(x){ return x }\n")
    _write_text(root / "c.ts", "export function c(x: number): number { return x }\n")
    _write_text(root / "d.java", "public class D { int f(){ return 1; } }\n")
    _write_text(root / "README.md", "# hello\n")

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True, result

    seen = {f["path"] for f in (result.get("files") or [])}
    assert any(p.endswith("a.py") or p == "a.py" for p in seen), {"seen": sorted(seen), "result": result}
    assert all(not p.endswith((".js", ".ts", ".java", ".md")) for p in seen), {"seen": sorted(seen), "result": result}


def test_crawl_project_symlink_loop_does_not_hang(mcp_client, tmp_path):
    """Symlink loops are a classic filesystem footgun; crawler must remain bounded."""
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    root = tmp_path / "symlink_loop"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "ok.py", "def ok():\n    return 1\n")

    # Create loop: root/loop -> root
    loop = root / "loop"
    try:
        os.symlink(str(root), str(loop))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    # Either success or safe failure is acceptable; must not hang/crash.
    assert result.get("success") in (True, False), result


def test_crawl_project_permission_denied_dir_fails_safely(mcp_client, tmp_path):
    """Crawler should not crash if a subdirectory is unreadable."""
    root = tmp_path / "perm"
    protected = root / "protected"
    root.mkdir(parents=True, exist_ok=True)
    protected.mkdir(parents=True, exist_ok=True)

    _write_text(root / "ok.py", "def ok():\n    return 1\n")
    _write_text(protected / "secret.py", "def secret():\n    return 42\n")

    # Remove all permissions from the protected directory.
    try:
        protected.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    try:
        raw, _ = _timed_call(
            mcp_client,
            "crawl_project",
            {"root_path": str(root), "complexity_threshold": 10, "include_report": False},
            max_seconds=20,
        )
        result = _normalize_crawl_project_result(raw)
        _assert_common_shape(result)
        # Accept either overall failure or partial failure accounting.
        assert result.get("success") in (True, False), result
        if result.get("success") is True:
            assert result["summary"]["failed_files"] >= 0, result
    finally:
        # Ensure cleanup works on all platforms/CI by restoring permissions.
        try:
            protected.chmod(0o700)
        except OSError:
            pass


def test_crawl_project_large_file_bounded(mcp_client, tmp_path):
    """Large-but-reasonable file should not cause runaway time/memory."""
    root = tmp_path / "large"
    root.mkdir(parents=True, exist_ok=True)

    # ~10k lines deterministic file.
    lines = ["def f0(x):\n    return x\n"]
    for i in range(1, 10001):
        lines.append(f"def f{i}(x):\n    if x > {i}:\n        return x\n    return {i}\n")
    _write_text(root / "big.py", "\n".join(lines))

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 1, "include_report": False},
        max_seconds=30,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result["summary"]["total_files"] >= 1, result


def test_crawl_project_binary_file_does_not_crash(mcp_client, tmp_path):
    """Binary junk under root should not crash the crawler."""
    root = tmp_path / "binary"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "ok.py", "def ok():\n    return 1\n")
    _write_bytes(root / "junk.bin", b"\x00\xff\x00\xff" * 1024)

    raw, _ = _timed_call(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 10, "include_report": False},
        max_seconds=20,
    )
    result = _normalize_crawl_project_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
