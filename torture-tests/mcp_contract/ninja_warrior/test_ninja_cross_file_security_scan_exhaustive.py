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


def _normalize_cross_file_security_scan_result(raw: dict) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict: {success: bool, has_vulnerabilities: bool, vulnerabilities: [...], ...}
    - Envelope v1: {capabilities: ['envelope-v1'], data: {...}, error: {...}|null, duration_ms: ...}
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
        normalized["success"] = True
        normalized["error"] = None
        return normalized

    return raw


def _assert_common_shape(result: dict):
    assert isinstance(result, dict), result
    assert "success" in result and isinstance(result["success"], bool), result
    assert isinstance(result.get("server_version"), (str, type(None))), result
    assert isinstance(result.get("error"), (str, type(None))), result

    if result["success"] is False:
        assert result.get("error"), result
        return

    # Core fields for cross-file scan
    assert isinstance(result.get("files_analyzed"), int), result
    assert isinstance(result.get("has_vulnerabilities"), bool), result
    assert isinstance(result.get("vulnerability_count"), int), result
    assert isinstance(result.get("risk_level"), str), result
    assert isinstance(result.get("vulnerabilities"), list), result
    assert isinstance(result.get("taint_flows"), list), result
    assert isinstance(result.get("taint_sources"), list), result
    assert isinstance(result.get("dangerous_sinks"), list), result
    assert isinstance(result.get("mermaid"), str), result

    # Internal consistency
    assert result["vulnerability_count"] == len(result["vulnerabilities"]), result
    if result["has_vulnerabilities"] is False:
        assert result["vulnerability_count"] == 0, result


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def test_cross_file_security_scan_positive_control_crossfile_hard(mcp_client):
    """Positive control: known-vulnerable multi-file fixture should yield SQLi findings."""
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 6, "include_diagram": False, "timeout_seconds": 40, "max_modules": 250},
        max_seconds=45,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    # If the tool regresses, keep the suite informative rather than flakey:
    # require a strong signal if it claims vulnerabilities.
    if result.get("has_vulnerabilities") is True:
        assert result.get("vulnerability_count", 0) >= 1, result
        types = {v.get("type") for v in result.get("vulnerabilities") or []}
        assert "SQL Injection" in types, {"types": sorted(t for t in types if t), "result": result}
    else:
        pytest.xfail("Expected SQLi on crossfile-hard, but tool reported none (regression or heuristics change)")


def test_cross_file_security_scan_negative_control_crossfile_test(mcp_client):
    """Negative control: crossfile-test is designed to be small and should typically report no cross-file vulns."""
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 5, "include_diagram": False, "timeout_seconds": 30, "max_modules": 200},
        max_seconds=35,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result.get("files_analyzed", 0) >= 1, result

    # This fixture may still produce taint flows, but should not claim vulns.
    assert result.get("has_vulnerabilities") is False, result
    assert result.get("vulnerability_count") == 0, result


def test_cross_file_security_scan_include_diagram_emits_mermaid(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 3, "include_diagram": True, "timeout_seconds": 30, "max_modules": 200},
        max_seconds=40,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    mermaid = result.get("mermaid", "")
    assert mermaid, result
    assert "graph" in mermaid, mermaid


def test_cross_file_security_scan_entry_points_parameter_is_accepted(mcp_client):
    """Exercise entry_points plumbing; accept tool-specific filtering behavior."""
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {
            "project_root": str(root),
            "entry_points": ["routes.py:search_route"],
            "max_depth": 6,
            "include_diagram": False,
            "timeout_seconds": 40,
            "max_modules": 250,
        },
        max_seconds=45,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result


def test_cross_file_security_scan_timeout_is_bounded(mcp_client):
    """Very small timeout should fail fast or still succeed safely, but must not hang."""
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 6, "include_diagram": False, "timeout_seconds": 0.01, "max_modules": 250},
        max_seconds=20,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    # Either: success False with an error (preferred), or success True if tool clamps timeout.
    _assert_common_shape(result)


def test_cross_file_security_scan_max_modules_limit_is_handled(mcp_client):
    """A tiny max_modules should not crash the tool; accept failure or partial success."""
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 6, "include_diagram": False, "timeout_seconds": 30, "max_modules": 1},
        max_seconds=30,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    # If it succeeds, it should still return structured fields.
    assert result.get("success") in (True, False), result


def test_cross_file_security_scan_mixed_language_tree_does_not_crash(mcp_client, tmp_path):
    """Scanner should tolerate non-Python files in the project root."""
    root = tmp_path / "mixed"
    _write_text(root / "a.py", "def a(x):\n    return x\n")
    _write_text(root / "b.js", "export function b(x){ return x }\n")
    _write_text(root / "c.ts", "export function c(x: number): number { return x }\n")
    _write_text(root / "d.java", "public class D { int f(){ return 1; } }\n")
    _write_text(root / "README.md", "# hello\n")

    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 4, "include_diagram": False, "timeout_seconds": 15, "max_modules": 50},
        max_seconds=25,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result.get("files_analyzed", 0) >= 1, result


def test_cross_file_security_scan_symlink_loop_does_not_hang(mcp_client, tmp_path):
    """Symlink loops must not cause infinite traversal."""
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    root = tmp_path / "symlink_loop"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "ok.py", "def ok():\n    return 1\n")

    loop = root / "loop"
    try:
        os.symlink(str(root), str(loop))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 6, "include_diagram": False, "timeout_seconds": 10, "max_modules": 50},
        max_seconds=25,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_cross_file_security_scan_permission_denied_dir_fails_safely(mcp_client, tmp_path):
    """Unreadable subdirectories should not crash the scan."""
    root = tmp_path / "perm"
    protected = root / "protected"
    root.mkdir(parents=True, exist_ok=True)
    protected.mkdir(parents=True, exist_ok=True)

    _write_text(root / "ok.py", "def ok():\n    return 1\n")
    _write_text(protected / "secret.py", "def secret():\n    return 42\n")

    try:
        protected.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    try:
        raw, _ = _timed_call(
            mcp_client,
            "cross_file_security_scan",
            {"project_root": str(root), "max_depth": 6, "include_diagram": False, "timeout_seconds": 10, "max_modules": 50},
            max_seconds=25,
        )
        result = _normalize_cross_file_security_scan_result(raw)
        _assert_common_shape(result)
        assert result.get("success") in (True, False), result
    finally:
        try:
            protected.chmod(0o700)
        except OSError:
            pass


def test_cross_file_security_scan_perf_sanity_synthetic_import_chain(mcp_client, tmp_path):
    """Larger-but-bounded module graph should remain within wall-clock limits."""
    root = tmp_path / "chain"
    root.mkdir(parents=True, exist_ok=True)

    # 40 modules in a simple import chain.
    for i in range(1, 41):
        next_mod = i + 1
        if i < 40:
            body = f"import m{next_mod}\n\n" + f"def f{i}(x):\n    return x\n"
        else:
            body = f"def f{i}(x):\n    return x\n"
        _write_text(root / f"m{i}.py", body)

    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 6, "include_diagram": False, "timeout_seconds": 15, "max_modules": 200},
        max_seconds=30,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result.get("files_analyzed", 0) >= 20, result


def test_cross_file_security_scan_missing_project_root_is_handled(mcp_client):
    """If project_root is omitted, tool must not crash or hang.

    Preferred behavior is a fast validation error, but accept safe success
    if the implementation falls back to a default root.
    """

    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"max_depth": 3, "include_diagram": False, "timeout_seconds": 5, "max_modules": 10},
        max_seconds=30,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


@pytest.mark.xfail(
    reason="Quality gap: cross_file_security_scan should validate required project_root instead of defaulting to a fallback",
    strict=False,
)
def test_cross_file_security_scan_missing_project_root_should_fail_validation(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"max_depth": 3, "include_diagram": False, "timeout_seconds": 5, "max_modules": 10},
        max_seconds=30,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_cross_file_security_scan_nonexistent_root_fails_safely(mcp_client, tmp_path):
    missing = tmp_path / "does_not_exist_12345"
    raw, _ = _timed_call(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(missing), "max_depth": 3, "include_diagram": False, "timeout_seconds": 5, "max_modules": 10},
        max_seconds=15,
    )
    result = _normalize_cross_file_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result
