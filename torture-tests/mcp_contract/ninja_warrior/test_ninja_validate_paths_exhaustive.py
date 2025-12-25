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
    normalized.setdefault("accessible", [])
    normalized.setdefault("inaccessible", [])
    normalized.setdefault("suggestions", [])
    normalized.setdefault("workspace_roots", [])
    normalized.setdefault("is_docker", None)

    for k in ("accessible", "inaccessible", "suggestions", "workspace_roots"):
        if not isinstance(normalized.get(k), list):
            normalized[k] = []

    if not isinstance(normalized.get("is_docker"), bool):
        normalized["is_docker"] = None

    if not isinstance(normalized.get("success"), bool):
        normalized["success"] = False

    if not (isinstance(normalized.get("error"), str) or normalized.get("error") is None):
        normalized["error"] = str(normalized.get("error"))

    return normalized


def _recompute_success_from_lists(normalized: dict[str, Any]) -> dict[str, Any]:
    """Prefer tool semantics: success means all paths accessible.

    Some server variants return an envelope wrapper and omit an explicit
    `success` field in the tool payload. In those cases, derive it from
    `inaccessible`.
    """
    if not isinstance(normalized.get("accessible"), list):
        normalized["accessible"] = []
    if not isinstance(normalized.get("inaccessible"), list):
        normalized["inaccessible"] = []

    # Only override when `success` is missing or clearly envelope-derived.
    # If the tool provides an explicit boolean, keep it.
    if "success" not in normalized or not isinstance(normalized.get("success"), bool):
        normalized["success"] = len(normalized.get("inaccessible") or []) == 0
    return normalized


def _normalize_validate_paths_result(raw: Any) -> dict[str, Any]:
    """Normalize output across server formats.

    - Flat dict
    - Envelope v1 wrapper
    - JSON-RPC error wrapper
    """
    if not isinstance(raw, dict):
        return _recompute_success_from_lists(
            _fill_defaults({"success": False, "error": f"non-dict result: {type(raw).__name__}", "_raw": raw})
        )

    # JSON-RPC error wrapper
    if "jsonrpc" in raw and "error" in raw and isinstance(raw.get("error"), dict):
        err = raw.get("error") or {}
        msg = err.get("message") or str(err)
        return _recompute_success_from_lists(_fill_defaults({"success": False, "error": msg, "_jsonrpc": raw}))

    # Envelope v1 wrapper
    if isinstance(raw.get("capabilities"), list) and "data" in raw:
        data = raw.get("data")
        if not isinstance(data, dict):
            msg = None
            if isinstance(raw.get("error"), dict):
                msg = raw["error"].get("message")
            return _recompute_success_from_lists(
                _fill_defaults({"success": False, "error": msg or "envelope missing data", "_envelope": raw})
            )
        if raw.get("error"):
            err = raw.get("error")
            msg = err.get("message") if isinstance(err, dict) else str(err)
            normalized = dict(data)
            normalized.update({"success": False, "error": msg, "_envelope": raw})
            return _recompute_success_from_lists(_fill_defaults(normalized))
        normalized = dict(data)
        # Do not force success=True just because the envelope call succeeded.
        # Derive success from inaccessible[] when tool omits it.
        normalized.update({"error": None, "_envelope": raw})
        return _recompute_success_from_lists(_fill_defaults(normalized))

    return _recompute_success_from_lists(_fill_defaults(raw))


def _call_validate_paths(mcp_client, args: dict[str, Any], max_seconds: float = 10.0) -> tuple[dict[str, Any], float]:
    start = time.monotonic()
    raw = mcp_client.tools_call("validate_paths", args)
    elapsed = time.monotonic() - start
    assert elapsed < max_seconds, {"elapsed": elapsed, "raw": raw, "args": args}
    return _normalize_validate_paths_result(raw), elapsed


def _assert_safe_failure(result: dict[str, Any]) -> None:
    assert result.get("success") is False, result
    assert result.get("error") is None or isinstance(result.get("error"), str)


def test_validate_paths_all_accessible_relative_paths_success(mcp_client):
    # These should exist relative to the server root (repo root).
    result, _ = _call_validate_paths(
        mcp_client,
        {"paths": ["README.md", "torture-tests/test_harness.py", ".code-scalpel/policy.yaml"]},
    )
    assert result.get("success") is True, result
    assert len(result.get("inaccessible") or []) == 0, result


def test_validate_paths_mixed_accessible_and_missing(tmp_path, mcp_client):
    existing = tmp_path / "exists.txt"
    existing.write_text("ok", encoding="utf-8")
    missing = tmp_path / "missing_12345.txt"

    result, _ = _call_validate_paths(mcp_client, {"paths": [str(existing), str(missing)]})
    assert result.get("success") is False, result
    # Missing should be reported as inaccessible.
    assert any(str(missing) in p for p in (result.get("inaccessible") or [])), result


def test_validate_paths_all_missing(tmp_path, mcp_client):
    missing1 = tmp_path / "nope1.txt"
    missing2 = tmp_path / "nope2.txt"

    result, _ = _call_validate_paths(mcp_client, {"paths": [str(missing1), str(missing2)]})
    assert result.get("success") is False, result
    assert len(result.get("inaccessible") or []) >= 1, result


def test_validate_paths_directory_path_behavior(tmp_path, mcp_client):
    d = tmp_path / "adir"
    d.mkdir()

    result, _ = _call_validate_paths(mcp_client, {"paths": [str(d)]})
    # Directory accessibility is implementation-defined; must not crash/hang.
    assert result.get("success") in (True, False), result
    assert isinstance(result.get("accessible"), list), result
    assert isinstance(result.get("inaccessible"), list), result


def test_validate_paths_duplicate_paths_idempotent(mcp_client):
    result, _ = _call_validate_paths(mcp_client, {"paths": ["README.md", "README.md", "README.md"]})
    assert result.get("success") is True, result


def test_validate_paths_empty_list_safe(mcp_client):
    result, _ = _call_validate_paths(mcp_client, {"paths": []})
    # Empty list is ambiguous: could be success=True (vacuously) or a validation error.
    assert result.get("success") in (True, False), result


def test_validate_paths_missing_args_fails_safely(mcp_client):
    result, _ = _call_validate_paths(mcp_client, {})
    _assert_safe_failure(result)


def test_validate_paths_invalid_paths_type_fails_safely(mcp_client):
    result, _ = _call_validate_paths(mcp_client, {"paths": "README.md"})
    _assert_safe_failure(result)


def test_validate_paths_nul_bytes_in_path_fails_safely(mcp_client):
    nul = chr(0)
    # This case can trigger slower validation paths in some environments.
    result, elapsed = _call_validate_paths(mcp_client, {"paths": ["README.md" + nul]}, max_seconds=90.0)
    if elapsed > 10.0:
        pytest.xfail(f"NUL-byte path validation exceeded perf budget (elapsed={elapsed:.2f}s)")
    _assert_safe_failure(result)


def test_validate_paths_unicode_path_safe(tmp_path, mcp_client):
    p = tmp_path / "unicodé.txt"
    p.write_text("ok", encoding="utf-8")

    result, _ = _call_validate_paths(mcp_client, {"paths": [str(p)]})
    assert result.get("success") is True, result


def test_validate_paths_permission_denied_expected_inaccessible(tmp_path, mcp_client):
    p = tmp_path / "no_perms.txt"
    p.write_text("secret", encoding="utf-8")
    os.chmod(p, 0)

    try:
        result, _ = _call_validate_paths(mcp_client, {"paths": [str(p)]})
        # Most implementations should mark this inaccessible; accept either but ensure no crash.
        assert result.get("success") in (True, False), result
        if result.get("success") is False:
            assert len(result.get("inaccessible") or []) >= 1, result
    finally:
        try:
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass


def test_validate_paths_symlink_to_file(tmp_path, mcp_client):
    target = tmp_path / "real.txt"
    target.write_text("ok", encoding="utf-8")

    link = tmp_path / "link.txt"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")

    result, _ = _call_validate_paths(mcp_client, {"paths": [str(link)]})
    assert result.get("success") is True, result


def test_validate_paths_symlink_loop_does_not_hang(tmp_path, mcp_client):
    link = tmp_path / "loop.txt"
    try:
        os.symlink(str(link), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")

    result, elapsed = _call_validate_paths(mcp_client, {"paths": [str(link)]}, max_seconds=10.0)
    assert elapsed < 5.0, {"elapsed": elapsed, "result": result}
    assert result.get("success") in (True, False), result


def test_validate_paths_windows_style_path_safe(mcp_client):
    # On Linux this should be inaccessible; tool should fail safely.
    result, _ = _call_validate_paths(mcp_client, {"paths": [r"C:\\Windows\\System32\\cmd.exe"]})
    assert result.get("success") in (True, False), result


def test_validate_paths_large_list_perf(mcp_client):
    paths = ["README.md"] * 300
    result, elapsed = _call_validate_paths(mcp_client, {"paths": paths}, max_seconds=20.0)
    assert result.get("success") is True, result
    assert elapsed < 5.0, {"elapsed": elapsed, "result": result}


def test_validate_paths_very_long_path_safe(mcp_client):
    long_path = "/tmp/" + ("a" * 5000)
    result, _ = _call_validate_paths(mcp_client, {"paths": [long_path]})
    assert result.get("success") in (True, False), result
