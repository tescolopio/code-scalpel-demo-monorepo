from __future__ import annotations

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


def _normalize_extract_code_result(raw: dict) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict: {success: bool, target_code: str, line_start: int, ...}
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

    # Core shape
    assert isinstance(result.get("target_name"), str) and result["target_name"], result
    assert isinstance(result.get("target_code"), str), result
    assert isinstance(result.get("context_code"), str), result
    assert isinstance(result.get("full_code"), str), result
    assert isinstance(result.get("context_items"), list), result
    assert isinstance(result.get("line_start"), int), result
    assert isinstance(result.get("line_end"), int), result
    assert isinstance(result.get("total_lines"), int), result
    assert isinstance(result.get("token_estimate"), int), result

    # JSX-related fields should always be present for compatibility
    assert isinstance(result.get("jsx_normalized"), bool), result
    assert isinstance(result.get("is_server_component"), bool), result
    assert isinstance(result.get("is_server_action"), bool), result
    assert isinstance(result.get("component_type"), (str, type(None))), result

    # Basic consistency
    assert result["line_start"] > 0, result
    assert result["line_end"] >= result["line_start"], result

    # When cross-file deps are included, context_items should reflect that.
    # (Not strictly required for all runs.)


def test_extract_code_python_function_basic(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "function", "target_name": "divide", "file_path": str(path), "include_token_estimate": True},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True
    assert "def divide" in result.get("target_code", ""), result
    assert result.get("token_estimate", 0) > 0, result


def test_extract_code_python_method_basic(mcp_client):
    path = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test" / "database.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "method", "target_name": "UserDatabase.search_users", "file_path": str(path)},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True
    assert "def search_users" in result.get("target_code", ""), result


def test_extract_code_python_class_basic(mcp_client):
    path = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test" / "database.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "class", "target_name": "UserDatabase", "file_path": str(path)},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True
    assert "class UserDatabase" in result.get("target_code", ""), result


def test_extract_code_include_context_adds_helpers(mcp_client, tmp_path):
    # Synthetic intra-file deps.
    demo = tmp_path / "demo_context.py"
    demo.write_text(
        """
def helper(x):
    return x + 1

def target(y):
    return helper(y) * 2
""".lstrip(),
        encoding="utf-8",
    )

    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {
            "target_type": "function",
            "target_name": "target",
            "file_path": str(demo),
            "include_context": True,
            "context_depth": 1,
        },
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True
    assert "def target" in result.get("target_code", ""), result
    # Helper should be pulled into context/full when include_context=True.
    assert "def helper" in result.get("context_code", "") or "def helper" in result.get("full_code", ""), result


def test_extract_code_include_cross_file_deps_adds_imported_symbols(mcp_client):
    path = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test" / "routes.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {
            "target_type": "function",
            "target_name": "search_route",
            "file_path": str(path),
            "include_cross_file_deps": True,
        },
        max_seconds=20,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True
    assert "def search_route" in result.get("target_code", ""), result
    assert result.get("context_items"), result
    assert "UserDatabase" in result.get("context_code", "") or "class UserDatabase" in result.get("full_code", ""), result


def test_extract_code_token_estimate_can_be_disabled(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "function", "target_name": "divide", "file_path": str(path), "include_token_estimate": False},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True
    # Current implementation keeps the field but sets it to 0.
    assert result.get("token_estimate") == 0, result


def test_extract_code_missing_file_fails(mcp_client, tmp_path):
    missing = tmp_path / "nope_12345.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "function", "target_name": "f", "file_path": str(missing)},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is False, result


def test_extract_code_symbol_not_found_fails(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "function", "target_name": "does_not_exist_123", "file_path": str(path)},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is False, result


def test_extract_code_wrong_target_type_fails(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        # divide is a function, not a class
        {"target_type": "class", "target_name": "divide", "file_path": str(path)},
        max_seconds=15,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is False, result


def test_extract_code_tsx_component_extraction_smoke(mcp_client, tmp_path):
    # Smoke test TSX/JSX parsing path.
    tsx = tmp_path / "UserCard.tsx"
    tsx.write_text(
        """
import React from 'react'

type Props = { name: string }

export function UserCard(props: Props) {
  return <div>{props.name}</div>
}
""".lstrip(),
        encoding="utf-8",
    )

    raw, _ = _timed_call(
        mcp_client,
        "extract_code",
        {"target_type": "function", "target_name": "UserCard", "file_path": str(tsx)},
        max_seconds=20,
    )
    result = _normalize_extract_code_result(raw)
    _assert_common_shape(result)
    assert result["success"] is True, result
    assert "UserCard" in result.get("target_code", ""), result
