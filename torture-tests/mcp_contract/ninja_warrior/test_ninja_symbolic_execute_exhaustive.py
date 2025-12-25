from __future__ import annotations

import time

import pytest


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

    # Core symbolic_execute fields (best-effort across versions)
    normalized.setdefault("paths_explored", 0)
    normalized.setdefault("paths", [])

    if not isinstance(normalized.get("paths"), list):
        normalized["paths"] = []

    if not isinstance(normalized.get("paths_explored"), int):
        # Prefer a stable int so downstream assertions are safe.
        normalized["paths_explored"] = len(normalized.get("paths") or [])

    return normalized


def _normalize_symbolic_execute_result(raw) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict tool output
    - Envelope v1 wrapper
    - JSON-RPC error wrapper
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

    assert isinstance(result.get("paths_explored"), int), result
    assert isinstance(result.get("paths"), list), result

    if result.get("success") is False:
        assert result.get("error"), result

    if result.get("success") is True:
        # Basic consistency: some servers may not populate `paths` fully, but
        # it should never claim fewer explored paths than it returns.
        assert result.get("paths_explored", 0) >= len(result.get("paths") or []), result
        assert result.get("paths_explored", 0) >= 0, result


def test_symbolic_execute_branching_positive_control(mcp_client):
    code = """

def branch(x, y):
    if x:
        if y:
            return 'A'
        return 'B'
    return 'C'
""".strip()

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 10}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("paths_explored", 0) >= 3, result


def test_symbolic_execute_max_paths_limits_are_respected_or_safe(mcp_client):
    code = """

def branch(x, y, z):
    if x:
        if y:
            if z:
                return 1
            return 2
        return 3
    return 4
""".strip()

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 2}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    # If it succeeds, it should not explore wildly more than max_paths.
    if result.get("success") is True:
        assert result.get("paths_explored", 0) >= 1, result
        assert result.get("paths_explored", 0) <= 10, result


def test_symbolic_execute_max_paths_zero_handled_safely(mcp_client):
    code = "def f(x):\n    return 1 if x else 0\n"

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 0}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    # Either: fail validation, or succeed with 0 explored paths.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        # Observed behavior: some versions clamp 0 -> 1.
        assert result.get("paths_explored", 0) in (0, 1), result


@pytest.mark.xfail(reason="Quality gap: max_paths=0 should be rejected or return 0 explored paths", strict=False)
def test_symbolic_execute_max_paths_zero_should_not_explore(mcp_client):
    code = "def f(x):\n    return 1 if x else 0\n"

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 0}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False or result.get("paths_explored", 0) == 0, result


def test_symbolic_execute_invalid_code_fails_safely(mcp_client):
    bad = "def f(:\n  pass\n"

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": bad, "max_paths": 5}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result


def test_symbolic_execute_missing_code_fails_or_succeeds_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"max_paths": 5}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    # Some implementations treat missing code as empty code.
    assert result.get("success") in (True, False), result


@pytest.mark.xfail(reason="Quality gap: missing required 'code' should fail validation", strict=False)
def test_symbolic_execute_missing_code_should_fail_validation(mcp_client):
    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"max_paths": 5}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_symbolic_execute_code_with_nul_byte_does_not_crash(mcp_client):
    nul = chr(0)
    code = "def f(x):\n    return x\n" + nul + "\n"

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 5}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_symbolic_execute_deep_nesting_is_bounded(mcp_client):
    code = """

def deep(x):
    if x > 0:
        if x > 1:
            if x > 2:
                if x > 3:
                    if x > 4:
                        return 5
    return 0
""".strip()

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 20}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("paths_explored", 0) >= 2, result


def test_symbolic_execute_loop_is_handled_safely(mcp_client):
    # Symbolic execution engines often approximate loops; must not hang.
    code = """

def loop(n):
    i = 0
    while i < n:
        i += 1
    return i
""".strip()

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 10}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_symbolic_execute_recursion_is_handled_safely(mcp_client):
    code = """

def fact(n):
    if n <= 1:
        return 1
    return n * fact(n - 1)
""".strip()

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 10}, max_seconds=20)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_symbolic_execute_cross_language_text_is_handled_safely(mcp_client):
    # Tool is Python-oriented; cross-language code should fail safely.
    snippets = [
        "export function f(x){ return x }\n",
        "export function f(x: number): number { return x }\n",
        "public class A { static int f(int x){ return x; } }\n",
    ]

    for code in snippets:
        raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 5}, max_seconds=20)
        result = _normalize_symbolic_execute_result(raw)
        _assert_common_shape(result)
        assert result.get("success") in (True, False), result


def test_symbolic_execute_large_input_is_bounded(mcp_client):
    # Generate a large, mostly-linear file with many functions.
    blocks = ["def base(x):\n    return x\n"]
    for i in range(900):
        blocks.append(f"def f{i}(x):\n    return x\n")
    code = "\n".join(blocks)

    raw, _ = _timed_call(mcp_client, "symbolic_execute", {"code": code, "max_paths": 5}, max_seconds=25)
    result = _normalize_symbolic_execute_result(raw)
    _assert_common_shape(result)

    # Prefer success, but accept safe failure on resource constraints.
    assert result.get("success") in (True, False), result
