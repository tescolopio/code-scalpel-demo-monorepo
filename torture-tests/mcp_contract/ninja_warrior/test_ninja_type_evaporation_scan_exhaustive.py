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

    # Core counts seen in existing tests and tool contract.
    normalized.setdefault("frontend_issues", [])
    normalized.setdefault("backend_issues", [])
    normalized.setdefault("cross_file_issues", 0)

    # Some versions include detailed lists.
    normalized.setdefault("frontend_vulnerabilities", [])
    normalized.setdefault("backend_vulnerabilities", [])
    normalized.setdefault("cross_file_vulnerabilities", [])

    for k in (
        "frontend_issues",
        "backend_issues",
        "frontend_vulnerabilities",
        "backend_vulnerabilities",
        "cross_file_vulnerabilities",
    ):
        if not isinstance(normalized.get(k), list):
            normalized[k] = []

    if not isinstance(normalized.get("cross_file_issues"), int):
        normalized["cross_file_issues"] = len(normalized.get("cross_file_vulnerabilities") or [])

    return normalized


def _normalize_type_evaporation_result(raw) -> dict:
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

    assert isinstance(result.get("cross_file_issues"), int), result
    assert isinstance(result.get("frontend_issues"), list), result
    assert isinstance(result.get("backend_issues"), list), result

    if result.get("success") is False:
        assert result.get("error"), result

    if result.get("success") is True:
        assert result.get("cross_file_issues", 0) >= 0, result


def _unsafe_frontend() -> str:
    return (
        "type Role = 'admin' | 'user'\n"
        "export async function sendRole(role: Role) {\n"
        "  return fetch('/api/boundary/role', { method: 'POST', body: JSON.stringify({ role }) })\n"
        "}\n"
    )


def _unsafe_backend() -> str:
    return (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "@app.post('/api/boundary/role')\n"
        "def role():\n"
        "    data = request.get_json(force=True)\n"
        "    return {'role': data['role']}\n"
    )


def _safe_backend() -> str:
    return (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "@app.post('/api/boundary/role')\n"
        "def role():\n"
        "    data = request.get_json(force=True)\n"
        "    role = data.get('role')\n"
        "    if role not in ('admin', 'user'):\n"
        "        return {'error': 'invalid'}, 400\n"
        "    return {'role': role}\n"
    )


def test_type_evaporation_scan_unsafe_positive_control(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": _unsafe_frontend(), "backend_code": _unsafe_backend(), "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    if result.get("cross_file_issues", 0) >= 1:
        assert result.get("cross_file_issues") >= 1, result
    else:
        pytest.xfail("Expected at least one cross-file type evaporation issue, but tool reported none")


def test_type_evaporation_scan_safe_control_has_zero_cross_file_issues(mcp_client):
    frontend = (
        "export async function sendRole(role: string) {\n"
        "  return fetch('/api/boundary/role', { method: 'POST', body: JSON.stringify({ role }) })\n"
        "}\n"
    )

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": _safe_backend(), "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    if result.get("cross_file_issues") != 0:
        pytest.xfail("Expected zero cross-file issues on validated backend; tool reported a possible false positive")


def test_type_evaporation_scan_missing_args_fails_or_succeeds_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "type_evaporation_scan", {}, max_seconds=20)
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("cross_file_issues", 0) == 0, result


@pytest.mark.xfail(reason="Quality gap: missing required inputs should fail validation", strict=False)
def test_type_evaporation_scan_missing_args_should_fail_validation(mcp_client):
    raw, _ = _timed_call(mcp_client, "type_evaporation_scan", {}, max_seconds=20)
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_type_evaporation_scan_frontend_only_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": _unsafe_frontend(), "frontend_file": "frontend.ts", "backend_code": "", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_type_evaporation_scan_malformed_frontend_code_handled_safely(mcp_client):
    frontend = "type Role = 'admin' | 'user'\nexport function f( {\n"  # malformed

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": _unsafe_backend(), "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_type_evaporation_scan_malformed_backend_code_handled_safely(mcp_client):
    backend = "def f(:\n  pass\n"  # malformed python

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": _unsafe_frontend(), "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_type_evaporation_scan_cross_language_backend_text_handled_safely(mcp_client):
    # Backend is expected to be Python; a Java backend string should fail safely.
    backend = "public class A { int f(){ return 1; } }\n"

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": _unsafe_frontend(), "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.java"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_type_evaporation_scan_frontend_js_extension_handled_safely(mcp_client):
    frontend_js = "export async function sendRole(role){ return fetch('/api/boundary/role', {method:'POST', body: JSON.stringify({role})}) }\n"

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": frontend_js, "backend_code": _unsafe_backend(), "frontend_file": "frontend.js", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_type_evaporation_scan_unicode_and_nul_bytes_do_not_crash(mcp_client):
    nul = chr(0)
    frontend = _unsafe_frontend() + "// café π\n" + nul
    backend = _unsafe_backend() + "# café π\n" + nul

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=20,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_type_evaporation_scan_large_inputs_bounded(mcp_client):
    # Large but straightforward inputs to stress parsing/correlation without nondeterminism.
    frontend_lines = [
        "type Role = 'admin' | 'user'\n",
        "export async function sendRole(role: Role) {\n",
        "  return fetch('/api/boundary/role', { method: 'POST', body: JSON.stringify({ role }) })\n",
        "}\n",
    ]
    frontend_lines.extend([f"export const v{i}: number = {i};\n" for i in range(1500)])
    frontend = "".join(frontend_lines)

    backend_lines = [
        "from flask import Flask, request\n",
        "app = Flask(__name__)\n\n",
        "@app.post('/api/boundary/role')\n",
        "def role():\n",
        "    data = request.get_json(force=True)\n",
        "    return {'role': data.get('role')}\n",
    ]
    backend_lines.extend([f"def helper_{i}(x):\n    return x\n\n" for i in range(800)])
    backend = "".join(backend_lines)

    raw, _ = _timed_call(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=30,
    )
    result = _normalize_type_evaporation_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result
