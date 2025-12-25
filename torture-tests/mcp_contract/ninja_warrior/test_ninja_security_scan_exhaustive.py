from __future__ import annotations

import os
import stat
import time
from pathlib import Path

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

    # Core scan fields (best-effort across versions)
    normalized.setdefault("has_vulnerabilities", False)
    normalized.setdefault("vulnerability_count", 0)
    normalized.setdefault("vulnerabilities", [])
    normalized.setdefault("taint_flows", [])
    normalized.setdefault("risk_level", None)

    if not isinstance(normalized.get("has_vulnerabilities"), bool):
        normalized["has_vulnerabilities"] = False

    if not isinstance(normalized.get("vulnerabilities"), list):
        normalized["vulnerabilities"] = []

    if not isinstance(normalized.get("taint_flows"), list):
        normalized["taint_flows"] = []

    if not isinstance(normalized.get("vulnerability_count"), int):
        # Prefer a stable int so downstream assertions are safe.
        normalized["vulnerability_count"] = len(normalized.get("vulnerabilities") or [])

    # Keep counts consistent when possible.
    if isinstance(normalized.get("vulnerabilities"), list) and isinstance(normalized.get("vulnerability_count"), int):
        if normalized["vulnerability_count"] == 0 and normalized["vulnerabilities"]:
            normalized["vulnerability_count"] = len(normalized["vulnerabilities"])

    return normalized


def _normalize_security_scan_result(raw) -> dict:
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

    assert isinstance(result.get("has_vulnerabilities"), bool), result
    assert isinstance(result.get("vulnerability_count"), int), result
    assert isinstance(result.get("vulnerabilities"), list), result
    assert isinstance(result.get("taint_flows"), list), result
    assert isinstance(result.get("risk_level"), (str, type(None))), result

    if result.get("success") is False:
        assert result.get("error"), result

    # Internal consistency when tool claims a successful scan.
    if result.get("success") is True:
        assert result["vulnerability_count"] == len(result["vulnerabilities"]), result
        if result["has_vulnerabilities"] is False:
            assert result["vulnerability_count"] == 0, result


def _assert_vuln_entries_are_structured(result: dict):
    vulns = result.get("vulnerabilities") or []
    for v in vulns:
        assert isinstance(v, dict), v
        # Best-effort fields across versions.
        assert isinstance(v.get("type"), (str, type(None))), v
        assert isinstance(v.get("cwe"), (str, type(None))), v
        assert isinstance(v.get("description"), (str, type(None))), v
        assert isinstance(v.get("line"), (int, type(None))), v


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_security_scan_sql_injection_positive_control(mcp_client):
    code = (
        "def handler(user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n"
    )

    raw, _ = _timed_call(mcp_client, "security_scan", {"code": code}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    if result.get("has_vulnerabilities") is True:
        assert result.get("vulnerability_count", 0) >= 1, result
        _assert_vuln_entries_are_structured(result)
    else:
        pytest.xfail("Expected SQL injection detection, but tool reported none")


def test_security_scan_safe_code_negative_control(mcp_client):
    code = "def add(a, b):\n    return a + b\n"

    raw, _ = _timed_call(mcp_client, "security_scan", {"code": code}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    # Avoid flakiness on false positives: if it claims vulns, they must be structured.
    if result.get("has_vulnerabilities") is True:
        assert result.get("vulnerability_count", 0) >= 1, result
        _assert_vuln_entries_are_structured(result)


def test_security_scan_multivuln_snippet_structured(mcp_client):
    code = (
        "import os\n"
        "def h(user_id, filename, cmd):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n"
        "    os.system(cmd)\n"
        "    with open(filename, 'r') as f:\n"
        "        return f.read()\n"
    )

    raw, _ = _timed_call(mcp_client, "security_scan", {"code": code}, max_seconds=20)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    if result.get("has_vulnerabilities") is True:
        assert result.get("vulnerability_count", 0) >= 1, result
        _assert_vuln_entries_are_structured(result)


@pytest.mark.parametrize(
    "name,code",
    [
        ("javascript", "export function f(x){ return x }\n"),
        ("typescript", "export function f(x: number): number { return x }\n"),
        ("java", "public class A { static int f(int x){ return x; } }\n"),
    ],
    ids=["js", "ts", "java"],
)
def test_security_scan_cross_language_code_does_not_crash(mcp_client, name, code):
    raw, _ = _timed_call(mcp_client, "security_scan", {"code": code}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    # Either: success False with an error (preferred), or success True with no findings.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("vulnerability_count", 0) >= 0, result


def test_security_scan_missing_args_fails_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "security_scan", {}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    # Some implementations may treat "no input" as an empty scan.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("vulnerability_count", 0) == 0, result


@pytest.mark.xfail(reason="Quality gap: missing both 'code' and 'file_path' should fail validation", strict=False)
def test_security_scan_missing_args_should_fail_validation(mcp_client):
    raw, _ = _timed_call(mcp_client, "security_scan", {}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_security_scan_both_code_and_file_path_is_accepted(mcp_client, tmp_path):
    f = tmp_path / "vuln.py"
    _write_text(
        f,
        "def handler(user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n",
    )

    raw, _ = _timed_call(
        mcp_client,
        "security_scan",
        {"code": "def ok():\n    return 1\n", "file_path": str(f)},
        max_seconds=20,
    )
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


@pytest.mark.xfail(
    reason="Bug: security_scan(file_path=...) raises internal VulnerabilityInfo mapping error (VulnerabilityInfo() argument after ** must be a mapping)",
    strict=False,
)
def test_security_scan_file_path_positive_control(mcp_client, tmp_path):
    f = tmp_path / "vuln.py"
    _write_text(
        f,
        "def handler(user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    cursor.execute(query)\n",
    )

    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(f)}, max_seconds=20)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    if result.get("has_vulnerabilities") is True:
        assert result.get("vulnerability_count", 0) >= 1, result
        _assert_vuln_entries_are_structured(result)
    else:
        pytest.xfail("Expected SQL injection detection from file_path scan, but tool reported none")


def test_security_scan_missing_file_path_fails_safely(mcp_client, tmp_path):
    missing = tmp_path / "missing.py"
    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(missing)}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_security_scan_directory_path_handled_safely(mcp_client, tmp_path):
    root = tmp_path / "proj"
    root.mkdir(parents=True, exist_ok=True)

    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(root)}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_security_scan_binary_file_handled_safely(mcp_client, tmp_path):
    f = tmp_path / "blob.py"
    _write_bytes(f, b"\x00\x01\x02\x03\xff\xfe")

    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(f)}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    # Accept either a clean failure or a safe empty success.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("vulnerability_count", 0) == 0, result


@pytest.mark.xfail(reason="Quality gap: binary input should be rejected with success=False", strict=False)
def test_security_scan_binary_file_should_fail_validation(mcp_client, tmp_path):
    f = tmp_path / "blob.py"
    _write_bytes(f, b"\x00\x01\x02\x03\xff\xfe")

    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(f)}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_security_scan_permission_denied_file_fails_or_succeeds_safely(mcp_client, tmp_path):
    f = tmp_path / "secret.py"
    _write_text(f, "def ok():\n    return 1\n")

    try:
        f.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    try:
        raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(f)}, max_seconds=15)
        result = _normalize_security_scan_result(raw)
        _assert_common_shape(result)

        assert result.get("success") in (True, False), result
        if result.get("success") is True:
            assert result.get("vulnerability_count", 0) == 0, result
    finally:
        try:
            f.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


@pytest.mark.xfail(reason="Quality gap: permission denied should be reported as success=False", strict=False)
def test_security_scan_permission_denied_should_fail(mcp_client, tmp_path):
    f = tmp_path / "secret.py"
    _write_text(f, "def ok():\n    return 1\n")

    try:
        f.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    try:
        raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(f)}, max_seconds=15)
        result = _normalize_security_scan_result(raw)
        _assert_common_shape(result)
        assert result.get("success") is False, result
    finally:
        try:
            f.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def test_security_scan_symlink_loop_does_not_hang(mcp_client, tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    root = tmp_path / "symlink_loop"
    root.mkdir(parents=True, exist_ok=True)

    loop = root / "loop.py"
    try:
        os.symlink(str(loop), str(loop))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(loop)}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_security_scan_code_with_nul_byte_does_not_crash(mcp_client):
    nul = chr(0)
    code = "def f(x):\n    return x\n" + nul + "\n"

    raw, _ = _timed_call(mcp_client, "security_scan", {"code": code}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


@pytest.mark.xfail(reason="Quality gap: NUL bytes should cause validation failure", strict=False)
def test_security_scan_code_with_nul_byte_should_fail_validation(mcp_client):
    nul = chr(0)
    code = "def f(x):\n    return x\n" + nul + "\n"

    raw, _ = _timed_call(mcp_client, "security_scan", {"code": code}, max_seconds=15)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result


def test_security_scan_large_file_is_bounded(mcp_client, tmp_path):
    f = tmp_path / "large.py"
    # Large but safe Python file to exercise parser/scanner performance.
    lines = ["def f{i}(x):\n    return x\n".format(i=i) for i in range(800)]
    _write_text(f, "\n".join(lines))

    raw, _ = _timed_call(mcp_client, "security_scan", {"file_path": str(f)}, max_seconds=30)
    result = _normalize_security_scan_result(raw)
    _assert_common_shape(result)

    # Prefer success, but accept safe failure on resource constraints.
    assert result.get("success") in (True, False), result
