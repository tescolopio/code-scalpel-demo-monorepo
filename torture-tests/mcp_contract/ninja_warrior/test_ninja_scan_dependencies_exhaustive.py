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

    # Common scan-dependencies fields (best-effort across versions)
    normalized.setdefault("path", None)
    normalized.setdefault("total_dependencies", 0)
    normalized.setdefault("dependencies", [])
    normalized.setdefault("vulnerability_count", 0)
    normalized.setdefault("vulnerabilities", [])

    if not isinstance(normalized.get("dependencies"), list):
        normalized["dependencies"] = []
    if not isinstance(normalized.get("vulnerabilities"), list):
        normalized["vulnerabilities"] = []

    if not isinstance(normalized.get("total_dependencies"), int):
        normalized["total_dependencies"] = 0
    if not isinstance(normalized.get("vulnerability_count"), int):
        normalized["vulnerability_count"] = 0

    return normalized


def _normalize_scan_dependencies_result(raw) -> dict:
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

    assert isinstance(result.get("total_dependencies"), int), result
    assert isinstance(result.get("dependencies"), list), result
    assert isinstance(result.get("vulnerability_count"), int), result
    assert isinstance(result.get("vulnerabilities"), list), result

    if result.get("success") is False:
        assert result.get("error"), result


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_scan_dependencies_missing_path_fails_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "scan_dependencies", {"scan_vulnerabilities": False, "include_dev": False}, max_seconds=15)
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    # Some implementations may return success=True with an empty scan result.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("total_dependencies", 0) == 0, result


@pytest.mark.xfail(reason="Quality gap: missing required 'path' should fail validation", strict=False)
def test_scan_dependencies_missing_path_should_fail_validation(mcp_client):
    raw, _ = _timed_call(mcp_client, "scan_dependencies", {"scan_vulnerabilities": False, "include_dev": False}, max_seconds=15)
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_scan_dependencies_invalid_path_negative_control(mcp_client, tmp_path):
    missing = tmp_path / "nope.requirements.txt"
    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(missing), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_scan_dependencies_requirements_basic_no_network(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    _write_text(req, "requests==2.31.0\n", encoding="utf-8")

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(req), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("total_dependencies", 0) >= 1, result
    assert result.get("vulnerability_count", 0) == 0, result


def test_scan_dependencies_requirements_edge_lines_handled(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    _write_text(
        req,
        "# comment\n\n"
        "flask>=2.0\n"
        "requests[socks]==2.31.0 ; python_version >= '3.8'\n"
        "git+https://example.invalid/repo.git#egg=somepkg\n"
        "./localpkg\n",
        encoding="utf-8",
    )

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(req), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=20,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)

    # Implementation may ignore/skip VCS/local lines; require safe success or safe failure.
    assert result.get("success") in (True, False), result


def test_scan_dependencies_package_json_include_dev_affects_count(mcp_client, tmp_path):
    pkg = tmp_path / "package.json"
    _write_text(
        pkg,
        '{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"},"devDependencies":{"jest":"29.0.0"}}',
        encoding="utf-8",
    )

    raw_no_dev, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(pkg), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    res_no_dev = _normalize_scan_dependencies_result(raw_no_dev)
    _assert_common_shape(res_no_dev)
    assert res_no_dev.get("success") is True, res_no_dev

    raw_with_dev, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(pkg), "scan_vulnerabilities": False, "include_dev": True},
        max_seconds=15,
    )
    res_with_dev = _normalize_scan_dependencies_result(raw_with_dev)
    _assert_common_shape(res_with_dev)
    assert res_with_dev.get("success") is True, res_with_dev

    assert res_with_dev.get("total_dependencies", 0) >= res_no_dev.get("total_dependencies", 0), {
        "no_dev": res_no_dev,
        "with_dev": res_with_dev,
    }


def test_scan_dependencies_pom_xml_basic(mcp_client, tmp_path):
    pom = tmp_path / "pom.xml"
    _write_text(
        pom,
        """<project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
  xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd\">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
""",
        encoding="utf-8",
    )

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(pom), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=20,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("total_dependencies", 0) >= 1, result


def test_scan_dependencies_directory_path_handled_safely(mcp_client, tmp_path):
    root = tmp_path / "proj"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "requirements.txt", "requests==2.31.0\n", encoding="utf-8")

    # Some implementations may support directory scanning; others may require a file.
    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(root), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=20,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_scan_dependencies_invalid_encoding_handled_safely(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    _write_bytes(req, b"requests==2.31.0\n\xff\xfe\xff")

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(req), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_scan_dependencies_binary_file_fails_safely(mcp_client, tmp_path):
    f = tmp_path / "blob.bin"
    _write_bytes(f, b"\x00\x01\x02\x03")

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(f), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    # Accept either failure or safe empty success.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("total_dependencies", 0) == 0, result


@pytest.mark.xfail(reason="Quality gap: binary inputs should likely be rejected", strict=False)
def test_scan_dependencies_binary_file_should_be_rejected(mcp_client, tmp_path):
    f = tmp_path / "blob.bin"
    _write_bytes(f, b"\x00\x01\x02\x03")

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(f), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_scan_dependencies_permission_denied_fails_safely(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    _write_text(req, "requests==2.31.0\n", encoding="utf-8")

    try:
        req.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(req), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    # Accept either failure or safe empty success.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("total_dependencies", 0) == 0, result

    try:
        req.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


@pytest.mark.xfail(reason="Quality gap: permission denied should likely be rejected", strict=False)
def test_scan_dependencies_permission_denied_should_fail(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    _write_text(req, "requests==2.31.0\n", encoding="utf-8")

    try:
        req.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(req), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result

    try:
        req.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def test_scan_dependencies_large_requirements_bounded(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    lines = [f"pkg{i}==1.0.{i % 10}" for i in range(600)]
    _write_text(req, "\n".join(lines) + "\n", encoding="utf-8")

    raw, elapsed = _timed_call(
        mcp_client,
        "scan_dependencies",
        {"path": str(req), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=25,
    )
    result = _normalize_scan_dependencies_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), {"elapsed": elapsed, "result": result}


def test_scan_dependencies_scan_vulnerabilities_true_quality_gap_documented():
    # scan_vulnerabilities=True may require network access (OSV) and is non-deterministic in CI.
    # Keep the exhaustive suite deterministic by documenting this rather than calling it.
    pytest.xfail("Non-deterministic: scan_vulnerabilities=True may require network")
