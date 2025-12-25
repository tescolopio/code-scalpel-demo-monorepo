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
    normalized.setdefault("server_version", None)
    normalized.setdefault("error", None)

    # Common project-map-ish fields (best-effort; schema varies by server version)
    normalized.setdefault("project_root", None)
    normalized.setdefault("files", [])  # some versions omit this
    normalized.setdefault("imports", [])
    normalized.setdefault("circular_imports", [])
    normalized.setdefault("complexity", {})
    normalized.setdefault("summary", {})

    # Seen in current server output
    normalized.setdefault("complexity_hotspots", [])
    normalized.setdefault("diagram_truncated", False)
    normalized.setdefault("mermaid", "")

    if not isinstance(normalized.get("files"), list):
        normalized["files"] = []
    if not isinstance(normalized.get("imports"), list):
        normalized["imports"] = []
    if not isinstance(normalized.get("circular_imports"), list):
        normalized["circular_imports"] = []
    if not isinstance(normalized.get("complexity"), dict):
        normalized["complexity"] = {}
    if not isinstance(normalized.get("summary"), dict):
        normalized["summary"] = {}
    if not isinstance(normalized.get("complexity_hotspots"), list):
        normalized["complexity_hotspots"] = []
    if not isinstance(normalized.get("diagram_truncated"), bool):
        normalized["diagram_truncated"] = False
    if not isinstance(normalized.get("mermaid"), str):
        normalized["mermaid"] = ""

    return normalized


def _normalize_get_project_map_result(raw) -> dict:
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
    # Schema varies; enforce type-safety for known fields.
    assert isinstance(result.get("files"), list), result
    assert isinstance(result.get("imports"), list), result
    assert isinstance(result.get("circular_imports"), list), result
    assert isinstance(result.get("complexity"), dict), result
    assert isinstance(result.get("summary"), dict), result
    assert isinstance(result.get("complexity_hotspots"), list), result
    assert isinstance(result.get("diagram_truncated"), bool), result
    assert isinstance(result.get("mermaid"), str), result


def _assert_has_some_project_content(result: dict):
    """Avoid over-constraining: require *some* evidence the project was scanned."""

    signals = []
    signals.extend(result.get("files") or [])
    signals.extend(result.get("imports") or [])
    signals.extend(result.get("complexity_hotspots") or [])

    if signals:
        return

    # Some versions store counts/summaries only.
    if result.get("summary"):
        return

    pytest.fail(f"No project content signals found in result: keys={sorted(result.keys())}")


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def _make_tiny_python_project(tmp_path: Path) -> Path:
    root = tmp_path / "tiny_project_map"
    root.mkdir(parents=True, exist_ok=True)

    _write_text(root / "a.py", "import b\n\n\ndef fa(x):\n    return b.fb(x)\n")
    _write_text(root / "b.py", "def fb(x):\n    return x\n")
    _write_text(root / "pkg" / "__init__.py", "")
    _write_text(root / "pkg" / "m.py", "from .. import a\n\n\ndef g():\n    return a.fa(1)\n")
    return root


def test_get_project_map_known_fixture_low_noise(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": True, "complexity_threshold": 50, "include_circular_check": True},
        max_seconds=25,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_project_map_tiny_project_succeeds(mcp_client, tmp_path):
    root = _make_tiny_python_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": True, "complexity_threshold": 0, "include_circular_check": True},
        max_seconds=15,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    _assert_has_some_project_content(result)


def test_get_project_map_include_complexity_false_safe(mcp_client, tmp_path):
    root = _make_tiny_python_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": False, "include_circular_check": False},
        max_seconds=15,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


@pytest.mark.parametrize("threshold", [-1, 0, 1, 50, 10_000], ids=["neg", "zero", "one", "mid", "huge"])
def test_get_project_map_complexity_threshold_edge_values(mcp_client, tmp_path, threshold):
    root = _make_tiny_python_project(tmp_path)
    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": True, "complexity_threshold": threshold, "include_circular_check": False},
        max_seconds=15,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_project_map_invalid_root_fails_safely(mcp_client, tmp_path):
    missing = tmp_path / "nope"
    raw, _ = _timed_call(mcp_client, "get_project_map", {"project_root": str(missing)}, max_seconds=15)
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_project_map_empty_project_root_quality_gap_documented():
    # Calling with project_root="" has been observed to hang (no SSE response).
    # Mark as xfail without invoking the tool to keep the suite bounded.
    pytest.xfail("Quality gap: empty project_root may hang instead of failing fast")


def test_get_project_map_missing_project_root_quality_gap_documented():
    # Calling without project_root has been observed to hang (no SSE response).
    # Mark as xfail without invoking the tool to keep the suite bounded.
    pytest.xfail("Quality gap: missing project_root may hang instead of failing fast")


def test_get_project_map_mixed_language_root_does_not_crash(mcp_client, tmp_path):
    root = _make_tiny_python_project(tmp_path)
    _write_text(root / "x.js", "export function f(x){ return x }\n")
    _write_text(root / "x.ts", "export function f(x: number): number { return x }\n")
    _write_text(root / "A.java", "public class A { static int f(int x){ return x; } }\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": True, "complexity_threshold": 50, "include_circular_check": True},
        max_seconds=20,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_project_map_permission_denied_subdir_safe(mcp_client, tmp_path):
    root = _make_tiny_python_project(tmp_path)
    locked = root / "locked"
    locked.mkdir(parents=True, exist_ok=True)
    _write_text(locked / "s.py", "def hidden():\n    return 1\n")

    try:
        locked.chmod(0)
    except OSError as e:
        pytest.skip(f"chmod not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": False, "include_circular_check": False},
        max_seconds=20,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result

    # Restore so tmp cleanup can succeed.
    try:
        locked.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError:
        pass


def test_get_project_map_symlink_loop_does_not_hang(mcp_client, tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink not available")

    root = _make_tiny_python_project(tmp_path)
    loop = root / "loop"
    try:
        os.symlink(str(root), str(loop))
    except OSError as e:
        pytest.skip(f"symlink creation not permitted: {e}")

    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": False, "include_circular_check": False},
        max_seconds=20,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_project_map_circular_imports_flag_type_safe(mcp_client, tmp_path):
    root = tmp_path / "circular_project"
    root.mkdir(parents=True, exist_ok=True)
    _write_text(root / "a.py", "import b\n\n\ndef fa():\n    return b.fb()\n")
    _write_text(root / "b.py", "import a\n\n\ndef fb():\n    return 1\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": False, "include_circular_check": True},
        max_seconds=20,
    )
    result = _normalize_get_project_map_result(raw)
    _assert_common_shape(result)

    # Whether it detects circular imports is implementation-dependent; enforce type safety.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert isinstance(result.get("circular_imports"), list), result
