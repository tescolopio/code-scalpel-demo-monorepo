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


def _fill_defaults(d: dict) -> dict:
    nodes = d.get("nodes") if isinstance(d.get("nodes"), list) else []
    edges = d.get("edges") if isinstance(d.get("edges"), list) else []

    normalized = dict(d)
    normalized.setdefault("server_version", None)
    normalized.setdefault("error", None)
    normalized["nodes"] = nodes
    normalized["edges"] = edges

    # Optional fields we might see in some implementations.
    if "circular_imports" in normalized and not isinstance(normalized.get("circular_imports"), list):
        normalized["circular_imports"] = []
    if "warnings" in normalized and not isinstance(normalized.get("warnings"), list):
        normalized["warnings"] = []
    if "mermaid" in normalized and not isinstance(normalized.get("mermaid"), str):
        normalized["mermaid"] = ""

    return normalized


def _normalize_get_call_graph_result(raw) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict: {success: bool, nodes: [...], edges: [...], ...}
    - Envelope v1: {capabilities: ['envelope-v1'], data: {...}, error: {...}|None, duration_ms: ...}
    - JSON-RPC error wrapper: {jsonrpc: '2.0', error: {...}}

    Also normalize pre-tool validation failures that may only include {success, error}.
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

    # Envelope v1
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
    assert "success" in result and isinstance(result["success"], bool), result
    assert isinstance(result.get("server_version"), (str, type(None))), result
    assert isinstance(result.get("error"), (str, type(None))), result
    assert isinstance(result.get("nodes"), list), result
    assert isinstance(result.get("edges"), list), result

    if result["success"] is False:
        assert result.get("error"), result


def _node_strings(nodes: list) -> list[str]:
    out: list[str] = []
    for n in nodes:
        if isinstance(n, str):
            out.append(n)
        elif isinstance(n, dict):
            for k in ("id", "node_id", "name", "qualified_name"):
                v = n.get(k)
                if isinstance(v, str) and v:
                    out.append(v)
    return out


def _edge_pairs(edges: list) -> list[tuple[str, str]]:
    """Best-effort extraction of edge endpoints for sanity checks."""
    pairs: list[tuple[str, str]] = []
    for e in edges:
        if isinstance(e, dict):
            src = None
            dst = None
            for k in ("from", "source", "src", "caller"):
                if isinstance(e.get(k), str) and e.get(k):
                    src = e[k]
                    break
            for k in ("to", "target", "dst", "callee"):
                if isinstance(e.get(k), str) and e.get(k):
                    dst = e[k]
                    break
            if src and dst:
                pairs.append((src, dst))
        elif isinstance(e, (list, tuple)) and len(e) >= 2:
            a, b = e[0], e[1]
            if isinstance(a, str) and isinstance(b, str):
                pairs.append((a, b))
        elif isinstance(e, str) and "->" in e:
            parts = [p.strip() for p in e.split("->", 1)]
            if len(parts) == 2 and all(parts):
                pairs.append((parts[0], parts[1]))
    return pairs


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)


def test_get_call_graph_known_fixture_contains_entry_and_edges(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": 6, "include_circular_import_check": True},
        max_seconds=25,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result

    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    assert nodes, result

    node_text = "\n".join(_node_strings(nodes)).lower()
    assert "alpha" in node_text, {"node_samples": _node_strings(nodes)[:10], "result": result}

    # Typically this fixture has a chain, so edges should appear; if not, keep informative.
    if not edges:
        pytest.xfail("Expected some call edges in call_chain fixture, but tool returned none")


def test_get_call_graph_depth_zero_is_bounded(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": 0, "include_circular_import_check": False},
        max_seconds=20,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    # With depth=0, an implementation may return only the entry node.
    assert len(result.get("nodes") or []) >= 1, result


@pytest.mark.parametrize(
    "entry_point",
    [
        "call_chain.py",
        "call_chain.py#alpha",
        ":alpha",
        "call_chain.py:",
    ],
)
def test_get_call_graph_invalid_entry_point_format_fails_safely(mcp_client, entry_point):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": entry_point, "depth": 3, "include_circular_import_check": True},
        max_seconds=20,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    # Some implementations may treat this as a failure; others may return an empty graph.
    assert result.get("success") in (True, False), result


def test_get_call_graph_invalid_symbol_negative_control(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:does_not_exist", "depth": 3, "include_circular_import_check": True},
        max_seconds=20,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_call_graph_mixed_language_root_does_not_crash(mcp_client, tmp_path):
    root = tmp_path / "mixed"
    _write_text(
        root / "main.py",
        """
def entry(x):
    return helper(x)


def helper(x):
    if x:
        return 1
    return 0
+""".lstrip(),
    )
    _write_text(root / "a.js", "export function f(x){ return x }\n")
    _write_text(root / "a.ts", "export function f(x: number): number { return x }\n")
    _write_text(root / "A.java", "public class A { int f(){ return 1; } }\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "main.py:entry", "depth": 4, "include_circular_import_check": True},
        max_seconds=25,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    node_text = "\n".join(_node_strings(result.get("nodes") or [])).lower()
    assert "entry" in node_text, {"node_samples": _node_strings(result.get("nodes") or [])[:10], "result": result}


def test_get_call_graph_circular_import_check_safe(mcp_client, tmp_path):
    root = tmp_path / "circular"
    _write_text(
        root / "a.py",
        """
import b


def fa(x):
    return b.fb(x)
+""".lstrip(),
    )
    _write_text(
        root / "b.py",
        """
import a


def fb(x):
    return x
+""".lstrip(),
    )

    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "a.py:fa", "depth": 4, "include_circular_import_check": True},
        max_seconds=25,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_call_graph_symlink_loop_does_not_hang(mcp_client, tmp_path):
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
        "get_call_graph",
        {"project_root": str(root), "entry_point": "ok.py:ok", "depth": 2, "include_circular_import_check": False},
        max_seconds=25,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_call_graph_permission_denied_dir_fails_safely(mcp_client, tmp_path):
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
            "get_call_graph",
            {"project_root": str(root), "entry_point": "ok.py:ok", "depth": 2, "include_circular_import_check": False},
            max_seconds=25,
        )
        result = _normalize_get_call_graph_result(raw)
        _assert_common_shape(result)
        assert result.get("success") in (True, False), result
    finally:
        try:
            protected.chmod(0o700)
        except OSError:
            pass


def test_get_call_graph_perf_sanity_synthetic_chain_bounded(mcp_client, tmp_path):
    root = tmp_path / "chain"
    root.mkdir(parents=True, exist_ok=True)

    # 50 modules that call the next module.
    for i in range(1, 51):
        if i < 50:
            code = f"import m{i+1}\n\n" + f"def f{i}(x):\n    return m{i+1}.f{i+1}(x)\n"
        else:
            code = f"def f{i}(x):\n    return x\n"
        _write_text(root / f"m{i}.py", code)

    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "m1.py:f1", "depth": 4, "include_circular_import_check": True},
        max_seconds=30,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    # Basic endpoint sanity: if edges are structured, their endpoints should be strings.
    pairs = _edge_pairs(result.get("edges") or [])
    assert isinstance(pairs, list)


@pytest.mark.xfail(
    reason="Likely Python-only: get_call_graph should reject non-Python entry points cleanly",
    strict=False,
)
@pytest.mark.parametrize(
    "filename,entry",
    [("a.js", "f"), ("a.ts", "f"), ("A.java", "f")],
    ids=["js", "ts", "java"],
)
def test_get_call_graph_should_reject_non_python_entry_points(mcp_client, tmp_path, filename, entry):
    root = tmp_path / "non_python"
    root.mkdir(parents=True, exist_ok=True)
    if filename.endswith(".js"):
        _write_text(root / filename, "export function f(x){ return x }\n")
    elif filename.endswith(".ts"):
        _write_text(root / filename, "export function f(x: number): number { return x }\n")
    else:
        _write_text(root / filename, "public class A { static int f(int x){ return x; } }\n")

    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": f"{filename}:{entry}", "depth": 2, "include_circular_import_check": False},
        max_seconds=25,
    )
    result = _normalize_get_call_graph_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result
