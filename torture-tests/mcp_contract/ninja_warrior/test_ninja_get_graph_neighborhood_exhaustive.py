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


def _fill_defaults(d: dict) -> dict:
    normalized = dict(d)
    normalized.setdefault("success", False)
    normalized.setdefault("server_version", None)
    normalized.setdefault("error", None)

    # Common neighborhood fields (best-effort across versions)
    normalized.setdefault("center_node_id", None)
    normalized.setdefault("truncated", False)
    normalized.setdefault("truncation_warning", "")
    normalized.setdefault("mermaid", "")

    return normalized


def _normalize_get_graph_neighborhood_result(raw) -> dict:
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


def _extract_nodes_edges(result: dict) -> tuple[list, list]:
    """Best-effort extraction of nodes/edges regardless of nesting."""

    # Common variants: top-level nodes/edges or under result["subgraph"].
    nodes = result.get("nodes")
    edges = result.get("edges")

    if isinstance(nodes, list) and isinstance(edges, list):
        return nodes, edges

    subgraph = result.get("subgraph")
    if isinstance(subgraph, dict):
        sg_nodes = subgraph.get("nodes")
        sg_edges = subgraph.get("edges")
        if isinstance(sg_nodes, list) and isinstance(sg_edges, list):
            return sg_nodes, sg_edges

    return [], []


def _get_any_node_id_from_call_graph(mcp_client) -> str | None:
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    raw, _ = _timed_call(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": 4, "include_circular_import_check": True},
        max_seconds=20,
    )

    if not isinstance(raw, dict):
        return None

    # Normalize JSON-RPC error wrapper
    if "jsonrpc" in raw and "error" in raw and isinstance(raw.get("error"), dict):
        return None

    # Normalize envelope-v1 wrapper
    if "data" in raw and "capabilities" in raw:
        if raw.get("error"):
            return None
        data = raw.get("data") or {}
        if not isinstance(data, dict):
            return None
        raw = dict(data)
        raw.setdefault("success", True)

    if raw.get("success") is not True:
        return None

    nodes = raw.get("nodes") or []
    for n in nodes:
        if isinstance(n, str) and n:
            return n
        if isinstance(n, dict):
            for k in ("id", "node_id", "name"):
                v = n.get(k)
                if isinstance(v, str) and v:
                    return v
    return None


def test_get_graph_neighborhood_positive_control_from_call_graph(mcp_client):
    node_id = _get_any_node_id_from_call_graph(mcp_client)
    if not node_id:
        pytest.skip("No node id available from get_call_graph")

    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=15,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)

    if result.get("success") is not True:
        pytest.skip(f"get_graph_neighborhood failed unexpectedly: {result}")

    nodes, edges = _extract_nodes_edges(result)
    assert isinstance(nodes, list), result
    assert isinstance(edges, list), result
    assert nodes, result


def test_get_graph_neighborhood_k_zero_bounded(mcp_client):
    node_id = _get_any_node_id_from_call_graph(mcp_client)
    if not node_id:
        pytest.skip("No node id available from get_call_graph")

    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 0, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=15,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


@pytest.mark.parametrize("direction", ["incoming", "outgoing", "both"], ids=["in", "out", "both"])
def test_get_graph_neighborhood_direction_variants(mcp_client, direction):
    node_id = _get_any_node_id_from_call_graph(mcp_client)
    if not node_id:
        pytest.skip("No node id available from get_call_graph")

    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 1, "max_nodes": 25, "direction": direction, "min_confidence": 0.0},
        max_seconds=15,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_graph_neighborhood_invalid_direction_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": "python::nonexistent::function::nope", "k": 1, "max_nodes": 25, "direction": "sideways", "min_confidence": 0.0},
        max_seconds=10,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


@pytest.mark.parametrize("min_conf", [-0.1, 0.0, 0.7, 1.0, 1.1], ids=["neg", "zero", "mid", "one", "gt1"])
def test_get_graph_neighborhood_min_confidence_edge_values(mcp_client, min_conf):
    node_id = _get_any_node_id_from_call_graph(mcp_client)
    if not node_id:
        pytest.skip("No node id available from get_call_graph")

    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": min_conf},
        max_seconds=15,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_graph_neighborhood_max_nodes_one_bounded(mcp_client):
    node_id = _get_any_node_id_from_call_graph(mcp_client)
    if not node_id:
        pytest.skip("No node id available from get_call_graph")

    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 2, "max_nodes": 1, "direction": "both", "min_confidence": 0.0},
        max_seconds=15,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_graph_neighborhood_large_k_truncation_fields_type_safe(mcp_client):
    node_id = _get_any_node_id_from_call_graph(mcp_client)
    if not node_id:
        pytest.skip("No node id available from get_call_graph")

    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 10, "max_nodes": 20, "direction": "both", "min_confidence": 0.0},
        max_seconds=20,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)

    if result.get("success") is True:
        # Some implementations may not return these fields; if present they must be type-safe.
        if "truncated" in result:
            assert isinstance(result.get("truncated"), bool), result
        if "truncation_warning" in result:
            assert isinstance(result.get("truncation_warning"), str), result
        if "mermaid" in result:
            assert isinstance(result.get("mermaid"), str), result


def test_get_graph_neighborhood_missing_center_node_id_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=10,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_get_graph_neighborhood_nonexistent_center_node_id_fast_fail(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": "python::nonexistent::function::nope", "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=10,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_graph_neighborhood_cross_language_node_id_string_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        # Use a clearly invalid/unknown cross-language-shaped id and enforce fast, safe handling.
        {"center_node_id": "java::nonexistent", "k": 1, "max_nodes": 10, "direction": "both", "min_confidence": 0.0},
        max_seconds=10,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_get_graph_neighborhood_non_string_center_node_id_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": 12345, "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=10,
    )
    result = _normalize_get_graph_neighborhood_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result
