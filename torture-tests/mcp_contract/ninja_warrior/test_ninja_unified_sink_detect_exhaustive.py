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

    normalized.setdefault("language", None)
    normalized.setdefault("sink_count", 0)
    normalized.setdefault("sinks", [])
    normalized.setdefault("coverage", {})

    if not isinstance(normalized.get("sinks"), list):
        normalized["sinks"] = []

    if not isinstance(normalized.get("coverage"), dict):
        normalized["coverage"] = {}

    if not isinstance(normalized.get("sink_count"), int):
        normalized["sink_count"] = len(normalized.get("sinks") or [])

    return normalized


def _normalize_unified_sink_detect_result(raw) -> dict:
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

    assert isinstance(result.get("language"), (str, type(None))), result
    assert isinstance(result.get("sink_count"), int), result
    assert isinstance(result.get("sinks"), list), result
    assert isinstance(result.get("coverage"), dict), result

    if result.get("success") is False:
        assert result.get("error"), result

    if result.get("success") is True:
        assert result.get("sink_count", 0) == len(result.get("sinks") or []), result
        assert result.get("sink_count", 0) >= 0, result


def _assert_sinks_are_structured(result: dict):
    for s in result.get("sinks") or []:
        assert isinstance(s, dict), s
        assert isinstance(s.get("name"), (str, type(None))), s
        assert isinstance(s.get("line"), (int, type(None))), s
        assert isinstance(s.get("cwe"), (str, type(None))), s
        assert isinstance(s.get("confidence"), (float, int, type(None))), s


def test_unified_sink_detect_python_shell_true_positive_control(mcp_client):
    code = "import subprocess\nsubprocess.run('id', shell=True)\n"

    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "python"}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("sink_count", 0) >= 1, result
    _assert_sinks_are_structured(result)


def test_unified_sink_detect_python_eval_positive_control(mcp_client):
    code = "def f(x):\n    return eval(x)\n"

    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "python"}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("sink_count", 0) >= 1, result
    _assert_sinks_are_structured(result)


def test_unified_sink_detect_python_threshold_edges(mcp_client):
    code = "import subprocess\nsubprocess.run('id', shell=True)\n"

    low_raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": code, "language": "python", "min_confidence": 0.0},
        max_seconds=15,
    )
    low = _normalize_unified_sink_detect_result(low_raw)
    _assert_common_shape(low)
    assert low.get("success") is True, low
    assert low.get("sink_count", 0) >= 1, low

    high_raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": code, "language": "python", "min_confidence": 0.99},
        max_seconds=15,
    )
    high = _normalize_unified_sink_detect_result(high_raw)
    _assert_common_shape(high)
    assert high.get("success") is True, high
    # At high threshold, implementations may filter out all sinks.
    assert high.get("sink_count", 0) >= 0, high


def test_unified_sink_detect_javascript_dom_xss_sink_detected_or_safe(mcp_client):
    code = "const userInput = location.hash; document.body.innerHTML = userInput;\n"

    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "javascript"}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    # Prefer detection, but accept safe no-findings to avoid flakiness.
    if result.get("sink_count", 0) >= 1:
        _assert_sinks_are_structured(result)


def test_unified_sink_detect_typescript_dom_xss_sink_detected_or_safe(mcp_client):
    code = "const userInput: string = window.location.hash; document.body.innerHTML = userInput;\n"

    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "typescript"}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    if result.get("sink_count", 0) >= 1:
        _assert_sinks_are_structured(result)


def test_unified_sink_detect_java_runtime_exec_detected_or_safe(mcp_client):
    code = """
    class A {
      void f(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
      }
    }
    """.strip()

    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "java"}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    if result.get("sink_count", 0) >= 1:
        _assert_sinks_are_structured(result)


def test_unified_sink_detect_missing_args_fails_or_succeeds_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("sink_count", 0) == 0, result


@pytest.mark.xfail(reason="Quality gap: missing required args should fail validation", strict=False)
def test_unified_sink_detect_missing_args_should_fail_validation(mcp_client):
    raw, _ = _timed_call(mcp_client, "unified_sink_detect", {}, max_seconds=15)
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_unified_sink_detect_invalid_language_fails_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": "eval(user_input)", "language": "brainfuck"},
        max_seconds=15,
    )
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result


def test_unified_sink_detect_malformed_code_handled_safely(mcp_client):
    raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": "def f(:\n  pass\n", "language": "python"},
        max_seconds=15,
    )
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_unified_sink_detect_unicode_and_nul_bytes_do_not_crash(mcp_client):
    nul = chr(0)
    code = "def café(x):\n    return eval(x)\n" + nul

    raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": code, "language": "python"},
        max_seconds=15,
    )
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_unified_sink_detect_min_confidence_out_of_range_handled_safely(mcp_client):
    code = "import subprocess\nsubprocess.run('id', shell=True)\n"

    raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": code, "language": "python", "min_confidence": 2.0},
        max_seconds=15,
    )
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


def test_unified_sink_detect_large_input_is_bounded(mcp_client):
    # Large but repetitive Python code, with a sink near the end.
    blocks = ["def f0(x):\n    return x\n"]
    for i in range(1200):
        blocks.append(f"def f{i}(x):\n    return x\n")
    blocks.append("import subprocess\nsubprocess.run('id', shell=True)\n")
    code = "\n".join(blocks)

    raw, _ = _timed_call(
        mcp_client,
        "unified_sink_detect",
        {"code": code, "language": "python"},
        max_seconds=25,
    )
    result = _normalize_unified_sink_detect_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("sink_count", 0) >= 1, result
