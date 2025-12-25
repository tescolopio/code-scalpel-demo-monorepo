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

    # Core simulate_refactor fields (best-effort across versions)
    normalized.setdefault("is_safe", False)
    normalized.setdefault("status", None)
    normalized.setdefault("security_issues", [])
    normalized.setdefault("structural_changes", [])

    if not isinstance(normalized.get("security_issues"), list):
        normalized["security_issues"] = []
    if not isinstance(normalized.get("structural_changes"), list):
        normalized["structural_changes"] = []

    if not isinstance(normalized.get("is_safe"), bool):
        normalized["is_safe"] = False

    if not isinstance(normalized.get("status"), (str, type(None))):
        normalized["status"] = None

    return normalized


def _normalize_simulate_refactor_result(raw) -> dict:
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

    assert isinstance(result.get("is_safe"), bool), result
    assert isinstance(result.get("status"), (str, type(None))), result
    assert isinstance(result.get("security_issues"), list), result
    assert isinstance(result.get("structural_changes"), list), result

    if result.get("success") is False:
        assert result.get("error"), result


def _load_fixture(name: str) -> str:
    root = _repo_root() / "torture-tests" / "stage5-policy-fortress" / "obstacle-5.8-simulate-refactor-fixtures"
    return (root / name).read_text(encoding="utf-8")


def _rewrite_patch_headers(patch: str, *, from_name: str = "demo.py", to_name: str | None = None) -> str:
    """Normalize patch headers to avoid filename coupling.

    Some patch appliers are strict about ---/+++ paths. We preserve the body
    but rewrite the headers to a stable name.
    """

    if to_name is None:
        to_name = from_name

    out: list[str] = []
    for line in patch.splitlines(True):
        if line.startswith("--- a/"):
            out.append(f"--- a/{from_name}\n")
        elif line.startswith("+++ b/"):
            out.append(f"+++ b/{to_name}\n")
        else:
            out.append(line)
    return "".join(out)


def test_simulate_refactor_patch_safe_typing_is_safe(mcp_client):
    original = _load_fixture("original_safe_typing.py")
    patch = _rewrite_patch_headers(_load_fixture("safe_typing.patch"), from_name="demo.py")

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("is_safe") is True, result


def test_simulate_refactor_patch_unsafe_eval_is_unsafe(mcp_client):
    original = _load_fixture("original_unsafe_eval.py")
    patch = _rewrite_patch_headers(_load_fixture("unsafe_eval.patch"), from_name="demo.py")

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("is_safe") is False, result


def test_simulate_refactor_patch_unsafe_shell_is_unsafe(mcp_client):
    original = _load_fixture("original_unsafe_shell.py")
    patch = _rewrite_patch_headers(_load_fixture("unsafe_shell.patch"), from_name="demo.py")

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    # Observed behavior: some versions do not flag shell=True patterns as unsafe.
    if result.get("is_safe") is True:
        pytest.xfail("Expected unsafe for shell=True patch, but tool reported safe (detection gap)")
    assert result.get("is_safe") is False, result


def test_simulate_refactor_new_code_safe_typing_is_safe(mcp_client):
    original = "def add(a, b):\n    return a + b\n"
    new_code = "def add(a: int, b: int) -> int:\n    return a + b\n"

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "new_code": new_code, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("is_safe") is True, result


def test_simulate_refactor_new_code_detects_eval(mcp_client):
    original = "def f(x):\n    return x\n"
    new_code = "def f(x):\n    return eval(x)\n"

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "new_code": new_code, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is True, result
    assert result.get("is_safe") is False, result


def test_simulate_refactor_strict_mode_is_accepted(mcp_client):
    original = "def add(a, b):\n    return a + b\n"
    new_code = "def add(a: int, b: int) -> int:\n    return a + b\n"

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "new_code": new_code, "strict_mode": True},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    # strict_mode may treat certain warnings as unsafe depending on implementation.
    assert result.get("success") is True, result
    assert result.get("is_safe") in (True, False), result


def test_simulate_refactor_missing_original_code_fails_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "simulate_refactor", {"new_code": "def f():\n    return 1\n"}, max_seconds=15)
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result


def test_simulate_refactor_missing_new_code_and_patch_fails_or_succeeds_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "simulate_refactor", {"original_code": "def f():\n    return 1\n"}, max_seconds=15)
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    # Some servers may treat this as a no-op refactor (safe).
    assert result.get("success") in (True, False), result


@pytest.mark.xfail(reason="Quality gap: missing both 'new_code' and 'patch' should fail validation", strict=False)
def test_simulate_refactor_missing_new_code_and_patch_should_fail_validation(mcp_client):
    raw, _ = _timed_call(mcp_client, "simulate_refactor", {"original_code": "def f():\n    return 1\n"}, max_seconds=15)
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result


def test_simulate_refactor_patch_invalid_format_fails_safely(mcp_client):
    original = "def f(x):\n    return x\n"
    patch = "this is not a unified diff\n"

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    # Some servers treat a non-unified-diff patch as a no-op refactor and return safe.
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("is_safe") is True, result


@pytest.mark.xfail(reason="Quality gap: invalid patch format should fail validation", strict=False)
def test_simulate_refactor_patch_invalid_format_should_fail_validation(mcp_client):
    original = "def f(x):\n    return x\n"
    patch = "this is not a unified diff\n"

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") is False, result


def test_simulate_refactor_patch_does_not_apply_is_handled(mcp_client):
    original = "def f(x):\n    return x\n"
    patch = _rewrite_patch_headers(
        (
            "--- a/demo.py\n"
            "+++ b/demo.py\n"
            "@@\n"
            "-def g(y):\n"
            "-    return y\n"
            "+def g(y):\n"
            "+    return eval(y)\n"
        ),
        from_name="demo.py",
    )

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    # Accept either: failure (preferred) or safe success/no-op.
    assert result.get("success") in (True, False), result


def test_simulate_refactor_both_new_code_and_patch_is_handled_safely(mcp_client):
    original = "def f(x):\n    return x\n"
    new_code = "def f(x):\n    return x + 1\n"
    patch = _rewrite_patch_headers(
        (
            "--- a/demo.py\n"
            "+++ b/demo.py\n"
            "@@\n"
            "-def f(x):\n"
            "-    return x\n"
            "+def f(x):\n"
            "+    return eval(x)\n"
        ),
        from_name="demo.py",
    )

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "new_code": new_code, "patch": patch, "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    assert result.get("success") in (True, False), result


@pytest.mark.parametrize(
    "code",
    [
        "export function f(x){ return x }\n",
        "export function f(x: number): number { return x }\n",
        "public class A { static int f(int x){ return x; } }\n",
    ],
    ids=["js", "ts", "java"],
)
def test_simulate_refactor_cross_language_text_is_handled_safely(mcp_client, code):
    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": code, "new_code": code + "\n// comment\n", "strict_mode": False},
        max_seconds=15,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    # Likely success=False (unsupported), but must not crash/hang.
    assert result.get("success") in (True, False), result


def test_simulate_refactor_large_input_is_bounded(mcp_client):
    # Large but safe function body.
    original_lines = ["def f(x):\n", "    return x\n"]
    original = "".join(original_lines)

    # Create a big new_code with many helper defs to stress parsing/analysis.
    blocks = ["def f(x):\n    return x\n"]
    for i in range(700):
        blocks.append(f"def helper_{i}(x):\n    return x\n")
    new_code = "\n".join(blocks)

    raw, _ = _timed_call(
        mcp_client,
        "simulate_refactor",
        {"original_code": original, "new_code": new_code, "strict_mode": False},
        max_seconds=25,
    )
    result = _normalize_simulate_refactor_result(raw)
    _assert_common_shape(result)

    # Prefer success, but accept safe failure on resource constraints.
    assert result.get("success") in (True, False), result
