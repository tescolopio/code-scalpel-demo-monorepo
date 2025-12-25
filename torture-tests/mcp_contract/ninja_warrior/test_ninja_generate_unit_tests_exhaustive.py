from __future__ import annotations

import ast
import subprocess
import sys
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


def _normalize_generate_unit_tests_result(raw: dict) -> dict:
    """Normalize tool output across server formats.

    Accept either:
    - Flat dict: {success: bool, pytest_code: str, test_cases: [...], ...}
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

    assert isinstance(result.get("function_name"), str) and result["function_name"], result
    assert isinstance(result.get("test_count"), int), result
    assert isinstance(result.get("test_cases"), list), result
    assert isinstance(result.get("pytest_code"), str), result
    assert isinstance(result.get("unittest_code"), str), result

    # Basic internal consistency
    assert result["test_count"] == len(result.get("test_cases") or []), result
    for tc in result.get("test_cases") or []:
        assert isinstance(tc, dict), tc
        assert isinstance(tc.get("path_id"), int), tc
        assert isinstance(tc.get("function_name"), str), tc
        assert isinstance(tc.get("inputs"), dict), tc
        assert isinstance(tc.get("path_conditions"), list), tc


def _safe_eval_condition(expr: str, inputs: dict) -> bool:
    """Evaluate a simple boolean expression safely.

    This is used to validate whether tool-provided `path_conditions` match the
    concrete `inputs` it also provides.
    """
    node = ast.parse(expr, mode="eval")

    allowed_nodes = (
        ast.Expression,
        ast.BoolOp,
        ast.UnaryOp,
        ast.Compare,
        ast.Name,
        ast.Constant,
        ast.Load,
        ast.And,
        ast.Or,
        ast.Not,
        ast.Gt,
        ast.GtE,
        ast.Lt,
        ast.LtE,
        ast.Eq,
        ast.NotEq,
    )

    for n in ast.walk(node):
        if not isinstance(n, allowed_nodes):
            raise ValueError(f"Unsupported node in condition: {type(n).__name__}")

    compiled = compile(node, filename="<cond>", mode="eval")
    # No builtins, only provided inputs.
    return bool(eval(compiled, {"__builtins__": {}}, dict(inputs)))


def _write_and_run_pytest(tmp_path: Path, code: str) -> subprocess.CompletedProcess[str]:
    test_file = tmp_path / "test_generated.py"
    test_file.write_text(code, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(test_file), "-q"],
        cwd=str(tmp_path),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _write_and_run_unittest(tmp_path: Path, code: str) -> subprocess.CompletedProcess[str]:
    test_file = tmp_path / "generated_unittest.py"
    test_file.write_text(code, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "unittest", "-q", str(test_file)],
        cwd=str(tmp_path),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _case(*, name: str, code: str, framework: str = "pytest", function_name: str | None = None, expect_success: bool | None = None):
    return {
        "name": name,
        "code": code.strip(),
        "framework": framework,
        "function_name": function_name,
        "expect_success": expect_success,
    }


BRANCHING_SNIPPET = """
def branchy(x: int, y: int):
    if x > 100:
        if y < 0:
            return 'A'
        return 'B'
    return 'C'
""".strip()


UNTYPED_BRANCHING_SNIPPET = """
def branchy(x, y):
    if x > 100:
        if y < 0:
            return 'A'
        return 'B'
    return 'C'
""".strip()


PYTHON_WEIRD_UNICODE_IDENTIFIERS = """
def café(x: int):
    if x:
        return 1
    return 0
""".strip()


PYTHON_LOOP_SNIPPET = """
def loop_sum(n: int):
    total = 0
    i = 0
    while i < n:
        total += i
        i += 1
    return total
""".strip()


PYTHON_MATCH_CASE_SNIPPET = """
def matcher(x: int):
    match x:
        case 1:
            return 10
        case 2 | 3:
            return 20
        case _:
            return 0
""".strip()


JS_SNIPPET = """
export function f(x) { if (x) { return 1 } return 0 }
""".strip()


TS_SNIPPET = """
export function f(x: number): number { if (x > 0) return 1; return 0 }
""".strip()


JAVA_SNIPPET = """
public class A { static int f(int x){ if (x>0) return 1; return 0; } }
""".strip()


def test_generate_unit_tests_contract_shape_pytest(mcp_client):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result.get("function_name") == "branchy", result
    assert "def test_branchy_path_" in result.get("pytest_code", ""), result


def test_generate_unit_tests_contract_shape_unittest(mcp_client):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "unittest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result.get("function_name") == "branchy", result
    assert "class TestBranchy" in result.get("unittest_code", ""), result


def test_generate_unit_tests_pytest_code_executes(mcp_client, tmp_path):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    proc = _write_and_run_pytest(tmp_path, result.get("pytest_code", ""))
    assert proc.returncode == 0, {"stdout": proc.stdout, "stderr": proc.stderr, "result": result}


def test_generate_unit_tests_unittest_code_executes(mcp_client, tmp_path):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "unittest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    proc = _write_and_run_unittest(tmp_path, result.get("unittest_code", ""))
    assert proc.returncode == 0, {"stdout": proc.stdout, "stderr": proc.stderr, "result": result}


def test_generate_unit_tests_is_deterministic_for_same_input(mcp_client):
    raw1, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    raw2, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    r1 = _normalize_generate_unit_tests_result(raw1)
    r2 = _normalize_generate_unit_tests_result(raw2)
    _assert_common_shape(r1)
    _assert_common_shape(r2)
    assert r1.get("success") is True and r2.get("success") is True
    # Determinism expectations: test_cases should match exactly.
    assert r1.get("test_cases") == r2.get("test_cases"), {"first": r1.get("test_cases"), "second": r2.get("test_cases")}


def test_generate_unit_tests_rejects_empty_code(mcp_client):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": "", "framework": "pytest"}, max_seconds=20)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


@pytest.mark.parametrize(
    "case",
    [
        # NOTE: Current behavior may accept non-Python and still return success.
        # Treat as "safe behavior" here and separately document as a quality-gap xfail.
        _case(name="js-negative-control", code=JS_SNIPPET, framework="pytest", expect_success=None),
        _case(name="ts-negative-control", code=TS_SNIPPET, framework="pytest", expect_success=None),
        _case(name="java-negative-control", code=JAVA_SNIPPET, framework="pytest", expect_success=None),
        _case(name="python-unicode-identifiers", code=PYTHON_WEIRD_UNICODE_IDENTIFIERS, framework="pytest", expect_success=True),
        _case(name="python-loop-snippet-bounded", code=PYTHON_LOOP_SNIPPET, framework="pytest", expect_success=True),
        # match/case may or may not be supported by the symbolic engine; require safe behavior.
        _case(name="python-match-case-safe", code=PYTHON_MATCH_CASE_SNIPPET, framework="pytest", expect_success=None),
    ],
    ids=lambda c: c["name"],
)
def test_generate_unit_tests_language_and_weird_cases(mcp_client, case):
    args = {"code": case["code"], "framework": case["framework"]}
    if case.get("function_name"):
        args["function_name"] = case["function_name"]

    raw, _ = _timed_call(mcp_client, "generate_unit_tests", args, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)

    expected = case.get("expect_success")
    if expected is not None:
        assert result.get("success") is expected, result

    # If it claims success, make sure it produced runnable-looking code blocks.
    if result.get("success") is True:
        assert result.get("pytest_code"), result
        assert result.get("unittest_code"), result


@pytest.mark.xfail(
    reason="Known quality gap: generate_unit_tests returns success for non-Python inputs; expected safe failure or language validation",
    strict=False,
)
@pytest.mark.parametrize(
    "code",
    [JS_SNIPPET, TS_SNIPPET, JAVA_SNIPPET],
    ids=["js", "ts", "java"],
)
def test_generate_unit_tests_should_reject_non_python_code(mcp_client, code):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": code, "framework": "pytest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_generate_unit_tests_file_path_mode_selects_named_function(mcp_client, tmp_path):
    src = tmp_path / "multi.py"
    src.write_text(
        """
def first(x: int):
    if x:
        return 1
    return 0

def second(y: int):
    if y > 10:
        return 2
    return 3
""".lstrip(),
        encoding="utf-8",
    )

    raw, _ = _timed_call(
        mcp_client,
        "generate_unit_tests",
        {"file_path": str(src), "function_name": "second", "framework": "pytest"},
        max_seconds=30,
    )
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result
    assert result.get("function_name") == "second", result
    assert "def second" in result.get("pytest_code", ""), result


def test_generate_unit_tests_invalid_framework_fails_safely(mcp_client):
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "nose"}, max_seconds=20)
    result = _normalize_generate_unit_tests_result(raw)
    # Some implementations may default to pytest; accept either success or safe failure.
    _assert_common_shape(result)
    assert result.get("success") in (True, False), result


def test_generate_unit_tests_perf_sanity_many_branches_bounded(mcp_client):
    # Create a deterministic function with many branches but no loops.
    # Goal: ensure tool remains bounded and does not hang.
    lines = ["def many(x: int):"]
    for i in range(1, 31):
        prefix = "if" if i == 1 else "elif"
        lines.append(f"    {prefix} x == {i}:")
        lines.append(f"        return {i}")
    lines.append("    return 0")
    code = "\n".join(lines)

    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": code, "framework": "pytest"}, max_seconds=45)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)

    # Tool may cap paths; require only safe success.
    assert result.get("success") is True, result
    assert result.get("test_count", 0) >= 1, result


def _normalize_condition(expr: str) -> str:
    # Tool sometimes emits Z3-ish `Not(...)` conditions.
    expr = expr.strip()
    if expr.startswith("Not(") and expr.endswith(")"):
        inner = expr[len("Not(") : -1]
        return f"not ({inner})"
    return expr


def test_generate_unit_tests_quality_path_conditions_match_inputs(mcp_client):
    """Quality check: each test_case's path_conditions should be true for its inputs."""
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True

    failures = []
    for tc in result.get("test_cases") or []:
        inputs = tc.get("inputs") or {}
        for cond in tc.get("path_conditions") or []:
            try:
                ok = _safe_eval_condition(_normalize_condition(str(cond)), inputs)
            except Exception as e:  # noqa: BLE001 - test audit
                failures.append({"path_id": tc.get("path_id"), "cond": cond, "inputs": inputs, "error": str(e)})
                continue
            if not ok:
                failures.append({"path_id": tc.get("path_id"), "cond": cond, "inputs": inputs, "error": "condition false"})

    assert not failures, failures


def test_generate_unit_tests_quality_asserts_expected_values_xfail(mcp_client):
    """Quality check: generated pytest should assert expected return values per path.

    Marked xfail because current generator may only assert reachability (e.g.,
    `assert result is not None`) for some paths.
    """
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True

    code = result.get("pytest_code", "")
    # Heuristic: require at least one equality assert.
    if "assert result ==" not in code:
        pytest.xfail("Generated pytest_code lacks equality assertions for return values")


def test_generate_unit_tests_pytest_generated_code_may_break_without_type_hints_xfail(mcp_client, tmp_path):
    """Regression/robustness check: untyped numeric comparisons can lead to bad input types.

    Marked xfail because current generator may pick non-numeric inputs for `x`/`y`,
    which can make the generated tests fail with TypeError.
    """
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": UNTYPED_BRANCHING_SNIPPET, "framework": "pytest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True

    proc = _write_and_run_pytest(tmp_path, result.get("pytest_code", ""))
    if proc.returncode != 0:
        pytest.xfail(f"Generated pytest tests failed to run (likely type mismatch): {proc.stdout.strip()}")


def test_generate_unit_tests_unittest_does_not_assert_return_values_xfail(mcp_client):
    """Quality check: unittest output should assert expected values, not just reachability.

    Marked xfail because current unittest_code typically uses `assertTrue(True)`.
    """
    raw, _ = _timed_call(mcp_client, "generate_unit_tests", {"code": BRANCHING_SNIPPET, "framework": "unittest"}, max_seconds=30)
    result = _normalize_generate_unit_tests_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True
    code = result.get("unittest_code", "")
    if "assertEqual" not in code and "self.assertEqual" not in code:
        pytest.xfail("unittest_code lacks assertEqual-style return assertions")
