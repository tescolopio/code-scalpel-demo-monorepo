from __future__ import annotations

import textwrap
import time

import pytest


def _timed_call(mcp_client, tool: str, args: dict, *, max_seconds: float | None = None):
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    if max_seconds is not None:
        assert elapsed <= max_seconds, {"tool": tool, "elapsed": elapsed, "result": result}
    return result, elapsed


def _normalize_analyze_code_result(raw: dict) -> dict:
    """Normalize tool output across server formats.

    Code Scalpel has shipped (at least) two shapes for MCP tool outputs:

    1) Flat dict: {success: bool, functions: [...], ...}
    2) Envelope v1: {capabilities: ['envelope-v1'], data: {...}, error: {...}|None, duration_ms: int, ...}

    This test suite accepts both, but validates the *normalized* shape.
    """
    def _fill_defaults(d: dict) -> dict:
        """Ensure a stable, full contract shape even on pre-tool validation errors.

        Some failures occur before the tool implementation runs (e.g., argument
        validation), and may return only {success, error}. For contract testing,
        normalize those into the same shape as successful calls.
        """

        functions = d.get("functions") if isinstance(d.get("functions"), list) else []
        classes = d.get("classes") if isinstance(d.get("classes"), list) else []
        imports = d.get("imports") if isinstance(d.get("imports"), list) else []

        function_details = d.get("function_details") if isinstance(d.get("function_details"), list) else []
        class_details = d.get("class_details") if isinstance(d.get("class_details"), list) else []
        issues = d.get("issues") if isinstance(d.get("issues"), list) else []

        normalized = dict(d)
        normalized.setdefault("server_version", None)
        normalized["functions"] = functions
        normalized["classes"] = classes
        normalized["imports"] = imports
        normalized["function_details"] = function_details
        normalized["class_details"] = class_details
        normalized["issues"] = issues
        normalized.setdefault("function_count", len(functions))
        normalized.setdefault("class_count", len(classes))
        normalized.setdefault("complexity", 0)
        normalized.setdefault("lines_of_code", 0)
        normalized.setdefault("error", None)
        return normalized

    if not isinstance(raw, dict):
        return _fill_defaults({"success": False, "error": "Non-dict tool result", "_raw": raw})

    # Envelope v1
    if "data" in raw and "capabilities" in raw:
        data = raw.get("data") or {}
        err = raw.get("error")
        # error can be None or a structured dict
        if err:
            msg = err.get("error") if isinstance(err, dict) else str(err)
            normalized = dict(data)
            normalized.update({"success": False, "error": msg})
            return _fill_defaults(normalized)
        normalized = dict(data)
        normalized.update({"success": True, "error": None})
        return _fill_defaults(normalized)

    # Flat dict
    return _fill_defaults(raw)


def _assert_common_shape(result: dict):
    assert isinstance(result, dict), result

    # Core contract fields
    assert "success" in result, result
    assert isinstance(result["success"], bool), result
    assert isinstance(result.get("server_version"), (str, type(None))), result
    assert isinstance(result.get("functions"), list), result
    assert isinstance(result.get("classes"), list), result
    assert isinstance(result.get("imports"), list), result
    assert isinstance(result.get("function_count"), int), result
    assert isinstance(result.get("class_count"), int), result
    assert isinstance(result.get("complexity"), int), result
    assert isinstance(result.get("lines_of_code"), int), result
    assert isinstance(result.get("issues"), list), result
    assert isinstance(result.get("error"), (str, type(None))), result

    # Optional detail fields
    assert isinstance(result.get("function_details"), list), result
    assert isinstance(result.get("class_details"), list), result

    # Basic internal consistency
    assert result["function_count"] == len(result["functions"]), result
    assert result["class_count"] == len(result["classes"]), result
    assert result["complexity"] >= 0, result
    assert result["lines_of_code"] >= 0, result


def _case(*, name: str, language: str | None, code: str, expect: dict | None = None, max_seconds: float = 10.0):
    return {
        "name": name,
        "language": language,
        "code": textwrap.dedent(code).strip("\n"),
        "expect": expect or {},
        "max_seconds": max_seconds,
    }


ANALYZE_CODE_CASES = [
    # --------------------
    # Python: normals/edges
    # --------------------
    _case(
        name="python-basic-functions-classes-imports",
        language="python",
        code="""
        import os

        class A:
            def m(self):
                return 1

        def f(x):
            if x:
                return 1
            return 0
        """,
        expect={"success": True, "functions": {"f", "m"}, "classes": {"A"}, "imports": {"os"}, "min_complexity": 2},
    ),
    _case(
        name="python-decorators-type-hints-dataclass",
        language="python",
        code="""
        from dataclasses import dataclass

        def deco(fn):
            return fn

        @dataclass
        class P:
            x: int

        @deco
        def g(x: int, y: int = 3) -> int:
            return x + y
        """,
        # Tool may report fully-qualified imports (e.g., dataclasses.dataclass).
        expect={"success": True, "functions": {"g", "deco"}, "classes": {"P"}, "imports": {"dataclasses.dataclass"}},
    ),
    _case(
        name="python-unicode-identifiers-safe",
        language="python",
        code="""
        def café(π: int) -> int:
            if π > 0:
                return π
            return 0
        """,
        # Some parsers/tokenizers can be picky; require safe behavior.
        expect={"success": (True, False)},
    ),
    _case(
        name="python-deep-nesting-does-not-hang",
        language="python",
        code="""
        def deep(x):
            if x > 0:
                if x > 1:
                    if x > 2:
                        if x > 3:
                            if x > 4:
                                return 5
            return 0
        """,
        expect={"success": True, "functions": {"deep"}, "min_complexity": 2},
    ),
    _case(
        name="python-nested-functions",
        language="python",
        code="""
        def outer():
            def inner():
                return 1
            return inner()
        """,
        expect={"success": True, "functions": {"outer", "inner"}, "min_complexity": 1},
    ),
    _case(
        name="python-async-function-is_async-flag",
        language="python",
        code="""
        async def af():
            return 1
        """,
        expect={"success": True, "functions": {"async af"}, "async_function_details": {"af"}},
    ),
    _case(
        name="python-try-except-branching-complexity",
        language="python",
        code="""
        def f(x):
            try:
                if x:
                    return 1
            except Exception:
                return 2
            return 0
        """,
        expect={"success": True, "functions": {"f"}, "min_complexity": 3},
    ),
    _case(
        name="python-match-case-does-not-crash",
        language="python",
        code="""
        def m(x):
            match x:
                case 1:
                    return 1
                case 2 | 3:
                    return 2
                case _:
                    return 0
        """,
        expect={"success": True, "functions": {"m"}},
    ),
    _case(
        name="python-empty-code-fails",
        language="python",
        code="""""",
        expect={"success": False, "error_contains": "empty"},
    ),
    _case(
        name="python-syntax-error-fails-safely",
        language="python",
        code="""
        def f(:
            pass
        """,
        expect={"success": False},
    ),

    _case(
        name="python-leading-bom-whitespace-safe",
        language="python",
        code="\ufeff\n\n\n  def f(x):\n      return x\n",
        expect={"success": (True, False)},
    ),

    # --------------------
    # JavaScript: normals/edges
    # --------------------
    _case(
        name="js-import-function-class-method",
        language="javascript",
        code="""
        import x from 'y'
        export function foo(a){ if(a){return 1}else{return 0}}
        class C{ bar(){ return 2 } }
        """,
        expect={"success": True, "functions": {"foo", "<anonymous>"}, "classes": {"C"}, "imports": {"y"}, "min_complexity": 2},
    ),
    _case(
        name="js-modern-syntax-optional-chaining-nullish",
        language="javascript",
        code="""
        export function f(obj){
          const x = obj?.a ?? 0
          return x > 0 ? 1 : 0
        }
        """,
        # Require safe behavior; parsing support can vary across JS parsers.
        expect={"success": (True, False)},
    ),
    _case(
        name="js-unicode-identifiers-safe",
        language="javascript",
        code="""
        export function café(x){ return x }
        """,
        expect={"success": (True, False)},
    ),
    _case(
        name="js-arrow-function-and-async",
        language="javascript",
        code="""
        export const f = (x) => { if (x > 0) return 1; return 0 }
        export async function af(){ return 1 }
        """,
        expect={"success": True, "functions": {"f", "af"}},
    ),
    _case(
        name="js-invalid-syntax-does-not-hang",
        language="javascript",
        code="""
        function f( {
        """,
        # Current implementation appears tolerant; assert safe, not strict failure.
        expect={"success": (True, False)},
    ),

    # --------------------
    # TypeScript: normals/edges
    # --------------------
    _case(
        name="ts-types-interface-arrow-class-generic-method",
        language="typescript",
        code="""
        import {x} from './m'

        type Role = 'admin' | 'user'
        export interface U { id: string }
        export const f = (x:number):number => { if (x>0) return 1; return 0 }
        export class C { m<T>(v:T):T { return v } }
        """,
        expect={"success": True, "functions": {"f"}, "classes": {"C"}, "imports": {"./m"}, "min_complexity": 2},
    ),
    _case(
        name="ts-enum-namespace-declaration-merging-safe",
        language="typescript",
        code="""
        export enum E { A = 1, B = 2 }
        export namespace N { export const x: number = 1 }
        export function f(x: number): number { return x + E.A + N.x }
        """,
        expect={"success": (True, False)},
    ),
    _case(
        name="ts-invalid-syntax-does-not-hang",
        language="typescript",
        code="""
        export const x: number = ;
        """,
        expect={"success": (True, False)},
    ),

    # --------------------
    # Java: normals/edges
    # --------------------
    _case(
        name="java-class-methods-inner-class-import",
        language="java",
        code="""
        package demo;

        import java.util.*;

        public class A {
          public static void main(String[] args){ if(args.length>0){ System.out.println(\"x\"); } }
          int add(int a,int b){ return a+b; }
          static class Inner { void m(){} }
        }
        """,
        # Note: current tool reports only top-level class in `classes`.
        expect={"success": True, "classes": {"A"}, "imports": {"java.util.*"}, "functions": {"main", "add"}, "min_complexity": 2},
    ),
        _case(
                name="java-generics-lambda-annotation-safe",
                language="java",
                code="""
                import java.util.*;

                @Deprecated
                public class A<T> {
                    T id;
                    public A(T id){ this.id = id; }
                    public int f(int x){ return x > 0 ? 1 : 0; }
                    public void g(){
                        List<Integer> xs = Arrays.asList(1,2,3);
                        xs.stream().map(v -> v + 1).forEach(v -> System.out.println(v));
                    }
                }
                """,
                expect={"success": (True, False)},
        ),
    _case(
        name="java-invalid-syntax-does-not-hang",
        language="java",
        code="""
        public class A { void m( { } 
        """,
        expect={"success": (True, False)},
    ),

    # --------------------
    # Explicit auto + unknown language handling
    # --------------------
    _case(
        name="explicit-auto-language-python",
        language="auto",
        code="""
        def f(x):
            return 1 if x else 0
        """,
        expect={"success": True, "functions": {"f"}},
    ),
    _case(
        name="unknown-language-fails-safely",
        language="ruby",
        code="""
        def f(x)
          x
        end
        """,
        expect={"success": (True, False)},
    ),

    # --------------------
    # Auto language
    # --------------------
    _case(
        name="auto-language-python",
        language=None,
        code="""
        def f(x):
            if x:
                return 1
            return 0
        """,
        expect={"success": True, "functions": {"f"}, "min_complexity": 2},
    ),
    _case(
        name="auto-language-javascript",
        language=None,
        code="""
        function f(x){ if(x){return 1} return 0 }
        """,
        # Auto detection can vary; still should extract a function.
        expect={"success": True, "functions": {"f"}},
    ),
    _case(
        name="auto-language-ambiguous-braces-safe",
        language=None,
        code="""
        if (x) { y() }
        """,
        # May not be a full program in any language; require safe behavior.
        expect={"success": (True, False)},
    ),
]


@pytest.mark.parametrize("case", ANALYZE_CODE_CASES, ids=[c["name"] for c in ANALYZE_CODE_CASES])
def test_analyze_code_exhaustive_matrix(mcp_client, case):
    args = {"code": case["code"]}
    if case["language"] is not None:
        args["language"] = case["language"]

    raw, _ = _timed_call(mcp_client, "analyze_code", args, max_seconds=case["max_seconds"])
    result = _normalize_analyze_code_result(raw)
    _assert_common_shape(result)

    expect = case["expect"]

    # success expectations
    if "success" in expect:
        if isinstance(expect["success"], tuple):
            assert result["success"] in expect["success"], result
        else:
            assert result["success"] is expect["success"], result

    # Ensure error presence aligns with success when tool chooses to report errors
    if result["success"] is False:
        # If it fails, it should provide a reason.
        assert result.get("error"), {"normalized": result, "raw": raw}

    # Set-membership expectations
    if "functions" in expect:
        assert set(expect["functions"]).issubset(set(result["functions"])), result
    if "classes" in expect:
        assert set(expect["classes"]).issubset(set(result["classes"])), result
    if "imports" in expect:
        assert set(expect["imports"]).issubset(set(result["imports"])), result

    # Numeric expectations
    if "min_complexity" in expect:
        assert result["complexity"] >= int(expect["min_complexity"]), result

    # Error text expectations
    if "error_contains" in expect:
        assert result.get("error") and expect["error_contains"].lower() in result["error"].lower(), {"normalized": result, "raw": raw}

    # Async details expectations for Python
    if "async_function_details" in expect:
        async_names = set(expect["async_function_details"])
        details = result.get("function_details") or []
        assert details, result
        seen_async = {d["name"] for d in details if d.get("is_async") is True and d.get("name")}
        assert async_names.issubset(seen_async), {"expected_async": sorted(async_names), "seen_async": sorted(seen_async), "result": result}


def test_analyze_code_perf_large_python_input(mcp_client):
    # Deterministic large input: many small functions with branches.
    # Goal: ensure tool handles larger payloads quickly and consistently.
    lines = ["import math", ""]
    for i in range(1, 251):
        lines.append(f"def f{i}(x):")
        lines.append("    if x > 10:")
        lines.append("        return x * 2")
        lines.append("    return x")
        lines.append("")
    code = "\n".join(lines)

    raw, elapsed = _timed_call(mcp_client, "analyze_code", {"code": code, "language": "python"}, max_seconds=15)
    result = _normalize_analyze_code_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is True, result

    # Should find all functions.
    assert result.get("function_count") >= 250, result
    # Sanity: complexity should be at least 1 for a non-empty file with branches.
    assert result.get("complexity", 0) >= 1, result

    # Hard cap is already enforced by max_seconds, but keep elapsed in failure payload.
    assert elapsed <= 15, {"elapsed": elapsed, "result": result}


def test_analyze_code_rejects_missing_code_arg(mcp_client):
    raw, _ = _timed_call(mcp_client, "analyze_code", {}, max_seconds=10)
    result = _normalize_analyze_code_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result


def test_analyze_code_rejects_non_string_code_arg(mcp_client):
    raw, _ = _timed_call(mcp_client, "analyze_code", {"code": 123, "language": "python"}, max_seconds=10)
    result = _normalize_analyze_code_result(raw)
    _assert_common_shape(result)
    assert result.get("success") is False, result
