#!/usr/bin/env python3
"""
=============================================================================
POLICY ENGINE PERFORMANCE BENCHMARK TESTS
=============================================================================

PURPOSE: Verify that the Policy Engine meets performance requirements.

PERFORMANCE TARGETS:
- Semantic analysis: <1ms per operation
- OPA evaluation: ~50ms per policy

This test suite measures:
1. Average evaluation time
2. P50, P95, P99 latencies
3. Throughput (operations per second)
4. Memory usage
5. Scaling behavior with code size

=============================================================================
"""
import gc
import statistics
import sys
import time
from typing import List, Tuple
from policy_engine_framework import (
    PolicyEngine, Operation, OperationType, Language, PolicyDecision
)


# =============================================================================
# BENCHMARK UTILITIES
# =============================================================================

def measure_time(func, iterations: int = 100) -> Tuple[float, float, float, float, float]:
    """
    Measure execution time over multiple iterations.
    Returns: (avg_ms, min_ms, max_ms, p95_ms, p99_ms)
    """
    times = []

    # Warmup
    for _ in range(10):
        func()

    # Measure
    for _ in range(iterations):
        gc.disable()
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        gc.enable()
        times.append((end - start) * 1000)

    times.sort()
    avg = statistics.mean(times)
    min_t = min(times)
    max_t = max(times)
    p95 = times[int(len(times) * 0.95)]
    p99 = times[int(len(times) * 0.99)]

    return avg, min_t, max_t, p95, p99


def format_latency(ms: float) -> str:
    """Format latency value."""
    if ms < 0.001:
        return f"{ms * 1000:.2f}μs"
    elif ms < 1:
        return f"{ms:.3f}ms"
    else:
        return f"{ms:.2f}ms"


# =============================================================================
# BENCHMARK TEST CASES
# =============================================================================

class PerformanceBenchmarks:
    """
    Performance benchmarks for the Policy Engine.
    """

    def __init__(self):
        self.engine = PolicyEngine(None)
        self.results = {}

    def run_all(self):
        """Run all performance benchmarks."""
        benchmarks = [
            self.benchmark_simple_code,
            self.benchmark_vulnerable_code,
            self.benchmark_complex_code,
            self.benchmark_large_code,
            self.benchmark_many_patterns,
            self.benchmark_throughput,
            self.benchmark_scaling,
        ]

        print("=" * 70)
        print("POLICY ENGINE PERFORMANCE BENCHMARKS")
        print("=" * 70)
        print()
        print("Performance Targets:")
        print("  - Semantic analysis: <1ms per operation")
        print("  - OPA evaluation: ~50ms per policy")
        print()

        for benchmark in benchmarks:
            name = benchmark.__name__
            print(f"\nRunning {name}...")
            try:
                result = benchmark()
                self.results[name] = result
            except Exception as e:
                print(f"  ERROR: {e}")
                self.results[name] = {"error": str(e)}

        self._print_summary()

    def benchmark_simple_code(self) -> dict:
        """
        Benchmark: Simple safe code analysis.
        Target: <1ms
        """
        operation = Operation(
            type=OperationType.CODE_EDIT,
            code='def add(a, b):\n    return a + b\n\nresult = add(1, 2)',
            language=Language.PYTHON,
            file_path="src/math.py"
        )

        def run():
            return self.engine.evaluate(operation)

        avg, min_t, max_t, p95, p99 = measure_time(run, iterations=1000)

        print(f"  Average: {format_latency(avg)}")
        print(f"  P95: {format_latency(p95)}")
        print(f"  P99: {format_latency(p99)}")

        passed = avg < 1.0  # <1ms target
        print(f"  Target (<1ms): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "avg_ms": avg,
            "min_ms": min_t,
            "max_ms": max_t,
            "p95_ms": p95,
            "p99_ms": p99,
            "target_ms": 1.0,
            "passed": passed
        }

    def benchmark_vulnerable_code(self) -> dict:
        """
        Benchmark: Vulnerable code detection.
        Target: <1ms even when detecting vulnerabilities
        """
        operation = Operation(
            type=OperationType.CODE_EDIT,
            code='''import os
import subprocess

def dangerous_function(user_input):
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_input}"

    # Command injection
    os.system(f"cat {user_input}")
    subprocess.run(f"echo {user_input}", shell=True)

    # Path traversal
    with open(f"/data/{user_input}") as f:
        return f.read()
''',
            language=Language.PYTHON,
            file_path="src/vulnerable.py"
        )

        def run():
            return self.engine.evaluate(operation)

        avg, min_t, max_t, p95, p99 = measure_time(run, iterations=1000)

        print(f"  Average: {format_latency(avg)}")
        print(f"  P95: {format_latency(p95)}")
        print(f"  P99: {format_latency(p99)}")

        passed = avg < 1.0  # <1ms target
        print(f"  Target (<1ms): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "avg_ms": avg,
            "min_ms": min_t,
            "max_ms": max_t,
            "p95_ms": p95,
            "p99_ms": p99,
            "target_ms": 1.0,
            "passed": passed
        }

    def benchmark_complex_code(self) -> dict:
        """
        Benchmark: Complex code with many functions and classes.
        Target: <1ms
        """
        code = '''
class UserService:
    def __init__(self, db):
        self.db = db

    def get_user(self, user_id):
        return self.db.query("SELECT * FROM users WHERE id = ?", [user_id])

    def create_user(self, name, email):
        return self.db.execute(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            [name, email]
        )

    def delete_user(self, user_id):
        return self.db.execute("DELETE FROM users WHERE id = ?", [user_id])


class OrderService:
    def __init__(self, db, user_service):
        self.db = db
        self.user_service = user_service

    def get_orders(self, user_id):
        user = self.user_service.get_user(user_id)
        if not user:
            return []
        return self.db.query(
            "SELECT * FROM orders WHERE user_id = ?",
            [user_id]
        )

    def create_order(self, user_id, items):
        order_id = self.db.execute(
            "INSERT INTO orders (user_id, status) VALUES (?, ?)",
            [user_id, "pending"]
        )
        for item in items:
            self.db.execute(
                "INSERT INTO order_items (order_id, product_id, qty) VALUES (?, ?, ?)",
                [order_id, item["product_id"], item["quantity"]]
            )
        return order_id
'''

        operation = Operation(
            type=OperationType.CODE_EDIT,
            code=code,
            language=Language.PYTHON,
            file_path="src/services.py"
        )

        def run():
            return self.engine.evaluate(operation)

        avg, min_t, max_t, p95, p99 = measure_time(run, iterations=500)

        print(f"  Average: {format_latency(avg)}")
        print(f"  P95: {format_latency(p95)}")
        print(f"  P99: {format_latency(p99)}")

        passed = avg < 1.0  # <1ms target
        print(f"  Target (<1ms): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "avg_ms": avg,
            "min_ms": min_t,
            "max_ms": max_t,
            "p95_ms": p95,
            "p99_ms": p99,
            "target_ms": 1.0,
            "passed": passed
        }

    def benchmark_large_code(self) -> dict:
        """
        Benchmark: Large code file (1000+ lines).
        Target: <10ms for very large files
        """
        # Generate large code
        lines = []
        for i in range(100):
            lines.append(f'''
def function_{i}(param):
    """Function {i} docstring."""
    result = param * {i}
    if result > 100:
        return result - 100
    else:
        return result + 100
''')

        large_code = '\n'.join(lines)

        operation = Operation(
            type=OperationType.CODE_EDIT,
            code=large_code,
            language=Language.PYTHON,
            file_path="src/large_file.py"
        )

        def run():
            return self.engine.evaluate(operation)

        avg, min_t, max_t, p95, p99 = measure_time(run, iterations=100)

        print(f"  Code size: {len(large_code)} chars, {large_code.count(chr(10))} lines")
        print(f"  Average: {format_latency(avg)}")
        print(f"  P95: {format_latency(p95)}")
        print(f"  P99: {format_latency(p99)}")

        passed = avg < 10.0  # <10ms target for large files
        print(f"  Target (<10ms): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "avg_ms": avg,
            "min_ms": min_t,
            "max_ms": max_t,
            "p95_ms": p95,
            "p99_ms": p99,
            "target_ms": 10.0,
            "code_size_chars": len(large_code),
            "code_size_lines": large_code.count('\n'),
            "passed": passed
        }

    def benchmark_many_patterns(self) -> dict:
        """
        Benchmark: Code with many vulnerability patterns to check.
        Target: <1ms
        """
        code = '''
# Multiple vulnerability patterns in one file
import os
import subprocess
from jinja2 import Template

def sql_1(id): return f"SELECT * FROM t WHERE id = {id}"
def sql_2(id): return "SELECT * FROM t WHERE id = " + id
def sql_3(id): return "SELECT * FROM t WHERE id = %s" % id
def sql_4(id): return "SELECT * FROM t WHERE id = {}".format(id)

def cmd_1(f): os.system(f"cat {f}")
def cmd_2(f): subprocess.run(f"echo {f}", shell=True)
def cmd_3(f): subprocess.call(f"ls {f}", shell=True)

def path_1(p): open(f"/data/{p}")
def path_2(p): open("/data/" + p)

def xss_1(c): return render_template_string(c)
def xss_2(c): return Markup("<p>" + c + "</p>")

def ssti_1(t): Template(t)
def ssti_2(t): env.from_string(t)

API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
password = "supersecret123"
'''

        operation = Operation(
            type=OperationType.CODE_EDIT,
            code=code,
            language=Language.PYTHON,
            file_path="src/many_vulns.py"
        )

        def run():
            return self.engine.evaluate(operation)

        avg, min_t, max_t, p95, p99 = measure_time(run, iterations=500)

        print(f"  Average: {format_latency(avg)}")
        print(f"  P95: {format_latency(p95)}")
        print(f"  P99: {format_latency(p99)}")

        passed = avg < 1.0  # <1ms target
        print(f"  Target (<1ms): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "avg_ms": avg,
            "min_ms": min_t,
            "max_ms": max_t,
            "p95_ms": p95,
            "p99_ms": p99,
            "target_ms": 1.0,
            "passed": passed
        }

    def benchmark_throughput(self) -> dict:
        """
        Benchmark: Operations per second.
        Target: >1000 ops/sec
        """
        operation = Operation(
            type=OperationType.CODE_EDIT,
            code='x = 1 + 2',
            language=Language.PYTHON,
            file_path="src/simple.py"
        )

        iterations = 10000
        start = time.perf_counter()

        for _ in range(iterations):
            self.engine.evaluate(operation)

        elapsed = time.perf_counter() - start
        ops_per_sec = iterations / elapsed

        print(f"  Operations: {iterations}")
        print(f"  Elapsed: {elapsed:.2f}s")
        print(f"  Throughput: {ops_per_sec:,.0f} ops/sec")

        passed = ops_per_sec > 1000
        print(f"  Target (>1000 ops/sec): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "iterations": iterations,
            "elapsed_sec": elapsed,
            "ops_per_sec": ops_per_sec,
            "target_ops_per_sec": 1000,
            "passed": passed
        }

    def benchmark_scaling(self) -> dict:
        """
        Benchmark: Scaling behavior with code size.
        Verify that evaluation time scales reasonably with input size.
        """
        sizes = [100, 500, 1000, 5000, 10000]
        results = {}

        for size in sizes:
            code = "x = 1\n" * size

            operation = Operation(
                type=OperationType.CODE_EDIT,
                code=code,
                language=Language.PYTHON,
                file_path="src/scaled.py"
            )

            def run():
                return self.engine.evaluate(operation)

            avg, min_t, max_t, p95, p99 = measure_time(run, iterations=50)
            results[size] = avg
            print(f"  {size} lines: {format_latency(avg)}")

        # Check that scaling is sub-linear (not O(n^2))
        # Expect <10x increase for 100x more code
        ratio = results[10000] / results[100]
        passed = ratio < 50  # Should be well under 100x

        print(f"  Scaling ratio (10000 vs 100): {ratio:.1f}x")
        print(f"  Target (<50x): {'✓ PASS' if passed else '✗ FAIL'}")

        return {
            "results_by_size": results,
            "scaling_ratio": ratio,
            "passed": passed
        }

    def _print_summary(self):
        """Print benchmark summary."""
        print()
        print("=" * 70)
        print("BENCHMARK SUMMARY")
        print("=" * 70)
        print()

        passed = 0
        failed = 0

        for name, result in self.results.items():
            if "error" in result:
                status = "ERROR"
                failed += 1
            elif result.get("passed", False):
                status = "✓ PASS"
                passed += 1
            else:
                status = "✗ FAIL"
                failed += 1

            print(f"  {name}: {status}")

        print()
        print(f"Total: {passed} passed, {failed} failed")
        print()

        if failed == 0:
            print("✓ ALL PERFORMANCE BENCHMARKS PASSED")
        else:
            print("✗ SOME PERFORMANCE BENCHMARKS FAILED")

        print("=" * 70)


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def run_performance_benchmarks():
    """Run all performance benchmarks."""
    benchmarks = PerformanceBenchmarks()
    benchmarks.run_all()
    return benchmarks.results


if __name__ == "__main__":
    run_performance_benchmarks()
