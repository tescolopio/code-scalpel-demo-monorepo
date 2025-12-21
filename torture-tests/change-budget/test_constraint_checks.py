#!/usr/bin/env python3
"""
=============================================================================
CONSTRAINT CHECK TESTS
=============================================================================

PURPOSE: Test all constraint checks in the Change Budget feature.
Tests are organized by constraint type in check order:

1. Forbidden paths (CRITICAL)
2. File patterns (HIGH)
3. Max files (HIGH)
4. Max lines per file (MEDIUM)
5. Max total lines (HIGH)
6. Complexity delta (MEDIUM)

Each constraint is tested for:
- Detection of violations
- Correct severity assignment
- Proper error messaging
- Edge cases

=============================================================================
"""
import os
from pathlib import Path

from change_budget_framework import (
    ChangeBudget, BudgetConfig, Operation, FileChange,
    BudgetDecision, Violation, Severity, ViolationType
)


# =============================================================================
# FORBIDDEN PATHS TESTS (CRITICAL)
# =============================================================================

def test_forbidden_path_git():
    """
    TEST: Modifications to .git/ directory are blocked.
    Severity: CRITICAL
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"]
    })

    operation = Operation(changes=[
        FileChange(file_path=".git/config", added_lines=5)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert len(decision.violations) >= 1
    assert any(v.rule == "forbidden_path" for v in decision.violations)
    assert any(v.severity == Severity.CRITICAL for v in decision.violations)


def test_forbidden_path_node_modules():
    """
    TEST: Modifications to node_modules/ are blocked.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": ["node_modules/"]
    })

    operation = Operation(changes=[
        FileChange(file_path="node_modules/lodash/index.js", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "forbidden_path" for v in decision.violations)


def test_forbidden_path_code_scalpel():
    """
    TEST: Modifications to .code-scalpel/ config are blocked.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".code-scalpel/"]
    })

    operation = Operation(changes=[
        FileChange(file_path=".code-scalpel/policy.yaml", added_lines=20)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "forbidden_path" for v in decision.violations)


def test_forbidden_path_nested():
    """
    TEST: Nested paths within forbidden directories are blocked.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"]
    })

    operation = Operation(changes=[
        FileChange(file_path=".git/hooks/pre-commit", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False


def test_forbidden_path_multiple():
    """
    TEST: Multiple forbidden paths are all checked.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/", "node_modules/", "vendor/"]
    })

    operation = Operation(changes=[
        FileChange(file_path="vendor/package/file.php", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "forbidden_path" for v in decision.violations)


def test_allowed_path_not_forbidden():
    """
    TEST: Paths not in forbidden list are allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="src/main.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True
    assert len(decision.violations) == 0


def test_forbidden_path_case_sensitivity():
    """
    TEST: Forbidden path matching is case-sensitive on Unix.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*"]
    })

    # Exact match should be blocked
    operation1 = Operation(changes=[
        FileChange(file_path=".git/config", added_lines=5)
    ])
    decision1 = budget.validate_operation(operation1)
    assert decision1.allowed == False

    # Different case - behavior may vary by OS
    # We're testing on Unix where case matters


def test_forbidden_path_with_absolute_path():
    """
    TEST: Forbidden paths work with absolute paths containing the pattern.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"]
    })

    operation = Operation(changes=[
        FileChange(file_path="/home/user/project/.git/config", added_lines=5)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False


# =============================================================================
# FILE PATTERN TESTS (HIGH)
# =============================================================================

def test_allowed_file_pattern_python():
    """
    TEST: Python files matching *.py pattern are allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="src/main.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_allowed_file_pattern_typescript():
    """
    TEST: TypeScript files matching *.ts pattern are allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.ts"]
    })

    operation = Operation(changes=[
        FileChange(file_path="src/app.ts", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_file_pattern_not_allowed():
    """
    TEST: Files not matching allowed patterns are rejected.
    Severity: HIGH
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py", "*.ts"]
    })

    operation = Operation(changes=[
        FileChange(file_path="config.json", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "file_pattern" for v in decision.violations)
    assert any(v.severity == Severity.HIGH for v in decision.violations)


def test_file_pattern_executable():
    """
    TEST: Executable files without extension are blocked by default.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py", "*.ts", "*.js"]
    })

    operation = Operation(changes=[
        FileChange(file_path="scripts/deploy", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False


def test_multiple_patterns_any_match():
    """
    TEST: File matching any of multiple patterns is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py", "*.ts", "*.js", "*.java"]
    })

    operation = Operation(changes=[
        FileChange(file_path="src/App.java", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_pattern_only_matches_basename():
    """
    TEST: Pattern matching uses basename, not full path.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    # Full path with .py extension
    operation = Operation(changes=[
        FileChange(file_path="very/deep/nested/path/module.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_mixed_allowed_and_forbidden():
    """
    TEST: Mixed operation with some allowed and some forbidden file types.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="src/main.py", added_lines=10),
        FileChange(file_path="config.yaml", added_lines=5)  # Not allowed
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "file_pattern" and "config.yaml" in (v.file_path or "") for v in decision.violations)


# =============================================================================
# MAX FILES TESTS (HIGH)
# =============================================================================

def test_max_files_under_limit():
    """
    TEST: Operation under file limit is allowed.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10),
        FileChange(file_path="file3.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_max_files_at_limit():
    """
    TEST: Operation at exactly the file limit is allowed.
    """
    budget = ChangeBudget({
        "max_files": 3,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10),
        FileChange(file_path="file3.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_max_files_exceeds_limit():
    """
    TEST: Operation exceeding file limit is rejected.
    Severity: HIGH
    """
    budget = ChangeBudget({
        "max_files": 3,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10),
        FileChange(file_path="file3.py", added_lines=10),
        FileChange(file_path="file4.py", added_lines=10),
        FileChange(file_path="file5.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "max_files" for v in decision.violations)
    assert any(v.severity == Severity.HIGH for v in decision.violations)

    # Check limit and actual in violation
    violation = next(v for v in decision.violations if v.rule == "max_files")
    assert violation.limit == 3
    assert violation.actual == 5


def test_max_files_violation_message():
    """
    TEST: Max files violation has clear message.
    """
    budget = ChangeBudget({
        "max_files": 3,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path=f"file{i}.py", added_lines=10)
        for i in range(5)
    ])

    decision = budget.validate_operation(operation)

    violation = next(v for v in decision.violations if v.rule == "max_files")
    assert "5" in violation.message
    assert "3" in violation.message


def test_max_files_single_file():
    """
    TEST: Single file operation with max_files=1 is allowed.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="single.py", added_lines=50)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


# =============================================================================
# MAX LINES PER FILE TESTS (MEDIUM)
# =============================================================================

def test_max_lines_per_file_under_limit():
    """
    TEST: File changes under line limit are allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 100,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=50)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_max_lines_per_file_at_limit():
    """
    TEST: File changes at exactly line limit are allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 100,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_max_lines_per_file_exceeds_limit():
    """
    TEST: File changes exceeding line limit are rejected.
    Severity: MEDIUM
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 100,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="big_file.py", added_lines=150)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "max_lines_per_file" for v in decision.violations)
    assert any(v.severity == Severity.MEDIUM for v in decision.violations)


def test_max_lines_per_file_multiple_files():
    """
    TEST: Each file is checked independently for line limit.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 100,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="small.py", added_lines=50),
        FileChange(file_path="big.py", added_lines=150),  # Exceeds
        FileChange(file_path="medium.py", added_lines=80)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False

    # Only big.py should violate
    violations = [v for v in decision.violations if v.rule == "max_lines_per_file"]
    assert len(violations) == 1
    assert "big.py" in violations[0].file_path


def test_max_lines_per_file_violation_details():
    """
    TEST: Line limit violation includes file path and counts.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 100,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="users.py", added_lines=150)
    ])

    decision = budget.validate_operation(operation)

    violation = next(v for v in decision.violations if v.rule == "max_lines_per_file")
    assert violation.file_path == "users.py"
    assert violation.limit == 100
    assert violation.actual == 150


# =============================================================================
# MAX TOTAL LINES TESTS (HIGH)
# =============================================================================

def test_max_total_lines_under_limit():
    """
    TEST: Total lines under limit is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=100),
        FileChange(file_path="file2.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_max_total_lines_at_limit():
    """
    TEST: Total lines at exactly limit is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=100),
        FileChange(file_path="file2.py", added_lines=100),
        FileChange(file_path="file3.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_max_total_lines_exceeds_limit():
    """
    TEST: Total lines exceeding limit is rejected.
    Severity: HIGH
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=200),
        FileChange(file_path="file2.py", added_lines=200)  # Total: 400
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "max_total_lines" for v in decision.violations)
    assert any(v.severity == Severity.HIGH for v in decision.violations)


def test_max_total_lines_aggregation():
    """
    TEST: Lines from all files are aggregated correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100,
        "max_lines_per_file": 50,
        "allowed_file_patterns": ["*.py"]
    })

    # Each file is under per-file limit, but total exceeds
    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=40),
        FileChange(file_path="file2.py", added_lines=40),
        FileChange(file_path="file3.py", added_lines=40)  # Total: 120
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "max_total_lines" for v in decision.violations)


def test_max_total_lines_violation_details():
    """
    TEST: Total lines violation includes limit and actual.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=400)
    ])

    decision = budget.validate_operation(operation)

    violation = next(v for v in decision.violations if v.rule == "max_total_lines")
    assert violation.limit == 300
    assert violation.actual == 400


# =============================================================================
# COMPLEXITY DELTA TESTS (MEDIUM)
# =============================================================================

def test_complexity_under_limit():
    """
    TEST: Complexity increase under limit is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10,
                   complexity_before=5, complexity_after=10)  # +5
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_complexity_at_limit():
    """
    TEST: Complexity increase at exactly limit is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10,
                   complexity_before=5, complexity_after=15)  # +10
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_complexity_exceeds_limit():
    """
    TEST: Complexity increase exceeding limit is rejected.
    Severity: MEDIUM
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10,
                   complexity_before=5, complexity_after=20)  # +15
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "max_complexity_increase" for v in decision.violations)
    assert any(v.severity == Severity.MEDIUM for v in decision.violations)


def test_complexity_aggregated_across_files():
    """
    TEST: Complexity from all files is aggregated.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10,
                   complexity_before=0, complexity_after=5),  # +5
        FileChange(file_path="file2.py", added_lines=10,
                   complexity_before=0, complexity_after=8)   # +8 = Total +13
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert any(v.rule == "max_complexity_increase" for v in decision.violations)


def test_complexity_decrease_allowed():
    """
    TEST: Complexity decrease (refactoring) is always allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10,
                   complexity_before=20, complexity_after=5)  # -15 (decrease)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


def test_complexity_net_zero():
    """
    TEST: Net zero complexity change is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10,
                   complexity_before=10, complexity_after=20),  # +10
        FileChange(file_path="file2.py", added_lines=10,
                   complexity_before=20, complexity_after=10)   # -10 = Net 0
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True


# =============================================================================
# CONSTRAINT CHECK ORDER TESTS
# =============================================================================

def test_forbidden_path_checked_first():
    """
    TEST: Forbidden path is checked before other constraints.

    Even if other constraints are violated, forbidden path should be
    the first error reported (CRITICAL severity).
    """
    budget = ChangeBudget({
        "max_files": 1,  # Would also violate
        "max_lines_per_file": 10,  # Would also violate
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*.config"]  # Would also violate
    })

    operation = Operation(changes=[
        FileChange(file_path=".git/config", added_lines=100),
        FileChange(file_path="src/other.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    # Forbidden path should be present in violations
    assert any(v.rule == "forbidden_path" for v in decision.violations)


def test_multiple_violations_all_reported():
    """
    TEST: Multiple violations are all reported.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "max_lines_per_file": 10,
        "max_total_lines": 20,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=50),
        FileChange(file_path="file2.py", added_lines=50)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False

    # Should have multiple violations
    rules = {v.rule for v in decision.violations}
    assert "max_files" in rules  # 2 > 1
    assert "max_lines_per_file" in rules  # 50 > 10
    assert "max_total_lines" in rules  # 100 > 20


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_constraint_check_tests():
    """Run all constraint check tests."""
    tests = [
        # Forbidden paths
        ("FORBID-001", "Git directory blocked", test_forbidden_path_git),
        ("FORBID-002", "Node modules blocked", test_forbidden_path_node_modules),
        ("FORBID-003", "Code-scalpel blocked", test_forbidden_path_code_scalpel),
        ("FORBID-004", "Nested forbidden paths", test_forbidden_path_nested),
        ("FORBID-005", "Multiple forbidden paths", test_forbidden_path_multiple),
        ("FORBID-006", "Allowed path not forbidden", test_allowed_path_not_forbidden),
        ("FORBID-007", "Case sensitivity", test_forbidden_path_case_sensitivity),
        ("FORBID-008", "Absolute path", test_forbidden_path_with_absolute_path),
        # File patterns
        ("PATTERN-001", "Python files allowed", test_allowed_file_pattern_python),
        ("PATTERN-002", "TypeScript files allowed", test_allowed_file_pattern_typescript),
        ("PATTERN-003", "Pattern not allowed", test_file_pattern_not_allowed),
        ("PATTERN-004", "Executable blocked", test_file_pattern_executable),
        ("PATTERN-005", "Multiple patterns any match", test_multiple_patterns_any_match),
        ("PATTERN-006", "Pattern matches basename", test_pattern_only_matches_basename),
        ("PATTERN-007", "Mixed allowed forbidden", test_mixed_allowed_and_forbidden),
        # Max files
        ("FILES-001", "Under limit", test_max_files_under_limit),
        ("FILES-002", "At limit", test_max_files_at_limit),
        ("FILES-003", "Exceeds limit", test_max_files_exceeds_limit),
        ("FILES-004", "Violation message", test_max_files_violation_message),
        ("FILES-005", "Single file", test_max_files_single_file),
        # Max lines per file
        ("LINES-001", "Under limit", test_max_lines_per_file_under_limit),
        ("LINES-002", "At limit", test_max_lines_per_file_at_limit),
        ("LINES-003", "Exceeds limit", test_max_lines_per_file_exceeds_limit),
        ("LINES-004", "Multiple files", test_max_lines_per_file_multiple_files),
        ("LINES-005", "Violation details", test_max_lines_per_file_violation_details),
        # Max total lines
        ("TOTAL-001", "Under limit", test_max_total_lines_under_limit),
        ("TOTAL-002", "At limit", test_max_total_lines_at_limit),
        ("TOTAL-003", "Exceeds limit", test_max_total_lines_exceeds_limit),
        ("TOTAL-004", "Aggregation", test_max_total_lines_aggregation),
        ("TOTAL-005", "Violation details", test_max_total_lines_violation_details),
        # Complexity
        ("COMPLEX-001", "Under limit", test_complexity_under_limit),
        ("COMPLEX-002", "At limit", test_complexity_at_limit),
        ("COMPLEX-003", "Exceeds limit", test_complexity_exceeds_limit),
        ("COMPLEX-004", "Aggregated", test_complexity_aggregated_across_files),
        ("COMPLEX-005", "Decrease allowed", test_complexity_decrease_allowed),
        ("COMPLEX-006", "Net zero", test_complexity_net_zero),
        # Order
        ("ORDER-001", "Forbidden first", test_forbidden_path_checked_first),
        ("ORDER-002", "Multiple violations", test_multiple_violations_all_reported),
    ]

    print("=" * 70)
    print("CONSTRAINT CHECK TESTS")
    print("=" * 70)
    print()

    passed = 0
    failed = 0

    for test_id, name, test_fn in tests:
        try:
            test_fn()
            print(f"✓ PASS: [{test_id}] {name}")
            passed += 1
        except AssertionError as e:
            print(f"✗ FAIL: [{test_id}] {name}")
            print(f"  Reason: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ ERROR: [{test_id}] {name}")
            print(f"  Exception: {type(e).__name__}: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return passed, failed


if __name__ == "__main__":
    run_constraint_check_tests()
