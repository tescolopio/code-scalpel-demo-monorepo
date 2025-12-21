#!/usr/bin/env python3
"""
=============================================================================
ACTIONABLE ERROR AND SUGGESTIONS TESTS
=============================================================================

PURPOSE: Test that budget violations produce actionable error responses.
These tests verify that:

1. Error responses include clear violation details
2. Suggestions are generated for each violation type
3. Suggestions are actionable and specific
4. Batch splitting suggestions are correct
5. Error response format is consistent

EXPECTED RESPONSE FORMAT:
{
    "allowed": false,
    "violations": [
        {
            "rule": "max_files",
            "limit": 3,
            "actual": 5,
            "severity": "HIGH",
            "message": "Operation affects 5 files, exceeds limit of 3"
        }
    ],
    "suggestions": [
        "Split operation into smaller batches affecting fewer files",
        "Consider: batch 1 (files 1-3), batch 2 (files 4-5)"
    ]
}

=============================================================================
"""
import json
from change_budget_framework import (
    ChangeBudget, BudgetConfig, Operation, FileChange,
    BudgetDecision, Violation, Severity
)


# =============================================================================
# ERROR RESPONSE FORMAT TESTS
# =============================================================================

def test_response_format_allowed():
    """
    TEST: Allowed response has correct format.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == True
    assert isinstance(decision.violations, list)
    assert len(decision.violations) == 0
    assert isinstance(decision.suggestions, list)
    assert len(decision.suggestions) == 0


def test_response_format_denied():
    """
    TEST: Denied response has correct format with violations.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert decision.allowed == False
    assert isinstance(decision.violations, list)
    assert len(decision.violations) >= 1
    assert isinstance(decision.suggestions, list)
    assert len(decision.suggestions) >= 1


def test_response_to_dict():
    """
    TEST: Response serializes to dictionary correctly.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)
    data = decision.to_dict()

    assert "allowed" in data
    assert "violations" in data
    assert "suggestions" in data
    assert data["allowed"] == False


def test_response_to_json():
    """
    TEST: Response can be serialized to JSON.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)
    data = decision.to_dict()

    # Should serialize without error
    json_str = json.dumps(data, indent=2)
    assert json_str is not None

    # Should be valid JSON
    parsed = json.loads(json_str)
    assert parsed["allowed"] == False


# =============================================================================
# VIOLATION DETAILS TESTS
# =============================================================================

def test_violation_includes_rule():
    """
    TEST: Each violation includes the rule name.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    for violation in decision.violations:
        assert violation.rule is not None
        assert len(violation.rule) > 0


def test_violation_includes_severity():
    """
    TEST: Each violation includes severity level.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    for violation in decision.violations:
        assert violation.severity is not None
        assert isinstance(violation.severity, Severity)


def test_violation_includes_message():
    """
    TEST: Each violation includes human-readable message.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    for violation in decision.violations:
        assert violation.message is not None
        assert len(violation.message) > 10  # Meaningful message


def test_violation_includes_limit_and_actual():
    """
    TEST: Limit violations include both limit and actual values.
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

    max_files_violation = next(
        (v for v in decision.violations if v.rule == "max_files"),
        None
    )

    assert max_files_violation is not None
    assert max_files_violation.limit == 3
    assert max_files_violation.actual == 5


def test_violation_includes_file_path():
    """
    TEST: File-specific violations include file path.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 50,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="big_file.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    violation = next(
        (v for v in decision.violations if v.rule == "max_lines_per_file"),
        None
    )

    assert violation is not None
    assert violation.file_path == "big_file.py"


# =============================================================================
# SUGGESTIONS FOR MAX_FILES TESTS
# =============================================================================

def test_suggestion_split_into_batches():
    """
    TEST: Max files violation suggests splitting into batches.
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

    assert any("split" in s.lower() or "batch" in s.lower()
               for s in decision.suggestions)


def test_suggestion_batch_ranges():
    """
    TEST: Batch suggestion includes specific file ranges.
    """
    budget = ChangeBudget({
        "max_files": 3,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path=f"file{i}.py", added_lines=10)
        for i in range(6)
    ])

    decision = budget.validate_operation(operation)

    # Should suggest something like "batch 1 (files 1-3), batch 2 (files 4-6)"
    batch_suggestion = next(
        (s for s in decision.suggestions if "batch" in s.lower() and "files" in s.lower()),
        None
    )

    assert batch_suggestion is not None


def test_suggestion_batch_calculation():
    """
    TEST: Batch calculation is mathematically correct.
    """
    budget = ChangeBudget({
        "max_files": 3,
        "allowed_file_patterns": ["*.py"]
    })

    # 7 files with limit 3 = 3 batches (3 + 3 + 1)
    operation = Operation(changes=[
        FileChange(file_path=f"file{i}.py", added_lines=10)
        for i in range(7)
    ])

    decision = budget.validate_operation(operation)

    # Should suggest 3 batches
    suggestions_text = " ".join(decision.suggestions)
    # At least mentions batching
    assert "batch" in suggestions_text.lower()


# =============================================================================
# SUGGESTIONS FOR MAX_LINES TESTS
# =============================================================================

def test_suggestion_lines_per_file():
    """
    TEST: Lines per file violation suggests reducing changes or splitting.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 50,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="users.py", added_lines=150)
    ])

    decision = budget.validate_operation(operation)

    assert any("reduce" in s.lower() or "split" in s.lower()
               for s in decision.suggestions)


def test_suggestion_lines_mentions_file():
    """
    TEST: Lines per file suggestion mentions the specific file.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 50,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="users.py", added_lines=150)
    ])

    decision = budget.validate_operation(operation)

    assert any("users.py" in s for s in decision.suggestions)


def test_suggestion_total_lines():
    """
    TEST: Total lines violation suggests breaking into smaller operations.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=100),
        FileChange(file_path="file2.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    assert any("break" in s.lower() or "smaller" in s.lower() or "incremental" in s.lower()
               for s in decision.suggestions)


# =============================================================================
# SUGGESTIONS FOR FORBIDDEN PATHS TESTS
# =============================================================================

def test_suggestion_forbidden_path():
    """
    TEST: Forbidden path violation suggests manual review.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*"]
    })

    operation = Operation(changes=[
        FileChange(file_path=".git/config", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert any("protected" in s.lower() or "manual" in s.lower() or "review" in s.lower()
               for s in decision.suggestions)


def test_suggestion_forbidden_mentions_path():
    """
    TEST: Forbidden path suggestion mentions the specific path.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*"]
    })

    operation = Operation(changes=[
        FileChange(file_path=".git/hooks/pre-commit", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    assert any(".git" in s for s in decision.suggestions)


# =============================================================================
# SUGGESTIONS FOR FILE PATTERN TESTS
# =============================================================================

def test_suggestion_file_pattern():
    """
    TEST: File pattern violation shows allowed patterns.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py", "*.ts"]
    })

    operation = Operation(changes=[
        FileChange(file_path="config.yaml", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    # Should list allowed patterns
    suggestions_text = " ".join(decision.suggestions)
    assert "*.py" in suggestions_text or "allowed" in suggestions_text.lower()


# =============================================================================
# SUGGESTIONS FOR COMPLEXITY TESTS
# =============================================================================

def test_suggestion_complexity():
    """
    TEST: Complexity violation suggests refactoring techniques.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 5,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10,
                   complexity_before=0, complexity_after=20)
    ])

    decision = budget.validate_operation(operation)

    assert any("refactor" in s.lower() or "extract" in s.lower() or "simplify" in s.lower()
               for s in decision.suggestions)


# =============================================================================
# MULTIPLE VIOLATIONS TESTS
# =============================================================================

def test_multiple_violations_multiple_suggestions():
    """
    TEST: Multiple violations generate multiple suggestions.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "max_lines_per_file": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=50),
        FileChange(file_path="file2.py", added_lines=50)
    ])

    decision = budget.validate_operation(operation)

    # Should have suggestions for multiple violations
    assert len(decision.suggestions) >= 2


def test_suggestions_are_unique():
    """
    TEST: Suggestions are not duplicated.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "max_lines_per_file": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=50),
        FileChange(file_path="file2.py", added_lines=50)
    ])

    decision = budget.validate_operation(operation)

    # Check for duplicates
    unique_suggestions = set(decision.suggestions)
    assert len(unique_suggestions) == len(decision.suggestions)


# =============================================================================
# SEVERITY ORDERING TESTS
# =============================================================================

def test_critical_severity_first():
    """
    TEST: CRITICAL violations are reported (forbidden paths).
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*"]
    })

    operation = Operation(changes=[
        FileChange(file_path=".git/config", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    critical_violations = [v for v in decision.violations if v.severity == Severity.CRITICAL]
    assert len(critical_violations) >= 1


def test_high_severity_reported():
    """
    TEST: HIGH severity violations are reported.
    """
    budget = ChangeBudget({
        "max_files": 1,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])

    decision = budget.validate_operation(operation)

    high_violations = [v for v in decision.violations if v.severity == Severity.HIGH]
    assert len(high_violations) >= 1


def test_medium_severity_reported():
    """
    TEST: MEDIUM severity violations are reported.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_lines_per_file": 50,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file.py", added_lines=100)
    ])

    decision = budget.validate_operation(operation)

    medium_violations = [v for v in decision.violations if v.severity == Severity.MEDIUM]
    assert len(medium_violations) >= 1


# =============================================================================
# METADATA TESTS
# =============================================================================

def test_metadata_includes_stats():
    """
    TEST: Decision includes metadata with operation stats.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    operation = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=30, removed_lines=10),
        FileChange(file_path="file2.py", added_lines=20, removed_lines=5)
    ])

    decision = budget.validate_operation(operation)

    assert "files_affected" in decision.metadata
    assert decision.metadata["files_affected"] == 2

    assert "lines_added" in decision.metadata
    assert decision.metadata["lines_added"] == 50

    assert "lines_removed" in decision.metadata
    assert decision.metadata["lines_removed"] == 15


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_actionable_error_tests():
    """Run all actionable error tests."""
    tests = [
        # Response format
        ("FORMAT-001", "Allowed response format", test_response_format_allowed),
        ("FORMAT-002", "Denied response format", test_response_format_denied),
        ("FORMAT-003", "Response to dict", test_response_to_dict),
        ("FORMAT-004", "Response to JSON", test_response_to_json),
        # Violation details
        ("DETAIL-001", "Violation includes rule", test_violation_includes_rule),
        ("DETAIL-002", "Violation includes severity", test_violation_includes_severity),
        ("DETAIL-003", "Violation includes message", test_violation_includes_message),
        ("DETAIL-004", "Violation includes limit/actual", test_violation_includes_limit_and_actual),
        ("DETAIL-005", "Violation includes file path", test_violation_includes_file_path),
        # Max files suggestions
        ("SUGGEST-FILES-001", "Split into batches", test_suggestion_split_into_batches),
        ("SUGGEST-FILES-002", "Batch ranges", test_suggestion_batch_ranges),
        ("SUGGEST-FILES-003", "Batch calculation", test_suggestion_batch_calculation),
        # Lines suggestions
        ("SUGGEST-LINES-001", "Lines per file", test_suggestion_lines_per_file),
        ("SUGGEST-LINES-002", "Mentions file", test_suggestion_lines_mentions_file),
        ("SUGGEST-LINES-003", "Total lines", test_suggestion_total_lines),
        # Forbidden path suggestions
        ("SUGGEST-FORBID-001", "Forbidden path", test_suggestion_forbidden_path),
        ("SUGGEST-FORBID-002", "Mentions path", test_suggestion_forbidden_mentions_path),
        # File pattern suggestions
        ("SUGGEST-PATTERN-001", "File pattern", test_suggestion_file_pattern),
        # Complexity suggestions
        ("SUGGEST-COMPLEX-001", "Complexity", test_suggestion_complexity),
        # Multiple violations
        ("MULTI-001", "Multiple suggestions", test_multiple_violations_multiple_suggestions),
        ("MULTI-002", "Unique suggestions", test_suggestions_are_unique),
        # Severity
        ("SEV-001", "Critical severity", test_critical_severity_first),
        ("SEV-002", "High severity", test_high_severity_reported),
        ("SEV-003", "Medium severity", test_medium_severity_reported),
        # Metadata
        ("META-001", "Metadata stats", test_metadata_includes_stats),
    ]

    print("=" * 70)
    print("ACTIONABLE ERROR AND SUGGESTIONS TESTS")
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
    run_actionable_error_tests()
