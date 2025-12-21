#!/usr/bin/env python3
"""
=============================================================================
CUMULATIVE TRACKING AND REFRESH TESTS
=============================================================================

PURPOSE: Test cumulative budget tracking across multiple operations.
These tests verify that:

1. Budgets track cumulative file counts
2. Budgets track cumulative line counts
3. Budgets track cumulative complexity
4. Budget refresh resets counters
5. Non-cumulative mode works correctly
6. Remaining budget calculations are correct
7. Usage statistics are accurate

CONFIGURATION:
refresh:
  interval_hours: 24  # Budget resets daily
  cumulative: true    # Track cumulative changes

=============================================================================
"""
import time
from datetime import datetime, timezone, timedelta

from change_budget_framework import (
    ChangeBudget, BudgetConfig, Operation, FileChange,
    BudgetDecision, BudgetConfigLoader
)


# =============================================================================
# CUMULATIVE FILE TRACKING TESTS
# =============================================================================

def test_cumulative_files_tracked():
    """
    TEST: Files are tracked cumulatively across operations.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "allowed_file_patterns": ["*.py"]
    })

    # First operation: 2 files
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second operation: 2 more files (total 4)
    op2 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=10),
        FileChange(file_path="file4.py", added_lines=10)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True

    # Third operation: 2 more would exceed limit (6 > 5)
    op3 = Operation(changes=[
        FileChange(file_path="file5.py", added_lines=10),
        FileChange(file_path="file6.py", added_lines=10)
    ])
    result3 = budget.validate_operation(op3)
    assert result3.allowed == False


def test_cumulative_same_file_not_double_counted():
    """
    TEST: Same file in multiple operations is counted once.
    """
    budget = ChangeBudget({
        "max_files": 3,
        "allowed_file_patterns": ["*.py"]
    })

    # First operation
    op1 = Operation(changes=[
        FileChange(file_path="shared.py", added_lines=10),
        FileChange(file_path="file1.py", added_lines=10)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second operation touches same file
    op2 = Operation(changes=[
        FileChange(file_path="shared.py", added_lines=5),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True  # 3 unique files: shared, file1, file2

    # Third operation - would be 4th unique file
    op3 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=10)
    ])
    result3 = budget.validate_operation(op3)
    assert result3.allowed == False  # 4 > 3


def test_cumulative_file_count_in_stats():
    """
    TEST: Usage stats show correct cumulative file count.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    budget.validate_operation(op)

    stats = budget.get_usage_stats()
    assert stats["files_used"] == 2
    assert stats["files_limit"] == 10


# =============================================================================
# CUMULATIVE LINE TRACKING TESTS
# =============================================================================

def test_cumulative_lines_tracked():
    """
    TEST: Lines are tracked cumulatively across operations.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100,
        "allowed_file_patterns": ["*.py"]
    })

    # First operation: 40 lines
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=40)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second operation: 40 more lines (total 80)
    op2 = Operation(changes=[
        FileChange(file_path="file2.py", added_lines=40)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True

    # Third operation: 30 more would exceed (110 > 100)
    op3 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=30)
    ])
    result3 = budget.validate_operation(op3)
    assert result3.allowed == False


def test_cumulative_lines_in_stats():
    """
    TEST: Usage stats show correct cumulative line count.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=50)
    ])
    budget.validate_operation(op1)

    op2 = Operation(changes=[
        FileChange(file_path="file2.py", added_lines=30)
    ])
    budget.validate_operation(op2)

    stats = budget.get_usage_stats()
    assert stats["lines_used"] == 80
    assert stats["lines_limit"] == 300


def test_lines_only_count_added():
    """
    TEST: Only added lines count toward limit (not removed).
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100,
        "allowed_file_patterns": ["*.py"]
    })

    # Add 60 lines, remove 40 - only 60 should count
    op = Operation(changes=[
        FileChange(file_path="file.py", added_lines=60, removed_lines=40)
    ])
    result = budget.validate_operation(op)
    assert result.allowed == True

    stats = budget.get_usage_stats()
    assert stats["lines_used"] == 60


# =============================================================================
# CUMULATIVE COMPLEXITY TRACKING TESTS
# =============================================================================

def test_cumulative_complexity_tracked():
    """
    TEST: Complexity is tracked cumulatively across operations.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 15,
        "allowed_file_patterns": ["*.py"]
    })

    # First operation: +5 complexity
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10,
                   complexity_before=0, complexity_after=5)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second operation: +5 more (total 10)
    op2 = Operation(changes=[
        FileChange(file_path="file2.py", added_lines=10,
                   complexity_before=0, complexity_after=5)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True

    # Third operation: +10 more would exceed (20 > 15)
    op3 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=10,
                   complexity_before=0, complexity_after=10)
    ])
    result3 = budget.validate_operation(op3)
    assert result3.allowed == False


def test_cumulative_complexity_in_stats():
    """
    TEST: Usage stats show correct cumulative complexity.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 20,
        "allowed_file_patterns": ["*.py"]
    })

    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10,
                   complexity_before=5, complexity_after=10)  # +5
    ])
    budget.validate_operation(op1)

    op2 = Operation(changes=[
        FileChange(file_path="file2.py", added_lines=10,
                   complexity_before=0, complexity_after=3)  # +3
    ])
    budget.validate_operation(op2)

    stats = budget.get_usage_stats()
    assert stats["complexity_used"] == 8
    assert stats["complexity_limit"] == 20


# =============================================================================
# BUDGET REFRESH TESTS
# =============================================================================

def test_manual_refresh():
    """
    TEST: Manual refresh resets all counters.
    """
    budget = ChangeBudget({
        "max_files": 3,
        "max_total_lines": 100,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    # Use up budget
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=50,
                   complexity_before=0, complexity_after=5)
    ])
    budget.validate_operation(op1)

    # Verify usage
    stats = budget.get_usage_stats()
    assert stats["files_used"] == 1
    assert stats["lines_used"] == 50
    assert stats["complexity_used"] == 5

    # Refresh
    budget.refresh()

    # Verify reset
    stats = budget.get_usage_stats()
    assert stats["files_used"] == 0
    assert stats["lines_used"] == 0
    assert stats["complexity_used"] == 0


def test_refresh_restores_budget():
    """
    TEST: After refresh, full budget is available again.
    """
    budget = ChangeBudget({
        "max_files": 2,
        "allowed_file_patterns": ["*.py"]
    })

    # Use up file budget
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    budget.validate_operation(op1)

    # Third file should fail
    op2 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=10)
    ])
    result = budget.validate_operation(op2)
    assert result.allowed == False

    # Refresh
    budget.refresh()

    # Same operation should now succeed
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True


def test_refresh_clears_operation_history():
    """
    TEST: Refresh clears the operation history.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    for i in range(5):
        op = Operation(changes=[
            FileChange(file_path=f"file{i}.py", added_lines=10)
        ])
        budget.validate_operation(op)

    stats = budget.get_usage_stats()
    assert stats["operations_count"] == 5

    budget.refresh()

    stats = budget.get_usage_stats()
    assert stats["operations_count"] == 0


# =============================================================================
# NON-CUMULATIVE MODE TESTS
# =============================================================================

def test_non_cumulative_mode():
    """
    TEST: Non-cumulative mode checks each operation independently.
    """
    config = BudgetConfig(
        max_files=2,
        cumulative=False,
        allowed_file_patterns=["*.py"]
    )
    budget = ChangeBudget(config)

    # First operation: 2 files (at limit)
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second operation: 2 more files (also at limit - no cumulative tracking)
    op2 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=10),
        FileChange(file_path="file4.py", added_lines=10)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True


def test_non_cumulative_lines():
    """
    TEST: Non-cumulative mode doesn't track lines across operations.
    """
    config = BudgetConfig(
        max_files=10,
        max_total_lines=100,
        cumulative=False,
        allowed_file_patterns=["*.py"]
    )
    budget = ChangeBudget(config)

    # First operation: 80 lines
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=80)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second operation: 80 more lines (would fail if cumulative)
    op2 = Operation(changes=[
        FileChange(file_path="file2.py", added_lines=80)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True


# =============================================================================
# REMAINING BUDGET TESTS
# =============================================================================

def test_remaining_budget_initial():
    """
    TEST: Initial remaining budget equals limits.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "max_total_lines": 300,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    remaining = budget.get_remaining_budget()

    assert remaining["files"] == 5
    assert remaining["lines"] == 300
    assert remaining["complexity"] == 10


def test_remaining_budget_after_usage():
    """
    TEST: Remaining budget decreases after operations.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "max_total_lines": 300,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=100,
                   complexity_before=0, complexity_after=3),
        FileChange(file_path="file2.py", added_lines=50,
                   complexity_before=0, complexity_after=2)
    ])
    budget.validate_operation(op)

    remaining = budget.get_remaining_budget()

    assert remaining["files"] == 3  # 5 - 2
    assert remaining["lines"] == 150  # 300 - 150
    assert remaining["complexity"] == 5  # 10 - 5


def test_remaining_budget_minimum_zero():
    """
    TEST: Remaining budget never goes below zero.
    """
    budget = ChangeBudget({
        "max_files": 2,
        "max_total_lines": 50,
        "allowed_file_patterns": ["*.py"]
    })

    # Use up all budget
    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=30),
        FileChange(file_path="file2.py", added_lines=30)
    ])
    budget.validate_operation(op)

    remaining = budget.get_remaining_budget()

    assert remaining["files"] == 0
    # Lines might be negative in tracking but remaining should be 0
    assert remaining["lines"] == 0


def test_remaining_budget_after_refresh():
    """
    TEST: Remaining budget restored after refresh.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    # Use some budget
    op = Operation(changes=[
        FileChange(file_path="file.py", added_lines=100)
    ])
    budget.validate_operation(op)

    remaining_before = budget.get_remaining_budget()
    assert remaining_before["files"] == 4
    assert remaining_before["lines"] == 200

    # Refresh
    budget.refresh()

    remaining_after = budget.get_remaining_budget()
    assert remaining_after["files"] == 5
    assert remaining_after["lines"] == 300


# =============================================================================
# USAGE STATS TESTS
# =============================================================================

def test_usage_stats_complete():
    """
    TEST: Usage stats include all required fields.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "max_total_lines": 300,
        "max_complexity_increase": 10,
        "allowed_file_patterns": ["*.py"]
    })

    stats = budget.get_usage_stats()

    required_fields = [
        "files_used", "files_limit",
        "lines_used", "lines_limit",
        "complexity_used", "complexity_limit",
        "operations_count", "last_reset"
    ]

    for field in required_fields:
        assert field in stats, f"Missing field: {field}"


def test_usage_stats_operations_count():
    """
    TEST: Operations count increments correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    for i in range(3):
        op = Operation(changes=[
            FileChange(file_path=f"file{i}.py", added_lines=10)
        ])
        budget.validate_operation(op)

    stats = budget.get_usage_stats()
    assert stats["operations_count"] == 3


def test_usage_stats_last_reset():
    """
    TEST: Last reset timestamp is tracked.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    stats = budget.get_usage_stats()
    assert "last_reset" in stats

    # Should be recent
    last_reset = datetime.fromisoformat(stats["last_reset"])
    now = datetime.now(timezone.utc)
    assert (now - last_reset).total_seconds() < 10


def test_usage_stats_updates_on_refresh():
    """
    TEST: Last reset timestamp updates on refresh.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    stats1 = budget.get_usage_stats()
    first_reset = datetime.fromisoformat(stats1["last_reset"])

    # Small delay
    time.sleep(0.1)

    # Refresh
    budget.refresh()

    stats2 = budget.get_usage_stats()
    second_reset = datetime.fromisoformat(stats2["last_reset"])

    assert second_reset > first_reset


# =============================================================================
# FAILED OPERATIONS DON'T COUNT TESTS
# =============================================================================

def test_failed_operation_not_counted():
    """
    TEST: Failed operations don't count toward cumulative budget.
    """
    budget = ChangeBudget({
        "max_files": 2,
        "allowed_file_patterns": ["*.py"]
    })

    # Use 2 files
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Try to use 2 more (should fail)
    op2 = Operation(changes=[
        FileChange(file_path="file3.py", added_lines=10),
        FileChange(file_path="file4.py", added_lines=10)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == False

    # Stats should still show 2 files (not 4)
    stats = budget.get_usage_stats()
    assert stats["files_used"] == 2


def test_failed_lines_not_counted():
    """
    TEST: Lines from failed operations don't count.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100,
        "allowed_file_patterns": ["*.py"]
    })

    # Use 80 lines
    op1 = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=80)
    ])
    budget.validate_operation(op1)

    # Try to use 50 more (should fail)
    op2 = Operation(changes=[
        FileChange(file_path="file2.py", added_lines=50)
    ])
    result = budget.validate_operation(op2)
    assert result.allowed == False

    # Stats should show 80, not 130
    stats = budget.get_usage_stats()
    assert stats["lines_used"] == 80


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_cumulative_tracking_tests():
    """Run all cumulative tracking tests."""
    tests = [
        # Cumulative files
        ("CUM-FILES-001", "Files tracked cumulatively", test_cumulative_files_tracked),
        ("CUM-FILES-002", "Same file not double counted", test_cumulative_same_file_not_double_counted),
        ("CUM-FILES-003", "File count in stats", test_cumulative_file_count_in_stats),
        # Cumulative lines
        ("CUM-LINES-001", "Lines tracked cumulatively", test_cumulative_lines_tracked),
        ("CUM-LINES-002", "Line count in stats", test_cumulative_lines_in_stats),
        ("CUM-LINES-003", "Only added lines count", test_lines_only_count_added),
        # Cumulative complexity
        ("CUM-COMPLEX-001", "Complexity tracked", test_cumulative_complexity_tracked),
        ("CUM-COMPLEX-002", "Complexity in stats", test_cumulative_complexity_in_stats),
        # Refresh
        ("REFRESH-001", "Manual refresh", test_manual_refresh),
        ("REFRESH-002", "Refresh restores budget", test_refresh_restores_budget),
        ("REFRESH-003", "Refresh clears history", test_refresh_clears_operation_history),
        # Non-cumulative
        ("NONCUM-001", "Non-cumulative mode", test_non_cumulative_mode),
        ("NONCUM-002", "Non-cumulative lines", test_non_cumulative_lines),
        # Remaining budget
        ("REMAIN-001", "Initial remaining", test_remaining_budget_initial),
        ("REMAIN-002", "After usage", test_remaining_budget_after_usage),
        ("REMAIN-003", "Minimum zero", test_remaining_budget_minimum_zero),
        ("REMAIN-004", "After refresh", test_remaining_budget_after_refresh),
        # Usage stats
        ("STATS-001", "Complete stats", test_usage_stats_complete),
        ("STATS-002", "Operations count", test_usage_stats_operations_count),
        ("STATS-003", "Last reset", test_usage_stats_last_reset),
        ("STATS-004", "Updates on refresh", test_usage_stats_updates_on_refresh),
        # Failed operations
        ("FAIL-001", "Failed not counted", test_failed_operation_not_counted),
        ("FAIL-002", "Failed lines not counted", test_failed_lines_not_counted),
    ]

    print("=" * 70)
    print("CUMULATIVE TRACKING AND REFRESH TESTS")
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
    run_cumulative_tracking_tests()
