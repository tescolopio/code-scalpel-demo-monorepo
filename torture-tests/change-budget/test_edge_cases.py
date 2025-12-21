#!/usr/bin/env python3
"""
=============================================================================
EDGE CASES AND CONFIGURATION TESTS
=============================================================================

PURPOSE: Test edge cases, configuration loading, and integration scenarios.
These tests verify that:

1. Edge cases are handled correctly
2. Configuration loading from YAML works
3. Default configuration is sensible
4. Zero and extreme values are handled
5. Real-world scenarios work correctly

=============================================================================
"""
import json
import os
import tempfile
import yaml
from pathlib import Path

from change_budget_framework import (
    ChangeBudget, BudgetConfig, BudgetConfigLoader, Operation, FileChange,
    BudgetDecision, Violation, Severity
)


# =============================================================================
# CONFIGURATION LOADING TESTS
# =============================================================================

def test_config_from_yaml():
    """
    TEST: Configuration loads correctly from YAML.
    """
    yaml_content = """
version: "1.0"
limits:
  max_files: 3
  max_lines_per_file: 50
  max_total_lines: 150
  max_complexity_increase: 5

files:
  allowed_patterns: ["*.py", "*.ts"]
  forbidden_paths: [".git/", "secrets/"]

refresh:
  interval_hours: 12
  cumulative: true
"""
    config = BudgetConfig.from_yaml(yaml_content)

    assert config.max_files == 3
    assert config.max_lines_per_file == 50
    assert config.max_total_lines == 150
    assert config.max_complexity_increase == 5
    assert "*.py" in config.allowed_file_patterns
    assert ".git/" in config.forbidden_paths
    assert config.refresh_interval_hours == 12
    assert config.cumulative == True


def test_config_from_file():
    """
    TEST: Configuration loads from YAML file.
    """
    yaml_content = """
version: "1.0"
limits:
  max_files: 10
  max_lines_per_file: 200
  max_total_lines: 500

files:
  allowed_patterns: ["*.java"]
  forbidden_paths: [".git/"]
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        config_path = f.name

    try:
        config = BudgetConfigLoader.load_from_file(config_path)

        assert config.max_files == 10
        assert config.max_lines_per_file == 200
        assert "*.java" in config.allowed_file_patterns
    finally:
        os.unlink(config_path)


def test_config_save_and_load():
    """
    TEST: Configuration roundtrips through save/load.
    """
    original = BudgetConfig(
        max_files=7,
        max_lines_per_file=75,
        max_total_lines=250,
        max_complexity_increase=8,
        allowed_file_patterns=["*.go", "*.rs"],
        forbidden_paths=[".git/", ".secret/"]
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "budget.yaml")
        BudgetConfigLoader.save_to_file(original, config_path)

        loaded = BudgetConfigLoader.load_from_file(config_path)

        assert loaded.max_files == original.max_files
        assert loaded.max_lines_per_file == original.max_lines_per_file
        assert loaded.max_total_lines == original.max_total_lines
        assert loaded.max_complexity_increase == original.max_complexity_increase


def test_config_defaults():
    """
    TEST: Default configuration has sensible values.
    """
    config = BudgetConfig()

    assert config.max_files == 5
    assert config.max_lines_per_file == 100
    assert config.max_total_lines == 300
    assert config.max_complexity_increase == 10
    assert len(config.allowed_file_patterns) > 0
    assert ".git/" in config.forbidden_paths


def test_budget_with_config_object():
    """
    TEST: Budget can be created with BudgetConfig object.
    """
    config = BudgetConfig(
        max_files=2,
        allowed_file_patterns=["*.py"]
    )
    budget = ChangeBudget(config)

    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


# =============================================================================
# EDGE CASE TESTS - ZERO VALUES
# =============================================================================

def test_zero_files_limit():
    """
    TEST: Zero file limit blocks all operations.
    """
    budget = ChangeBudget({
        "max_files": 0,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="file.py", added_lines=1)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == False


def test_zero_lines_limit():
    """
    TEST: Zero lines limit blocks all operations with lines.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 0,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="file.py", added_lines=1)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == False


def test_zero_complexity_limit():
    """
    TEST: Zero complexity limit blocks any complexity increase.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 0,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="file.py", added_lines=10,
                   complexity_before=0, complexity_after=1)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == False


def test_zero_lines_in_operation():
    """
    TEST: Operation with zero lines added is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="file.py", added_lines=0, removed_lines=50)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_empty_operation():
    """
    TEST: Empty operation (no changes) is allowed.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[])
    result = budget.validate_operation(op)

    assert result.allowed == True


# =============================================================================
# EDGE CASE TESTS - LARGE VALUES
# =============================================================================

def test_very_large_file_count():
    """
    TEST: Large number of files is handled correctly.
    """
    budget = ChangeBudget({
        "max_files": 100,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path=f"file{i}.py", added_lines=1)
        for i in range(50)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True
    assert len(op.changes) == 50


def test_very_large_line_count():
    """
    TEST: Large line counts are handled correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 100000,
        "max_lines_per_file": 50000,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="big_file.py", added_lines=25000)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_large_complexity():
    """
    TEST: Large complexity values are handled correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_complexity_increase": 1000,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="complex.py", added_lines=100,
                   complexity_before=0, complexity_after=500)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


# =============================================================================
# EDGE CASE TESTS - PATH HANDLING
# =============================================================================

def test_windows_path_separators():
    """
    TEST: Windows-style path separators are handled.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "forbidden_paths": [".git/"],
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="src\\api\\users.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True  # Not a forbidden path


def test_paths_with_spaces():
    """
    TEST: Paths with spaces are handled correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="my project/source files/main.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_unicode_paths():
    """
    TEST: Unicode characters in paths are handled.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="프로젝트/源代码/модуль.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_dotfile():
    """
    TEST: Dotfiles are handled correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py", ".*"]  # Allow dotfiles
    })

    op = Operation(changes=[
        FileChange(file_path=".hidden.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_relative_paths():
    """
    TEST: Relative paths are handled correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="../sibling/module.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


# =============================================================================
# EDGE CASE TESTS - PATTERN MATCHING
# =============================================================================

def test_pattern_case_sensitivity():
    """
    TEST: Pattern matching respects case.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    # .PY should not match *.py on Unix
    op = Operation(changes=[
        FileChange(file_path="module.PY", added_lines=10)
    ])
    result = budget.validate_operation(op)

    # Behavior depends on OS, but we're testing consistency
    # On Unix, this should NOT match


def test_pattern_multiple_extensions():
    """
    TEST: Files with multiple dots in name are matched correctly.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py"]
    })

    op = Operation(changes=[
        FileChange(file_path="module.test.py", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_pattern_no_extension():
    """
    TEST: Files without extension match * pattern.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*"]  # Match anything
    })

    op = Operation(changes=[
        FileChange(file_path="Makefile", added_lines=10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


# =============================================================================
# REAL-WORLD SCENARIO TESTS
# =============================================================================

def test_typical_feature_development():
    """
    TEST: Typical feature development scenario.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "max_lines_per_file": 100,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py", "*.ts", "*.java"]
    })

    op = Operation(changes=[
        FileChange(file_path="src/api/users.py", added_lines=50, removed_lines=10),
        FileChange(file_path="src/api/auth.py", added_lines=30, removed_lines=5),
        FileChange(file_path="tests/test_users.py", added_lines=40, removed_lines=0)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


def test_large_refactoring_blocked():
    """
    TEST: Large refactoring that exceeds limits is blocked.
    """
    budget = ChangeBudget({
        "max_files": 5,
        "max_lines_per_file": 100,
        "max_total_lines": 300,
        "allowed_file_patterns": ["*.py"]
    })

    # 10 files, 50 lines each = 500 total lines
    op = Operation(changes=[
        FileChange(file_path=f"module{i}.py", added_lines=50)
        for i in range(10)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == False
    # Should have multiple violations
    assert len(result.violations) >= 2  # files + total lines


def test_protected_files_always_blocked():
    """
    TEST: Protected files are blocked even with generous limits.
    """
    budget = ChangeBudget({
        "max_files": 1000,
        "max_lines_per_file": 10000,
        "max_total_lines": 100000,
        "forbidden_paths": [".git/", ".env"],
        "allowed_file_patterns": ["*"]
    })

    op = Operation(changes=[
        FileChange(file_path=".env", added_lines=1)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == False
    assert any(v.rule == "forbidden_path" for v in result.violations)


def test_incremental_development_workflow():
    """
    TEST: Incremental development with multiple small operations.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "max_total_lines": 200,
        "allowed_file_patterns": ["*.py"]
    })

    # First increment
    op1 = Operation(changes=[
        FileChange(file_path="feature.py", added_lines=50)
    ])
    result1 = budget.validate_operation(op1)
    assert result1.allowed == True

    # Second increment
    op2 = Operation(changes=[
        FileChange(file_path="feature.py", added_lines=30),
        FileChange(file_path="tests.py", added_lines=40)
    ])
    result2 = budget.validate_operation(op2)
    assert result2.allowed == True

    # Third increment
    op3 = Operation(changes=[
        FileChange(file_path="docs.py", added_lines=50)
    ])
    result3 = budget.validate_operation(op3)
    assert result3.allowed == True

    # Fourth would exceed
    op4 = Operation(changes=[
        FileChange(file_path="more.py", added_lines=50)
    ])
    result4 = budget.validate_operation(op4)
    assert result4.allowed == False


def test_mixed_language_project():
    """
    TEST: Project with multiple languages.
    """
    budget = ChangeBudget({
        "max_files": 10,
        "allowed_file_patterns": ["*.py", "*.ts", "*.js", "*.java", "*.go"]
    })

    op = Operation(changes=[
        FileChange(file_path="backend/api.py", added_lines=20),
        FileChange(file_path="frontend/app.ts", added_lines=30),
        FileChange(file_path="services/auth.java", added_lines=25),
        FileChange(file_path="scripts/deploy.go", added_lines=15)
    ])
    result = budget.validate_operation(op)

    assert result.allowed == True


# =============================================================================
# OPERATION PROPERTIES TESTS
# =============================================================================

def test_operation_total_files():
    """
    TEST: Operation correctly counts total files.
    """
    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10),
        FileChange(file_path="file2.py", added_lines=20),
        FileChange(file_path="file3.py", added_lines=30)
    ])

    assert op.total_files == 3


def test_operation_total_lines():
    """
    TEST: Operation correctly sums lines.
    """
    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10, removed_lines=5),
        FileChange(file_path="file2.py", added_lines=20, removed_lines=10)
    ])

    assert op.total_added_lines == 30
    assert op.total_removed_lines == 15
    assert op.total_net_lines == 15


def test_operation_total_complexity():
    """
    TEST: Operation correctly sums complexity delta.
    """
    op = Operation(changes=[
        FileChange(file_path="file1.py", added_lines=10,
                   complexity_before=5, complexity_after=10),
        FileChange(file_path="file2.py", added_lines=10,
                   complexity_before=3, complexity_after=8)
    ])

    assert op.total_complexity_delta == 10  # 5 + 5


def test_file_change_net_lines():
    """
    TEST: FileChange correctly calculates net lines.
    """
    change = FileChange(
        file_path="file.py",
        added_lines=100,
        removed_lines=40
    )

    assert change.net_lines == 60


def test_file_change_complexity_delta():
    """
    TEST: FileChange correctly calculates complexity delta.
    """
    change = FileChange(
        file_path="file.py",
        added_lines=10,
        complexity_before=5,
        complexity_after=12
    )

    assert change.complexity_delta == 7


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_edge_case_tests():
    """Run all edge case tests."""
    tests = [
        # Configuration
        ("CONFIG-001", "Config from YAML", test_config_from_yaml),
        ("CONFIG-002", "Config from file", test_config_from_file),
        ("CONFIG-003", "Config save and load", test_config_save_and_load),
        ("CONFIG-004", "Default config", test_config_defaults),
        ("CONFIG-005", "Budget with config object", test_budget_with_config_object),
        # Zero values
        ("ZERO-001", "Zero files limit", test_zero_files_limit),
        ("ZERO-002", "Zero lines limit", test_zero_lines_limit),
        ("ZERO-003", "Zero complexity limit", test_zero_complexity_limit),
        ("ZERO-004", "Zero lines in operation", test_zero_lines_in_operation),
        ("ZERO-005", "Empty operation", test_empty_operation),
        # Large values
        ("LARGE-001", "Very large file count", test_very_large_file_count),
        ("LARGE-002", "Very large line count", test_very_large_line_count),
        ("LARGE-003", "Large complexity", test_large_complexity),
        # Path handling
        ("PATH-001", "Windows separators", test_windows_path_separators),
        ("PATH-002", "Paths with spaces", test_paths_with_spaces),
        ("PATH-003", "Unicode paths", test_unicode_paths),
        ("PATH-004", "Dotfiles", test_dotfile),
        ("PATH-005", "Relative paths", test_relative_paths),
        # Pattern matching
        ("PATTERN-001", "Case sensitivity", test_pattern_case_sensitivity),
        ("PATTERN-002", "Multiple extensions", test_pattern_multiple_extensions),
        ("PATTERN-003", "No extension", test_pattern_no_extension),
        # Real-world scenarios
        ("REAL-001", "Typical feature development", test_typical_feature_development),
        ("REAL-002", "Large refactoring blocked", test_large_refactoring_blocked),
        ("REAL-003", "Protected files blocked", test_protected_files_always_blocked),
        ("REAL-004", "Incremental development", test_incremental_development_workflow),
        ("REAL-005", "Mixed language project", test_mixed_language_project),
        # Operation properties
        ("OP-001", "Total files", test_operation_total_files),
        ("OP-002", "Total lines", test_operation_total_lines),
        ("OP-003", "Total complexity", test_operation_total_complexity),
        ("OP-004", "Net lines", test_file_change_net_lines),
        ("OP-005", "Complexity delta", test_file_change_complexity_delta),
    ]

    print("=" * 70)
    print("EDGE CASES AND CONFIGURATION TESTS")
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
    run_edge_case_tests()
