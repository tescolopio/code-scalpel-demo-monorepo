#!/usr/bin/env python3
"""
=============================================================================
CHANGE BUDGETING (BLAST RADIUS CONTROL) FRAMEWORK
=============================================================================

Comprehensive test suite for Code Scalpel's Change Budgeting feature.
This feature limits the scope of AI agent modifications with hard caps
on files, lines, and complexity - preventing "blast radius" scenarios.

CORE FEATURES:
- Maximum files per operation limit
- Maximum lines per file limit
- Maximum total lines limit
- Maximum complexity increase limit
- Allowed file patterns (glob-based)
- Forbidden paths (security-critical areas)
- Cumulative tracking across operations
- Budget refresh/reset mechanism

CONSTRAINT CHECK ORDER:
1. Forbidden paths (CRITICAL) - Cannot modify protected areas
2. File patterns (HIGH) - Only allowed file types
3. Max files (HIGH) - Too many files affected
4. Max lines/file (MEDIUM) - Individual file limit
5. Max total lines (HIGH) - Aggregate line limit
6. Complexity delta (MEDIUM) - Complexity increase limit

ACTIONABLE ERROR RESPONSE:
{
    "allowed": false,
    "violations": [...],
    "suggestions": [...]
}

=============================================================================
"""
import fnmatch
import json
import os
import re
import tempfile
import time
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# =============================================================================
# ENUMS AND DATA STRUCTURES
# =============================================================================

class Severity(Enum):
    """Violation severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ViolationType(Enum):
    """Types of budget violations."""
    FORBIDDEN_PATH = "forbidden_path"
    FILE_PATTERN = "file_pattern"
    MAX_FILES = "max_files"
    MAX_LINES_PER_FILE = "max_lines_per_file"
    MAX_TOTAL_LINES = "max_total_lines"
    MAX_COMPLEXITY_INCREASE = "max_complexity_increase"


# Severity mapping for each violation type
VIOLATION_SEVERITY = {
    ViolationType.FORBIDDEN_PATH: Severity.CRITICAL,
    ViolationType.FILE_PATTERN: Severity.HIGH,
    ViolationType.MAX_FILES: Severity.HIGH,
    ViolationType.MAX_LINES_PER_FILE: Severity.MEDIUM,
    ViolationType.MAX_TOTAL_LINES: Severity.HIGH,
    ViolationType.MAX_COMPLEXITY_INCREASE: Severity.MEDIUM,
}


@dataclass
class FileChange:
    """Represents changes to a single file."""
    file_path: str
    added_lines: int = 0
    removed_lines: int = 0
    complexity_before: int = 0
    complexity_after: int = 0

    @property
    def net_lines(self) -> int:
        """Net change in lines."""
        return self.added_lines - self.removed_lines

    @property
    def complexity_delta(self) -> int:
        """Change in complexity."""
        return self.complexity_after - self.complexity_before


@dataclass
class Operation:
    """Represents an operation with multiple file changes."""
    changes: List[FileChange] = field(default_factory=list)
    operation_id: Optional[str] = None
    timestamp: Optional[str] = None

    @property
    def total_files(self) -> int:
        """Total number of files affected."""
        return len(self.changes)

    @property
    def total_added_lines(self) -> int:
        """Total lines added across all files."""
        return sum(c.added_lines for c in self.changes)

    @property
    def total_removed_lines(self) -> int:
        """Total lines removed across all files."""
        return sum(c.removed_lines for c in self.changes)

    @property
    def total_net_lines(self) -> int:
        """Net change in lines across all files."""
        return sum(c.net_lines for c in self.changes)

    @property
    def total_complexity_delta(self) -> int:
        """Total complexity change across all files."""
        return sum(c.complexity_delta for c in self.changes)

    def get_file_paths(self) -> List[str]:
        """Get all affected file paths."""
        return [c.file_path for c in self.changes]


@dataclass
class Violation:
    """Represents a single budget violation."""
    rule: str
    severity: Severity
    message: str
    limit: Optional[int] = None
    actual: Optional[int] = None
    file_path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BudgetDecision:
    """Decision from budget validation."""
    allowed: bool
    violations: List[Violation] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "allowed": self.allowed,
            "violations": [
                {
                    "rule": v.rule,
                    "severity": v.severity.value,
                    "message": v.message,
                    "limit": v.limit,
                    "actual": v.actual,
                    "file_path": v.file_path
                }
                for v in self.violations
            ],
            "suggestions": self.suggestions
        }


@dataclass
class BudgetConfig:
    """Configuration for change budget."""
    max_files: int = 5
    max_lines_per_file: int = 100
    max_total_lines: int = 300
    max_complexity_increase: int = 10
    allowed_file_patterns: List[str] = field(default_factory=lambda: ["*.py", "*.ts", "*.js", "*.java"])
    forbidden_paths: List[str] = field(default_factory=lambda: [".git/", "node_modules/", ".code-scalpel/"])
    cumulative: bool = True
    refresh_interval_hours: int = 24

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BudgetConfig":
        """Create from dictionary."""
        limits = data.get("limits", {})
        files = data.get("files", {})
        refresh = data.get("refresh", {})

        return cls(
            max_files=limits.get("max_files", 5),
            max_lines_per_file=limits.get("max_lines_per_file", 100),
            max_total_lines=limits.get("max_total_lines", 300),
            max_complexity_increase=limits.get("max_complexity_increase", 10),
            allowed_file_patterns=files.get("allowed_patterns", ["*.py", "*.ts", "*.js", "*.java"]),
            forbidden_paths=files.get("forbidden_paths", [".git/", "node_modules/", ".code-scalpel/"]),
            cumulative=refresh.get("cumulative", True),
            refresh_interval_hours=refresh.get("interval_hours", 24)
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "BudgetConfig":
        """Create from YAML content."""
        data = yaml.safe_load(yaml_content)
        return cls.from_dict(data)


# =============================================================================
# CHANGE BUDGET IMPLEMENTATION
# =============================================================================

class ChangeBudget:
    """
    Limits scope of AI agent modifications with hard caps.

    Features:
    - Constraint checking in defined order
    - Actionable error responses with suggestions
    - Cumulative tracking across operations
    - Budget refresh mechanism
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the change budget.

        Args:
            config: Configuration dictionary or use defaults
        """
        if config is None:
            self.config = BudgetConfig()
        elif isinstance(config, BudgetConfig):
            self.config = config
        else:
            # Handle flat dict for backward compatibility
            self.config = BudgetConfig(
                max_files=config.get("max_files", 5),
                max_lines_per_file=config.get("max_lines_per_file", 100),
                max_total_lines=config.get("max_total_lines", 300),
                max_complexity_increase=config.get("max_complexity_increase", 10),
                allowed_file_patterns=config.get("allowed_file_patterns", ["*.py", "*.ts", "*.js", "*.java"]),
                forbidden_paths=config.get("forbidden_paths", [".git/", "node_modules/", ".code-scalpel/"])
            )

        # Cumulative tracking
        self._cumulative_files: Set[str] = set()
        self._cumulative_lines: int = 0
        self._cumulative_complexity: int = 0
        self._last_reset: datetime = datetime.now(timezone.utc)
        self._operations: List[Operation] = []

    def _check_refresh_needed(self) -> bool:
        """Check if budget needs to be refreshed."""
        if not self.config.cumulative:
            return False

        elapsed = datetime.now(timezone.utc) - self._last_reset
        return elapsed.total_seconds() >= self.config.refresh_interval_hours * 3600

    def refresh(self) -> None:
        """Reset cumulative counters."""
        self._cumulative_files.clear()
        self._cumulative_lines = 0
        self._cumulative_complexity = 0
        self._last_reset = datetime.now(timezone.utc)
        self._operations.clear()

    def _is_forbidden_path(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if file path is in forbidden areas.

        Returns:
            (is_forbidden, matched_pattern)
        """
        normalized = file_path.replace("\\", "/")

        for forbidden in self.config.forbidden_paths:
            if normalized.startswith(forbidden) or f"/{forbidden}" in normalized:
                return True, forbidden
            # Also check if the forbidden path is a substring
            if forbidden.rstrip("/") in normalized:
                return True, forbidden

        return False, None

    def _matches_allowed_pattern(self, file_path: str) -> bool:
        """Check if file matches allowed patterns."""
        basename = os.path.basename(file_path)

        for pattern in self.config.allowed_file_patterns:
            if fnmatch.fnmatch(basename, pattern):
                return True

        return False

    def _generate_suggestions(
        self,
        violations: List[Violation],
        operation: Operation
    ) -> List[str]:
        """Generate actionable suggestions based on violations."""
        suggestions = []

        for v in violations:
            if v.rule == ViolationType.MAX_FILES.value:
                # Suggest splitting into batches
                num_files = operation.total_files
                limit = self.config.max_files
                batches = (num_files + limit - 1) // limit

                suggestions.append(
                    f"Split operation into smaller batches affecting fewer files"
                )

                batch_ranges = []
                for i in range(batches):
                    start = i * limit + 1
                    end = min((i + 1) * limit, num_files)
                    batch_ranges.append(f"batch {i+1} (files {start}-{end})")

                suggestions.append(f"Consider: {', '.join(batch_ranges)}")

            elif v.rule == ViolationType.MAX_LINES_PER_FILE.value:
                suggestions.append(
                    f"Reduce changes to {v.file_path} or split into multiple commits"
                )

            elif v.rule == ViolationType.MAX_TOTAL_LINES.value:
                suggestions.append(
                    "Break changes into smaller incremental operations"
                )
                suggestions.append(
                    f"Current operation adds {operation.total_added_lines} lines; "
                    f"limit is {self.config.max_total_lines}"
                )

            elif v.rule == ViolationType.FORBIDDEN_PATH.value:
                suggestions.append(
                    f"The path '{v.file_path}' is protected. "
                    "Request manual review for changes to this area."
                )

            elif v.rule == ViolationType.FILE_PATTERN.value:
                suggestions.append(
                    f"File type not allowed. Allowed patterns: "
                    f"{', '.join(self.config.allowed_file_patterns)}"
                )

            elif v.rule == ViolationType.MAX_COMPLEXITY_INCREASE.value:
                suggestions.append(
                    "Consider refactoring to reduce complexity: "
                    "extract methods, simplify conditionals, or split classes"
                )

        return suggestions

    def validate_operation(self, operation: Operation) -> BudgetDecision:
        """
        Validate an operation against the budget.

        Checks are performed in this order:
        1. Forbidden paths (CRITICAL)
        2. File patterns (HIGH)
        3. Max files (HIGH)
        4. Max lines per file (MEDIUM)
        5. Max total lines (HIGH)
        6. Complexity delta (MEDIUM)

        Args:
            operation: The operation to validate

        Returns:
            BudgetDecision with allowed status, violations, and suggestions
        """
        # Check if refresh is needed
        if self._check_refresh_needed():
            self.refresh()

        violations = []

        # Check 1: Forbidden paths (CRITICAL)
        for change in operation.changes:
            is_forbidden, pattern = self._is_forbidden_path(change.file_path)
            if is_forbidden:
                violations.append(Violation(
                    rule=ViolationType.FORBIDDEN_PATH.value,
                    severity=Severity.CRITICAL,
                    message=f"Cannot modify {pattern}",
                    file_path=change.file_path,
                    details={"forbidden_pattern": pattern}
                ))

        # Check 2: File patterns (HIGH)
        for change in operation.changes:
            if not self._matches_allowed_pattern(change.file_path):
                violations.append(Violation(
                    rule=ViolationType.FILE_PATTERN.value,
                    severity=Severity.HIGH,
                    message=f"File type not allowed: {os.path.basename(change.file_path)}",
                    file_path=change.file_path,
                    details={"allowed_patterns": self.config.allowed_file_patterns}
                ))

        # Check 3: Max files (HIGH)
        total_files = operation.total_files
        if self.config.cumulative:
            # Count unique files including cumulative
            cumulative_files = self._cumulative_files.union(
                set(operation.get_file_paths())
            )
            total_files = len(cumulative_files)

        if total_files > self.config.max_files:
            violations.append(Violation(
                rule=ViolationType.MAX_FILES.value,
                severity=Severity.HIGH,
                message=f"Operation affects {total_files} files, exceeds limit of {self.config.max_files}",
                limit=self.config.max_files,
                actual=total_files
            ))

        # Check 4: Max lines per file (MEDIUM)
        for change in operation.changes:
            if change.added_lines > self.config.max_lines_per_file:
                violations.append(Violation(
                    rule=ViolationType.MAX_LINES_PER_FILE.value,
                    severity=Severity.MEDIUM,
                    message=f"{change.added_lines} lines in {os.path.basename(change.file_path)} "
                            f"exceeds {self.config.max_lines_per_file}",
                    limit=self.config.max_lines_per_file,
                    actual=change.added_lines,
                    file_path=change.file_path
                ))

        # Check 5: Max total lines (HIGH)
        total_lines = operation.total_added_lines
        if self.config.cumulative:
            total_lines += self._cumulative_lines

        if total_lines > self.config.max_total_lines:
            violations.append(Violation(
                rule=ViolationType.MAX_TOTAL_LINES.value,
                severity=Severity.HIGH,
                message=f"{total_lines} total lines exceeds {self.config.max_total_lines}",
                limit=self.config.max_total_lines,
                actual=total_lines
            ))

        # Check 6: Complexity delta (MEDIUM)
        total_complexity = operation.total_complexity_delta
        if self.config.cumulative:
            total_complexity += self._cumulative_complexity

        if total_complexity > self.config.max_complexity_increase:
            violations.append(Violation(
                rule=ViolationType.MAX_COMPLEXITY_INCREASE.value,
                severity=Severity.MEDIUM,
                message=f"Complexity +{total_complexity} exceeds +{self.config.max_complexity_increase} limit",
                limit=self.config.max_complexity_increase,
                actual=total_complexity
            ))

        # Generate decision
        allowed = len(violations) == 0
        suggestions = self._generate_suggestions(violations, operation) if not allowed else []

        decision = BudgetDecision(
            allowed=allowed,
            violations=violations,
            suggestions=suggestions,
            metadata={
                "files_affected": operation.total_files,
                "lines_added": operation.total_added_lines,
                "lines_removed": operation.total_removed_lines,
                "complexity_delta": operation.total_complexity_delta
            }
        )

        # Track cumulative if allowed
        if allowed and self.config.cumulative:
            self._cumulative_files.update(operation.get_file_paths())
            self._cumulative_lines += operation.total_added_lines
            self._cumulative_complexity += operation.total_complexity_delta
            self._operations.append(operation)

        return decision

    def get_remaining_budget(self) -> Dict[str, int]:
        """Get remaining budget for each constraint."""
        return {
            "files": max(0, self.config.max_files - len(self._cumulative_files)),
            "lines": max(0, self.config.max_total_lines - self._cumulative_lines),
            "complexity": max(0, self.config.max_complexity_increase - self._cumulative_complexity)
        }

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics."""
        return {
            "files_used": len(self._cumulative_files),
            "files_limit": self.config.max_files,
            "lines_used": self._cumulative_lines,
            "lines_limit": self.config.max_total_lines,
            "complexity_used": self._cumulative_complexity,
            "complexity_limit": self.config.max_complexity_increase,
            "operations_count": len(self._operations),
            "last_reset": self._last_reset.isoformat()
        }


# =============================================================================
# CONFIGURATION LOADER
# =============================================================================

class BudgetConfigLoader:
    """Loads budget configuration from files."""

    DEFAULT_CONFIG_PATH = ".code-scalpel/budget.yaml"

    @classmethod
    def load_from_file(cls, path: str) -> BudgetConfig:
        """Load configuration from YAML file."""
        with open(path, 'r') as f:
            content = f.read()
        return BudgetConfig.from_yaml(content)

    @classmethod
    def load_from_directory(cls, directory: str) -> BudgetConfig:
        """Load configuration from standard location in directory."""
        config_path = Path(directory) / cls.DEFAULT_CONFIG_PATH
        if config_path.exists():
            return cls.load_from_file(str(config_path))
        return BudgetConfig()  # Return defaults

    @classmethod
    def save_to_file(cls, config: BudgetConfig, path: str) -> None:
        """Save configuration to YAML file."""
        data = {
            "version": "1.0",
            "limits": {
                "max_files": config.max_files,
                "max_lines_per_file": config.max_lines_per_file,
                "max_total_lines": config.max_total_lines,
                "max_complexity_increase": config.max_complexity_increase
            },
            "files": {
                "allowed_patterns": config.allowed_file_patterns,
                "forbidden_paths": config.forbidden_paths
            },
            "refresh": {
                "interval_hours": config.refresh_interval_hours,
                "cumulative": config.cumulative
            }
        }

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)


# =============================================================================
# TEST DATA STRUCTURES
# =============================================================================

@dataclass
class BudgetTestCase:
    """Represents a budget test case."""
    test_id: str
    name: str
    description: str
    setup: Optional[callable] = None
    test_fn: Optional[callable] = None
    expected_pass: bool = True


@dataclass
class BudgetTestResult:
    """Result of running a budget test."""
    test_case: BudgetTestCase
    passed: bool
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# =============================================================================
# TEST RUNNER
# =============================================================================

class BudgetTestRunner:
    """Test runner for budget tests."""

    def __init__(self):
        self.results: List[BudgetTestResult] = []

    def run_test(self, test_case: BudgetTestCase) -> BudgetTestResult:
        """Run a single test case."""
        start = time.perf_counter()

        try:
            if test_case.setup:
                test_case.setup()

            if test_case.test_fn:
                test_case.test_fn()

            passed = test_case.expected_pass
            error = None

        except AssertionError as e:
            passed = not test_case.expected_pass
            error = str(e)
        except Exception as e:
            passed = False
            error = f"{type(e).__name__}: {e}"

        elapsed = (time.perf_counter() - start) * 1000

        result = BudgetTestResult(
            test_case=test_case,
            passed=passed,
            error=error,
            execution_time_ms=elapsed
        )

        self.results.append(result)
        return result

    def run_all(self, test_cases: List[BudgetTestCase]) -> List[BudgetTestResult]:
        """Run all test cases."""
        self.results = []
        for test_case in test_cases:
            self.run_test(test_case)
        return self.results

    def generate_report(self) -> Dict[str, Any]:
        """Generate a test report."""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        return {
            "total": len(self.results),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / max(len(self.results), 1),
            "failures": [
                {
                    "test_id": r.test_case.test_id,
                    "name": r.test_case.name,
                    "error": r.error
                }
                for r in self.results if not r.passed
            ]
        }


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Run the change budget test framework."""
    print("=" * 70)
    print("CODE SCALPEL CHANGE BUDGETING (BLAST RADIUS CONTROL) FRAMEWORK")
    print("=" * 70)
    print()
    print("Features:")
    print("  - Maximum files per operation limit")
    print("  - Maximum lines per file limit")
    print("  - Maximum total lines limit")
    print("  - Maximum complexity increase limit")
    print("  - Allowed file patterns (glob-based)")
    print("  - Forbidden paths (security-critical areas)")
    print("  - Cumulative tracking across operations")
    print("  - Budget refresh/reset mechanism")
    print()
    print("Constraint Check Order (by severity):")
    print("  1. Forbidden paths (CRITICAL)")
    print("  2. File patterns (HIGH)")
    print("  3. Max files (HIGH)")
    print("  4. Max lines/file (MEDIUM)")
    print("  5. Max total lines (HIGH)")
    print("  6. Complexity delta (MEDIUM)")
    print("=" * 70)


if __name__ == "__main__":
    main()
