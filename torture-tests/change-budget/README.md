# Change Budgeting (Blast Radius Control) Test Suite

Comprehensive test suite for Code Scalpel's **Change Budgeting** feature - limiting the scope of AI agent modifications with hard caps on files, lines, and complexity to control "blast radius."

## Overview

The Change Budget feature provides:
- **Maximum files per operation** - Limit how many files can be modified
- **Maximum lines per file** - Limit changes to individual files
- **Maximum total lines** - Aggregate limit across all files
- **Maximum complexity increase** - Control cyclomatic complexity growth
- **Allowed file patterns** - Glob-based file type restrictions
- **Forbidden paths** - Protect security-critical areas
- **Cumulative tracking** - Track changes across multiple operations
- **Budget refresh** - Daily reset for cumulative tracking

## Test Files

| File | Purpose | Test Count |
|------|---------|------------|
| `change_budget_framework.py` | Core ChangeBudget implementation | - |
| `test_constraint_checks.py` | All constraint types with severity ordering | 38 |
| `test_actionable_errors.py` | Error responses and suggestions | 26 |
| `test_cumulative_tracking.py` | Cumulative budget tracking and refresh | 23 |
| `test_edge_cases.py` | Configuration, edge cases, real-world scenarios | 30 |

**Total: 117 test cases**

## Constraint Check Order (by Severity)

| Order | Constraint | Severity | Example Error |
|-------|------------|----------|---------------|
| 1 | Forbidden paths | CRITICAL | "Cannot modify .git/" |
| 2 | File patterns | HIGH | "File type not allowed: config.json" |
| 3 | Max files | HIGH | "5 files exceeds limit of 3" |
| 4 | Max lines/file | MEDIUM | "150 lines in users.py exceeds 100" |
| 5 | Max total lines | HIGH | "400 total lines exceeds 300" |
| 6 | Complexity delta | MEDIUM | "Complexity +15 exceeds +10 limit" |

## Actionable Error Response

```json
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
```

## Configuration File

`.code-scalpel/budget.yaml`:

```yaml
version: "1.0"
limits:
  max_files: 5
  max_lines_per_file: 100
  max_total_lines: 300
  max_complexity_increase: 10

files:
  allowed_patterns: ["*.py", "*.ts", "*.js", "*.java"]
  forbidden_paths: [".git/", "node_modules/", ".code-scalpel/"]

refresh:
  interval_hours: 24  # Budget resets daily
  cumulative: true    # Track cumulative changes
```

## Running Tests

```bash
cd torture-tests/change-budget

# Run individual test files
python test_constraint_checks.py
python test_actionable_errors.py
python test_cumulative_tracking.py
python test_edge_cases.py

# Run all tests
for f in test_*.py; do python "$f"; done
```

### Expected Output

```
======================================================================
CONSTRAINT CHECK TESTS
======================================================================

✓ PASS: [FORBID-001] Git directory blocked
✓ PASS: [FORBID-002] Node modules blocked
✓ PASS: [PATTERN-001] Python files allowed
...

Results: 38 passed, 0 failed
======================================================================
```

## Usage Example

```python
from change_budget_framework import ChangeBudget, Operation, FileChange

# Initialize budget
budget = ChangeBudget({
    "max_files": 5,
    "max_lines_per_file": 100,
    "max_total_lines": 300,
    "max_complexity_increase": 10,
    "allowed_file_patterns": ["*.py", "*.ts", "*.java"],
    "forbidden_paths": [".git/", "node_modules/", ".code-scalpel/"]
})

# Create an operation
operation = Operation(
    changes=[
        FileChange(file_path="src/api/users.py", added_lines=50, removed_lines=10),
        FileChange(file_path="src/api/auth.py", added_lines=30, removed_lines=5),
    ]
)

# Validate
decision = budget.validate_operation(operation)

if decision.allowed:
    print("✓ Operation allowed")
    print(f"  Files: {decision.metadata['files_affected']}")
    print(f"  Lines: +{decision.metadata['lines_added']} -{decision.metadata['lines_removed']}")
else:
    print("✗ Operation blocked")
    for v in decision.violations:
        print(f"  [{v.severity.value}] {v.message}")
    for s in decision.suggestions:
        print(f"  Suggestion: {s}")
```

## Cumulative Tracking

```python
# Track changes across multiple operations
budget = ChangeBudget({"max_files": 5, "max_total_lines": 200})

# First operation (uses 2 files, 80 lines)
op1 = Operation(changes=[
    FileChange(file_path="file1.py", added_lines=40),
    FileChange(file_path="file2.py", added_lines=40)
])
budget.validate_operation(op1)

# Check remaining budget
remaining = budget.get_remaining_budget()
print(f"Remaining files: {remaining['files']}")  # 3
print(f"Remaining lines: {remaining['lines']}")  # 120

# Get usage stats
stats = budget.get_usage_stats()
print(f"Files used: {stats['files_used']}/{stats['files_limit']}")
print(f"Lines used: {stats['lines_used']}/{stats['lines_limit']}")

# Manual refresh
budget.refresh()  # Resets all cumulative counters
```

## Test Categories

### Constraint Check Tests (38)
- Forbidden paths (CRITICAL severity)
- File patterns (HIGH severity)
- Max files limit (HIGH severity)
- Max lines per file (MEDIUM severity)
- Max total lines (HIGH severity)
- Complexity delta (MEDIUM severity)
- Constraint ordering

### Actionable Error Tests (26)
- Response format (allowed/denied)
- Violation details (rule, severity, message, limit, actual)
- Suggestions per violation type
- Batch splitting calculations
- Multiple violations handling

### Cumulative Tracking Tests (23)
- Cumulative file counting
- Cumulative line counting
- Cumulative complexity tracking
- Budget refresh mechanism
- Non-cumulative mode
- Remaining budget calculations
- Usage statistics
- Failed operations don't count

### Edge Case Tests (30)
- Configuration loading (YAML, file, defaults)
- Zero value limits
- Large value handling
- Path handling (Windows, spaces, Unicode)
- Pattern matching edge cases
- Real-world scenarios

## Severity Levels

| Level | Impact | Example Constraints |
|-------|--------|---------------------|
| CRITICAL | Operation must be blocked | Forbidden paths (.git/, secrets) |
| HIGH | Significant limit exceeded | Max files, max total lines, file patterns |
| MEDIUM | Minor limit exceeded | Max lines per file, complexity |
| LOW | Warning only | (reserved for future use) |

## Best Practices

1. **Set appropriate limits** - Balance productivity with safety
2. **Use cumulative tracking** - Prevent gradual scope creep
3. **Protect critical paths** - Always include `.git/`, credentials, configs
4. **Review suggestions** - They provide actionable remediation steps
5. **Monitor usage stats** - Track budget consumption over time
