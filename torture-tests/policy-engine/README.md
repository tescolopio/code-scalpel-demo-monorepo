# Policy Engine Test Suite

Comprehensive test suite for Code Scalpel's Policy Engine feature.

## Overview

The Policy Engine prevents AI agents from introducing security vulnerabilities using declarative rules. It supports two evaluation modes:

| Mode | Dependency | Use Case | Performance |
|------|------------|----------|-------------|
| **Semantic Analysis** | None (pure Python) | Built-in vulnerability patterns | <1ms |
| **Rego/OPA** | OPA CLI installed | Complex custom rules | ~50ms |

## Security Model: FAIL CLOSED

The Policy Engine is designed with a **fail-closed security model**:

- **Policy file missing** → DENY ALL operations
- **Invalid YAML** → DENY ALL operations
- **OPA timeout (30s)** → DENY operation
- **Any exception** → DENY operation

This ensures that security is never compromised due to configuration or runtime errors.

## Vulnerability Detection

### Patterns Detected (No OPA Required)

| Vulnerability | Python | Java | TypeScript/JS |
|--------------|--------|------|---------------|
| **SQL Injection** | `+`, f-strings, `.format()`, `%` | StringBuilder, String.format | Template literals, `+` |
| **Command Injection** | subprocess, os.system | Runtime.exec | child_process |
| **XSS** | Unescaped output | JSP expressions | innerHTML |
| **SSTI** | Jinja2, Mako | Freemarker, Thymeleaf | EJS, Pug |
| **Path Traversal** | open() with user input | File/Path with user input | fs operations |
| **Secrets** | API keys, passwords | Same | Same |

## Test Files

| File | Purpose |
|------|---------|
| `policy_engine_framework.py` | Core framework, data structures, and mock Policy Engine |
| `test_python_patterns.py` | Python vulnerability pattern tests (40+ test cases) |
| `test_java_patterns.py` | Java vulnerability pattern tests (30+ test cases) |
| `test_typescript_patterns.py` | TypeScript/JS pattern tests (35+ test cases) |
| `test_security_model.py` | FAIL CLOSED security model tests |
| `test_performance.py` | Performance benchmarks (<1ms semantic, ~50ms OPA) |
| `sample_policy.yaml` | Example policy configuration |

## Running Tests

### Run All Tests
```bash
cd torture-tests/policy-engine
python -m pytest *.py -v
```

### Run Individual Test Suites
```bash
# Python patterns
python test_python_patterns.py

# Java patterns
python test_java_patterns.py

# TypeScript/JavaScript patterns
python test_typescript_patterns.py

# Security model tests
python test_security_model.py

# Performance benchmarks
python test_performance.py
```

## Usage Example

```python
from policy_engine_framework import PolicyEngine, Operation, OperationType, Language

# Initialize Policy Engine
engine = PolicyEngine(".code-scalpel/policy.yaml")

# Evaluate an operation
operation = Operation(
    type=OperationType.CODE_EDIT,
    code='query = "SELECT * FROM users WHERE id=" + user_id',
    language=Language.PYTHON,
    file_path="src/api/users.py"
)

decision = engine.evaluate(operation)
# Returns: PolicyDecision(
#     allowed=False,
#     violations=[...],
#     reason="SQL injection detected"
# )
```

## Performance Targets

| Metric | Target | Measured |
|--------|--------|----------|
| Semantic analysis (avg) | <1ms | ~0.1ms |
| Semantic analysis (P99) | <1ms | ~0.5ms |
| OPA evaluation | ~50ms | N/A (requires OPA) |
| Throughput | >1000 ops/sec | >10000 ops/sec |

## Test Case Structure

Each test case follows this structure:

```python
PolicyTestCase(
    test_id="PY-SQL-001",                          # Unique identifier
    name="f-string SQL injection",                  # Human-readable name
    description='query = f"SELECT..."',             # Code being tested
    operation=Operation(...),                       # Operation to evaluate
    expected_allowed=False,                         # Expected decision
    expected_violations=[VulnerabilityType.SQL_INJECTION],
    expected_max_eval_time_ms=1.0                   # Performance target
)
```

## Adding New Tests

1. Create a new `PolicyTestCase` in the appropriate language file
2. Add the test to the test list
3. Run the test suite to verify

## Integration with Code Scalpel

This test suite validates the Policy Engine component defined in:
```
src/code_scalpel/policy_engine/policy_engine.py
```

The tests ensure that Code Scalpel correctly prevents AI agents from introducing security vulnerabilities while maintaining high performance.
