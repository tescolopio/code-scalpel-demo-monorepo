#!/usr/bin/env python3
"""
=============================================================================
POLICY ENGINE TEST FRAMEWORK
=============================================================================

Comprehensive test suite for Code Scalpel's Policy Engine feature.
Tests both evaluation modes:
1. Rego/OPA Mode: Complex custom rules (requires OPA CLI)
2. Semantic Analysis Mode: Built-in vulnerability patterns (pure Python)

COVERAGE TARGETS:
- SQL Injection: Python (+, f-strings, .format(), %), Java (StringBuilder), JS (template literals)
- Command Injection: Python (subprocess, os.system), Java (Runtime.exec), JS (child_process)
- XSS: Python (unescaped output), Java (JSP expressions), JS (innerHTML)
- SSTI: Python (Jinja2, Mako), Java (Freemarker, Thymeleaf), JS (EJS, Pug)
- Path Traversal: Python (open() with user input), Java (File/Path), JS (fs operations)
- Secrets: API keys, passwords, tokens across all languages

SECURITY MODEL: FAIL CLOSED
- Policy file missing → DENY ALL
- Invalid YAML → DENY ALL
- OPA timeout (30s) → DENY operation
- Any exception → DENY operation

PERFORMANCE TARGETS:
- Semantic analysis: <1ms
- OPA evaluation: ~50ms per policy

=============================================================================
"""
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import yaml


# =============================================================================
# ENUMS AND DATA STRUCTURES
# =============================================================================

class OperationType(Enum):
    """Types of operations the Policy Engine evaluates."""
    CODE_EDIT = "code_edit"
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    DEPENDENCY_ADD = "dependency_add"
    CONFIG_CHANGE = "config_change"
    SHELL_COMMAND = "shell_command"


class Language(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVA = "java"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"


class VulnerabilityType(Enum):
    """Vulnerability types detected by semantic analysis."""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    SECRETS_EXPOSURE = "secrets_exposure"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    XXE = "xxe"
    SSRF = "ssrf"
    LDAP_INJECTION = "ldap_injection"


class EvaluationMode(Enum):
    """Policy Engine evaluation modes."""
    SEMANTIC = "semantic"  # Pure Python, <1ms
    OPA = "opa"            # Rego rules, ~50ms


@dataclass
class Operation:
    """Represents an operation to be evaluated by the Policy Engine."""
    type: OperationType
    code: str
    language: Language
    file_path: str
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyViolation:
    """Represents a detected policy violation."""
    vulnerability_type: VulnerabilityType
    severity: str  # "critical", "high", "medium", "low"
    line_number: int
    code_snippet: str
    description: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    violations: List[PolicyViolation] = field(default_factory=list)
    reason: str = ""
    evaluation_time_ms: float = 0.0
    evaluation_mode: EvaluationMode = EvaluationMode.SEMANTIC


@dataclass
class PolicyTestCase:
    """A single Policy Engine test case."""
    test_id: str
    name: str
    description: str
    operation: Operation
    expected_allowed: bool
    expected_violations: List[VulnerabilityType]
    expected_max_eval_time_ms: float = 100.0


@dataclass
class PolicyTestResult:
    """Result of running a Policy Engine test."""
    test_case: PolicyTestCase
    actual_decision: PolicyDecision
    passed: bool
    failure_reason: str = ""


# =============================================================================
# MOCK POLICY ENGINE (for testing patterns)
# =============================================================================

class SemanticAnalyzer:
    """
    Pure Python semantic analyzer for vulnerability detection.
    Performance target: <1ms per analysis.
    """

    # SQL Injection patterns by language
    SQL_PATTERNS = {
        Language.PYTHON: [
            (r'f".*SELECT.*{.*}"', "f-string SQL"),
            (r"f'.*SELECT.*{.*}'", "f-string SQL"),
            (r'".*SELECT.*"\s*%', "%-format SQL"),
            (r"'.*SELECT.*'\s*%", "%-format SQL"),
            (r'".*SELECT.*"\.format\(', ".format() SQL"),
            (r"'.*SELECT.*'\.format\(", ".format() SQL"),
            (r'".*SELECT.*"\s*\+', "concatenation SQL"),
            (r"'.*SELECT.*'\s*\+", "concatenation SQL"),
            (r'execute\([^)]*\+', "execute with concat"),
            (r'cursor\.execute\(f', "cursor f-string"),
        ],
        Language.JAVA: [
            (r'StringBuilder.*SELECT', "StringBuilder SQL"),
            (r'String\.format\(.*SELECT', "String.format SQL"),
            (r'".*SELECT.*"\s*\+', "concatenation SQL"),
            (r'createStatement\(\)\.execute', "createStatement"),
            (r'executeQuery\([^)]*\+', "executeQuery concat"),
        ],
        Language.TYPESCRIPT: [
            (r'`.*SELECT.*\${', "template literal SQL"),
            (r'".*SELECT.*"\s*\+', "concatenation SQL"),
            (r"'.*SELECT.*'\s*\+", "concatenation SQL"),
        ],
        Language.JAVASCRIPT: [
            (r'`.*SELECT.*\${', "template literal SQL"),
            (r'".*SELECT.*"\s*\+', "concatenation SQL"),
            (r"'.*SELECT.*'\s*\+", "concatenation SQL"),
        ],
    }

    # Command Injection patterns by language
    COMMAND_PATTERNS = {
        Language.PYTHON: [
            (r'subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True', "subprocess shell=True"),
            (r'subprocess\.(run|call|check_output)\(f', "subprocess f-string"),
            (r'os\.system\(', "os.system"),
            (r'os\.popen\(', "os.popen"),
            (r'eval\(', "eval"),
            (r'exec\(', "exec"),
        ],
        Language.JAVA: [
            (r'Runtime\.getRuntime\(\)\.exec\(', "Runtime.exec"),
            (r'ProcessBuilder\([^)]*\+', "ProcessBuilder concat"),
            (r'new\s+ProcessBuilder\(.*user', "ProcessBuilder user input"),
        ],
        Language.TYPESCRIPT: [
            (r'exec\(.*\+', "exec concat"),
            (r'exec\(`', "exec template"),
            (r'execSync\(', "execSync"),
            (r'spawn\([^)]*shell:\s*true', "spawn shell"),
        ],
        Language.JAVASCRIPT: [
            (r'exec\(.*\+', "exec concat"),
            (r'exec\(`', "exec template"),
            (r'execSync\(', "execSync"),
            (r'spawn\([^)]*shell:\s*true', "spawn shell"),
            (r'child_process', "child_process import"),
        ],
    }

    # XSS patterns by language
    XSS_PATTERNS = {
        Language.PYTHON: [
            (r'render_template_string\(', "render_template_string"),
            (r'Markup\([^)]*\+', "Markup concat"),
            (r'\.safe\s*=', "mark as safe"),
            (r'\|safe\}', "Jinja safe filter"),
        ],
        Language.JAVA: [
            (r'out\.print\([^)]*\+', "JSP out.print concat"),
            (r'<%=.*request\.getParameter', "JSP parameter"),
            (r'response\.getWriter\(\)\.write\(', "response write"),
        ],
        Language.TYPESCRIPT: [
            (r'innerHTML\s*=', "innerHTML assignment"),
            (r'outerHTML\s*=', "outerHTML assignment"),
            (r'document\.write\(', "document.write"),
            (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
        ],
        Language.JAVASCRIPT: [
            (r'innerHTML\s*=', "innerHTML assignment"),
            (r'outerHTML\s*=', "outerHTML assignment"),
            (r'document\.write\(', "document.write"),
            (r'\.html\([^)]*\+', "jQuery .html() concat"),
        ],
    }

    # SSTI patterns by language
    SSTI_PATTERNS = {
        Language.PYTHON: [
            (r'Template\([^)]*\+', "Jinja2 Template concat"),
            (r'Template\(.*user', "Jinja2 Template user input"),
            (r'render_template_string\(', "render_template_string"),
            (r'MakoTemplate\(', "Mako template"),
            (r'\.from_string\(', "from_string"),
        ],
        Language.JAVA: [
            (r'Freemarker.*Template', "Freemarker template"),
            (r'Thymeleaf.*process', "Thymeleaf process"),
            (r'VelocityEngine', "Velocity engine"),
        ],
        Language.TYPESCRIPT: [
            (r'ejs\.render\([^,]*\+', "EJS render concat"),
            (r'pug\.render\(', "Pug render"),
            (r'nunjucks\.renderString\(', "Nunjucks renderString"),
        ],
        Language.JAVASCRIPT: [
            (r'ejs\.render\([^,]*\+', "EJS render concat"),
            (r'pug\.render\(', "Pug render"),
            (r'nunjucks\.renderString\(', "Nunjucks renderString"),
            (r'handlebars\.compile\(.*user', "Handlebars user input"),
        ],
    }

    # Path Traversal patterns by language
    PATH_TRAVERSAL_PATTERNS = {
        Language.PYTHON: [
            (r'open\([^)]*\+', "open with concat"),
            (r'open\(f', "open with f-string"),
            (r'Path\([^)]*\+', "Path concat"),
            (r'os\.path\.join\([^)]*user', "os.path.join user input"),
            (r'\.read\(\).*user', "file read user input"),
        ],
        Language.JAVA: [
            (r'new\s+File\([^)]*\+', "File concat"),
            (r'new\s+FileInputStream\([^)]*\+', "FileInputStream concat"),
            (r'Files\.read.*\+', "Files.read concat"),
            (r'Paths\.get\([^)]*\+', "Paths.get concat"),
        ],
        Language.TYPESCRIPT: [
            (r'fs\.readFile\([^)]*\+', "fs.readFile concat"),
            (r'fs\.readFileSync\([^)]*\+', "fs.readFileSync concat"),
            (r'path\.join\([^)]*user', "path.join user input"),
            (r'fs\.promises\.readFile', "fs.promises user input"),
        ],
        Language.JAVASCRIPT: [
            (r'fs\.readFile\([^)]*\+', "fs.readFile concat"),
            (r'fs\.readFileSync\([^)]*\+', "fs.readFileSync concat"),
            (r'path\.join\([^)]*user', "path.join user input"),
            (r'require\([^)]*\+', "dynamic require"),
        ],
    }

    # Secrets patterns (language agnostic)
    SECRETS_PATTERNS = [
        (r'api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', "API key"),
        (r'password\s*[=:]\s*["\'][^"\']+["\']', "hardcoded password"),
        (r'secret\s*[=:]\s*["\'][^"\']{10,}["\']', "hardcoded secret"),
        (r'token\s*[=:]\s*["\'][^"\']{20,}["\']', "hardcoded token"),
        (r'aws_access_key_id\s*[=:]\s*["\']AKIA', "AWS access key"),
        (r'private_key\s*[=:]\s*["\']-----BEGIN', "private key"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub token"),
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API key"),
        (r'xox[baprs]-[a-zA-Z0-9-]+', "Slack token"),
    ]

    def analyze(self, operation: Operation) -> List[PolicyViolation]:
        """
        Perform semantic analysis on an operation.
        Returns list of detected violations.
        """
        import re
        violations = []
        code = operation.code
        language = operation.language

        # Check SQL Injection
        if language in self.SQL_PATTERNS:
            for pattern, desc in self.SQL_PATTERNS[language]:
                if re.search(pattern, code, re.IGNORECASE):
                    violations.append(PolicyViolation(
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        severity="critical",
                        line_number=self._find_line_number(code, pattern),
                        code_snippet=self._extract_snippet(code, pattern),
                        description=f"SQL Injection detected: {desc}",
                        cwe_id="CWE-89",
                        owasp_category="A03:2021"
                    ))

        # Check Command Injection
        if language in self.COMMAND_PATTERNS:
            for pattern, desc in self.COMMAND_PATTERNS[language]:
                if re.search(pattern, code, re.IGNORECASE):
                    violations.append(PolicyViolation(
                        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                        severity="critical",
                        line_number=self._find_line_number(code, pattern),
                        code_snippet=self._extract_snippet(code, pattern),
                        description=f"Command Injection detected: {desc}",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021"
                    ))

        # Check XSS
        if language in self.XSS_PATTERNS:
            for pattern, desc in self.XSS_PATTERNS[language]:
                if re.search(pattern, code, re.IGNORECASE):
                    violations.append(PolicyViolation(
                        vulnerability_type=VulnerabilityType.XSS,
                        severity="high",
                        line_number=self._find_line_number(code, pattern),
                        code_snippet=self._extract_snippet(code, pattern),
                        description=f"XSS detected: {desc}",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021"
                    ))

        # Check SSTI
        if language in self.SSTI_PATTERNS:
            for pattern, desc in self.SSTI_PATTERNS[language]:
                if re.search(pattern, code, re.IGNORECASE):
                    violations.append(PolicyViolation(
                        vulnerability_type=VulnerabilityType.SSTI,
                        severity="critical",
                        line_number=self._find_line_number(code, pattern),
                        code_snippet=self._extract_snippet(code, pattern),
                        description=f"SSTI detected: {desc}",
                        cwe_id="CWE-1336",
                        owasp_category="A03:2021"
                    ))

        # Check Path Traversal
        if language in self.PATH_TRAVERSAL_PATTERNS:
            for pattern, desc in self.PATH_TRAVERSAL_PATTERNS[language]:
                if re.search(pattern, code, re.IGNORECASE):
                    violations.append(PolicyViolation(
                        vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                        severity="high",
                        line_number=self._find_line_number(code, pattern),
                        code_snippet=self._extract_snippet(code, pattern),
                        description=f"Path Traversal detected: {desc}",
                        cwe_id="CWE-22",
                        owasp_category="A01:2021"
                    ))

        # Check Secrets (language agnostic)
        for pattern, desc in self.SECRETS_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                violations.append(PolicyViolation(
                    vulnerability_type=VulnerabilityType.SECRETS_EXPOSURE,
                    severity="critical",
                    line_number=self._find_line_number(code, pattern),
                    code_snippet=self._extract_snippet(code, pattern),
                    description=f"Secrets exposure detected: {desc}",
                    cwe_id="CWE-798",
                    owasp_category="A02:2021"
                ))

        return violations

    def _find_line_number(self, code: str, pattern: str) -> int:
        """Find line number of pattern match."""
        import re
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            return code[:match.start()].count('\n') + 1
        return 0

    def _extract_snippet(self, code: str, pattern: str) -> str:
        """Extract code snippet around pattern match."""
        import re
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(code), match.end() + 20)
            return code[start:end].strip()
        return ""


class PolicyEngine:
    """
    Policy Engine that prevents AI agents from introducing security vulnerabilities.

    Two evaluation modes:
    - Semantic Analysis: Pure Python, <1ms (default)
    - OPA/Rego: Complex custom rules, ~50ms (requires OPA CLI)

    Security Model: FAIL CLOSED
    - Policy file missing → DENY ALL
    - Invalid YAML → DENY ALL
    - OPA timeout (30s) → DENY operation
    - Any exception → DENY operation
    """

    DEFAULT_OPA_TIMEOUT = 30  # seconds

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path
        self.policy: Dict[str, Any] = {}
        self.semantic_analyzer = SemanticAnalyzer()
        self._opa_available = self._check_opa_available()
        self._load_policy()

    def _check_opa_available(self) -> bool:
        """Check if OPA CLI is installed."""
        import shutil
        return shutil.which("opa") is not None

    def _load_policy(self) -> None:
        """Load policy from YAML file. FAIL CLOSED on any error."""
        if not self.policy_path:
            return

        try:
            with open(self.policy_path, 'r') as f:
                self.policy = yaml.safe_load(f)
                if self.policy is None:
                    raise ValueError("Empty policy file")
        except FileNotFoundError:
            # FAIL CLOSED: Policy file missing
            self.policy = {"deny_all": True, "reason": "Policy file not found"}
        except yaml.YAMLError as e:
            # FAIL CLOSED: Invalid YAML
            self.policy = {"deny_all": True, "reason": f"Invalid YAML: {e}"}
        except Exception as e:
            # FAIL CLOSED: Any exception
            self.policy = {"deny_all": True, "reason": f"Policy load error: {e}"}

    def evaluate(self, operation: Operation) -> PolicyDecision:
        """
        Evaluate an operation against security policies.

        Returns PolicyDecision with:
        - allowed: bool
        - violations: List[PolicyViolation]
        - reason: str
        - evaluation_time_ms: float
        """
        start_time = time.perf_counter()

        try:
            # FAIL CLOSED: Deny all if policy mandates
            if self.policy.get("deny_all", False):
                return PolicyDecision(
                    allowed=False,
                    violations=[],
                    reason=self.policy.get("reason", "Deny all policy active"),
                    evaluation_time_ms=(time.perf_counter() - start_time) * 1000
                )

            # Determine evaluation mode
            use_opa = (
                self._opa_available and
                self.policy.get("use_opa", False) and
                "rego_policy" in self.policy
            )

            if use_opa:
                decision = self._evaluate_with_opa(operation)
            else:
                decision = self._evaluate_semantic(operation)

            decision.evaluation_time_ms = (time.perf_counter() - start_time) * 1000
            return decision

        except Exception as e:
            # FAIL CLOSED: Any exception during evaluation
            return PolicyDecision(
                allowed=False,
                violations=[],
                reason=f"Evaluation error (FAIL CLOSED): {e}",
                evaluation_time_ms=(time.perf_counter() - start_time) * 1000
            )

    def _evaluate_semantic(self, operation: Operation) -> PolicyDecision:
        """Evaluate using pure Python semantic analysis (<1ms)."""
        violations = self.semantic_analyzer.analyze(operation)

        if violations:
            critical_violations = [v for v in violations if v.severity == "critical"]
            return PolicyDecision(
                allowed=False,
                violations=violations,
                reason=f"Detected {len(violations)} violations ({len(critical_violations)} critical)",
                evaluation_mode=EvaluationMode.SEMANTIC
            )

        return PolicyDecision(
            allowed=True,
            violations=[],
            reason="No violations detected",
            evaluation_mode=EvaluationMode.SEMANTIC
        )

    def _evaluate_with_opa(self, operation: Operation) -> PolicyDecision:
        """Evaluate using OPA/Rego rules (~50ms)."""
        import subprocess

        # Create input JSON for OPA
        input_data = {
            "operation": {
                "type": operation.type.value,
                "code": operation.code,
                "language": operation.language.value,
                "file_path": operation.file_path,
                "context": operation.context
            }
        }

        try:
            # Run OPA evaluation with timeout
            result = subprocess.run(
                ["opa", "eval", "-d", self.policy["rego_policy"],
                 "-i", "-", "data.policy.allow"],
                input=json.dumps(input_data),
                capture_output=True,
                text=True,
                timeout=self.DEFAULT_OPA_TIMEOUT
            )

            if result.returncode != 0:
                # FAIL CLOSED: OPA error
                return PolicyDecision(
                    allowed=False,
                    violations=[],
                    reason=f"OPA evaluation error: {result.stderr}",
                    evaluation_mode=EvaluationMode.OPA
                )

            # Parse OPA result
            opa_result = json.loads(result.stdout)
            allowed = opa_result.get("result", [{}])[0].get("expressions", [{}])[0].get("value", False)

            return PolicyDecision(
                allowed=allowed,
                violations=[],  # OPA provides custom violation format
                reason="OPA evaluation complete",
                evaluation_mode=EvaluationMode.OPA
            )

        except subprocess.TimeoutExpired:
            # FAIL CLOSED: OPA timeout
            return PolicyDecision(
                allowed=False,
                violations=[],
                reason=f"OPA timeout after {self.DEFAULT_OPA_TIMEOUT}s (FAIL CLOSED)",
                evaluation_mode=EvaluationMode.OPA
            )


# =============================================================================
# TEST RUNNER
# =============================================================================

class PolicyEngineTestRunner:
    """Test runner for Policy Engine tests."""

    def __init__(self):
        self.test_cases: List[PolicyTestCase] = []
        self.results: List[PolicyTestResult] = []
        self.engine = PolicyEngine()

    def add_test(self, test_case: PolicyTestCase) -> None:
        """Add a test case."""
        self.test_cases.append(test_case)

    def run_all(self) -> List[PolicyTestResult]:
        """Run all test cases."""
        self.results = []
        for test_case in self.test_cases:
            result = self._run_test(test_case)
            self.results.append(result)
        return self.results

    def _run_test(self, test_case: PolicyTestCase) -> PolicyTestResult:
        """Run a single test case."""
        decision = self.engine.evaluate(test_case.operation)

        # Check if test passed
        passed = True
        failure_reason = ""

        # Check allowed status
        if decision.allowed != test_case.expected_allowed:
            passed = False
            failure_reason = f"Expected allowed={test_case.expected_allowed}, got {decision.allowed}"

        # Check violation types if not allowed
        if not test_case.expected_allowed:
            detected_types = {v.vulnerability_type for v in decision.violations}
            expected_types = set(test_case.expected_violations)
            if not expected_types.issubset(detected_types):
                passed = False
                missing = expected_types - detected_types
                failure_reason = f"Missing expected violations: {missing}"

        # Check performance
        if decision.evaluation_time_ms > test_case.expected_max_eval_time_ms:
            passed = False
            failure_reason = f"Too slow: {decision.evaluation_time_ms:.2f}ms > {test_case.expected_max_eval_time_ms}ms"

        return PolicyTestResult(
            test_case=test_case,
            actual_decision=decision,
            passed=passed,
            failure_reason=failure_reason
        )

    def generate_report(self) -> Dict[str, Any]:
        """Generate test report."""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        return {
            "total_tests": len(self.results),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / max(len(self.results), 1),
            "avg_eval_time_ms": sum(r.actual_decision.evaluation_time_ms for r in self.results) / max(len(self.results), 1),
            "failures": [
                {
                    "test_id": r.test_case.test_id,
                    "name": r.test_case.name,
                    "reason": r.failure_reason
                }
                for r in self.results if not r.passed
            ]
        }


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Run Policy Engine tests."""
    print("=" * 70)
    print("CODE SCALPEL POLICY ENGINE TEST FRAMEWORK")
    print("=" * 70)
    print()
    print("Evaluation Modes:")
    print("  - Semantic Analysis: Pure Python, <1ms per operation")
    print("  - OPA/Rego: Complex custom rules, ~50ms per policy")
    print()
    print("Security Model: FAIL CLOSED")
    print("  - Policy file missing → DENY ALL")
    print("  - Invalid YAML → DENY ALL")
    print("  - OPA timeout (30s) → DENY operation")
    print("  - Any exception → DENY operation")
    print()
    print("Vulnerability Detection:")
    print("  - SQL Injection (Python, Java, TypeScript/JS)")
    print("  - Command Injection (Python, Java, TypeScript/JS)")
    print("  - XSS (Python, Java, TypeScript/JS)")
    print("  - SSTI (Python, Java, TypeScript/JS)")
    print("  - Path Traversal (Python, Java, TypeScript/JS)")
    print("  - Secrets Exposure (All languages)")
    print("=" * 70)


if __name__ == "__main__":
    main()
