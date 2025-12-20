#!/usr/bin/env python3
"""
=============================================================================
POLICY ENGINE PYTHON VULNERABILITY PATTERN TESTS
=============================================================================

PURPOSE: Test Policy Engine detection of Python-specific vulnerability patterns.
These tests verify that the Policy Engine correctly identifies and blocks:

1. SQL Injection via +, f-strings, .format(), %
2. Command Injection via subprocess, os.system
3. XSS via unescaped output
4. SSTI via Jinja2, Mako templates
5. Path Traversal via open() with user input
6. Secrets exposure via hardcoded credentials

EXPECTED BEHAVIOR:
- All vulnerable code snippets should be BLOCKED
- All safe code snippets should be ALLOWED
- Semantic analysis should complete in <1ms

=============================================================================
"""
from policy_engine_framework import (
    PolicyEngine, PolicyTestCase, PolicyTestRunner,
    Operation, OperationType, Language, VulnerabilityType
)


# =============================================================================
# SQL INJECTION TEST CASES (Python)
# =============================================================================

PYTHON_SQL_INJECTION_TESTS = [
    # Test 1: f-string SQL injection (double quotes)
    PolicyTestCase(
        test_id="PY-SQL-001",
        name="f-string SQL injection (double quotes)",
        description='query = f"SELECT * FROM users WHERE id = {user_id}"',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='query = f"SELECT * FROM users WHERE id = {user_id}"',
            language=Language.PYTHON,
            file_path="src/api/users.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: f-string SQL injection (single quotes)
    PolicyTestCase(
        test_id="PY-SQL-002",
        name="f-string SQL injection (single quotes)",
        description="query = f'SELECT * FROM users WHERE name = {name}'",
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code="query = f'SELECT * FROM users WHERE name = {name}'",
            language=Language.PYTHON,
            file_path="src/api/users.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: %-format SQL injection
    PolicyTestCase(
        test_id="PY-SQL-003",
        name="%-format SQL injection",
        description='query = "SELECT * FROM users WHERE id = %s" % user_id',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='query = "SELECT * FROM users WHERE id = %s" % user_id',
            language=Language.PYTHON,
            file_path="src/api/users.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: .format() SQL injection
    PolicyTestCase(
        test_id="PY-SQL-004",
        name=".format() SQL injection",
        description='query = "SELECT * FROM users WHERE id = {}".format(user_id)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='query = "SELECT * FROM users WHERE id = {}".format(user_id)',
            language=Language.PYTHON,
            file_path="src/api/users.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: String concatenation SQL injection
    PolicyTestCase(
        test_id="PY-SQL-005",
        name="String concatenation SQL injection",
        description='query = "SELECT * FROM users WHERE id = " + user_id',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='query = "SELECT * FROM users WHERE id = " + user_id',
            language=Language.PYTHON,
            file_path="src/api/users.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 6: cursor.execute with f-string
    PolicyTestCase(
        test_id="PY-SQL-006",
        name="cursor.execute with f-string",
        description='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            language=Language.PYTHON,
            file_path="src/db/queries.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 7: Safe parameterized query (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-SQL-007",
        name="Safe parameterized query",
        description='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            language=Language.PYTHON,
            file_path="src/db/queries.py"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),

    # Test 8: Safe SQLAlchemy query (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-SQL-008",
        name="Safe SQLAlchemy query",
        description='session.query(User).filter(User.id == user_id).first()',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='session.query(User).filter(User.id == user_id).first()',
            language=Language.PYTHON,
            file_path="src/db/queries.py"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# COMMAND INJECTION TEST CASES (Python)
# =============================================================================

PYTHON_COMMAND_INJECTION_TESTS = [
    # Test 1: subprocess with shell=True
    PolicyTestCase(
        test_id="PY-CMD-001",
        name="subprocess.run with shell=True",
        description='subprocess.run(f"ls {user_dir}", shell=True)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='subprocess.run(f"ls {user_dir}", shell=True)',
            language=Language.PYTHON,
            file_path="src/utils/files.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: subprocess.call with shell=True
    PolicyTestCase(
        test_id="PY-CMD-002",
        name="subprocess.call with shell=True",
        description='subprocess.call(cmd, shell=True)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='subprocess.call(cmd, shell=True)',
            language=Language.PYTHON,
            file_path="src/utils/cmd.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: os.system command injection
    PolicyTestCase(
        test_id="PY-CMD-003",
        name="os.system command injection",
        description='os.system(f"cat {filename}")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='os.system(f"cat {filename}")',
            language=Language.PYTHON,
            file_path="src/utils/files.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: os.popen command injection
    PolicyTestCase(
        test_id="PY-CMD-004",
        name="os.popen command injection",
        description='os.popen(f"grep {pattern} /var/log/app.log")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='os.popen(f"grep {pattern} /var/log/app.log")',
            language=Language.PYTHON,
            file_path="src/utils/logs.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: eval with user input
    PolicyTestCase(
        test_id="PY-CMD-005",
        name="eval with user input",
        description='result = eval(user_expression)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='result = eval(user_expression)',
            language=Language.PYTHON,
            file_path="src/api/calc.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 6: exec with user input
    PolicyTestCase(
        test_id="PY-CMD-006",
        name="exec with user input",
        description='exec(user_code)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='exec(user_code)',
            language=Language.PYTHON,
            file_path="src/api/dynamic.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 7: Safe subprocess without shell (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-CMD-007",
        name="Safe subprocess without shell",
        description='subprocess.run(["ls", "-la", directory], check=True)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='subprocess.run(["ls", "-la", directory], check=True)',
            language=Language.PYTHON,
            file_path="src/utils/files.py"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# XSS TEST CASES (Python)
# =============================================================================

PYTHON_XSS_TESTS = [
    # Test 1: render_template_string (SSTI/XSS)
    PolicyTestCase(
        test_id="PY-XSS-001",
        name="render_template_string XSS",
        description='render_template_string(user_template)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='return render_template_string(user_template)',
            language=Language.PYTHON,
            file_path="src/views/render.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Markup concatenation
    PolicyTestCase(
        test_id="PY-XSS-002",
        name="Markup concatenation XSS",
        description='Markup("<p>" + user_content + "</p>")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='html = Markup("<p>" + user_content + "</p>")',
            language=Language.PYTHON,
            file_path="src/views/render.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Jinja safe filter misuse
    PolicyTestCase(
        test_id="PY-XSS-003",
        name="Jinja safe filter misuse",
        description='{{ user_content|safe }}',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='{{ user_content|safe }}',
            language=Language.PYTHON,
            file_path="templates/user.html"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Safe escaped output (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-XSS-004",
        name="Safe escaped output",
        description='{{ user_content }} (auto-escaped)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='{{ user_content }}',
            language=Language.PYTHON,
            file_path="templates/user.html"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# SSTI TEST CASES (Python)
# =============================================================================

PYTHON_SSTI_TESTS = [
    # Test 1: Jinja2 Template with user input
    PolicyTestCase(
        test_id="PY-SSTI-001",
        name="Jinja2 Template with user input",
        description='Template(user_template).render()',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='template = Template(user_template)\nresult = template.render()',
            language=Language.PYTHON,
            file_path="src/views/dynamic.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Template from_string
    PolicyTestCase(
        test_id="PY-SSTI-002",
        name="Template from_string SSTI",
        description='env.from_string(user_input)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='template = env.from_string(user_input)',
            language=Language.PYTHON,
            file_path="src/views/templates.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Mako template
    PolicyTestCase(
        test_id="PY-SSTI-003",
        name="Mako template SSTI",
        description='MakoTemplate(user_template)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='tmpl = MakoTemplate(user_template)',
            language=Language.PYTHON,
            file_path="src/views/mako.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Safe template from file (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-SSTI-004",
        name="Safe template from file",
        description='render_template("user.html", name=name)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='return render_template("user.html", name=name)',
            language=Language.PYTHON,
            file_path="src/views/users.py"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# PATH TRAVERSAL TEST CASES (Python)
# =============================================================================

PYTHON_PATH_TRAVERSAL_TESTS = [
    # Test 1: open() with concatenation
    PolicyTestCase(
        test_id="PY-PATH-001",
        name="open() with concatenation",
        description='open("/uploads/" + filename)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='with open("/uploads/" + filename) as f:\n    return f.read()',
            language=Language.PYTHON,
            file_path="src/files/download.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: open() with f-string
    PolicyTestCase(
        test_id="PY-PATH-002",
        name="open() with f-string",
        description='open(f"/data/{user_path}")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='with open(f"/data/{user_path}") as f:\n    return f.read()',
            language=Language.PYTHON,
            file_path="src/files/read.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Path concatenation
    PolicyTestCase(
        test_id="PY-PATH-003",
        name="Path concatenation",
        description='Path(base_dir) + filename',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='file_path = Path(base_dir) + filename',
            language=Language.PYTHON,
            file_path="src/files/paths.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: os.path.join with user input (potential traversal)
    PolicyTestCase(
        test_id="PY-PATH-004",
        name="os.path.join with user input",
        description='os.path.join(base, user_filename)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='path = os.path.join(base, user_filename)',
            language=Language.PYTHON,
            file_path="src/files/join.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Safe file access with validation (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-PATH-005",
        name="Safe file access with validation",
        description='ALLOWED_FILES = {"report.pdf", "data.csv"}',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='ALLOWED_FILES = {"report.pdf", "data.csv"}\nif filename in ALLOWED_FILES:\n    with open(f"/data/{filename}") as f:\n        return f.read()',
            language=Language.PYTHON,
            file_path="src/files/safe.py"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# SECRETS EXPOSURE TEST CASES (Python)
# =============================================================================

PYTHON_SECRETS_TESTS = [
    # Test 1: Hardcoded API key
    PolicyTestCase(
        test_id="PY-SEC-001",
        name="Hardcoded API key",
        description='API_KEY = "sk-1234567890abcdef..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890"',
            language=Language.PYTHON,
            file_path="src/config.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Hardcoded password
    PolicyTestCase(
        test_id="PY-SEC-002",
        name="Hardcoded password",
        description='password = "mysecretpassword123"',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='password = "mysecretpassword123"',
            language=Language.PYTHON,
            file_path="src/auth/config.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: AWS access key
    PolicyTestCase(
        test_id="PY-SEC-003",
        name="AWS access key",
        description='aws_access_key_id = "AKIA..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
            language=Language.PYTHON,
            file_path="src/aws/config.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: GitHub token
    PolicyTestCase(
        test_id="PY-SEC-004",
        name="GitHub personal access token",
        description='GITHUB_TOKEN = "ghp_..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
            language=Language.PYTHON,
            file_path="src/github/config.py"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Safe environment variable usage (SHOULD PASS)
    PolicyTestCase(
        test_id="PY-SEC-005",
        name="Safe environment variable usage",
        description='API_KEY = os.environ.get("API_KEY")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='API_KEY = os.environ.get("API_KEY")',
            language=Language.PYTHON,
            file_path="src/config.py"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# TEST RUNNER
# =============================================================================

def run_python_tests():
    """Run all Python vulnerability pattern tests."""
    runner = PolicyTestRunner()

    # Add all test cases
    all_tests = (
        PYTHON_SQL_INJECTION_TESTS +
        PYTHON_COMMAND_INJECTION_TESTS +
        PYTHON_XSS_TESTS +
        PYTHON_SSTI_TESTS +
        PYTHON_PATH_TRAVERSAL_TESTS +
        PYTHON_SECRETS_TESTS
    )

    for test in all_tests:
        runner.add_test(test)

    # Run tests
    results = runner.run_all()

    # Generate report
    report = runner.generate_report()

    # Print results
    print("=" * 70)
    print("PYTHON VULNERABILITY PATTERN TEST RESULTS")
    print("=" * 70)
    print(f"Total tests: {report['total_tests']}")
    print(f"Passed: {report['passed']}")
    print(f"Failed: {report['failed']}")
    print(f"Pass rate: {report['pass_rate']:.1%}")
    print(f"Average evaluation time: {report['avg_eval_time_ms']:.3f}ms")
    print()

    if report['failures']:
        print("FAILURES:")
        for failure in report['failures']:
            print(f"  - {failure['test_id']}: {failure['name']}")
            print(f"    Reason: {failure['reason']}")
        print()

    # Summary by category
    categories = {
        "SQL Injection": [r for r in results if r.test_case.test_id.startswith("PY-SQL")],
        "Command Injection": [r for r in results if r.test_case.test_id.startswith("PY-CMD")],
        "XSS": [r for r in results if r.test_case.test_id.startswith("PY-XSS")],
        "SSTI": [r for r in results if r.test_case.test_id.startswith("PY-SSTI")],
        "Path Traversal": [r for r in results if r.test_case.test_id.startswith("PY-PATH")],
        "Secrets": [r for r in results if r.test_case.test_id.startswith("PY-SEC")],
    }

    print("RESULTS BY CATEGORY:")
    for category, cat_results in categories.items():
        passed = sum(1 for r in cat_results if r.passed)
        total = len(cat_results)
        print(f"  {category}: {passed}/{total} passed")

    print("=" * 70)

    return report


if __name__ == "__main__":
    run_python_tests()
