#!/usr/bin/env python3
"""
=============================================================================
POLICY ENGINE TYPESCRIPT/JAVASCRIPT VULNERABILITY PATTERN TESTS
=============================================================================

PURPOSE: Test Policy Engine detection of TypeScript/JavaScript vulnerability patterns.
These tests verify that the Policy Engine correctly identifies and blocks:

1. SQL Injection via template literals, concatenation
2. Command Injection via child_process
3. XSS via innerHTML, document.write
4. SSTI via EJS, Pug, Nunjucks, Handlebars
5. Path Traversal via fs operations
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
# SQL INJECTION TEST CASES (TypeScript/JavaScript)
# =============================================================================

TS_SQL_INJECTION_TESTS = [
    # Test 1: Template literal SQL injection
    PolicyTestCase(
        test_id="TS-SQL-001",
        name="Template literal SQL injection",
        description='`SELECT * FROM users WHERE id = ${userId}`',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const query = `SELECT * FROM users WHERE id = ${userId}`;',
            language=Language.TYPESCRIPT,
            file_path="src/db/queries.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: String concatenation SQL injection
    PolicyTestCase(
        test_id="TS-SQL-002",
        name="String concatenation SQL injection",
        description='"SELECT * FROM users WHERE id = " + userId',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const query = "SELECT * FROM users WHERE id = " + userId;',
            language=Language.TYPESCRIPT,
            file_path="src/db/queries.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Single quote concatenation
    PolicyTestCase(
        test_id="TS-SQL-003",
        name="Single quote concatenation SQL",
        description="'SELECT * FROM users WHERE name = ' + name",
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code="const query = 'SELECT * FROM users WHERE name = ' + name;",
            language=Language.TYPESCRIPT,
            file_path="src/db/queries.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: JavaScript template literal injection
    PolicyTestCase(
        test_id="JS-SQL-001",
        name="JavaScript template literal SQL",
        description='`SELECT * FROM products WHERE category = ${category}`',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const sql = `SELECT * FROM products WHERE category = ${req.query.category}`;',
            language=Language.JAVASCRIPT,
            file_path="src/routes/products.js"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Safe parameterized query (SHOULD PASS)
    PolicyTestCase(
        test_id="TS-SQL-004",
        name="Safe parameterized query",
        description='db.query("SELECT * FROM users WHERE id = $1", [userId])',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
            language=Language.TYPESCRIPT,
            file_path="src/db/queries.ts"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# COMMAND INJECTION TEST CASES (TypeScript/JavaScript)
# =============================================================================

TS_COMMAND_INJECTION_TESTS = [
    # Test 1: exec with concatenation
    PolicyTestCase(
        test_id="TS-CMD-001",
        name="exec with concatenation",
        description='exec("cat " + filename)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='exec("cat " + filename, (err, stdout) => { console.log(stdout); });',
            language=Language.TYPESCRIPT,
            file_path="src/utils/files.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: exec with template literal
    PolicyTestCase(
        test_id="TS-CMD-002",
        name="exec with template literal",
        description='exec(`grep ${pattern} /var/log/app.log`)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='exec(`grep ${pattern} /var/log/app.log`, callback);',
            language=Language.TYPESCRIPT,
            file_path="src/utils/logs.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: execSync
    PolicyTestCase(
        test_id="TS-CMD-003",
        name="execSync command injection",
        description='execSync(userCommand)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const output = execSync(userCommand).toString();',
            language=Language.TYPESCRIPT,
            file_path="src/utils/cmd.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: spawn with shell option
    PolicyTestCase(
        test_id="TS-CMD-004",
        name="spawn with shell option",
        description='spawn(cmd, [], { shell: true })',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const child = spawn(cmd, args, { shell: true });',
            language=Language.TYPESCRIPT,
            file_path="src/utils/process.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: child_process import detection
    PolicyTestCase(
        test_id="JS-CMD-001",
        name="child_process with user input",
        description='child_process.exec(userInput)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''const child_process = require('child_process');
child_process.exec(req.body.command);''',
            language=Language.JAVASCRIPT,
            file_path="src/routes/admin.js"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 6: Safe spawn without shell (SHOULD PASS)
    PolicyTestCase(
        test_id="TS-CMD-005",
        name="Safe spawn without shell",
        description='spawn("ls", ["-la", dir])',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const child = spawn("ls", ["-la", directory]);',
            language=Language.TYPESCRIPT,
            file_path="src/utils/files.ts"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# XSS TEST CASES (TypeScript/JavaScript)
# =============================================================================

TS_XSS_TESTS = [
    # Test 1: innerHTML assignment
    PolicyTestCase(
        test_id="TS-XSS-001",
        name="innerHTML assignment",
        description='element.innerHTML = userContent',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='document.getElementById("output").innerHTML = userContent;',
            language=Language.TYPESCRIPT,
            file_path="src/views/render.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: outerHTML assignment
    PolicyTestCase(
        test_id="TS-XSS-002",
        name="outerHTML assignment",
        description='element.outerHTML = html',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='targetElement.outerHTML = response.html;',
            language=Language.TYPESCRIPT,
            file_path="src/views/dynamic.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: document.write
    PolicyTestCase(
        test_id="TS-XSS-003",
        name="document.write XSS",
        description='document.write(userHtml)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='document.write(`<h1>${userName}</h1>`);',
            language=Language.TYPESCRIPT,
            file_path="src/views/legacy.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: React dangerouslySetInnerHTML
    PolicyTestCase(
        test_id="TS-XSS-004",
        name="React dangerouslySetInnerHTML",
        description='dangerouslySetInnerHTML={{ __html: content }}',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='<div dangerouslySetInnerHTML={{ __html: userContent }} />',
            language=Language.TYPESCRIPT,
            file_path="src/components/UserContent.tsx"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: jQuery .html() with concatenation
    PolicyTestCase(
        test_id="JS-XSS-001",
        name="jQuery .html() with concatenation",
        description='$().html("<p>" + userInput + "</p>")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='$("#output").html("<p>" + userName + "</p>");',
            language=Language.JAVASCRIPT,
            file_path="src/views/jquery.js"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 6: Safe textContent (SHOULD PASS)
    PolicyTestCase(
        test_id="TS-XSS-005",
        name="Safe textContent",
        description='element.textContent = userContent',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='document.getElementById("output").textContent = userContent;',
            language=Language.TYPESCRIPT,
            file_path="src/views/safe.ts"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# SSTI TEST CASES (TypeScript/JavaScript)
# =============================================================================

TS_SSTI_TESTS = [
    # Test 1: EJS render with concatenation
    PolicyTestCase(
        test_id="TS-SSTI-001",
        name="EJS render with concatenation",
        description='ejs.render(userTemplate + data)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const html = ejs.render(userTemplate + "</div>", data);',
            language=Language.TYPESCRIPT,
            file_path="src/views/ejs.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Pug render
    PolicyTestCase(
        test_id="TS-SSTI-002",
        name="Pug render with user template",
        description='pug.render(userTemplate)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const html = pug.render(req.body.template, { name: user.name });',
            language=Language.TYPESCRIPT,
            file_path="src/views/pug.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Nunjucks renderString
    PolicyTestCase(
        test_id="TS-SSTI-003",
        name="Nunjucks renderString",
        description='nunjucks.renderString(userTemplate)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const result = nunjucks.renderString(userTemplate, context);',
            language=Language.TYPESCRIPT,
            file_path="src/views/nunjucks.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Handlebars compile with user input
    PolicyTestCase(
        test_id="JS-SSTI-001",
        name="Handlebars compile with user input",
        description='handlebars.compile(userTemplate)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const template = handlebars.compile(req.body.template);',
            language=Language.JAVASCRIPT,
            file_path="src/views/handlebars.js"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Safe template from file (SHOULD PASS)
    PolicyTestCase(
        test_id="TS-SSTI-004",
        name="Safe template from file",
        description='ejs.renderFile("templates/user.ejs", data)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const html = await ejs.renderFile("templates/user.ejs", { user });',
            language=Language.TYPESCRIPT,
            file_path="src/views/safe.ts"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# PATH TRAVERSAL TEST CASES (TypeScript/JavaScript)
# =============================================================================

TS_PATH_TRAVERSAL_TESTS = [
    # Test 1: fs.readFile with concatenation
    PolicyTestCase(
        test_id="TS-PATH-001",
        name="fs.readFile with concatenation",
        description='fs.readFile("/uploads/" + filename)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='fs.readFile("/uploads/" + filename, "utf8", callback);',
            language=Language.TYPESCRIPT,
            file_path="src/files/read.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: fs.readFileSync with concatenation
    PolicyTestCase(
        test_id="TS-PATH-002",
        name="fs.readFileSync with concatenation",
        description='fs.readFileSync(basePath + userPath)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const data = fs.readFileSync(basePath + userPath, "utf8");',
            language=Language.TYPESCRIPT,
            file_path="src/files/sync.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: path.join with user input
    PolicyTestCase(
        test_id="TS-PATH-003",
        name="path.join with user input",
        description='path.join(base, userFilename)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const fullPath = path.join(baseDir, userFilename);',
            language=Language.TYPESCRIPT,
            file_path="src/files/paths.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: fs.promises with user input
    PolicyTestCase(
        test_id="TS-PATH-004",
        name="fs.promises with user input",
        description='fs.promises.readFile(userPath)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const content = await fs.promises.readFile(`/data/${userPath}`, "utf8");',
            language=Language.TYPESCRIPT,
            file_path="src/files/async.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Dynamic require
    PolicyTestCase(
        test_id="JS-PATH-001",
        name="Dynamic require with user input",
        description='require(userModule)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const module = require("./modules/" + moduleName);',
            language=Language.JAVASCRIPT,
            file_path="src/loader.js"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 6: Safe static import (SHOULD PASS)
    PolicyTestCase(
        test_id="TS-PATH-005",
        name="Safe static import",
        description='import { util } from "./utils"',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='import { readFile } from "./utils/files";',
            language=Language.TYPESCRIPT,
            file_path="src/app.ts"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# SECRETS EXPOSURE TEST CASES (TypeScript/JavaScript)
# =============================================================================

TS_SECRETS_TESTS = [
    # Test 1: Hardcoded API key
    PolicyTestCase(
        test_id="TS-SEC-001",
        name="Hardcoded API key",
        description='const API_KEY = "sk-..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890";',
            language=Language.TYPESCRIPT,
            file_path="src/config.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Hardcoded password
    PolicyTestCase(
        test_id="TS-SEC-002",
        name="Hardcoded password",
        description='password: "mysecret123"',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const dbConfig = { password: "supersecretpassword" };',
            language=Language.TYPESCRIPT,
            file_path="src/db/config.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: GitHub token
    PolicyTestCase(
        test_id="TS-SEC-003",
        name="GitHub personal access token",
        description='const GITHUB_TOKEN = "ghp_..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";',
            language=Language.TYPESCRIPT,
            file_path="src/github/auth.ts"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: OpenAI API key pattern
    PolicyTestCase(
        test_id="JS-SEC-001",
        name="OpenAI API key",
        description='const OPENAI_KEY = "sk-..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const OPENAI_KEY = "sk-FAKE_TEST_KEY_DO_NOT_USE_abcdefghijklmnopqrst";',
            language=Language.JAVASCRIPT,
            file_path="src/openai/config.js"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Safe environment variable (SHOULD PASS)
    PolicyTestCase(
        test_id="TS-SEC-004",
        name="Safe environment variable",
        description='process.env.API_KEY',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='const apiKey = process.env.API_KEY || "";',
            language=Language.TYPESCRIPT,
            file_path="src/config.ts"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_typescript_tests():
    """Run all TypeScript/JavaScript vulnerability pattern tests."""
    runner = PolicyTestRunner()

    # Add all test cases
    all_tests = (
        TS_SQL_INJECTION_TESTS +
        TS_COMMAND_INJECTION_TESTS +
        TS_XSS_TESTS +
        TS_SSTI_TESTS +
        TS_PATH_TRAVERSAL_TESTS +
        TS_SECRETS_TESTS
    )

    for test in all_tests:
        runner.add_test(test)

    # Run tests
    results = runner.run_all()

    # Generate report
    report = runner.generate_report()

    # Print results
    print("=" * 70)
    print("TYPESCRIPT/JAVASCRIPT VULNERABILITY PATTERN TEST RESULTS")
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
        "SQL Injection": [r for r in results if "SQL" in r.test_case.test_id],
        "Command Injection": [r for r in results if "CMD" in r.test_case.test_id],
        "XSS": [r for r in results if "XSS" in r.test_case.test_id],
        "SSTI": [r for r in results if "SSTI" in r.test_case.test_id],
        "Path Traversal": [r for r in results if "PATH" in r.test_case.test_id],
        "Secrets": [r for r in results if "SEC" in r.test_case.test_id],
    }

    print("RESULTS BY CATEGORY:")
    for category, cat_results in categories.items():
        passed = sum(1 for r in cat_results if r.passed)
        total = len(cat_results)
        print(f"  {category}: {passed}/{total} passed")

    print("=" * 70)

    return report


if __name__ == "__main__":
    run_typescript_tests()
