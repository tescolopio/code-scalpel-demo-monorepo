#!/usr/bin/env python3
"""
=============================================================================
POLICY ENGINE JAVA VULNERABILITY PATTERN TESTS
=============================================================================

PURPOSE: Test Policy Engine detection of Java-specific vulnerability patterns.
These tests verify that the Policy Engine correctly identifies and blocks:

1. SQL Injection via StringBuilder, String.format, concatenation
2. Command Injection via Runtime.exec, ProcessBuilder
3. XSS via JSP expressions, response writer
4. SSTI via Freemarker, Thymeleaf, Velocity
5. Path Traversal via File, Path with user input
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
# SQL INJECTION TEST CASES (Java)
# =============================================================================

JAVA_SQL_INJECTION_TESTS = [
    # Test 1: StringBuilder SQL injection
    PolicyTestCase(
        test_id="JAVA-SQL-001",
        name="StringBuilder SQL injection",
        description='new StringBuilder("SELECT * FROM users WHERE id = ").append(userId)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''StringBuilder query = new StringBuilder("SELECT * FROM users WHERE id = ");
query.append(userId);
stmt.executeQuery(query.toString());''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/dao/UserDao.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: String.format SQL injection
    PolicyTestCase(
        test_id="JAVA-SQL-002",
        name="String.format SQL injection",
        description='String.format("SELECT * FROM users WHERE name = \'%s\'", userName)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='String query = String.format("SELECT * FROM users WHERE name = \'%s\'", userName);',
            language=Language.JAVA,
            file_path="src/main/java/com/app/dao/UserDao.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: String concatenation SQL injection
    PolicyTestCase(
        test_id="JAVA-SQL-003",
        name="String concatenation SQL injection",
        description='"SELECT * FROM users WHERE id = " + userId',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='String query = "SELECT * FROM users WHERE id = " + userId;',
            language=Language.JAVA,
            file_path="src/main/java/com/app/dao/UserDao.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: createStatement().executeQuery
    PolicyTestCase(
        test_id="JAVA-SQL-004",
        name="createStatement executeQuery injection",
        description='conn.createStatement().executeQuery(query)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''String query = "SELECT * FROM orders WHERE status = " + status;
ResultSet rs = conn.createStatement().executeQuery(query);''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/dao/OrderDao.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: executeQuery with concatenation
    PolicyTestCase(
        test_id="JAVA-SQL-005",
        name="executeQuery with concatenation",
        description='stmt.executeQuery("SELECT ... " + userInput)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='ResultSet rs = stmt.executeQuery("SELECT * FROM products WHERE category = " + category);',
            language=Language.JAVA,
            file_path="src/main/java/com/app/dao/ProductDao.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SQL_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 6: Safe PreparedStatement (SHOULD PASS)
    PolicyTestCase(
        test_id="JAVA-SQL-006",
        name="Safe PreparedStatement",
        description='PreparedStatement with parameter binding',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/dao/UserDao.java"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# COMMAND INJECTION TEST CASES (Java)
# =============================================================================

JAVA_COMMAND_INJECTION_TESTS = [
    # Test 1: Runtime.exec with user input
    PolicyTestCase(
        test_id="JAVA-CMD-001",
        name="Runtime.exec with user input",
        description='Runtime.getRuntime().exec("cmd " + userInput)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='Process p = Runtime.getRuntime().exec("cat " + filename);',
            language=Language.JAVA,
            file_path="src/main/java/com/app/util/FileUtil.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: ProcessBuilder with concatenation
    PolicyTestCase(
        test_id="JAVA-CMD-002",
        name="ProcessBuilder with concatenation",
        description='new ProcessBuilder("sh", "-c", cmd + userInput)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ls " + directory);',
            language=Language.JAVA,
            file_path="src/main/java/com/app/util/CmdUtil.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: ProcessBuilder with user controlled input
    PolicyTestCase(
        test_id="JAVA-CMD-003",
        name="ProcessBuilder with user input",
        description='new ProcessBuilder with user-controlled command',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''String cmd = request.getParameter("command");
ProcessBuilder pb = new ProcessBuilder("bash", "-c", cmd);
Process p = pb.start();''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/controller/AdminController.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.COMMAND_INJECTION],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Safe ProcessBuilder with fixed args (SHOULD PASS)
    PolicyTestCase(
        test_id="JAVA-CMD-004",
        name="Safe ProcessBuilder with fixed args",
        description='ProcessBuilder with hardcoded command',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='ProcessBuilder pb = new ProcessBuilder("ls", "-la", "/var/log");',
            language=Language.JAVA,
            file_path="src/main/java/com/app/util/LogUtil.java"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# XSS TEST CASES (Java)
# =============================================================================

JAVA_XSS_TESTS = [
    # Test 1: JSP out.print with concatenation
    PolicyTestCase(
        test_id="JAVA-XSS-001",
        name="JSP out.print with concatenation",
        description='out.print("<p>" + userContent + "</p>")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='out.print("<p>" + request.getParameter("name") + "</p>");',
            language=Language.JAVA,
            file_path="src/main/webapp/user.jsp"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: JSP expression with request parameter
    PolicyTestCase(
        test_id="JAVA-XSS-002",
        name="JSP expression with request parameter",
        description='<%= request.getParameter("name") %>',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='<%= request.getParameter("name") %>',
            language=Language.JAVA,
            file_path="src/main/webapp/profile.jsp"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Response writer with user input
    PolicyTestCase(
        test_id="JAVA-XSS-003",
        name="Response writer with user input",
        description='response.getWriter().write(userContent)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''String name = request.getParameter("name");
response.getWriter().write("<h1>Hello " + name + "</h1>");''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/servlet/GreetingServlet.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.XSS],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Safe JSTL c:out (SHOULD PASS)
    PolicyTestCase(
        test_id="JAVA-XSS-004",
        name="Safe JSTL c:out",
        description='<c:out value="${user.name}"/>',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='<c:out value="${user.name}" escapeXml="true"/>',
            language=Language.JAVA,
            file_path="src/main/webapp/user.jsp"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# SSTI TEST CASES (Java)
# =============================================================================

JAVA_SSTI_TESTS = [
    # Test 1: Freemarker template injection
    PolicyTestCase(
        test_id="JAVA-SSTI-001",
        name="Freemarker template injection",
        description='Freemarker Template with user input',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''String userTemplate = request.getParameter("template");
Template template = new Template("dynamic", new StringReader(userTemplate), cfg);''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/template/TemplateService.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Thymeleaf process with user input
    PolicyTestCase(
        test_id="JAVA-SSTI-002",
        name="Thymeleaf process with user input",
        description='Thymeleaf process user template',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''String template = request.getParameter("template");
engine.process(template, context, writer);''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/template/ThymeleafService.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Velocity engine with user template
    PolicyTestCase(
        test_id="JAVA-SSTI-003",
        name="Velocity engine with user template",
        description='VelocityEngine evaluate user template',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''VelocityEngine engine = new VelocityEngine();
engine.evaluate(context, writer, "log", userTemplate);''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/template/VelocityService.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SSTI],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Safe template from file (SHOULD PASS)
    PolicyTestCase(
        test_id="JAVA-SSTI-004",
        name="Safe template from file",
        description='Template loaded from classpath',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='Template template = cfg.getTemplate("user-profile.ftl");',
            language=Language.JAVA,
            file_path="src/main/java/com/app/template/TemplateService.java"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# PATH TRAVERSAL TEST CASES (Java)
# =============================================================================

JAVA_PATH_TRAVERSAL_TESTS = [
    # Test 1: File constructor with concatenation
    PolicyTestCase(
        test_id="JAVA-PATH-001",
        name="File constructor with concatenation",
        description='new File(basePath + userPath)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='File file = new File("/uploads/" + request.getParameter("filename"));',
            language=Language.JAVA,
            file_path="src/main/java/com/app/FileController.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: FileInputStream with concatenation
    PolicyTestCase(
        test_id="JAVA-PATH-002",
        name="FileInputStream with concatenation",
        description='new FileInputStream(basePath + fileName)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='InputStream is = new FileInputStream("/data/" + filename);',
            language=Language.JAVA,
            file_path="src/main/java/com/app/FileReader.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: Paths.get with concatenation
    PolicyTestCase(
        test_id="JAVA-PATH-003",
        name="Paths.get with concatenation",
        description='Paths.get(baseDir + userPath)',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='Path path = Paths.get("/var/data/" + userPath);',
            language=Language.JAVA,
            file_path="src/main/java/com/app/PathUtil.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Files.read with concatenation
    PolicyTestCase(
        test_id="JAVA-PATH-004",
        name="Files.read with concatenation",
        description='Files.readAllBytes(Paths.get(base + user))',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='byte[] data = Files.readAllBytes(Paths.get("/reports/" + reportName));',
            language=Language.JAVA,
            file_path="src/main/java/com/app/ReportService.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.PATH_TRAVERSAL],
        expected_max_eval_time_ms=1.0
    ),

    # Test 5: Safe file access with whitelist (SHOULD PASS)
    PolicyTestCase(
        test_id="JAVA-PATH-005",
        name="Safe file access with whitelist",
        description='Validated filename from whitelist',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='''Set<String> ALLOWED = Set.of("report.pdf", "data.csv");
if (ALLOWED.contains(filename)) {
    return Files.readAllBytes(Paths.get("/data/" + filename));
}''',
            language=Language.JAVA,
            file_path="src/main/java/com/app/SafeFileService.java"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]

# =============================================================================
# SECRETS EXPOSURE TEST CASES (Java)
# =============================================================================

JAVA_SECRETS_TESTS = [
    # Test 1: Hardcoded API key
    PolicyTestCase(
        test_id="JAVA-SEC-001",
        name="Hardcoded API key",
        description='private static final String API_KEY = "sk-..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='private static final String API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890";',
            language=Language.JAVA,
            file_path="src/main/java/com/app/config/ApiConfig.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 2: Hardcoded password
    PolicyTestCase(
        test_id="JAVA-SEC-002",
        name="Hardcoded password",
        description='String password = "admin123"',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='private static final String password = "supersecretpassword";',
            language=Language.JAVA,
            file_path="src/main/java/com/app/config/DbConfig.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 3: AWS access key
    PolicyTestCase(
        test_id="JAVA-SEC-003",
        name="AWS access key",
        description='String awsAccessKeyId = "AKIA..."',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='String aws_access_key_id = "AKIAIOSFODNN7EXAMPLE";',
            language=Language.JAVA,
            file_path="src/main/java/com/app/config/AwsConfig.java"
        ),
        expected_allowed=False,
        expected_violations=[VulnerabilityType.SECRETS_EXPOSURE],
        expected_max_eval_time_ms=1.0
    ),

    # Test 4: Safe environment variable (SHOULD PASS)
    PolicyTestCase(
        test_id="JAVA-SEC-004",
        name="Safe environment variable",
        description='System.getenv("API_KEY")',
        operation=Operation(
            type=OperationType.CODE_EDIT,
            code='String apiKey = System.getenv("API_KEY");',
            language=Language.JAVA,
            file_path="src/main/java/com/app/config/ApiConfig.java"
        ),
        expected_allowed=True,
        expected_violations=[],
        expected_max_eval_time_ms=1.0
    ),
]


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_java_tests():
    """Run all Java vulnerability pattern tests."""
    runner = PolicyTestRunner()

    # Add all test cases
    all_tests = (
        JAVA_SQL_INJECTION_TESTS +
        JAVA_COMMAND_INJECTION_TESTS +
        JAVA_XSS_TESTS +
        JAVA_SSTI_TESTS +
        JAVA_PATH_TRAVERSAL_TESTS +
        JAVA_SECRETS_TESTS
    )

    for test in all_tests:
        runner.add_test(test)

    # Run tests
    results = runner.run_all()

    # Generate report
    report = runner.generate_report()

    # Print results
    print("=" * 70)
    print("JAVA VULNERABILITY PATTERN TEST RESULTS")
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
        "SQL Injection": [r for r in results if r.test_case.test_id.startswith("JAVA-SQL")],
        "Command Injection": [r for r in results if r.test_case.test_id.startswith("JAVA-CMD")],
        "XSS": [r for r in results if r.test_case.test_id.startswith("JAVA-XSS")],
        "SSTI": [r for r in results if r.test_case.test_id.startswith("JAVA-SSTI")],
        "Path Traversal": [r for r in results if r.test_case.test_id.startswith("JAVA-PATH")],
        "Secrets": [r for r in results if r.test_case.test_id.startswith("JAVA-SEC")],
    }

    print("RESULTS BY CATEGORY:")
    for category, cat_results in categories.items():
        passed = sum(1 for r in cat_results if r.passed)
        total = len(cat_results)
        print(f"  {category}: {passed}/{total} passed")

    print("=" * 70)

    return report


if __name__ == "__main__":
    run_java_tests()
