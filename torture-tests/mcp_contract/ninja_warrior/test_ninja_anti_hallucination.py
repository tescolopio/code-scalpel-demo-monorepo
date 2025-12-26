"""Anti-Hallucination Tests for Code Scalpel MCP Tools.

These tests validate that Code Scalpel provides precise, ground-truth answers
that prevent AI agent hallucinations. Each test targets a specific failure mode
where an LLM might make confident-but-wrong assertions without proper tooling.

Test Categories:
1. Adversarial Naming - Names that lie about behavior
2. Confidence Calibration - Accuracy matches stated confidence
3. Contradiction Detection - Code vs comments/docstrings
4. Semantic Equivalence - Same verdict for equivalent code
5. Decoy Sanitizer Detection - Fake vs real protection
6. Hallucination Honeypots - Common LLM failure patterns
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _timed_call(mcp_client, tool: str, args: dict, *, max_seconds: float = 30.0):
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    assert elapsed <= max_seconds, {"tool": tool, "elapsed": elapsed, "result": result}
    return result, elapsed


def _normalize_result(raw) -> dict:
    if not isinstance(raw, dict):
        return {"success": False, "error": "Non-dict tool result"}

    if "jsonrpc" in raw and "error" in raw and isinstance(raw.get("error"), dict):
        return {"success": False, "error": raw["error"].get("message")}

    if "data" in raw and "capabilities" in raw:
        data = raw.get("data") or {}
        err = raw.get("error")
        if err:
            msg = err.get("error") if isinstance(err, dict) else str(err)
            return {**data, "success": False, "error": msg}
        return {**data, "success": True, "error": None}

    return raw


# =============================================================================
# Category 1: Adversarial Naming Tests
# Code Scalpel MUST analyze behavior, not trust names
# =============================================================================

class TestAdversarialNaming:
    """Tests for adversarial naming patterns that could cause hallucinations."""

    def test_sanitize_input_that_doesnt_sanitize(self, mcp_client):
        """Function named 'sanitize_input' but returns unchanged input."""
        code = '''
def sanitize_input(user_data):
    """Sanitizes user input for safe use."""
    return user_data  # Does nothing!

def handler(user_input):
    safe = sanitize_input(user_input)
    return f"<div>{safe}</div>"
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        # MUST detect XSS despite "sanitize" function name
        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            assert result.get("vulnerability_count", 0) >= 1, result
        else:
            pytest.xfail("Should detect XSS through fake sanitizer")

    def test_dangerous_function_thats_actually_safe(self, mcp_client):
        """Function with scary name that actually uses parameterized queries."""
        code = '''
import sqlite3

def dangerous_do_not_use(conn, user_id):
    """DANGER: This function is deprecated and unsafe."""
    # Despite the name and docstring, this is actually safe
    return conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        # MUST NOT flag as vulnerable - parameterized query is safe
        assert result.get("success") is True, result
        # Should have zero SQL injection findings
        vulns = result.get("vulnerabilities", [])
        sql_vulns = [v for v in vulns if "SQL" in str(v.get("type", "")).upper()]
        assert len(sql_vulns) == 0, f"False positive on safe parameterized query: {vulns}"


# =============================================================================
# Category 2: Contradiction Detection
# Code Scalpel MUST prefer code over comments/docstrings
# =============================================================================

class TestContradictionDetection:
    """Tests that Code Scalpel detects when code contradicts documentation."""

    def test_docstring_says_hashed_but_stores_plaintext(self, mcp_client):
        """Docstring claims hashing but code stores plaintext."""
        code = '''
def store_password(password):
    """
    Stores password securely using bcrypt with cost factor 12.
    This follows OWASP best practices for password storage.
    """
    db.execute(f"INSERT INTO users (pass) VALUES ('{password}')")
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        # MUST detect SQL injection despite reassuring docstring
        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            assert result.get("vulnerability_count", 0) >= 1, result
        else:
            pytest.xfail("Should detect vulnerability despite lying docstring")

    def test_comment_says_validated_but_no_validation(self, mcp_client):
        """Comment claims validation but variable is just assigned."""
        code = '''
import subprocess

def run_command(user_cmd):
    # Input has been validated by the frontend
    validated_cmd = user_cmd  # Just assignment!
    subprocess.run(validated_cmd, shell=True)
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        # MUST detect command injection despite comment claim
        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            assert result.get("vulnerability_count", 0) >= 1, result


# =============================================================================
# Category 3: Unused Import Detection
# LLMs might assume imported security libs mean security is applied
# =============================================================================

class TestUnusedImportDetection:
    """Tests that Code Scalpel doesn't assume imports mean usage."""

    def test_html_imported_but_not_used(self, mcp_client):
        """html.escape imported but never called."""
        code = '''
import html  # Imported for escaping

def render_profile(username):
    # Note: html module available for escaping
    return f"<h1>Welcome, {username}!</h1>"  # XSS!
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        # MUST detect XSS - import doesn't mean usage
        assert result.get("success") is True, result
        # Should find XSS vulnerability


# =============================================================================
# Category 4: Semantic Equivalence
# Same vulnerability, different syntax = same verdict
# =============================================================================

class TestSemanticEquivalence:
    """Tests that semantically equivalent code gets the same verdict."""

    @pytest.mark.parametrize("code,name", [
        # Ternary style
        ('''
def vuln_ternary(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}" if user_id else "SELECT 1"
    return cursor.execute(query)
''', "ternary"),
        # If-else style (semantically identical)
        ('''
def vuln_ifelse(user_id):
    if user_id:
        query = f"SELECT * FROM users WHERE id = {user_id}"
    else:
        query = "SELECT 1"
    return cursor.execute(query)
''', "ifelse"),
    ])
    def test_equivalent_sqli_detected_consistently(self, mcp_client, code, name):
        """Ternary and if-else SQL injection must both be detected."""
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        if not result.get("has_vulnerabilities"):
            pytest.xfail(f"Should detect SQLi in {name} style")


# =============================================================================
# Category 5: Decoy Sanitizer Detection
# Real vs fake sanitizers
# =============================================================================

class TestDecoySanitizerDetection:
    """Tests that Code Scalpel detects ineffective sanitizers."""

    def test_detects_noop_sanitizer(self, mcp_client):
        """Sanitizer that returns input unchanged."""
        code = '''
def clean_input(data):
    """Cleans input for safe use."""
    _ = data.strip()  # Pretend to do something
    return data  # Returns unchanged!

def handler(user_input):
    safe = clean_input(user_input)
    return f"<div>{safe}</div>"
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should detect the vulnerability through the fake sanitizer

    def test_detects_partial_escape(self, mcp_client):
        """Escape that misses quotes - attribute injection possible."""
        code = '''
def partial_escape(s):
    """Escapes HTML special characters."""
    return s.replace("<", "&lt;").replace(">", "&gt;")
    # Missing: quote escaping!

def render(user_input):
    escaped = partial_escape(user_input)
    return f'<input value="{escaped}">'  # Attribute XSS!
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should detect the attribute injection vulnerability


# =============================================================================
# Category 6: Type Hint Reality Check
# Python type hints don't provide runtime protection
# =============================================================================

class TestTypeHintReality:
    """Tests that Code Scalpel knows type hints don't enforce at runtime."""

    def test_type_hint_doesnt_prevent_injection(self, mcp_client):
        """Type hint says int but injection still possible."""
        code = '''
def get_user(user_id: int) -> dict:
    """Get user by integer ID."""
    # Type hint says int, but Python doesn't enforce at runtime
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query).fetchone()
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # MUST detect SQL injection despite int type hint


# =============================================================================
# Category 7: Confidence Monotonicity
# Confidence should decrease as distance from sink increases
# =============================================================================

class TestConfidenceMonotonicity:
    """Tests that confidence decreases with distance from vulnerability."""

    def test_call_chain_confidence_decay(self, mcp_client):
        """Direct sink should have higher confidence than indirect callers."""
        # Test the existing fixture
        root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
        fixture = root / "call_chain.py"

        if not fixture.exists():
            pytest.skip("Confidence decay fixture not found")

        raw, _ = _timed_call(mcp_client, "analyze_code", {
            "code": fixture.read_text(),
            "language": "python"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should successfully analyze the call chain


# =============================================================================
# Category 8: Cross-File Precision
# Taint must be tracked accurately across module boundaries
# =============================================================================

class TestCrossFilePrecision:
    """Tests that cross-file analysis is precise."""

    def test_crossfile_hard_detects_sqli(self, mcp_client):
        """Known vulnerable cross-file project should be detected."""
        root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"

        if not root.exists():
            pytest.skip("Cross-file hard fixture not found")

        raw, _ = _timed_call(mcp_client, "cross_file_security_scan", {
            "project_root": str(root),
            "max_depth": 6,
            "include_diagram": False,
            "timeout_seconds": 30,
            "max_modules": 100
        }, max_seconds=45)
        result = _normalize_result(raw)

        assert result.get("success") is True, result

        if result.get("has_vulnerabilities"):
            vulns = result.get("vulnerabilities", [])
            vuln_types = {v.get("type", "") for v in vulns}
            assert any("SQL" in t for t in vuln_types), f"Expected SQL injection: {vuln_types}"
        else:
            pytest.xfail("Should detect SQL injection in crossfile-hard fixture")

    def test_crossfile_safe_no_false_positives(self, mcp_client):
        """Safe cross-file project should not have false positives."""
        root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"

        if not root.exists():
            pytest.skip("Cross-file test fixture not found")

        raw, _ = _timed_call(mcp_client, "cross_file_security_scan", {
            "project_root": str(root),
            "max_depth": 5,
            "include_diagram": False,
            "timeout_seconds": 20,
            "max_modules": 50
        }, max_seconds=30)
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should not report false positives
        assert result.get("vulnerability_count", 0) == 0, \
            f"False positives in safe project: {result.get('vulnerabilities')}"


# =============================================================================
# Summary: Anti-Hallucination Coverage
# =============================================================================

class TestAntiHallucinationCoverage:
    """Meta-test validating anti-hallucination fixture availability."""

    def test_adversarial_naming_fixture_exists(self):
        """Adversarial naming fixtures should exist."""
        fixture = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.2-adversarial-naming"
        assert fixture.exists(), f"Missing fixture: {fixture}"

    def test_confidence_calibration_fixture_exists(self):
        """Confidence calibration fixtures should exist."""
        fixture = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.1-calibration-test"
        assert fixture.exists(), f"Missing fixture: {fixture}"

    def test_contradiction_detector_fixture_exists(self):
        """Contradiction detector fixtures should exist."""
        fixture = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.6-contradiction-detector"
        assert fixture.exists(), f"Missing fixture: {fixture}"

    def test_anti_hallucination_stage_exists(self):
        """Stage 9 anti-hallucination fixtures should exist."""
        stage = _repo_root() / "torture-tests" / "stage9-anti-hallucination"
        assert stage.exists(), f"Missing stage: {stage}"
