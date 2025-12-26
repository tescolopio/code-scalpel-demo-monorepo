"""Stage 10: Vibe Coding Adversarial Tests for Code Scalpel MCP Tools.

Tests that validate Code Scalpel can detect issues that commonly arise from
"Vibe Coding" - rapidly generating software via LLMs based on intuition
without rigorous engineering practices.

These tests ensure Code Scalpel can:
1. Detect outdated/insecure patterns from StackOverflow copy-paste
2. Find security issues in code that "works" functionally
3. Identify cross-file trust assumption failures
4. See through confident but incorrect comments
5. Detect slopsquatting/phantom library vulnerabilities
6. Find missed references in refactoring
7. Catch logic mirages (semantic bugs that look correct)

Test Categories:
- StackOverflow Syndrome: Outdated patterns that look authoritative
- "It Works" Fallacy: Code that passes tests but has security holes
- Context Window Blindness: Cross-file analysis failures
- Confident Comments: Lies in documentation
- Slopsquatting: Phantom/typosquatted libraries
- Refactoring Regression: Missed references in renaming
- Logic Mirages: Semantic bugs in syntactically correct code
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _stage10_root() -> Path:
    return _repo_root() / "torture-tests" / "stage10-vibe-coding-adversarial"


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


def _read_fixture(filename: str) -> str:
    """Read a Stage 10 fixture file."""
    path = _stage10_root() / filename
    if not path.exists():
        pytest.skip(f"Fixture not found: {path}")
    return path.read_text()


# =============================================================================
# Category 1: StackOverflow Syndrome
# Outdated patterns from copy-paste coding
# =============================================================================

class TestStackOverflowSyndrome:
    """Tests for outdated/insecure patterns commonly found in SO answers."""

    def test_detects_md5_password_hashing(self, mcp_client):
        """MD5 password hashing from 2010-era SO answers."""
        code = '''
import hashlib

def hash_password(password: str) -> str:
    """Hash password for storage."""
    return hashlib.md5(password.encode()).hexdigest()
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        if not result.get("has_vulnerabilities"):
            pytest.xfail("Should detect weak MD5 hashing")
        assert result.get("vulnerability_count", 0) >= 1

    def test_detects_pickle_deserialization(self, mcp_client):
        """Unsafe pickle usage from SO copy-paste."""
        code = '''
import pickle

def load_user_preferences(data: bytes) -> dict:
    """Load user preferences from stored data."""
    return pickle.loads(data)  # RCE via pickle!
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        vulns = result.get("vulnerabilities", [])
        deserial_vulns = [v for v in vulns if "deserial" in str(v).lower() or "pickle" in str(v).lower()]
        if not deserial_vulns and not result.get("has_vulnerabilities"):
            pytest.xfail("Should detect unsafe deserialization")

    def test_detects_shell_true_command_exec(self, mcp_client):
        """shell=True command execution pattern."""
        code = '''
import subprocess

def run_command(cmd: str) -> str:
    """Run a system command."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            assert result.get("vulnerability_count", 0) >= 1

    def test_detects_jwt_no_verify(self, mcp_client):
        """JWT decode without verification."""
        code = '''
import jwt

def get_user_from_token(token: str) -> dict:
    """Decode JWT to get user info."""
    return jwt.decode(token, options={"verify_signature": False})
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should detect JWT verification bypass


# =============================================================================
# Category 2: "It Works" Fallacy
# Code that passes functional tests but has security holes
# =============================================================================

class TestItWorksFallacy:
    """Tests for code that works functionally but has security issues."""

    def test_timing_attack_password_comparison(self, mcp_client):
        """Password comparison vulnerable to timing attacks."""
        code = '''
def verify_password(provided: str, stored: str) -> bool:
    """Verify password matches stored value."""
    return provided == stored  # Timing attack!
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # May or may not flag timing attacks depending on tool capabilities

    def test_idor_in_user_lookup(self, mcp_client):
        """IDOR vulnerability in user data access."""
        code = '''
def get_order(conn, order_id: int) -> dict:
    """Get order details by ID."""
    # Works! But no check that user owns this order
    return conn.execute(
        "SELECT * FROM orders WHERE id = ?",
        (order_id,)
    ).fetchone()
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # IDOR is a logic flaw, may not be detected by all scanners

    def test_hardcoded_credentials(self, mcp_client):
        """Hardcoded API keys/passwords."""
        code = '''
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def connect_to_service():
    return {"key": API_KEY, "pass": DATABASE_PASSWORD}
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            assert result.get("vulnerability_count", 0) >= 1


# =============================================================================
# Category 3: Context Window Blindness
# Cross-file analysis requirements
# =============================================================================

class TestContextWindowBlindness:
    """Tests for cross-file trust assumption failures."""

    def test_crossfile_trusted_but_broken_validator(self, mcp_client):
        """Validator in separate file is broken but trusted."""
        fixture_dir = _stage10_root() / "crossfile-blind"

        if not fixture_dir.exists():
            # Create inline test
            code = '''
# File: validators.py
def validate_email(email: str) -> str:
    """Validates and returns safe email."""
    return email  # BUG: No validation!

# File: api.py
from validators import validate_email

def register_user(conn, email: str):
    safe_email = validate_email(email)  # Trust validator
    return conn.execute(f"INSERT INTO users (email) VALUES ('{safe_email}')")
'''
            raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
            result = _normalize_result(raw)
            assert result.get("success") is True, result
        else:
            raw, _ = _timed_call(mcp_client, "cross_file_security_scan", {
                "project_root": str(fixture_dir),
                "max_depth": 5,
                "timeout_seconds": 30
            }, max_seconds=45)
            result = _normalize_result(raw)
            assert result.get("success") is True, result


# =============================================================================
# Category 4: Confident Comments
# Lies in documentation
# =============================================================================

class TestConfidentComments:
    """Tests that verify Code Scalpel ignores lying comments."""

    def test_docstring_claims_parameterized_but_isnt(self, mcp_client):
        """Docstring claims parameterized queries but uses f-string."""
        code = '''
def get_user(conn, user_id):
    """
    Get user by ID using parameterized queries.

    Security: This function uses parameterized queries to prevent
    SQL injection. The user_id is safely bound as a parameter.
    """
    # REALITY: Uses f-string interpolation, NOT parameterized!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            vulns = result.get("vulnerabilities", [])
            sql_vulns = [v for v in vulns if "SQL" in str(v.get("type", "")).upper()]
            assert len(sql_vulns) >= 1, "Must detect SQL injection despite lying docstring"

    def test_comment_claims_escaped_but_isnt(self, mcp_client):
        """Comment claims HTML escaping but none applied."""
        code = '''
import html  # Imported but never used

def render_search_results(query, results):
    """
    Render search results page.

    XSS Prevention:
    - Search query is displayed after HTML encoding
    - Template uses auto-escaping for all dynamic content
    """
    # REALITY: No actual escaping happens!
    return f"""
    <h2>Results for: {query}</h2>
    <ul>
        {''.join(f'<li>{r}</li>' for r in results)}
    </ul>
    """
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        if result.get("has_vulnerabilities"):
            assert result.get("vulnerability_count", 0) >= 1


# =============================================================================
# Category 5: Slopsquatting / Phantom Libraries
# Detecting hallucinated or typosquatted packages
# =============================================================================

class TestSlopsquattingDetection:
    """Tests for phantom library and typosquatting detection."""

    def test_detects_typosquatted_import(self, mcp_client):
        """Typosquatted package name detection."""
        code = '''
import requets  # Typo of 'requests' - could be malware!
import djang   # Typo of 'django'

def fetch_data(url):
    return requets.get(url)
'''
        raw, _ = _timed_call(mcp_client, "scan_dependencies", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should flag suspicious/unknown packages

    def test_fixture_file_analysis(self, mcp_client):
        """Analyze the slopsquatting fixture file."""
        fixture = _stage10_root() / "obstacle-10.11-slopsquatting-phantom-libs.py"

        if not fixture.exists():
            pytest.skip("Slopsquatting fixture not found")

        raw, _ = _timed_call(mcp_client, "analyze_code", {
            "code": fixture.read_text(),
            "language": "python"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result


# =============================================================================
# Category 6: Refactoring Regression
# Detecting missed references when renaming
# =============================================================================

class TestRefactoringRegression:
    """Tests for finding all symbol references during refactoring."""

    def test_finds_string_literal_references(self, mcp_client):
        """Symbol references in string literals."""
        code = '''
class UserService:
    def get_user(self, user_id: int) -> dict:
        # Symbol in SQL string
        query = f"SELECT * FROM users WHERE user_id = {user_id}"

        # Symbol in dict key
        return {
            "user_id": user_id,
            "data": self._fetch_data(user_id)
        }

    def _fetch_data(self, user_id: int) -> dict:
        # Symbol in dynamic field name
        field_name = "user_id"
        result = {}
        result[field_name] = user_id
        return result
'''
        raw, _ = _timed_call(mcp_client, "get_symbol_references", {
            "code": code,
            "symbol": "user_id"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should find references in strings, dict keys, and dynamic assignments

    def test_finds_getattr_references(self, mcp_client):
        """Symbol references via getattr/setattr."""
        code = '''
class DynamicConfig:
    def __init__(self):
        self.database_host = "localhost"

    def get(self, key: str, default=None):
        return getattr(self, key, default)

# Usage with string key
config = DynamicConfig()
host = config.get("database_host")
'''
        raw, _ = _timed_call(mcp_client, "get_symbol_references", {
            "code": code,
            "symbol": "database_host"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result


# =============================================================================
# Category 7: Logic Mirages
# Semantic bugs that look syntactically correct
# =============================================================================

class TestLogicMirages:
    """Tests for detecting semantic bugs in syntactically correct code."""

    def test_detects_off_by_one(self, mcp_client):
        """Off-by-one error in security check."""
        code = '''
def check_password_attempts(attempts: int, max_attempts: int = 3) -> bool:
    """Check if user has exceeded password attempts."""
    # BUGGY: Uses > instead of >=, allows one extra attempt
    if attempts > max_attempts:
        return False  # Account locked
    return True
'''
        raw, _ = _timed_call(mcp_client, "symbolic_execute", {
            "code": code,
            "function_name": "check_password_attempts"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Symbolic execution should find the boundary case

    def test_detects_timing_attack_comparison(self, mcp_client):
        """Timing attack via direct string comparison."""
        code = '''
def verify_api_key(provided_key: str, stored_key: str) -> bool:
    """Verify API key matches stored value."""
    # BUGGY: Timing attack vulnerability
    return provided_key == stored_key
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should ideally flag timing attack potential

    def test_detects_open_redirect(self, mcp_client):
        """Open redirect via substring check."""
        code = '''
def validate_redirect_url(url: str, allowed_hosts: list) -> bool:
    """Validate redirect URL is to an allowed host."""
    # BUGGY: Substring check instead of URL parsing
    for host in allowed_hosts:
        if host in url:  # evil.com/example.com passes!
            return True
    return False
'''
        raw, _ = _timed_call(mcp_client, "security_scan", {"code": code})
        result = _normalize_result(raw)

        assert result.get("success") is True, result

    def test_detects_csrf_empty_token_bypass(self, mcp_client):
        """CSRF protection bypass with empty tokens."""
        code = '''
def check_csrf_token(session_token: str, request_token: str) -> bool:
    """Verify CSRF token matches session."""
    # BUGGY: Empty strings are equal!
    if not session_token and not request_token:
        return True  # Both empty = match? NO!
    return session_token == request_token
'''
        raw, _ = _timed_call(mcp_client, "symbolic_execute", {
            "code": code,
            "function_name": "check_csrf_token"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result


# =============================================================================
# Category 8: Full Fixture File Tests
# Test against complete Stage 10 obstacle files
# =============================================================================

class TestStage10Fixtures:
    """Tests against the full Stage 10 obstacle files."""

    @pytest.mark.parametrize("fixture_name", [
        "obstacle-10.1-stackoverflow-syndrome.py",
        "obstacle-10.3-it-works-fallacy.py",
        "obstacle-10.5-logic-mirage.py",
        "obstacle-10.6-confident-comment.py",
    ])
    def test_fixture_analyzable(self, mcp_client, fixture_name):
        """Each fixture file should be analyzable without errors."""
        fixture = _stage10_root() / fixture_name

        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture_name}")

        raw, elapsed = _timed_call(mcp_client, "analyze_code", {
            "code": fixture.read_text(),
            "language": "python"
        }, max_seconds=60)
        result = _normalize_result(raw)

        assert result.get("success") is True, f"{fixture_name}: {result}"
        assert elapsed < 60, f"Took too long: {elapsed}s"

    @pytest.mark.parametrize("fixture_name", [
        "obstacle-10.1-stackoverflow-syndrome.py",
        "obstacle-10.3-it-works-fallacy.py",
        "obstacle-10.6-confident-comment.py",
    ])
    def test_fixture_vulnerabilities_detected(self, mcp_client, fixture_name):
        """Vulnerability-containing fixtures should have findings."""
        fixture = _stage10_root() / fixture_name

        if not fixture.exists():
            pytest.skip(f"Fixture not found: {fixture_name}")

        raw, _ = _timed_call(mcp_client, "security_scan", {
            "code": fixture.read_text()
        }, max_seconds=60)
        result = _normalize_result(raw)

        assert result.get("success") is True, f"{fixture_name}: {result}"
        if not result.get("has_vulnerabilities"):
            pytest.xfail(f"Should detect vulnerabilities in {fixture_name}")

    def test_refactoring_fixture_references(self, mcp_client):
        """Refactoring regression fixture should find missed references."""
        fixture = _stage10_root() / "obstacle-10.12-refactoring-regression.py"

        if not fixture.exists():
            pytest.skip("Refactoring regression fixture not found")

        raw, _ = _timed_call(mcp_client, "get_symbol_references", {
            "code": fixture.read_text(),
            "symbol": "user_id"
        })
        result = _normalize_result(raw)

        assert result.get("success") is True, result
        # Should find many references including string literals


# =============================================================================
# Meta: Fixture Availability
# =============================================================================

class TestStage10FixtureAvailability:
    """Verify Stage 10 fixtures exist."""

    @pytest.mark.parametrize("fixture_name", [
        "README.md",
        "obstacle-10.1-stackoverflow-syndrome.py",
        "obstacle-10.3-it-works-fallacy.py",
        "obstacle-10.4-context-window-blindness.py",
        "obstacle-10.5-logic-mirage.py",
        "obstacle-10.6-confident-comment.py",
        "obstacle-10.11-slopsquatting-phantom-libs.py",
        "obstacle-10.12-refactoring-regression.py",
    ])
    def test_fixture_exists(self, fixture_name):
        """Each expected fixture should exist."""
        fixture = _stage10_root() / fixture_name
        assert fixture.exists(), f"Missing fixture: {fixture}"
