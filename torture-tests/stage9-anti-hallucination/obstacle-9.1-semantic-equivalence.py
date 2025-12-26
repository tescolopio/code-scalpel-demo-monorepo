"""Obstacle 9.1: Semantic Equivalence Trap

Tests that Code Scalpel produces IDENTICAL verdicts for semantically
equivalent code patterns. An LLM without proper tooling might hallucinate
different risk levels based on superficial syntax differences.

PASS CRITERIA:
- All pairs of semantically equivalent code must receive the same verdict
- Confidence scores must be within 5% of each other
- No false divergence based on syntax preference
"""

import sqlite3

# =============================================================================
# PAIR 1: Ternary vs If-Else (Both VULNERABLE - SQL Injection)
# =============================================================================

def vuln_ternary_style(user_id):
    """SQL injection using ternary expression."""
    query = f"SELECT * FROM users WHERE id = {user_id}" if user_id else "SELECT 1"
    return sqlite3.connect(":memory:").execute(query)


def vuln_ifelse_style(user_id):
    """SQL injection using if-else block - SEMANTICALLY IDENTICAL."""
    if user_id:
        query = f"SELECT * FROM users WHERE id = {user_id}"
    else:
        query = "SELECT 1"
    return sqlite3.connect(":memory:").execute(query)


# =============================================================================
# PAIR 2: Loop vs Comprehension (Both VULNERABLE - Command Injection)
# =============================================================================
import subprocess

def vuln_loop_style(commands):
    """Command injection via loop."""
    results = []
    for cmd in commands:
        results.append(subprocess.run(cmd, shell=True, capture_output=True))
    return results


def vuln_comprehension_style(commands):
    """Command injection via comprehension - SEMANTICALLY IDENTICAL."""
    return [subprocess.run(cmd, shell=True, capture_output=True) for cmd in commands]


# =============================================================================
# PAIR 3: Class Method vs Module Function (Both SAFE - Parameterized)
# =============================================================================

class SafeQueryBuilder:
    """Safe queries via class method."""

    def __init__(self, conn):
        self.conn = conn

    def get_user(self, user_id):
        return self.conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


def safe_get_user(conn, user_id):
    """Safe query via module function - SEMANTICALLY IDENTICAL."""
    return conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()


# =============================================================================
# PAIR 4: Inline vs Extracted (Both VULNERABLE - XSS)
# =============================================================================

def vuln_inline_xss(username):
    """XSS with inline HTML construction."""
    return f"<div class='user'>{username}</div>"


def _build_div(content):
    return f"<div class='user'>{content}</div>"

def vuln_extracted_xss(username):
    """XSS with extracted helper - SEMANTICALLY IDENTICAL."""
    return _build_div(username)


# =============================================================================
# PAIR 5: Sync vs Async (Both VULNERABLE - Path Traversal)
# =============================================================================

def vuln_sync_read(filename):
    """Path traversal via sync read."""
    with open(f"/data/{filename}", "r") as f:
        return f.read()


async def vuln_async_read(filename):
    """Path traversal via async read - SEMANTICALLY IDENTICAL vulnerability."""
    import aiofiles
    async with aiofiles.open(f"/data/{filename}", "r") as f:
        return await f.read()


# =============================================================================
# PAIR 6: With vs Without Type Hints (Both SAFE)
# =============================================================================

def safe_add_untyped(a, b):
    return a + b


def safe_add_typed(a: int, b: int) -> int:
    return a + b


# =============================================================================
# EXPECTED VERDICTS - Code Scalpel must match these exactly
# =============================================================================

EXPECTED_EQUIVALENCES = [
    # (func1, func2, expected_verdict, max_confidence_delta)
    ("vuln_ternary_style", "vuln_ifelse_style", "VULNERABLE", 0.05),
    ("vuln_loop_style", "vuln_comprehension_style", "VULNERABLE", 0.05),
    ("SafeQueryBuilder.get_user", "safe_get_user", "SAFE", 0.05),
    ("vuln_inline_xss", "vuln_extracted_xss", "VULNERABLE", 0.05),
    ("vuln_sync_read", "vuln_async_read", "VULNERABLE", 0.10),  # Async might have lower confidence
    ("safe_add_untyped", "safe_add_typed", "SAFE", 0.05),
]
