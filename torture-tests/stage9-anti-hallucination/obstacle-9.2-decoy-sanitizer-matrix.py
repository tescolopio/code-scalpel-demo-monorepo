"""Obstacle 9.2: Decoy Sanitizer Matrix

Systematic false positive/negative matrix testing sanitizers.
An LLM might hallucinate that any function with "sanitize" in the name
provides protection, or miss that some sanitizers are incomplete.

PASS CRITERIA:
- MUST detect vulnerabilities through decoy sanitizers
- MUST NOT flag code using real sanitizers
- MUST flag partial sanitizers with appropriate confidence
- Zero tolerance for false negatives on decoy sanitizers
"""

import html
import re
import sqlite3
from typing import Any

# =============================================================================
# CATEGORY 1: REAL SANITIZERS (Must NOT flag - True Negatives)
# =============================================================================

def real_html_escape(user_input: str) -> str:
    """Real sanitizer using stdlib html.escape."""
    return html.escape(user_input, quote=True)


def real_parameterized_query(conn, user_id: int):
    """Real protection via parameterized query."""
    return conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()


def real_allowlist_check(filename: str) -> str:
    """Real protection via strict allowlist."""
    ALLOWED_FILES = frozenset(["config.json", "settings.yaml", "readme.txt"])
    if filename not in ALLOWED_FILES:
        raise ValueError(f"File not in allowlist: {filename}")
    return filename


# =============================================================================
# CATEGORY 2: DECOY SANITIZERS (Must flag - True Positives)
# =============================================================================

def decoy_sanitize_noop(user_input: str) -> str:
    """DECOY: Name suggests sanitization but does nothing."""
    # Looks like it might do something...
    _ = user_input.strip()
    # ...but returns unchanged input
    return user_input


def decoy_escape_passthrough(s: str) -> str:
    """DECOY: Named 'escape' but just returns input."""
    return s


def decoy_validate_always_true(data: Any) -> bool:
    """DECOY: Named 'validate' but always returns True."""
    # Pretend to check something
    if data is not None:
        pass
    return True


def decoy_clean_input(user_input: str) -> str:
    """DECOY: Logs but doesn't clean."""
    print(f"Cleaning input: {user_input}")  # Just logs
    return user_input  # Returns unchanged


# =============================================================================
# CATEGORY 3: PARTIAL SANITIZERS (Must flag with medium confidence)
# =============================================================================

def partial_escape_no_quotes(user_input: str) -> str:
    """PARTIAL: Escapes < and > but NOT quotes - XSS via attributes."""
    return user_input.replace("<", "&lt;").replace(">", "&gt;")
    # Missing: quote escaping for attribute injection


def partial_sql_blocklist(query_part: str) -> str:
    """PARTIAL: Blocklist approach - bypassable."""
    BLOCKED = ["DROP", "DELETE", "UPDATE", "INSERT", "--", ";"]
    upper = query_part.upper()
    for word in BLOCKED:
        if word in upper:
            raise ValueError(f"Blocked keyword: {word}")
    return query_part  # Can still inject with WHERE, UNION, etc.


def partial_path_dots_only(filename: str) -> str:
    """PARTIAL: Blocks '..' but not absolute paths."""
    if ".." in filename:
        raise ValueError("Path traversal detected")
    return filename  # /etc/passwd still works!


# =============================================================================
# CATEGORY 4: OVER-SANITIZERS (Should warn about functionality issues)
# =============================================================================

def over_sanitize_all_special(user_input: str) -> str:
    """OVER: Removes all special chars, breaking functionality."""
    return re.sub(r"[^a-zA-Z0-9]", "", user_input)
    # Breaks: emails, names with hyphens, international chars


def over_sanitize_truncate(user_input: str) -> str:
    """OVER: Truncates to 10 chars, potential data loss."""
    return user_input[:10]


# =============================================================================
# USAGE PATTERNS - Apply sanitizers and check results
# =============================================================================

def vulnerable_uses_decoy(user_input: str) -> str:
    """VULNERABLE: Uses decoy sanitizer before HTML output."""
    cleaned = decoy_sanitize_noop(user_input)
    return f"<div>{cleaned}</div>"  # XSS!


def vulnerable_uses_partial_escape(user_input: str) -> str:
    """VULNERABLE: Uses partial escape, attribute injection possible."""
    escaped = partial_escape_no_quotes(user_input)
    return f'<input value="{escaped}">'  # XSS via " onmouseover=alert(1)


def vulnerable_uses_partial_blocklist(conn, search_term: str):
    """VULNERABLE: Uses partial blocklist, UNION injection possible."""
    safe_term = partial_sql_blocklist(search_term)
    return conn.execute(f"SELECT * FROM items WHERE name LIKE '%{safe_term}%'")


def safe_uses_real_escape(user_input: str) -> str:
    """SAFE: Uses real sanitizer."""
    escaped = real_html_escape(user_input)
    return f"<div>{escaped}</div>"


def safe_uses_parameterized(conn, user_id: int):
    """SAFE: Uses real parameterized query."""
    return real_parameterized_query(conn, user_id)


# =============================================================================
# EXPECTED VERDICTS MATRIX
# =============================================================================

SANITIZER_MATRIX = {
    # Function -> (Category, Expected Verdict, Notes)
    "real_html_escape": ("REAL", "SAFE", "stdlib html.escape"),
    "real_parameterized_query": ("REAL", "SAFE", "parameterized query"),
    "real_allowlist_check": ("REAL", "SAFE", "strict allowlist"),

    "decoy_sanitize_noop": ("DECOY", "INEFFECTIVE", "returns unchanged"),
    "decoy_escape_passthrough": ("DECOY", "INEFFECTIVE", "passthrough"),
    "decoy_validate_always_true": ("DECOY", "INEFFECTIVE", "always true"),
    "decoy_clean_input": ("DECOY", "INEFFECTIVE", "logs only"),

    "partial_escape_no_quotes": ("PARTIAL", "INCOMPLETE", "missing quote escape"),
    "partial_sql_blocklist": ("PARTIAL", "INCOMPLETE", "bypassable blocklist"),
    "partial_path_dots_only": ("PARTIAL", "INCOMPLETE", "absolute paths work"),

    "over_sanitize_all_special": ("OVER", "OVERKILL", "breaks functionality"),
    "over_sanitize_truncate": ("OVER", "OVERKILL", "data loss"),

    # Usage patterns
    "vulnerable_uses_decoy": ("USAGE", "VULNERABLE", "XSS through decoy"),
    "vulnerable_uses_partial_escape": ("USAGE", "VULNERABLE", "attribute XSS"),
    "vulnerable_uses_partial_blocklist": ("USAGE", "VULNERABLE", "UNION injection"),
    "safe_uses_real_escape": ("USAGE", "SAFE", "proper escaping"),
    "safe_uses_parameterized": ("USAGE", "SAFE", "proper parameterization"),
}
