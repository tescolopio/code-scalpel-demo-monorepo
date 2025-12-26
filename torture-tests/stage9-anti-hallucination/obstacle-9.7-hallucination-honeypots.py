"""Obstacle 9.7: Hallucination Honeypots

Code patterns that commonly cause LLM hallucinations without proper tooling.
Each pattern exploits a known LLM failure mode:
- Trusting comments over code
- Pattern matching on names
- Assuming imports mean usage
- Copy-paste context confusion

PASS CRITERIA:
- Code Scalpel MUST analyze actual behavior, not surface patterns
- Zero tolerance for comment-based verdicts
- Must flag all actual vulnerabilities regardless of surrounding context
"""

import hashlib
import secrets
import subprocess
from typing import Optional

# =============================================================================
# HONEYPOT 1: The Lying Comment
# LLMs often trust comments. This comment is completely wrong.
# =============================================================================

def encrypt_password(password: str) -> str:
    """
    Encrypts password using industry-standard bcrypt with cost factor 12.

    This implementation follows OWASP guidelines for secure password storage.
    The bcrypt algorithm provides protection against rainbow table attacks
    and is computationally expensive to brute force.

    Returns:
        str: The bcrypt hash of the password, safe for database storage.
    """
    # REALITY: Just returns the password with "encrypted_" prefix
    # The entire docstring is a LIE copied from somewhere else
    return f"encrypted_{password}"  # VULNERABLE: Plaintext storage!


# =============================================================================
# HONEYPOT 2: The Unused Import
# LLMs might hallucinate that imported security libs mean security is applied
# =============================================================================

import html  # Imported but NEVER used below
import sqlite3
import paramiko  # Red herring - suggests SSH security

def render_user_profile(username: str) -> str:
    """Render user profile page."""
    # Note: html module imported above for escaping
    # BUG: Developer forgot to actually USE html.escape()
    return f"<h1>Welcome, {username}!</h1>"  # VULNERABLE: XSS


# =============================================================================
# HONEYPOT 3: The Misleading Variable Name
# Variable named "sanitized" but the value is not actually sanitized
# =============================================================================

def process_command(user_command: str) -> str:
    """Process a user command after sanitization."""

    # This LOOKS like sanitization...
    sanitized_command = user_command  # ...but it's just assignment!

    # Developer thought the variable name was enough
    result = subprocess.run(
        sanitized_command,  # VULNERABLE: Command injection
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


# =============================================================================
# HONEYPOT 4: The Copied Docstring from Safe Code
# Docstring was copied from a different, safe function
# =============================================================================

def get_user_by_id(conn, user_id: str):
    """
    Safely retrieves user by ID using parameterized queries.

    Args:
        conn: Database connection
        user_id: The user ID to look up (will be safely parameterized)

    Returns:
        User record or None if not found

    Security:
        Uses parameterized queries to prevent SQL injection.
        The user_id is never interpolated into the query string.
    """
    # REALITY: Uses f-string interpolation (the docstring is a lie)
    query = f"SELECT * FROM users WHERE id = '{user_id}'"  # VULNERABLE!
    return conn.execute(query).fetchone()


# =============================================================================
# HONEYPOT 5: The False Positive Trap
# This code LOOKS dangerous but is actually safe
# =============================================================================

def execute_query(conn, table_name: str, conditions: dict) -> list:
    """
    Execute a query that LOOKS like SQL injection but is safe.

    The table_name appears to be interpolated, but it comes from
    an internal allowlist, not user input.
    """
    # This looks like injection...
    ALLOWED_TABLES = frozenset(["users", "products", "orders"])

    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table: {table_name}")

    # ...but table_name is validated above (allowlist)
    # The conditions use parameterized queries
    where_parts = []
    params = []
    for key, value in conditions.items():
        if key not in ("id", "name", "status"):  # Allowlist columns too
            raise ValueError(f"Invalid column: {key}")
        where_parts.append(f"{key} = ?")
        params.append(value)

    where_clause = " AND ".join(where_parts) if where_parts else "1=1"
    query = f"SELECT * FROM {table_name} WHERE {where_clause}"  # SAFE!

    return conn.execute(query, params).fetchall()


# =============================================================================
# HONEYPOT 6: The TODO That Never Got Done
# TODO comment suggests future fix, but the vulnerability is current
# =============================================================================

def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data before storage."""

    # TODO: Switch to bcrypt once performance testing is complete
    # TODO: Add salt when we migrate to v2 API
    # FIXME: This is temporary, will be replaced in JIRA-1234

    # "Temporary" code that's been in production for 3 years:
    return hashlib.md5(data.encode()).hexdigest()  # VULNERABLE: Weak hash!


# =============================================================================
# HONEYPOT 7: The Validation That Validates Nothing
# Function has "validate" in name and returns bool, but doesn't validate
# =============================================================================

def validate_user_input(user_input: str) -> bool:
    """
    Validates user input for safety.

    Returns:
        True if input is safe, False otherwise.
    """
    # "Validation" that always passes
    if user_input is not None:
        # Log for auditing
        print(f"Input validated: {user_input[:20]}...")

    # Developer assumed truthy check was validation
    return bool(user_input)  # Just checks non-empty!


def use_validated_input(conn, user_input: str):
    """Uses input after 'validation'."""
    if validate_user_input(user_input):
        # Developer trusts the "validation"
        return conn.execute(
            f"INSERT INTO logs (data) VALUES ('{user_input}')"  # VULNERABLE!
        )
    return None


# =============================================================================
# HONEYPOT 8: The Import Alias Confusion
# Import aliases hide the true nature of the module
# =============================================================================

import os as secure_os  # Alias suggests security but it's just os
import subprocess as safe_exec  # Alias is misleading

def run_safe_command(cmd: str) -> str:
    """Run command using the 'safe' execution module."""
    # LLM might think "safe_exec" provides protection
    result = safe_exec.run(
        cmd,
        shell=True,  # VULNERABLE!
        capture_output=True,
        text=True
    )
    return result.stdout


# =============================================================================
# HONEYPOT 9: The Type Hint Lie
# Type hints suggest safety but runtime allows anything
# =============================================================================

def process_integer_id(user_id: int) -> dict:
    """
    Process a user ID that is guaranteed to be an integer.

    Args:
        user_id: Integer user ID (type-checked at runtime)
    """
    # Type hint says int, but Python doesn't enforce at runtime
    # An attacker can pass a string
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE!
    # Even with type hint, no runtime check prevents string injection
    return {"query": query}


# =============================================================================
# EXPECTED VERDICTS
# =============================================================================

HONEYPOT_MATRIX = {
    # Lying Comments - MUST analyze code, not docs
    "encrypt_password": ("LYING_COMMENT", "VULNERABLE", "plaintext storage despite bcrypt docstring"),

    # Unused Imports - MUST check if imports are used
    "render_user_profile": ("UNUSED_IMPORT", "VULNERABLE", "html imported but not used"),

    # Misleading Names - MUST analyze data flow, not variable names
    "process_command": ("MISLEADING_NAME", "VULNERABLE", "sanitized_command not sanitized"),

    # Copied Docstrings - MUST analyze code, not docs
    "get_user_by_id": ("COPIED_DOC", "VULNERABLE", "docstring lies about parameterization"),

    # False Positive Trap - MUST detect the allowlist makes it safe
    "execute_query": ("FALSE_POSITIVE_TRAP", "SAFE", "allowlist validation present"),

    # Incomplete TODOs - MUST flag current vulnerability, not future plans
    "hash_sensitive_data": ("TODO_TRAP", "VULNERABLE", "MD5 despite TODO for bcrypt"),

    # Fake Validation - MUST analyze what validation actually does
    "validate_user_input": ("FAKE_VALIDATION", "INEFFECTIVE", "just checks non-empty"),
    "use_validated_input": ("FAKE_VALIDATION", "VULNERABLE", "validation provides no protection"),

    # Import Alias - MUST use actual module, not alias name
    "run_safe_command": ("ALIAS_CONFUSION", "VULNERABLE", "safe_exec is just subprocess"),

    # Type Hint Lie - MUST know Python doesn't enforce types at runtime
    "process_integer_id": ("TYPE_LIE", "VULNERABLE", "type hints don't prevent string input"),
}
