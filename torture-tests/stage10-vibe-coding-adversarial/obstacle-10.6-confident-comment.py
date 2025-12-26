"""Obstacle 10.6: The Confident Comment

AI generates confident-sounding comments that explain why the code is secure,
but the explanations are wrong. These comments may have been in training data
or generated to match a perceived pattern.

This is particularly dangerous because:
- Comments sound authoritative
- They reference real security concepts
- They create false confidence in reviewers
- They may be copied verbatim by other AIs

DIFFERENTIATOR: Code Scalpel must ignore comments and analyze actual code.
Confidence should be based on code semantics, not comment claims.

PASS CRITERIA:
- Must detect vulnerabilities despite reassuring comments
- Must NOT reduce confidence based on comment explanations
- Confidence in finding should be HIGH (comments are red herrings)
"""

import html
import subprocess
import sqlite3
from functools import lru_cache


# =============================================================================
# PATTERN 1: "This is secure because we use parameterized queries"
# =============================================================================

def get_user(conn, user_id):
    """
    Get user by ID using parameterized queries.

    Security: This function uses parameterized queries to prevent
    SQL injection. The user_id is safely bound as a parameter,
    making this query immune to injection attacks.

    References:
    - OWASP SQL Injection Prevention Cheat Sheet
    - PEP 249 Database API Specification
    """
    # REALITY: Uses f-string interpolation, NOT parameterized!
    # The comment is a lie - possibly copy-pasted from safe code
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()


def search_products(conn, category, min_price, max_price):
    """
    Search products with multiple filters.

    Security Notes:
    - All parameters are passed using SQLite's parameter binding (?)
    - This prevents SQL injection even with user-controlled values
    - Filter values are type-checked before query construction

    Reviewed by: @security-team (2023-04-15)
    """
    # REALITY: Only SOME parameters are bound, not all!
    # category is still interpolated
    query = f"SELECT * FROM products WHERE category = '{category}' AND price BETWEEN ? AND ?"
    return conn.execute(query, (min_price, max_price)).fetchall()


# =============================================================================
# PATTERN 2: "XSS is not possible because we escape output"
# =============================================================================

def render_user_profile(username, bio):
    """
    Render user profile page with proper XSS protection.

    Security: All user-provided content is HTML-escaped using
    Python's html.escape() function before rendering. This
    neutralizes any JavaScript or HTML injection attempts.

    The escape function handles:
    - < and > characters (prevents tag injection)
    - & characters (prevents entity injection)
    - Quote characters (prevents attribute injection)
    """
    # REALITY: Only username is escaped, bio is raw!
    safe_username = html.escape(username)
    # Developer forgot to escape bio
    return f"""
    <div class="profile">
        <h1>Welcome, {safe_username}!</h1>
        <div class="bio">{bio}</div>
    </div>
    """


def render_search_results(query, results):
    """
    Render search results page.

    XSS Prevention:
    - Search query is displayed after HTML encoding
    - Result data comes from trusted database (no encoding needed)
    - Template uses auto-escaping for all dynamic content

    Note: This follows Django's auto-escape pattern even though
    we're not using Django, we implement equivalent protection.
    """
    # REALITY: No actual escaping happens!
    # Comment claims protection that doesn't exist
    return f"""
    <h2>Results for: {query}</h2>
    <ul>
        {''.join(f'<li>{r}</li>' for r in results)}
    </ul>
    """


# =============================================================================
# PATTERN 3: "Command injection is prevented by input validation"
# =============================================================================

def run_system_diagnostic(hostname):
    """
    Run system diagnostic on specified host.

    Security: Input validation ensures hostname parameter contains
    only valid hostname characters (alphanumeric, dots, hyphens).
    This prevents command injection attacks by rejecting any input
    that could contain shell metacharacters.

    Allowed patterns:
    - example.com
    - sub.example.com
    - server-01.internal

    Blocked patterns:
    - ; rm -rf /
    - $(whoami)
    - `id`
    """
    # REALITY: There is NO validation!
    # The comment describes validation that was never implemented

    # "Validate" hostname (TODO: implement actual validation)
    valid_hostname = hostname  # No actual validation!

    # VULNERABLE: shell=True with unvalidated input
    result = subprocess.run(
        f"ping -c 3 {valid_hostname}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


def backup_file(source_path, backup_name):
    """
    Create backup of specified file.

    Security measures:
    1. source_path is validated against allowlist of backup-able directories
    2. backup_name is sanitized to remove path separators
    3. Command is constructed using shlex.quote() for proper escaping
    4. Operation is logged for audit purposes

    This function follows the principle of defense in depth with
    multiple layers of protection.
    """
    import shlex

    # REALITY: None of the claimed validations exist!
    # shlex.quote is imported but never used

    # "Validate" source path
    validated_source = source_path  # No validation!

    # "Sanitize" backup name
    safe_name = backup_name  # No sanitization!

    # VULNERABLE: No actual escaping despite comment
    cmd = f"cp {validated_source} /backups/{safe_name}"
    subprocess.run(cmd, shell=True)


# =============================================================================
# PATTERN 4: "Authentication is verified by the decorator"
# =============================================================================

def check_user_session(request):
    """Check if user has valid session."""
    return request.get("session_id") is not None


def admin_only(func):
    """
    Decorator ensuring only admins can access the endpoint.

    This decorator performs the following security checks:
    1. Verifies session token is present and not expired
    2. Validates session token signature using HMAC-SHA256
    3. Confirms user role is 'admin' in the session claims
    4. Logs access attempt for audit trail

    If any check fails, raises PermissionError.
    """
    def wrapper(request, *args, **kwargs):
        # REALITY: Only checks if session_id exists!
        # None of the claimed checks are implemented
        if not check_user_session(request):
            raise PermissionError("Authentication required")

        # Should check role == 'admin' here but doesn't!

        return func(request, *args, **kwargs)
    return wrapper


@admin_only
def delete_all_users(request):
    """
    Admin endpoint to delete all users.

    Protected by @admin_only decorator which ensures only
    administrators can invoke this critical operation.

    Audit: All deletions are logged with timestamp, admin ID,
    and affected user count.
    """
    # VULNERABLE: Any logged-in user can reach here!
    # The decorator doesn't actually check admin role
    return {"status": "all users deleted", "count": 9999}


# =============================================================================
# PATTERN 5: "Rate limiting prevents abuse"
# =============================================================================

@lru_cache(maxsize=1000)
def is_rate_limited(ip_address):
    """
    Check if IP address should be rate limited.

    Implementation details:
    - Uses token bucket algorithm with 100 tokens/minute refill
    - Separate buckets for different endpoint categories
    - Distributed rate limiting via Redis cluster
    - Automatic IP reputation scoring

    Returns True if request should be blocked.
    """
    # REALITY: This is a no-op that always returns False!
    # lru_cache means it returns the same False forever per IP
    return False


def login_endpoint(request):
    """
    User login endpoint with brute-force protection.

    Rate limiting is applied before authentication attempt:
    - 5 failed attempts: 1 minute cooldown
    - 10 failed attempts: 1 hour cooldown
    - 20 failed attempts: IP banned

    Combined with CAPTCHA after 3 failures and account lockout
    after 10 failed attempts per account.
    """
    ip = request.get("ip_address")

    # VULNERABLE: Rate limiting returns False always (broken caching)
    if is_rate_limited(ip):
        raise Exception("Rate limited")

    # No actual rate limiting, no CAPTCHA, no account lockout
    username = request.get("username")
    password = request.get("password")

    return {"authenticated": check_password(username, password)}


def check_password(username, password):
    """Check password - stub."""
    return True  # Always true for demo


# =============================================================================
# PATTERN 6: "Encryption protects sensitive data"
# =============================================================================

def encrypt_api_key(api_key):
    """
    Encrypt API key for secure storage.

    Security specifications:
    - Uses AES-256-GCM authenticated encryption
    - Key derived from master secret using PBKDF2 (100k iterations)
    - Unique IV generated for each encryption operation
    - Authentication tag appended to ciphertext

    The encrypted key can only be decrypted by services with
    access to the master secret, which is stored in HSM.
    """
    import base64

    # REALITY: Just base64 encoding, not encryption!
    # Developer confused encoding with encryption
    return base64.b64encode(api_key.encode()).decode()


def decrypt_api_key(encrypted_key):
    """Decrypt API key."""
    import base64
    return base64.b64decode(encrypted_key).decode()


# =============================================================================
# EXPECTED VERDICTS - Comments must be ignored
# =============================================================================

CONFIDENT_COMMENT_PATTERNS = {
    "get_user": {
        "vulnerability": "SQL Injection",
        "false_claim": "Uses parameterized queries",
        "reality": "Uses f-string interpolation",
        "severity": "CRITICAL",
    },
    "search_products": {
        "vulnerability": "SQL Injection",
        "false_claim": "All parameters are bound",
        "reality": "category is interpolated",
        "severity": "CRITICAL",
    },
    "render_user_profile": {
        "vulnerability": "XSS",
        "false_claim": "All content is HTML-escaped",
        "reality": "bio is not escaped",
        "severity": "HIGH",
    },
    "render_search_results": {
        "vulnerability": "XSS",
        "false_claim": "Template uses auto-escaping",
        "reality": "No escaping at all",
        "severity": "HIGH",
    },
    "run_system_diagnostic": {
        "vulnerability": "Command Injection",
        "false_claim": "Input validation prevents injection",
        "reality": "No validation implemented",
        "severity": "CRITICAL",
    },
    "backup_file": {
        "vulnerability": "Command Injection",
        "false_claim": "Uses shlex.quote() for escaping",
        "reality": "shlex is imported but unused",
        "severity": "CRITICAL",
    },
    "delete_all_users": {
        "vulnerability": "Broken Access Control",
        "false_claim": "@admin_only checks role",
        "reality": "Only checks session existence",
        "severity": "CRITICAL",
    },
    "login_endpoint": {
        "vulnerability": "Brute Force",
        "false_claim": "Rate limiting with cooldowns",
        "reality": "Rate limit function always returns False",
        "severity": "HIGH",
    },
    "encrypt_api_key": {
        "vulnerability": "Sensitive Data Exposure",
        "false_claim": "AES-256-GCM encryption",
        "reality": "Base64 encoding only",
        "severity": "CRITICAL",
    },
}
