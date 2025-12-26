"""Obstacle 10.4: Context Window Blindness

Patterns where an AI assistant couldn't see relevant code in other files,
leading to incorrect assumptions about security boundaries, validation,
and trust relationships.

This simulates real vibe coding scenarios where:
- AI is asked to write a handler, assuming validation happens elsewhere
- AI trusts "internal" APIs without seeing their implementation
- AI assumes infrastructure (nginx, API gateway) handles security
- AI doesn't see that the "sanitizer" being imported is actually broken

DIFFERENTIATOR: Code Scalpel's cross-file analysis can see the full context
and detect when assumptions about other code are wrong.

PASS CRITERIA:
- Must detect vulnerabilities that require cross-file knowledge
- Must NOT assume validation exists when it doesn't
- Must verify trust boundaries across module boundaries
"""

# =============================================================================
# FILE 1: api_handlers.py - The visible file AI is working on
# =============================================================================

# AI was asked: "Add a handler for user search"
# AI assumed: "Validation is handled by the input_validator module"

from input_validator import validate_user_input  # Imported but what does it do?
from internal_api import get_user_data  # "Internal" API - must be safe, right?
from security_middleware import require_auth  # Decorator exists, must work!


def search_users_handler(request):
    """
    Search for users by query.

    Input validation is handled by the imported validator.
    This endpoint is protected by the auth middleware.
    """
    query = request.get("query")

    # AI assumes validate_user_input actually validates
    # VULNERABLE if validate_user_input is a no-op (spoiler: it is)
    validated_query = validate_user_input(query)

    # AI assumes internal API is safe
    # VULNERABLE if get_user_data has SQL injection (spoiler: it does)
    results = get_user_data(validated_query)

    return {"users": results}


@require_auth  # AI assumes this decorator works
def admin_panel_handler(request):
    """
    Admin panel - protected by authentication.

    The @require_auth decorator ensures only admins can access.
    """
    action = request.get("action")
    target = request.get("target")

    # AI trusts that @require_auth verified admin role
    # VULNERABLE if decorator only checks login, not role
    if action == "delete_user":
        return delete_user(target)
    elif action == "grant_admin":
        return grant_admin(target)

    return {"status": "unknown action"}


def webhook_handler(request):
    """
    Handle incoming webhooks from payment provider.

    Webhooks are only accessible from internal network.
    Security note: Access restricted by nginx to 10.0.0.0/8
    """
    # AI trusts the comment about nginx restriction
    # VULNERABLE: Comment might be wrong, nginx might be misconfigured
    # No verification of webhook signature!
    payment_id = request.get("payment_id")
    status = request.get("status")

    # Process payment without verifying authenticity
    return process_payment_update(payment_id, status)


def file_download_handler(request):
    """
    Download file by ID.

    Files are validated by the upload service before storage.
    We just serve whatever is in the verified_files directory.
    """
    file_id = request.get("file_id")

    # AI assumes upload service validated files
    # VULNERABLE: path traversal via file_id
    # file_id = "../../../etc/passwd"
    filepath = f"/verified_files/{file_id}"

    return serve_file(filepath)


# =============================================================================
# FILE 2: input_validator.py - The broken validator AI can't see
# =============================================================================

def validate_user_input(data):
    """
    Validate user input for safety.

    This function validates input and returns sanitized data.
    """
    # REALITY: This does NOTHING
    # A developer stubbed this out and forgot to implement it
    # AI assuming this provides protection is WRONG

    # TODO: Implement actual validation
    # For now, just return input unchanged
    return data


def sanitize_html(html_string):
    """Sanitize HTML to prevent XSS."""
    # REALITY: Only removes <script> tags, misses everything else
    return html_string.replace("<script>", "").replace("</script>", "")


# =============================================================================
# FILE 3: internal_api.py - The vulnerable "internal" API
# =============================================================================

def get_user_data(search_query):
    """
    Get user data from database.

    This is an internal API, only called by trusted services.
    """
    # REALITY: Has SQL injection because it's "internal"
    # Developer assumed internal callers are safe
    import sqlite3
    conn = sqlite3.connect("users.db")

    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE name LIKE '%{search_query}%'"
    return conn.execute(query).fetchall()


def get_user_by_id(user_id):
    """Get user by ID - internal use only."""
    # VULNERABLE: Also SQL injection, "internal" doesn't mean safe
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)


def log_action(user_id, action, details):
    """Log admin action - internal audit trail."""
    # VULNERABLE: Log injection via details
    # If details contains newlines, can forge log entries
    log_entry = f"[{user_id}] {action}: {details}\n"
    with open("/var/log/admin.log", "a") as f:
        f.write(log_entry)


# =============================================================================
# FILE 4: security_middleware.py - The incomplete middleware
# =============================================================================

def require_auth(func):
    """
    Decorator to require authentication.

    Ensures user is logged in before accessing endpoint.
    """
    def wrapper(request, *args, **kwargs):
        session = request.get("session")

        # VULNERABLE: Only checks if session exists, not role!
        # Any logged-in user can access admin endpoints
        if not session or not session.get("user_id"):
            raise PermissionError("Not authenticated")

        # Should check: session.get("role") == "admin"
        # But this check is missing!

        return func(request, *args, **kwargs)
    return wrapper


def require_admin(func):
    """
    Decorator to require admin role.

    This decorator exists but is NEVER USED.
    Developers use require_auth thinking it's the same.
    """
    def wrapper(request, *args, **kwargs):
        session = request.get("session")

        if not session:
            raise PermissionError("Not authenticated")

        if session.get("role") != "admin":
            raise PermissionError("Admin required")

        return func(request, *args, **kwargs)
    return wrapper


# =============================================================================
# FILE 5: config.py - Dangerous defaults AI can't see
# =============================================================================

# AI asks for config values, gets them, doesn't see the defaults

DEBUG = True  # "Temporarily" enabled 2 years ago

SECRET_KEY = "development-secret-key-change-in-prod"  # Never changed

DATABASE_URL = "sqlite:///app.db"

# These get imported and used throughout the app
CORS_ORIGINS = ["*"]  # Allow all origins!

RATE_LIMIT_ENABLED = False  # Disabled for "testing"

CSRF_PROTECTION = False  # "Conflicts with mobile app"


# =============================================================================
# FILE 6: utils.py - Helper functions with hidden vulnerabilities
# =============================================================================

import os
import subprocess


def get_env_or_default(key, default):
    """Get environment variable or return default."""
    # VULNERABLE: Defaults are used more often than env vars
    # AI sees get_env_or_default("API_KEY", "...") and thinks it's configurable
    # Reality: No one sets env vars, defaults always used
    return os.environ.get(key, default)


def run_report(report_name, format_type):
    """Run a report generation script."""
    # Called from: generate_sales_report(request.get("report_name"))
    # AI doesn't see the caller, doesn't know report_name is user-controlled

    # VULNERABLE: Command injection via report_name
    script = f"/scripts/reports/{report_name}.sh"
    subprocess.run(f"bash {script} --format {format_type}", shell=True)


def read_template(template_name):
    """Read a template file."""
    # VULNERABLE: Path traversal
    # Called with user input from template_handler that AI wrote
    path = f"/templates/{template_name}"
    with open(path) as f:
        return f.read()


# =============================================================================
# CROSS-FILE VULNERABILITY CHAINS
# These require seeing multiple files to understand the vulnerability
# =============================================================================

CROSS_FILE_CHAINS = [
    {
        "name": "Validation Bypass Chain",
        "files": ["api_handlers.py", "input_validator.py"],
        "description": "Handler trusts validate_user_input which does nothing",
        "vulnerability": "SQL Injection",
        "entry": "search_users_handler",
        "sink": "get_user_data",
    },
    {
        "name": "Privilege Escalation Chain",
        "files": ["api_handlers.py", "security_middleware.py"],
        "description": "@require_auth only checks login, not admin role",
        "vulnerability": "Broken Access Control",
        "entry": "admin_panel_handler",
        "missing_check": "role == 'admin'",
    },
    {
        "name": "Internal API Trust Chain",
        "files": ["api_handlers.py", "internal_api.py"],
        "description": "Internal API has SQL injection, caller trusts it",
        "vulnerability": "SQL Injection",
        "entry": "search_users_handler",
        "sink": "get_user_data (internal)",
    },
    {
        "name": "Config Default Chain",
        "files": ["api_handlers.py", "config.py"],
        "description": "DEBUG=True, CSRF_PROTECTION=False in config",
        "vulnerability": "Security Misconfiguration",
        "dangerous_defaults": ["DEBUG", "CSRF_PROTECTION", "CORS_ORIGINS"],
    },
    {
        "name": "Utility Function Chain",
        "files": ["any_handler.py", "utils.py"],
        "description": "run_report and read_template have injection",
        "vulnerability": "Command Injection / Path Traversal",
        "sinks": ["run_report", "read_template"],
    },
]


# =============================================================================
# EXPECTED VERDICTS
# =============================================================================

CONTEXT_BLINDNESS_PATTERNS = {
    # When analyzing api_handlers.py alone, AI might miss these
    "search_users_handler": ("SQL Injection via broken validator", "HIGH"),
    "admin_panel_handler": ("Privilege Escalation via weak auth", "CRITICAL"),
    "webhook_handler": ("Missing Webhook Signature Verification", "HIGH"),
    "file_download_handler": ("Path Traversal", "HIGH"),

    # The hidden broken functions
    "validate_user_input": ("No-op Validator", "CRITICAL"),
    "sanitize_html": ("Incomplete XSS Sanitization", "HIGH"),
    "get_user_data": ("SQL Injection in 'Internal' API", "CRITICAL"),
    "require_auth": ("Missing Role Check", "HIGH"),

    # Dangerous configs
    "DEBUG": ("Debug Mode Enabled", "HIGH"),
    "SECRET_KEY": ("Hardcoded Secret Key", "CRITICAL"),
    "CORS_ORIGINS": ("Permissive CORS", "MEDIUM"),
    "CSRF_PROTECTION": ("CSRF Disabled", "HIGH"),
}
