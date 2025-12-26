"""Obstacle 10.5: Logic Mirage

Code that looks syntactically correct and passes basic tests but contains
semantic bugs that cause runtime failures or security issues.

LLMs generate code that "looks right" based on patterns but may:
- Have off-by-one errors in edge cases
- Implement incorrect algorithm logic
- Miss edge cases that only appear in production
- Use wrong comparison operators
- Have subtle race conditions
- Implement incorrect business logic

DIFFERENTIATOR: Code Scalpel uses symbolic execution and semantic analysis
to detect logic bugs that syntax-based tools miss.

PASS CRITERIA:
- symbolic_execute must find paths to buggy conditions
- analyze_code must flag semantic inconsistencies
- security_scan must detect logic-based vulnerabilities
"""

import hashlib
import hmac
import time
from typing import Optional, List
from threading import Lock


# =============================================================================
# CATEGORY 1: Off-By-One Errors
# Classic bugs that LLMs frequently generate
# =============================================================================

def check_password_attempts(attempts: int, max_attempts: int = 3) -> bool:
    """Check if user has exceeded password attempts.

    LOGIC BUG: Off-by-one allows one extra attempt.
    Should be `attempts >= max_attempts` but uses `>`.
    """
    # BUGGY: Allows 4 attempts when max is 3
    if attempts > max_attempts:  # Should be >=
        return False  # Account locked
    return True  # Allow attempt


def get_page_items(items: list, page: int, per_page: int = 10) -> list:
    """Get items for a specific page.

    LOGIC BUG: Last page shows duplicate items from previous page.
    """
    start = page * per_page  # Should be (page - 1) * per_page if 1-indexed
    end = start + per_page
    # BUGGY: If page is 1-indexed (common), this returns wrong slice
    return items[start:end]


def validate_age(age: int) -> bool:
    """Validate user age is within acceptable range.

    LOGIC BUG: Boundary condition wrong, allows age 0.
    """
    # BUGGY: Should be age > 0 or age >= 1
    if age >= 0 and age <= 120:  # age=0 is invalid but accepted
        return True
    return False


# =============================================================================
# CATEGORY 2: Comparison Operator Errors
# Wrong operators that look correct at first glance
# =============================================================================

def is_admin_or_owner(user_id: int, resource_owner_id: int, user_role: str) -> bool:
    """Check if user can access resource.

    LOGIC BUG: Uses 'or' instead of checking both conditions properly.
    Any authenticated user with role != 'admin' can pass if they're owner,
    but the role check is inverted.
    """
    # BUGGY: Inverted logic - should check role == 'admin'
    if user_role != 'admin' or user_id == resource_owner_id:
        return True
    return False


def check_discount_eligibility(total: float, member: bool) -> float:
    """Calculate discount based on total and membership.

    LOGIC BUG: Comparison should be >= not > for boundary.
    """
    # BUGGY: Customer with exactly $100 gets no discount
    if total > 100 and member:  # Should be >= 100
        return 0.15  # 15% discount
    elif total > 50:  # Should be >= 50
        return 0.05  # 5% discount
    return 0.0


def should_rate_limit(request_count: int, time_window: int) -> bool:
    """Determine if request should be rate limited.

    LOGIC BUG: Wrong operator causes rate limit to never trigger.
    """
    requests_per_second = request_count / max(time_window, 1)
    # BUGGY: Uses < instead of > - limits normal users, allows attackers
    if requests_per_second < 10:  # Should be > 10
        return True
    return False


# =============================================================================
# CATEGORY 3: Null/None Handling Bugs
# LLMs often miss None edge cases
# =============================================================================

def get_user_display_name(user: Optional[dict]) -> str:
    """Get display name for user.

    LOGIC BUG: Checks user but not nested fields.
    """
    if user:
        # BUGGY: user['profile'] might be None
        return user['profile']['display_name']  # KeyError if profile is None
    return "Anonymous"


def safe_divide(a: float, b: float) -> float:
    """Safely divide two numbers.

    LOGIC BUG: Checks for zero but not None.
    """
    # BUGGY: Doesn't handle None inputs
    if b == 0:
        return 0.0
    return a / b  # TypeError if a or b is None


def merge_configs(base: dict, override: Optional[dict]) -> dict:
    """Merge two configuration dictionaries.

    LOGIC BUG: Shallow copy causes mutation of original.
    """
    if override is None:
        return base
    # BUGGY: Shallow copy, nested dicts still reference originals
    result = base.copy()
    result.update(override)  # Overwrites, doesn't deep merge
    return result


# =============================================================================
# CATEGORY 4: String Comparison Bugs
# Subtle issues with string handling
# =============================================================================

def verify_api_key(provided_key: str, stored_key: str) -> bool:
    """Verify API key matches stored value.

    LOGIC BUG: Direct comparison vulnerable to timing attack.
    """
    # BUGGY: Timing attack vulnerability - should use hmac.compare_digest
    return provided_key == stored_key


def normalize_email(email: str) -> str:
    """Normalize email address for comparison.

    LOGIC BUG: Only lowercases, doesn't handle + aliases or spaces.
    """
    # BUGGY: Incomplete normalization
    # "User+Alias@Gmail.com" != "user@gmail.com"
    # Also doesn't strip whitespace
    return email.lower()


def check_file_extension(filename: str, allowed: List[str]) -> bool:
    """Check if file extension is allowed.

    LOGIC BUG: Case-sensitive comparison and doesn't handle double extensions.
    """
    # BUGGY: "file.JPG" fails if allowed = [".jpg"]
    # BUGGY: "file.jpg.exe" passes if ".jpg" is allowed
    ext = filename[filename.rfind('.'):]
    return ext in allowed


# =============================================================================
# CATEGORY 5: Time and Date Bugs
# Timezone and timing issues
# =============================================================================

def is_token_valid(token_issued: int, ttl_seconds: int = 3600) -> bool:
    """Check if token is still valid.

    LOGIC BUG: Uses local time without timezone consideration.
    """
    # BUGGY: time.time() returns local time, token might use UTC
    current_time = time.time()
    return current_time - token_issued < ttl_seconds


def calculate_subscription_end(start_date, months: int):
    """Calculate subscription end date.

    LOGIC BUG: Naive month addition doesn't handle varying month lengths.
    """
    from datetime import datetime, timedelta

    # BUGGY: Adding 30 days * months != adding months
    # Jan 31 + 1 month should be Feb 28, not Mar 2
    end_date = start_date + timedelta(days=30 * months)
    return end_date


def check_business_hours(timestamp: float) -> bool:
    """Check if timestamp is during business hours (9 AM - 5 PM).

    LOGIC BUG: Ignores timezone - 9 AM where?
    """
    from datetime import datetime

    # BUGGY: No timezone handling - 9 AM in what timezone?
    dt = datetime.fromtimestamp(timestamp)  # Local time assumed
    return 9 <= dt.hour < 17


# =============================================================================
# CATEGORY 6: Collection/Iterator Bugs
# Bugs with lists, dicts, and iteration
# =============================================================================

def remove_duplicates(items: list) -> list:
    """Remove duplicate items from list.

    LOGIC BUG: set() doesn't preserve order in Python < 3.7.
    Also loses data if items aren't hashable.
    """
    # BUGGY: Order not preserved in older Python
    # BUGGY: Fails with unhashable types like dicts
    return list(set(items))


def find_common_elements(list_a: list, list_b: list) -> list:
    """Find elements present in both lists.

    LOGIC BUG: Doesn't handle duplicates correctly.
    """
    # BUGGY: If list_a = [1,1,2] and list_b = [1], returns [1,1]
    return [x for x in list_a if x in list_b]


def batch_process(items: list, batch_size: int = 100):
    """Process items in batches.

    LOGIC BUG: Last batch may be silently dropped.
    """
    results = []
    # BUGGY: If len(items) not divisible by batch_size, last items dropped
    for i in range(len(items) // batch_size):
        batch = items[i * batch_size:(i + 1) * batch_size]
        results.extend(process_batch(batch))
    return results


def process_batch(batch):
    """Stub for batch processing."""
    return batch


# =============================================================================
# CATEGORY 7: Concurrency Bugs
# Race conditions and thread safety issues
# =============================================================================

class Counter:
    """Thread-safe counter.

    LOGIC BUG: Not actually thread-safe despite claims.
    """
    def __init__(self):
        self.count = 0
        # BUGGY: Lock exists but isn't used correctly
        self.lock = Lock()

    def increment(self):
        # BUGGY: Read and write not atomic, lock unused
        self.count = self.count + 1  # Race condition!

    def get_and_increment(self):
        # BUGGY: Check-then-act race condition
        current = self.count
        self.count += 1
        return current


class Cache:
    """Thread-safe cache with expiry.

    LOGIC BUG: Race condition in get-or-set pattern.
    """
    def __init__(self):
        self.data = {}
        self.lock = Lock()

    def get_or_compute(self, key: str, compute_fn):
        # BUGGY: Check-then-act without holding lock
        if key in self.data:  # Check outside lock
            return self.data[key]

        with self.lock:
            # Should re-check here (double-checked locking)
            value = compute_fn()
            self.data[key] = value
            return value


# =============================================================================
# CATEGORY 8: Security Logic Bugs
# Vulnerabilities from incorrect security logic
# =============================================================================

def verify_signature(message: bytes, signature: bytes, key: bytes) -> bool:
    """Verify HMAC signature.

    LOGIC BUG: Wrong comparison order allows signature to be empty.
    """
    expected = hmac.new(key, message, hashlib.sha256).digest()
    # BUGGY: If signature is empty string, short circuit might pass
    # Should validate signature length first
    return signature == expected


def check_csrf_token(session_token: str, request_token: str) -> bool:
    """Verify CSRF token matches session.

    LOGIC BUG: Allows empty tokens.
    """
    # BUGGY: Empty strings are equal, so empty CSRF token passes!
    if not session_token and not request_token:
        return True  # Both empty = match? NO!
    return session_token == request_token


def validate_redirect_url(url: str, allowed_hosts: List[str]) -> bool:
    """Validate redirect URL is to an allowed host.

    LOGIC BUG: Substring check allows bypass.
    """
    # BUGGY: "evil.com/example.com" passes if "example.com" is allowed
    for host in allowed_hosts:
        if host in url:  # Should parse URL and check hostname
            return True
    return False


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private.

    LOGIC BUG: Incomplete check misses some private ranges.
    """
    # BUGGY: Missing 172.16.0.0/12 range
    # BUGGY: Missing IPv6 private ranges
    return (
        ip.startswith('10.') or
        ip.startswith('192.168.') or
        ip == '127.0.0.1'
        # Missing: 172.16-31.x.x, ::1, fc00::/7
    )


# =============================================================================
# EXPECTED VERDICTS
# =============================================================================

LOGIC_MIRAGE_PATTERNS = {
    # Off-by-one errors
    "check_password_attempts": {
        "category": "OFF_BY_ONE",
        "bug": "Uses > instead of >=",
        "impact": "Allows 4 attempts when max is 3",
        "severity": "MEDIUM"
    },
    "get_page_items": {
        "category": "OFF_BY_ONE",
        "bug": "Wrong page indexing",
        "impact": "Shows duplicate items on last page",
        "severity": "LOW"
    },
    "validate_age": {
        "category": "OFF_BY_ONE",
        "bug": "Allows age=0",
        "impact": "Invalid age accepted",
        "severity": "LOW"
    },

    # Comparison operator errors
    "is_admin_or_owner": {
        "category": "WRONG_OPERATOR",
        "bug": "Inverted != check",
        "impact": "Authorization bypass",
        "severity": "CRITICAL"
    },
    "check_discount_eligibility": {
        "category": "WRONG_OPERATOR",
        "bug": "Uses > instead of >=",
        "impact": "Boundary customers miss discount",
        "severity": "LOW"
    },
    "should_rate_limit": {
        "category": "WRONG_OPERATOR",
        "bug": "Uses < instead of >",
        "impact": "Rate limiting inverted, blocks good users",
        "severity": "HIGH"
    },

    # Null handling
    "get_user_display_name": {
        "category": "NULL_HANDLING",
        "bug": "Doesn't check nested None",
        "impact": "KeyError in production",
        "severity": "MEDIUM"
    },
    "safe_divide": {
        "category": "NULL_HANDLING",
        "bug": "Doesn't handle None inputs",
        "impact": "TypeError instead of safe result",
        "severity": "MEDIUM"
    },
    "merge_configs": {
        "category": "NULL_HANDLING",
        "bug": "Shallow copy mutates original",
        "impact": "Unexpected side effects",
        "severity": "MEDIUM"
    },

    # String comparison
    "verify_api_key": {
        "category": "TIMING_ATTACK",
        "bug": "Direct string comparison",
        "impact": "API key can be brute-forced via timing",
        "severity": "HIGH"
    },
    "normalize_email": {
        "category": "INCOMPLETE_LOGIC",
        "bug": "Incomplete normalization",
        "impact": "Duplicate accounts possible",
        "severity": "MEDIUM"
    },
    "check_file_extension": {
        "category": "INCOMPLETE_LOGIC",
        "bug": "Case-sensitive and double extension bypass",
        "impact": "Malicious file upload",
        "severity": "HIGH"
    },

    # Time/date bugs
    "is_token_valid": {
        "category": "TIMEZONE",
        "bug": "No timezone handling",
        "impact": "Tokens expire early/late in different zones",
        "severity": "MEDIUM"
    },
    "calculate_subscription_end": {
        "category": "DATE_MATH",
        "bug": "Uses days instead of months",
        "impact": "Subscription ends on wrong date",
        "severity": "MEDIUM"
    },
    "check_business_hours": {
        "category": "TIMEZONE",
        "bug": "No timezone specification",
        "impact": "Business hours wrong for other timezones",
        "severity": "LOW"
    },

    # Collection bugs
    "remove_duplicates": {
        "category": "COLLECTION",
        "bug": "set() loses order, fails on unhashable",
        "impact": "Order-dependent code breaks",
        "severity": "MEDIUM"
    },
    "find_common_elements": {
        "category": "COLLECTION",
        "bug": "Doesn't handle duplicates",
        "impact": "Wrong count of common elements",
        "severity": "LOW"
    },
    "batch_process": {
        "category": "COLLECTION",
        "bug": "Last partial batch dropped",
        "impact": "Data loss for remainder items",
        "severity": "HIGH"
    },

    # Concurrency bugs
    "Counter.increment": {
        "category": "RACE_CONDITION",
        "bug": "Non-atomic increment",
        "impact": "Lost updates under concurrency",
        "severity": "MEDIUM"
    },
    "Cache.get_or_compute": {
        "category": "RACE_CONDITION",
        "bug": "Check-then-act outside lock",
        "impact": "Duplicate computation, stale data",
        "severity": "MEDIUM"
    },

    # Security logic bugs
    "verify_signature": {
        "category": "SECURITY_LOGIC",
        "bug": "No length check on signature",
        "impact": "Potential bypass with empty signature",
        "severity": "CRITICAL"
    },
    "check_csrf_token": {
        "category": "SECURITY_LOGIC",
        "bug": "Empty tokens considered valid",
        "impact": "CSRF protection bypass",
        "severity": "CRITICAL"
    },
    "validate_redirect_url": {
        "category": "SECURITY_LOGIC",
        "bug": "Substring check instead of URL parsing",
        "impact": "Open redirect vulnerability",
        "severity": "HIGH"
    },
    "is_internal_ip": {
        "category": "SECURITY_LOGIC",
        "bug": "Missing private IP ranges",
        "impact": "SSRF filter bypass",
        "severity": "HIGH"
    },
}
