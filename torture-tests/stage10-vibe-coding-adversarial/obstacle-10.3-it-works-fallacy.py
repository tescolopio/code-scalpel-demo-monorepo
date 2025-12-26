"""Obstacle 10.3: The "It Works" Fallacy

Code that passes all functional tests, gets thumbs up from the AI assistant,
and appears to work correctly - but has critical security vulnerabilities.

This is the most dangerous category because:
- Unit tests pass ✅
- Integration tests pass ✅
- Manual testing works ✅
- Code review looks fine ✅
- But it's completely insecure ❌

DIFFERENTIATOR: Code Scalpel must find security issues in code that
"works perfectly" from a functional perspective.

PASS CRITERIA:
- ALL patterns must be flagged despite being functionally correct
- Must distinguish "works" from "secure"
- Must not be fooled by passing test assertions
"""

import hashlib
import hmac
import time
import uuid
from typing import Optional
from functools import wraps


# =============================================================================
# PATTERN 1: Authentication That Authenticates (But Wrong)
# This code correctly authenticates users! But the comparison is vulnerable.
# =============================================================================

USERS = {
    "admin": "5f4dcc3b5aa765d61d8327deb882cf99",  # password123
    "user": "d8578edf8458ce06fbc5bb76a58c5ca4",   # qwerty
}

def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate user with username and password.

    Returns True if authentication succeeds.

    Unit tests:
    - test_valid_login: PASSES ✅
    - test_invalid_password: PASSES ✅
    - test_unknown_user: PASSES ✅
    """
    if username not in USERS:
        return False

    # Hash the provided password
    provided_hash = hashlib.md5(password.encode()).hexdigest()
    stored_hash = USERS[username]

    # VULNERABLE: Timing attack!
    # String comparison is not constant-time
    # Attacker can determine password character by character
    return provided_hash == stored_hash  # Timing oracle


def authenticate_user_v2(username: str, password: str) -> bool:
    """
    'Fixed' version that still has issues.

    Added early return for unknown users for 'efficiency'.
    """
    # VULNERABLE: Username enumeration via timing
    if username not in USERS:
        return False  # Fast path reveals username doesn't exist

    # Now we hash and compare
    provided_hash = hashlib.md5(password.encode()).hexdigest()
    return hmac.compare_digest(provided_hash, USERS[username])


# =============================================================================
# PATTERN 2: Authorization That Authorizes (The Wrong Thing)
# This correctly checks permissions! But for the wrong resource.
# =============================================================================

def get_document(user_id: int, document_id: int, user_role: str) -> dict:
    """
    Get document by ID with permission check.

    Permission model:
    - Admins can access all documents
    - Users can only access their own documents

    Tests:
    - test_admin_access_any: PASSES ✅
    - test_user_access_own: PASSES ✅
    - test_user_denied_other: PASSES ✅
    """
    # Check if user has permission
    if user_role != "admin":
        # Check if user owns this document
        if not user_owns_document(user_id, document_id):
            raise PermissionError("Access denied")

    # VULNERABLE: IDOR - document_id comes from user input
    # We checked permission but then fetch by attacker-controlled ID
    # Attacker can increment document_id to access others' documents
    return fetch_document_by_id(document_id)


def user_owns_document(user_id: int, document_id: int) -> bool:
    """Check if user owns document."""
    # This function is never actually called with correct parameters!
    # The document_id is user-supplied, not the canonical one
    return True  # Bug: Always returns True in this stub


def fetch_document_by_id(doc_id: int) -> dict:
    """Fetch document from database."""
    return {"id": doc_id, "content": "sensitive data"}


# =============================================================================
# PATTERN 3: Encryption That Encrypts (With Hardcoded Key)
# This properly encrypts data! With a key visible in source code.
# =============================================================================

from cryptography.fernet import Fernet

# "Secret" key stored in code - AI might generate this pattern
# because it "works" and examples often show inline keys
ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='

def encrypt_pii(data: str) -> bytes:
    """
    Encrypt PII data before storage.

    Using Fernet symmetric encryption for data protection.
    GDPR compliant! ✅
    """
    # VULNERABLE: Hardcoded encryption key
    # Anyone with source code access can decrypt all data
    cipher = Fernet(ENCRYPTION_KEY)
    return cipher.encrypt(data.encode())


def decrypt_pii(encrypted_data: bytes) -> str:
    """Decrypt PII data for processing."""
    cipher = Fernet(ENCRYPTION_KEY)
    return cipher.decrypt(encrypted_data).decode()


# Even worse: key derived from predictable value
def get_user_encryption_key(user_id: int) -> bytes:
    """Get encryption key for user's data."""
    # VULNERABLE: Predictable key derivation
    # Key is just MD5 of user_id - trivially predictable
    import base64
    key_material = hashlib.md5(str(user_id).encode()).digest()
    return base64.urlsafe_b64encode(key_material + key_material)


# =============================================================================
# PATTERN 4: Rate Limiting That Limits (The Wrong Thing)
# This rate limiter works! But only limits by IP, not by account.
# =============================================================================

from collections import defaultdict

request_counts = defaultdict(int)
last_reset = time.time()

def rate_limit(ip_address: str) -> bool:
    """
    Check if request should be rate limited.

    Limits to 100 requests per minute per IP.

    Tests:
    - test_under_limit: PASSES ✅
    - test_at_limit: PASSES ✅
    - test_over_limit_blocked: PASSES ✅
    """
    global last_reset

    # Reset counts every minute
    if time.time() - last_reset > 60:
        request_counts.clear()
        last_reset = time.time()

    request_counts[ip_address] += 1

    # VULNERABLE: Only rate limits by IP
    # - Attacker behind NAT/VPN can rotate IPs
    # - Credential stuffing across many users from one IP = blocked
    # - But one user from many IPs = not blocked
    # - Should also rate limit by account/action
    return request_counts[ip_address] <= 100


def login_with_rate_limit(ip: str, username: str, password: str) -> bool:
    """Login endpoint with rate limiting."""
    if not rate_limit(ip):
        raise Exception("Too many requests")

    # VULNERABLE: No per-account rate limiting
    # Attacker can try 100 passwords per IP * unlimited IPs
    return authenticate_user(username, password)


# =============================================================================
# PATTERN 5: Session Management That Manages (Insecurely)
# Sessions work! But they're predictable.
# =============================================================================

sessions = {}

def create_session(user_id: int) -> str:
    """
    Create a new session for user.

    Generates unique session token for authentication.
    """
    # VULNERABLE: Predictable session ID
    # Using UUID1 which contains timestamp and MAC address
    # Attacker can predict other session IDs
    session_id = str(uuid.uuid1())

    sessions[session_id] = {
        "user_id": user_id,
        "created_at": time.time()
    }

    return session_id


def create_session_v2(user_id: int) -> str:
    """
    'Improved' session creation.

    Using timestamp + user_id for uniqueness.
    """
    # VULNERABLE: Even more predictable!
    # session_id = timestamp_userid - trivially guessable
    session_id = f"{int(time.time())}_{user_id}"
    sessions[session_id] = {"user_id": user_id}
    return session_id


# =============================================================================
# PATTERN 6: CSRF Protection That Protects (Sometimes)
# CSRF tokens work! But only checked on some endpoints.
# =============================================================================

def csrf_protect(func):
    """Decorator to require CSRF token validation."""
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        token = request.get("csrf_token")
        session_token = request.get("session", {}).get("csrf_token")

        if not token or token != session_token:
            raise Exception("CSRF validation failed")

        return func(request, *args, **kwargs)
    return wrapper


@csrf_protect
def update_email(request) -> dict:
    """Update user email with CSRF protection."""
    return {"status": "email updated"}


@csrf_protect
def update_password(request) -> dict:
    """Update user password with CSRF protection."""
    return {"status": "password updated"}


# VULNERABLE: Forgot to add @csrf_protect!
# This is common when adding new endpoints
def delete_account(request) -> dict:
    """Delete user account."""
    # No CSRF protection - attacker can delete any account
    user_id = request.get("user_id")
    return {"status": f"account {user_id} deleted"}


def transfer_funds(request) -> dict:
    """Transfer funds between accounts."""
    # VULNERABLE: Financial operation without CSRF
    from_account = request.get("from")
    to_account = request.get("to")
    amount = request.get("amount")
    return {"status": f"transferred {amount} from {from_account} to {to_account}"}


# =============================================================================
# PATTERN 7: Input Validation That Validates (Partially)
# Validation works! But only on the happy path.
# =============================================================================

def validate_and_process_order(order: dict) -> dict:
    """
    Validate and process customer order.

    Validates:
    - Product ID exists ✅
    - Quantity is positive ✅
    - Price matches catalog ✅
    """
    product_id = order.get("product_id")
    quantity = order.get("quantity")
    price = order.get("price")

    # Validate product exists
    if product_id not in PRODUCT_CATALOG:
        raise ValueError("Invalid product")

    # Validate quantity
    if not isinstance(quantity, int) or quantity <= 0:
        raise ValueError("Invalid quantity")

    # Validate price matches
    expected_price = PRODUCT_CATALOG[product_id]["price"]
    if price != expected_price:
        raise ValueError("Price mismatch")

    # VULNERABLE: No validation of discount field!
    # Attacker can add {"discount": 99.99} to get items nearly free
    discount = order.get("discount", 0)

    total = (price * quantity) - discount  # Attacker controls discount!

    return {"total": total, "product_id": product_id}


PRODUCT_CATALOG = {
    "PROD001": {"name": "Widget", "price": 9.99},
    "PROD002": {"name": "Gadget", "price": 19.99},
}


# =============================================================================
# PATTERN 8: File Upload That Uploads (Anything)
# File upload works! But allows arbitrary file types.
# =============================================================================

import os

def upload_avatar(user_id: int, filename: str, content: bytes) -> str:
    """
    Upload user avatar image.

    Saves file to user's directory.

    Tests:
    - test_upload_jpg: PASSES ✅
    - test_upload_png: PASSES ✅
    - test_file_saved: PASSES ✅
    """
    # Create user directory
    user_dir = f"/uploads/avatars/{user_id}"
    os.makedirs(user_dir, exist_ok=True)

    # VULNERABLE: No file type validation!
    # Attacker can upload .php, .jsp, .aspx for RCE
    # Also path traversal via filename
    filepath = os.path.join(user_dir, filename)  # filename = "../../../etc/cron.d/evil"

    with open(filepath, "wb") as f:
        f.write(content)

    return filepath


def upload_document(filename: str, content: bytes) -> str:
    """Upload user document."""
    # VULNERABLE: "Validates" extension but not content
    allowed = [".pdf", ".doc", ".docx"]

    _, ext = os.path.splitext(filename)
    if ext.lower() not in allowed:
        raise ValueError("Invalid file type")

    # VULNERABLE: Doesn't check actual content!
    # evil.pdf could be an executable with .pdf extension
    # Also: evil.pdf.php passes if only checking final extension
    filepath = f"/uploads/documents/{filename}"
    with open(filepath, "wb") as f:
        f.write(content)

    return filepath


# =============================================================================
# EXPECTED VERDICTS - All must be flagged despite "working"
# =============================================================================

IT_WORKS_PATTERNS = {
    # Authentication
    "authenticate_user": ("Timing Attack", "CWE-208", "MEDIUM"),
    "authenticate_user_v2": ("Username Enumeration", "CWE-204", "LOW"),

    # Authorization
    "get_document": ("IDOR", "CWE-639", "HIGH"),

    # Encryption
    "encrypt_pii": ("Hardcoded Encryption Key", "CWE-321", "CRITICAL"),
    "decrypt_pii": ("Hardcoded Encryption Key", "CWE-321", "CRITICAL"),
    "get_user_encryption_key": ("Weak Key Derivation", "CWE-328", "HIGH"),

    # Rate Limiting
    "rate_limit": ("Insufficient Rate Limiting", "CWE-770", "MEDIUM"),
    "login_with_rate_limit": ("Credential Stuffing Vulnerable", "CWE-307", "MEDIUM"),

    # Sessions
    "create_session": ("Predictable Session ID", "CWE-330", "HIGH"),
    "create_session_v2": ("Predictable Session ID", "CWE-330", "CRITICAL"),

    # CSRF
    "delete_account": ("Missing CSRF Protection", "CWE-352", "HIGH"),
    "transfer_funds": ("Missing CSRF Protection", "CWE-352", "CRITICAL"),

    # Validation
    "validate_and_process_order": ("Mass Assignment", "CWE-915", "HIGH"),

    # File Upload
    "upload_avatar": ("Unrestricted File Upload", "CWE-434", "CRITICAL"),
    "upload_document": ("Insufficient File Validation", "CWE-434", "HIGH"),
}
