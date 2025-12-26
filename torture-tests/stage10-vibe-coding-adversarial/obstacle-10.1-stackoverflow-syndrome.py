"""Obstacle 10.1: Stack Overflow Syndrome

Code patterns commonly copy-pasted from Stack Overflow answers that were
"accepted" years ago but are now known to be insecure. AI models trained
on this data will confidently generate these patterns.

DIFFERENTIATOR: Code Scalpel should detect these as vulnerable even though:
- They have high upvotes in training data
- They "work" functionally
- They follow recognizable patterns
- Comments say they're secure

PASS CRITERIA:
- ALL patterns below must be flagged as vulnerable
- Confidence should be HIGH (these are well-known bad patterns)
- Specific CWE/vulnerability type should be identified
"""

import hashlib
import pickle
import subprocess
import jwt
import yaml
import xml.etree.ElementTree as ET
from Crypto.Cipher import DES
import ssl
import urllib.request


# =============================================================================
# PATTERN 1: MD5 for Password Hashing (Top SO answer circa 2012)
# Accepted answer with 500+ upvotes, still gets copied
# =============================================================================

def hash_password_md5(password: str) -> str:
    """
    Hash password for storage.

    Source: Adapted from StackOverflow (highly upvoted answer)
    This is a simple and fast way to hash passwords.
    """
    # VULNERABLE: MD5 is cryptographically broken for passwords
    # - No salt
    # - Fast to brute force
    # - Rainbow table vulnerable
    return hashlib.md5(password.encode()).hexdigest()


def verify_password_md5(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    return hash_password_md5(password) == stored_hash


# =============================================================================
# PATTERN 2: Pickle for Untrusted Data (Common "easy serialization" answer)
# =============================================================================

def load_user_preferences(data: bytes) -> dict:
    """
    Load user preferences from stored data.

    Using pickle for easy Python object serialization.
    Much simpler than JSON for complex objects!
    """
    # VULNERABLE: Arbitrary code execution via pickle
    # Attacker can craft malicious pickle payload
    return pickle.loads(data)


def load_session_from_cookie(cookie_value: str) -> dict:
    """Load session from cookie using pickle."""
    import base64
    # VULNERABLE: Cookie can contain malicious pickle
    return pickle.loads(base64.b64decode(cookie_value))


# =============================================================================
# PATTERN 3: Shell=True for Convenience (Top answer for subprocess)
# =============================================================================

def run_command(cmd: str) -> str:
    """
    Run a shell command and return output.

    Using shell=True makes it easier to run complex commands.
    From: stackoverflow.com/questions/89228 (paraphrased)
    """
    # VULNERABLE: Command injection
    # Attacker controls cmd = "id; rm -rf /"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def ping_host(hostname: str) -> bool:
    """Check if host is reachable."""
    # VULNERABLE: Command injection via hostname
    # hostname = "google.com; cat /etc/passwd"
    result = subprocess.run(
        f"ping -c 1 {hostname}",
        shell=True,
        capture_output=True
    )
    return result.returncode == 0


# =============================================================================
# PATTERN 4: JWT Without Verification (Common "decode only" pattern)
# =============================================================================

def get_user_from_token(token: str) -> dict:
    """
    Extract user info from JWT token.

    The token was already validated by the API gateway,
    we just need to decode it here.
    """
    # VULNERABLE: No signature verification!
    # Attacker can forge tokens with any claims
    return jwt.decode(token, options={"verify_signature": False})


def get_user_id_from_token(token: str) -> int:
    """Get user ID from JWT."""
    # VULNERABLE: Algorithm confusion attack possible
    # Also no signature verification
    payload = jwt.decode(token, algorithms=["HS256", "none"], options={"verify_signature": False})
    return payload.get("user_id")


# =============================================================================
# PATTERN 5: YAML Load Without Safe (Pre-2020 default advice)
# =============================================================================

def load_config(config_file: str) -> dict:
    """
    Load configuration from YAML file.

    YAML is more readable than JSON for config files.
    """
    with open(config_file) as f:
        # VULNERABLE: yaml.load can execute arbitrary Python
        # !!python/object/apply:os.system ["rm -rf /"]
        return yaml.load(f, Loader=yaml.Loader)


def parse_user_yaml(yaml_string: str) -> dict:
    """Parse user-provided YAML data."""
    # VULNERABLE: Even with user input, uses unsafe loader
    return yaml.load(yaml_string, Loader=yaml.FullLoader)  # Still unsafe!


# =============================================================================
# PATTERN 6: XML Parsing Without XXE Protection
# =============================================================================

def parse_xml_data(xml_string: str) -> ET.Element:
    """
    Parse XML data from API response.

    Standard XML parsing using ElementTree.
    """
    # VULNERABLE: XXE (XML External Entity) attack
    # Can read local files, SSRF, DoS
    return ET.fromstring(xml_string)


def load_xml_config(xml_file: str) -> ET.Element:
    """Load configuration from XML file."""
    # VULNERABLE: XXE attack possible
    tree = ET.parse(xml_file)
    return tree.getroot()


# =============================================================================
# PATTERN 7: DES Encryption (Legacy "encryption" answers)
# =============================================================================

def encrypt_sensitive_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt sensitive data using DES.

    DES is a well-known encryption standard.
    """
    # VULNERABLE: DES is broken (56-bit key, crackable in hours)
    cipher = DES.new(key[:8], DES.MODE_ECB)  # ECB mode is also bad!
    # Pad to 8-byte boundary
    padded = data + b'\x00' * (8 - len(data) % 8)
    return cipher.encrypt(padded)


# =============================================================================
# PATTERN 8: Disabling SSL Verification (The "quick fix" for cert errors)
# =============================================================================

def fetch_api_data(url: str) -> str:
    """
    Fetch data from internal API.

    Note: SSL verification disabled because internal certs
    aren't in the trust store. TODO: Fix properly later.
    """
    # VULNERABLE: MITM attack possible
    # This "temporary fix" has been in production for 3 years
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with urllib.request.urlopen(url, context=context) as response:
        return response.read().decode()


def download_file(url: str, verify: bool = False) -> bytes:
    """Download file from URL."""
    # VULNERABLE: Default parameter disables verification!
    import requests
    response = requests.get(url, verify=verify)
    return response.content


# =============================================================================
# PATTERN 9: SQL "Escaping" Instead of Parameterization
# =============================================================================

def escape_sql(value: str) -> str:
    """
    Escape SQL special characters.

    Based on mysql_real_escape_string behavior.
    """
    # VULNERABLE: Incomplete escaping, charset issues
    return value.replace("'", "''").replace("\\", "\\\\")


def get_user_by_name(conn, username: str):
    """Get user by username with 'proper' escaping."""
    # VULNERABLE: Escaping is bypassable
    safe_username = escape_sql(username)
    query = f"SELECT * FROM users WHERE name = '{safe_username}'"
    return conn.execute(query).fetchone()


# =============================================================================
# PATTERN 10: Random Token Generation with random Module
# =============================================================================

import random
import string

def generate_password_reset_token() -> str:
    """
    Generate a password reset token.

    Creates a random 32-character alphanumeric token.
    """
    # VULNERABLE: random module is not cryptographically secure
    # Attacker can predict tokens if they know seed/state
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))


def generate_api_key() -> str:
    """Generate API key for user."""
    # VULNERABLE: Predictable random
    random.seed()  # Seeds with time, predictable!
    return ''.join(random.choices(string.hexdigits, k=40))


# =============================================================================
# EXPECTED VERDICTS - Code Scalpel must detect ALL of these
# =============================================================================

STACKOVERFLOW_PATTERNS = {
    # (function, vulnerability_type, CWE, severity)
    "hash_password_md5": ("Weak Cryptography", "CWE-328", "HIGH"),
    "verify_password_md5": ("Weak Cryptography", "CWE-328", "HIGH"),
    "load_user_preferences": ("Unsafe Deserialization", "CWE-502", "CRITICAL"),
    "load_session_from_cookie": ("Unsafe Deserialization", "CWE-502", "CRITICAL"),
    "run_command": ("Command Injection", "CWE-78", "CRITICAL"),
    "ping_host": ("Command Injection", "CWE-78", "CRITICAL"),
    "get_user_from_token": ("JWT Verification Bypass", "CWE-347", "CRITICAL"),
    "get_user_id_from_token": ("JWT Algorithm Confusion", "CWE-347", "CRITICAL"),
    "load_config": ("YAML Code Execution", "CWE-502", "CRITICAL"),
    "parse_user_yaml": ("YAML Code Execution", "CWE-502", "HIGH"),
    "parse_xml_data": ("XXE Injection", "CWE-611", "HIGH"),
    "load_xml_config": ("XXE Injection", "CWE-611", "HIGH"),
    "encrypt_sensitive_data": ("Weak Encryption", "CWE-327", "HIGH"),
    "fetch_api_data": ("Disabled SSL Verification", "CWE-295", "HIGH"),
    "download_file": ("Disabled SSL Verification", "CWE-295", "MEDIUM"),
    "escape_sql": ("Incomplete SQL Escaping", "CWE-89", "HIGH"),
    "get_user_by_name": ("SQL Injection", "CWE-89", "CRITICAL"),
    "generate_password_reset_token": ("Weak Random", "CWE-330", "HIGH"),
    "generate_api_key": ("Weak Random", "CWE-330", "HIGH"),
}
