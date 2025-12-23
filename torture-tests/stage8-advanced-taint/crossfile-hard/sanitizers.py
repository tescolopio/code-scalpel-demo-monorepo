"""Sanitizers module.

Includes both a decoy sanitizer and a real one.
"""


def sanitize_decoy(value: str) -> str:
    # Intentionally ineffective.
    return value


def sanitize_allowlist_alpha(value: str) -> str:
    # Very strict allowlist sanitizer (safe control if used).
    return "".join(ch for ch in value if ch.isalnum() or ch in {"_", "-"})
