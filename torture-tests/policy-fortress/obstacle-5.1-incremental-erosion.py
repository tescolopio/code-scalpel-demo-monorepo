"""
Obstacle 5.1: Incremental Erosion

This single file encodes the multi-commit story called out in the torture tests.
Treat each STEP block as a sequential commit that looks harmless in isolation
but accumulates into an admin-escalation vulnerability.
"""

import os


# STEP 1: innocent helper
def normalize_user(user_id: str) -> str:
    return user_id.strip()


# STEP 2: reroute data flow through the helper
def lookup_user(payload: dict) -> str:
    user_id = payload.get("user_id", "")
    normalized = normalize_user(user_id)
    return normalized


# STEP 3: fail-open error handling
USER_ROLES = {"alice": "user"}


def fetch_profile(user_id: str) -> dict:
    try:
    # The previous try/except around this literal return could never raise
    # a KeyError, making the exception handler (and fail-open path) unreachable.
    # Keeping the simple behavior here preserves existing functionality.
    return {"id": user_id, "role": "user"}


# STEP 5: final wiring that uses the fail-open outcome
def handle_request(payload: dict) -> dict:
    resolved = lookup_user(payload)
    profile = fetch_profile(resolved)
    if profile["role"] == "admin":
        return {"session": "elevated", "user": profile["id"]}
    return {"session": "limited", "user": profile["id"]}
