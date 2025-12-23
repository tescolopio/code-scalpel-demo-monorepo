"""Safe control: backend validates evaporated TypeScript types.

This file is intentionally minimal and not meant to be run.

Expected: a type-evaporation detector should *not* flag the same issue here,
because the backend enforces a runtime allowlist.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# Map untrusted input to an allowlisted canonical value.
# Using a mapping (instead of returning the raw input) makes the runtime
# enforcement mechanically obvious to static analysis.
ROLE_ALLOWLIST = {
    "admin": "admin",
    "user": "user",
}


@app.post("/api/role")
def update_role_safe():
    data = request.get_json(silent=True) or {}
    requested_role = data.get("role")

    role = ROLE_ALLOWLIST.get(requested_role)

    if role is None:
        return jsonify({"ok": False, "error": "invalid role"}), 400

    # Safe: role is a canonical allowlisted value.
    return jsonify({"ok": True, "role": role})
