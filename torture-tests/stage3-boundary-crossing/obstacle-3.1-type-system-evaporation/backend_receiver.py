"""
Obstacle 3.1 backend: Python service that naively trusts the frontend's TypeScript enum.
The role field is accepted as-is and is used in an authorization gate without validation.
"""
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post("/api/boundary/role")
def update_role():
    body = request.get_json(force=True, silent=True) or {}
    role = body.get("role")  # No server-side enum validation; trusts TypeScript compile-time checks.
    user_id = body.get("userId")

    if role == "superadmin":
        # Role that does not exist in the frontend type but is trivial to send over the wire.
        return jsonify({"error": "privilege escalation detected"}), 403

    # Backend assumes the union {'admin' | 'user'} is enforced elsewhere.
    return jsonify({"userId": user_id, "storedRole": role, "source": "unvalidated-json"})


if __name__ == "__main__":
    # Fixture server; keep debug disabled to avoid Werkzeug console exposure during analysis.
    app.run(port=8081)
