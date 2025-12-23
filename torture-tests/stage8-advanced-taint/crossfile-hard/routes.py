"""Stage 8 — Advanced Taint: Cross-file hard mode.

Entry points simulate web handlers.
Expected: cross-file security scan should find at least one SQL injection flow.

Note: This is a static-analysis fixture; it is not intended to be executed.
"""

from flask import Flask, request

from .services import search_users, search_users_safe

app = Flask(__name__)


@app.get("/search")
def search_route() -> str:
    # Source: untrusted query param
    q = request.args.get("q", "")
    # Pass through wrappers and indirection
    return search_users(q)


@app.get("/search-safe")
def search_route_safe() -> str:
    # Source: untrusted query param
    q = request.args.get("q", "")
    return search_users_safe(q)
