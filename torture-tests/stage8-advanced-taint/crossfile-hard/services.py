"""Service layer adds indirection and alias imports."""

from . import sanitizers as s
from .db import run_query as rq


def search_users(raw_query: str) -> str:
    # Vulnerable path: decoy sanitizer does nothing.
    query = s.sanitize_decoy(raw_query)
    return rq(query)


def search_users_safe(raw_query: str) -> str:
    # Safe control: strict allowlist.
    query = s.sanitize_allowlist_alpha(raw_query)
    return rq(query)
