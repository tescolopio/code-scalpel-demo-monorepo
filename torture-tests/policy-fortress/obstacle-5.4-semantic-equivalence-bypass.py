"""
Obstacle 5.4: Semantic Equivalence Bypass

Different syntax, same destructive intent. Policies should apply at the
semantic level, not just the literal string.
"""

import subprocess


def truncate_users(conn) -> None:
    conn.execute("TRUNCATE TABLE users")  # Equivalent to deleting all rows


def delete_users(conn) -> None:
    conn.execute("DELETE FROM users")  # Classic pattern


def wipe_data_via_shell() -> None:
    subprocess.check_call(["find", "/data", "-delete"])  # Same effect as rm -rf /data
