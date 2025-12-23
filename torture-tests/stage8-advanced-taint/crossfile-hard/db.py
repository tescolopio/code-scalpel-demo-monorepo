"""DB layer: sink is here, separate file from source.

This is a static-analysis fixture; it is not intended to be executed.
"""

import sqlite3


def run_query(user_supplied: str) -> str:
    # Sink: dynamic SQL string construction from untrusted data
    sql = f"SELECT * FROM users WHERE name = '{user_supplied}'"

    # Sink: executing SQL string
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(sql)
    conn.close()

    return sql
