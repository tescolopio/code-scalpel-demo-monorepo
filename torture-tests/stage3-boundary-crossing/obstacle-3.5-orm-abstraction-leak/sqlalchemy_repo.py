# Obstacle 3.5: SQLAlchemy escape hatch abusing text() with user-controlled column name.
# Intentional injection surface to force boundary-aware analysis; do not add whitelisting here.
from sqlalchemy import text


def list_orders(session, status: str, sort_column: str):
    unsafe_query = text(
        f"SELECT id, status, total_cents FROM orders WHERE status = :status ORDER BY {sort_column}"
    )  # no whitelist or bind parameter for column

    # Even though values are bound, the column identifier is injected directly.
    return session.execute(unsafe_query, {"status": status}).fetchall()
