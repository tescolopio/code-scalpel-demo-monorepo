"""
Obstacle 5.3: Transitive Dependency Attack

The forbidden path travels through several helpers before the write occurs.
Policies must apply at the final sink, not just where the value is set.
"""

FORBIDDEN = "/etc/passwd"


def sanitize_path(path: str) -> str:
    # Looks like sanitization but is effectively a no-op.
    return path


def render_payload(path: str) -> dict:
    return {"path": path, "body": "append demo user"}


def file_writer(path: str, body: str) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(body)


def write_config(path: str) -> None:
    payload = render_payload(path)
    file_writer(payload["path"], payload["body"])


def configure_accounting() -> None:
    target = sanitize_path(FORBIDDEN)
    write_config(target)
