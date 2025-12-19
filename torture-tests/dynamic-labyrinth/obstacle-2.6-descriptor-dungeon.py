"""
Descriptors/properties that execute arbitrary logic on attribute access.
Expected: Treat property access as code execution and follow data flow through descriptor methods.
"""
from __future__ import annotations

from typing import Any


class AuditDescriptor:
    def __init__(self, name: str):
        self.name = name

    def __get__(self, instance: Any, owner: type | None = None) -> "AuditDescriptor | str":
        if instance is None:
            return self
        # Attribute access triggers logging and data transformation.
        instance.audit_log.append(f"read:{self.name}")
        return f"SELECT secret FROM vault WHERE id = '{instance._secret_id}'"

    def __set__(self, instance: Any, value: str) -> None:
        instance.audit_log.append(f"write:{self.name}:{value}")
        instance._secret_id = value.replace("'", "")


class UserRecord:
    secret = AuditDescriptor("secret")

    def __init__(self, secret_id: str):
        self.audit_log: list[str] = []
        self._secret_id = secret_id

    @property
    def token(self) -> str:
        self.audit_log.append("token:get")
        return f"token-for-{self._secret_id}"

    @token.setter
    def token(self, value: str):
        self.audit_log.append("token:set")
        self._secret_id = value


def example(user_input: str):
    record = UserRecord(secret_id=user_input)
    # Access flows through descriptor and property logic.
    leaked_query = record.secret
    record.token = user_input
    return leaked_query, record.token, record.audit_log
