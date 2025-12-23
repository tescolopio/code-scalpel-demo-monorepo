from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Request:
    query: dict[str, str]
