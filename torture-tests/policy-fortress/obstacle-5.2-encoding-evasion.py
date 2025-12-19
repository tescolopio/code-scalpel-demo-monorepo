"""
Obstacle 5.2: Encoding Evasion Suite

Each payload hides a forbidden pattern (SQL injection, path traversal, XSS)
behind a different encoding layer. Policies should decode before evaluation.
"""

import base64
import codecs
import html
import urllib.parse


def decoded_sql() -> str:
    encoded_sql = "U0VMRUNUICogRlJPTSB1c2Vycw=="  # base64 for "SELECT * FROM users"
    return base64.b64decode(encoded_sql).decode()


def unicode_path_traversal() -> str:
    encoded_path = "\\u002e\\u002e\\u002fetc/passwd"
    return encoded_path.encode().decode("unicode_escape")


def hex_path_traversal() -> str:
    encoded = r"\x2e\x2e\x2fvar\x2flogs"
    return codecs.decode(encoded, "unicode_escape")


def url_encoded_payload() -> str:
    return urllib.parse.unquote("%2e%2e%2fapp.log")


def html_entity_xss() -> str:
    return html.unescape("&#60;script&#62;alert(1)&#60;/script&#62;")


def nested_encoding() -> str:
    # The payload is URL-encoded; a single decode reveals the path traversal.
    return urllib.parse.unquote("%2e%2e%2fsecret.txt")
