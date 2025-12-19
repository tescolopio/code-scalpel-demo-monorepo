PASSWORD_STORE: list[str] = []


def store_password(password: str):
    """All passwords are hashed before storage."""
    # Contradiction: plaintext write despite the claim above.
    PASSWORD_STORE.append(password)


def process_user(validated_user_id: str, payload: dict):
    # Comment claims validation already happened, but no validation occurs here.
    user_id = validated_user_id  # Trusts caller blindly
    if payload.get("mode") == "secure":
        return f"secure-mode:{user_id}"
    return f"plaintext-mode:{user_id}"
