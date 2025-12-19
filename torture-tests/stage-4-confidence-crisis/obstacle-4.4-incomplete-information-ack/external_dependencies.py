import json
import os
from pathlib import Path
from urllib.parse import urljoin

import requests


def fetch_user_profile(user_id: str) -> dict:
    api_base = os.environ.get("PROFILE_API")
    if not api_base:
        raise RuntimeError("PROFILE_API not configured")
    if not user_id.isalnum():
        raise ValueError("user_id failed basic validation")
    base = api_base if api_base.endswith("/") else f"{api_base}/"
    profile_url = urljoin(base, f"users/{user_id}")
    response = requests.get(profile_url, timeout=3)
    response.raise_for_status()
    # Trusting remote validation: Code Scalpel must flag this as unknown.
    return response.json()


def load_feature_flags() -> dict:
    config_path = Path(os.environ.get("FEATURE_FLAG_FILE", "/etc/app/flags.json"))
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    data = config_path.read_text()
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid feature flag file") from exc


def is_admin(user_id: str) -> bool:
    flags = load_feature_flags()
    profile = fetch_user_profile(user_id)
    # Security decision depends entirely on remote + config data.
    return flags.get("force_admin") is True or profile.get("role") == "admin"
