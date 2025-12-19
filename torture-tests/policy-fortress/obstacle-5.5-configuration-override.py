"""
Obstacle 5.5: Configuration Override

Shows how environment/config merges can silently disable enforcement.
"""

import json
import os
from pathlib import Path

DEFAULT_POLICY = {"block_eval": True, "enforce_admin_mfa": True}


def load_policy_from_file(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def effective_policy(config_path: str = "policy.json") -> dict:
    file_policy = load_policy_from_file(Path(config_path))
    raw_env_policy = os.getenv("CODE_SCALPEL_POLICY")
    env_policy = raw_env_policy if raw_env_policy else "{}"
    try:
        env_overrides = json.loads(env_policy)
    except json.JSONDecodeError:
        env_overrides = {}
    merged = {**DEFAULT_POLICY, **file_policy, **env_overrides}
    return merged


def dangerous_eval() -> None:
    policy = effective_policy()
    if not policy.get("block_eval", True):
        execute_untrusted("print('policy is disabled; executing arbitrary code')")


def execute_untrusted(payload: str) -> None:
    exec(payload, {})


if __name__ == "__main__":
    dangerous_eval()
