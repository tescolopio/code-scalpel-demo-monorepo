from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mcp_contract.mcp_http_client import McpHttpClient, McpHttpConfig


def _repo_root() -> Path:
    # file: torture-tests/mcp_contract/ninja_warrior/test_...
    # parents[3] == repo root (Code-Scalpel-Ninja-Warrior)
    return Path(__file__).resolve().parents[3]


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(host: str, port: int, timeout_seconds: float = 15.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except Exception as e:  # noqa: BLE001 - test harness utility
            last_error = e
            time.sleep(0.1)
    raise RuntimeError(f"MCP server did not start on {host}:{port}: {last_error}")


@dataclass
class _ServerHandle:
    base_url: str
    process: subprocess.Popen[str]


@pytest.fixture()
def policy_dir_in_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a temporary policy_dir under the repo root.

    Some MCP runtimes restrict tool file access to within the configured --root.
    """
    base = _repo_root() / "torture-tests" / "evidence" / "tmp_policy_integrity"
    base.mkdir(parents=True, exist_ok=True)
    policy_dir = base / f"case_{time.time_ns()}"
    policy_dir.mkdir()
    try:
        yield policy_dir
    finally:
        shutil.rmtree(policy_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def mcp_server_with_policy_secret(tmp_path_factory: pytest.TempPathFactory) -> _ServerHandle:
    """Start a dedicated MCP server with policy secret env configured.

    The default session server fixture does not (and cannot) inherit per-test env changes,
    so we launch a separate server process with deterministic env vars.
    """
    repo_root = _repo_root()
    port = _pick_free_port()
    host = "127.0.0.1"

    log_dir = tmp_path_factory.mktemp("mcp_policy_integrity")
    log_path = log_dir / "mcp_server_policy_integrity.log"

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    # Support both names seen in the repo and older tooling.
    # The MCP tool docs reference SCALPEL_MANIFEST_SECRET.
    env["SCALPEL_MANIFEST_SECRET"] = "test-manifest-secret"
    env["SCALPEL_POLICY_SECRET"] = "test-manifest-secret"

    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                "code-scalpel",
                "mcp",
                "--transport",
                "streamable-http",
                "--host",
                host,
                "--port",
                str(port),
                "--root",
                str(repo_root),
            ],
            cwd=str(repo_root),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )

    _wait_for_port(host, port, timeout_seconds=20.0)

    handle = _ServerHandle(base_url=f"http://{host}:{port}", process=process)
    try:
        yield handle
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except Exception:  # noqa: BLE001
            process.kill()


@pytest.fixture()
def mcp_client_policy(mcp_server_with_policy_secret: _ServerHandle) -> McpHttpClient:
    client = McpHttpClient(McpHttpConfig(base_url=mcp_server_with_policy_secret.base_url, timeout_seconds=10.0))
    init_resp = client.initialize()
    assert "result" in init_resp, f"initialize failed: {init_resp}"
    assert client.session_id, "initialize did not yield a session id"
    return client


def _fill_defaults(d: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(d)
    normalized.setdefault("success", False)
    normalized.setdefault("error", None)
    normalized.setdefault("files_verified", None)
    normalized.setdefault("files_verified_count", None)
    normalized.setdefault("files_checked", None)
    normalized.setdefault("files_verified_ok", None)
    normalized.setdefault("files_missing", None)
    normalized.setdefault("files_verified_details", None)
    return normalized


def _normalize_verify_policy_integrity_result(raw: Any) -> dict[str, Any]:
    """Normalize output across server formats.

    - Flat dict
    - Envelope v1 wrapper
    - JSON-RPC error wrapper
    """
    if not isinstance(raw, dict):
        return _fill_defaults({"success": False, "error": f"non-dict result: {type(raw).__name__}", "_raw": raw})

    # Some clients flatten envelope responses but preserve the original under _envelope.
    # If the tool-specific error lives in _envelope.data.error, surface it.
    if "_envelope" in raw and not raw.get("error"):
        env = raw.get("_envelope")
        if isinstance(env, dict) and isinstance(env.get("data"), dict):
            env_err = env["data"].get("error")
            if env_err:
                patched = dict(raw)
                patched["error"] = env_err
                raw = patched

    if "jsonrpc" in raw and "error" in raw and isinstance(raw.get("error"), dict):
        err = raw.get("error") or {}
        msg = err.get("message") or str(err)
        return _fill_defaults({"success": False, "error": msg, "_jsonrpc": raw})

    if isinstance(raw.get("capabilities"), list) and "data" in raw:
        data = raw.get("data")
        if not isinstance(data, dict):
            msg = None
            if isinstance(raw.get("error"), dict):
                msg = raw["error"].get("message")
            return _fill_defaults({"success": False, "error": msg or "envelope missing data", "_envelope": raw})
        if raw.get("error"):
            err = raw.get("error")
            msg = err.get("message") if isinstance(err, dict) else str(err)
            normalized = dict(data)
            normalized.update({"success": False, "error": msg, "_envelope": raw})
            return _fill_defaults(normalized)
        normalized = dict(data)
        if "success" not in normalized:
            normalized["success"] = False if normalized.get("error") else True
        if "error" not in normalized:
            normalized["error"] = None
        normalized["_envelope"] = raw
        return _fill_defaults(normalized)

    # Final fallback: if the tool (or client) preserved an envelope, prefer the
    # tool-specific error message embedded in the envelope payload.
    normalized = dict(raw)
    if not normalized.get("error") and isinstance(normalized.get("_envelope"), dict):
        env = normalized["_envelope"]
        if isinstance(env.get("data"), dict):
            env_err = env["data"].get("error")
            if env_err:
                normalized["error"] = env_err

    return _fill_defaults(normalized)


def _call_verify_policy_integrity(mcp_client: McpHttpClient, args: dict[str, Any], max_seconds: float = 20.0) -> tuple[dict[str, Any], float]:
    start = time.monotonic()
    raw = mcp_client.tools_call("verify_policy_integrity", args)
    elapsed = time.monotonic() - start
    assert elapsed < max_seconds, {"elapsed": elapsed, "raw": raw, "args": args}
    return _normalize_verify_policy_integrity_result(raw), elapsed


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hmac_sha256(secret: bytes, message: str) -> str:
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _make_manifest(policy_dir: Path, secret: str, files: dict[str, bytes]) -> dict[str, Any]:
    """Create a signed policy manifest matching the repo's crypto-verify schema."""
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    manifest_files: dict[str, dict[str, Any]] = {}
    for rel, content in files.items():
        path = policy_dir / rel
        path.write_bytes(content)
        manifest_files[rel] = {"hash": _sha256_bytes(content), "size": len(content)}

    unsigned = {"version": "1.0", "created_at": created_at, "files": manifest_files}
    signature = "hmac-sha256:" + _hmac_sha256(secret.encode("utf-8"), _canonical_json(unsigned))
    return {**unsigned, "signature": signature}


def _write_manifest_file(policy_dir: Path, manifest: dict[str, Any]) -> Path:
    manifest_path = policy_dir / "policy.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def _write_manifest_env_b64(manifest: dict[str, Any]) -> str:
    manifest_json = json.dumps(manifest)
    return base64.b64encode(manifest_json.encode("utf-8")).decode("utf-8")


def test_verify_policy_integrity_missing_manifest_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo
    (policy_dir / "policy.yaml").write_text("rules: []\n", encoding="utf-8")

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is False, result
    err = result.get("error")
    if not err and isinstance(result.get("_envelope"), dict) and isinstance(result["_envelope"].get("data"), dict):
        err = result["_envelope"]["data"].get("error")
    assert err, result


@pytest.mark.xfail(
    reason="Known MCP runtime blocker: verify_policy_integrity returns internal_error 'Failed to load policy manifest' even when a valid manifest is present.",
    strict=False,
)
def test_verify_policy_integrity_valid_manifest_succeeds(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo

    files = {
        "policy.yaml": b"rules: []\n",
        "budget.yaml": b"budget: 10\n",
        "policy.rego": b"package demo\nallow { true }\n",
        "config.json": b"{\"mode\":\"strict\"}\n",
    }
    manifest = _make_manifest(policy_dir, secret="test-manifest-secret", files=files)
    _write_manifest_file(policy_dir, manifest)

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is True, result


def test_verify_policy_integrity_hash_mismatch_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo

    files = {"policy.yaml": b"rules: []\n"}
    manifest = _make_manifest(policy_dir, secret="test-manifest-secret", files=files)
    _write_manifest_file(policy_dir, manifest)

    # Tamper after signing.
    (policy_dir / "policy.yaml").write_text("rules: [tampered]\n", encoding="utf-8")

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is False, result
    err = result.get("error")
    if not err and isinstance(result.get("_envelope"), dict) and isinstance(result["_envelope"].get("data"), dict):
        err = result["_envelope"]["data"].get("error")
    assert err, result


def test_verify_policy_integrity_signature_invalid_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo

    files = {"policy.yaml": b"rules: []\n"}
    manifest = _make_manifest(policy_dir, secret="test-manifest-secret", files=files)
    manifest["signature"] = "hmac-sha256:" + ("0" * 64)
    _write_manifest_file(policy_dir, manifest)

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is False, result
    err = result.get("error")
    if not err and isinstance(result.get("_envelope"), dict) and isinstance(result["_envelope"].get("data"), dict):
        err = result["_envelope"]["data"].get("error")
    assert err, result


def test_verify_policy_integrity_missing_file_in_manifest_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo

    # Create manifest referencing a file that does not exist.
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    unsigned = {
        "version": "1.0",
        "created_at": created_at,
        "files": {"policy.yaml": {"hash": "sha256:" + ("0" * 64), "size": 123}},
    }
    signature = "hmac-sha256:" + _hmac_sha256(b"test-manifest-secret", _canonical_json(unsigned))
    manifest = {**unsigned, "signature": signature}
    _write_manifest_file(policy_dir, manifest)

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is False, result
    err = result.get("error")
    if not err and isinstance(result.get("_envelope"), dict) and isinstance(result["_envelope"].get("data"), dict):
        err = result["_envelope"]["data"].get("error")
    assert err, result


def test_verify_policy_integrity_unexpected_file_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo

    files = {"policy.yaml": b"rules: []\n"}
    manifest = _make_manifest(policy_dir, secret="test-manifest-secret", files=files)
    _write_manifest_file(policy_dir, manifest)

    # Add an extra policy file not in manifest.
    (policy_dir / "extra.yaml").write_text("extra: true\n", encoding="utf-8")

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is False, result
    err = result.get("error")
    if not err and isinstance(result.get("_envelope"), dict) and isinstance(result["_envelope"].get("data"), dict):
        err = result["_envelope"]["data"].get("error")
    assert err, result


def test_verify_policy_integrity_invalid_manifest_json_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo
    (policy_dir / "policy.yaml").write_text("rules: []\n", encoding="utf-8")
    (policy_dir / "policy.manifest.json").write_text("{not json}", encoding="utf-8")

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is False, result
    err = result.get("error")
    if not err and isinstance(result.get("_envelope"), dict) and isinstance(result["_envelope"].get("data"), dict):
        err = result["_envelope"]["data"].get("error")
    assert err, result


def test_verify_policy_integrity_manifest_source_env_invalid_base64_fails_closed(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo
    (policy_dir / "policy.yaml").write_text("rules: []\n", encoding="utf-8")

    # Cannot mutate the server's env after launch; this asserts safe failure on missing/invalid env manifest.
    # When SCALPEL_POLICY_MANIFEST is absent (or invalid), env source should fail closed.
    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "env"})
    assert result.get("success") is False, result


def test_verify_policy_integrity_invalid_manifest_source_fails_safely(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo
    (policy_dir / "policy.yaml").write_text("rules: []\n", encoding="utf-8")

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "nope"})
    assert result.get("success") is False, result


def test_verify_policy_integrity_missing_args_fails_safely(mcp_client_policy):
    result, _ = _call_verify_policy_integrity(mcp_client_policy, {})
    assert result.get("success") is False, result


def test_verify_policy_integrity_nul_byte_policy_dir_fails_safely(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo
    nul = chr(0)

    result, _ = _call_verify_policy_integrity(
        mcp_client_policy,
        {"policy_dir": str(policy_dir) + nul, "manifest_source": "file"},
        max_seconds=20.0,
    )
    assert result.get("success") is False, result


@pytest.mark.xfail(
    reason="Known MCP runtime blocker: verify_policy_integrity returns internal_error 'Failed to load policy manifest' even with a valid manifest under a unicode policy_dir.",
    strict=False,
)
def test_verify_policy_integrity_unicode_policy_dir_safe(policy_dir_in_repo, mcp_client_policy):
    policy_dir = policy_dir_in_repo.parent / "policíes"
    policy_dir.mkdir()

    files = {"policy.yaml": b"rules: []\n"}
    manifest = _make_manifest(policy_dir, secret="test-manifest-secret", files=files)
    _write_manifest_file(policy_dir, manifest)

    result, _ = _call_verify_policy_integrity(mcp_client_policy, {"policy_dir": str(policy_dir), "manifest_source": "file"})
    assert result.get("success") is True, result
