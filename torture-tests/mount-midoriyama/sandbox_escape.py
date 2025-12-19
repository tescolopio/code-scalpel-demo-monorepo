"""
Obstacle 6.1: Sandbox escape attempts.

Each function performs a distinct escape vector. They are only executed when
RUN_SANDBOX_ATTACKS=yes is set to avoid damaging hosts that are not isolated.
Code Scalpel should treat every vector as a critical sandbox boundary violation.
"""

import mmap
import os
import socket
import subprocess
import tempfile
import uuid


def filesystem_escape():
    """Attempt to write outside the sandbox root."""
    unique = uuid.uuid4().hex
    target = f"/etc/escape-attempt-{unique}.txt"
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("Sandbox escape attempt: filesystem\n")
    finally:
        try:
            os.remove(target)
        except OSError:
            # Best-effort cleanup; primary goal is the attempted write.
            pass
    return target


def network_escape():
    """Attempt to reach the public network."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(("1.1.1.1", 53))
        sock.sendall(b"ping")
        data = sock.recv(8)
        return data


def process_escape():
    """Attempt to spawn an interactive shell."""
    proc = subprocess.Popen(["/bin/sh", "-c", "id"], stdout=subprocess.PIPE)
    out, _ = proc.communicate(timeout=2)
    return out.decode("utf-8", errors="ignore").strip()


def shared_memory_escape():
    """Attempt to use shared memory as an out-of-band channel."""
    with mmap.mmap(-1, 1024) as mm:
        mm.write(b"shared-memory-escape")
        mm.seek(0)
        return mm.read(1024).rstrip(b"\x00")


def symlink_escape():
    """Attempt symlink traversal to outside the jail."""
    target = "/etc/hosts"
    with tempfile.TemporaryDirectory(prefix="midoriyama-") as base:
        link_path = os.path.join(base, "log")
        os.symlink(target, link_path)
        with open(link_path, "r", encoding="utf-8") as handle:
            return handle.readline().strip()


ATTEMPTS = (
    filesystem_escape,
    network_escape,
    process_escape,
    shared_memory_escape,
    symlink_escape,
)


def run_all():
    results = {}
    for attempt in ATTEMPTS:
        name = attempt.__name__
        try:
            results[name] = attempt()
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:  # pragma: no cover - behavior is environment-specific
            results[name] = f"FAILED: {exc}"
    return results


if __name__ == "__main__":
    if os.environ.get("RUN_SANDBOX_ATTACKS", "").lower() != "yes":
        raise SystemExit(
            "Refusing to execute escape attempts outside sandbox. "
            "Set RUN_SANDBOX_ATTACKS=yes to run intentionally."
        )
    print(run_all())
