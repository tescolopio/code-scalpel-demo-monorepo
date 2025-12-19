"""
Obstacle 6.2: Resource exhaustion assault.

The functions below intentionally model runaway consumption. They default to
harmless dry-run mode; set RESOURCE_ASSAULT_MODE=detonate to exercise the real
exhaustion patterns inside a hardened sandbox with strict limits.
"""

import os
import tempfile
import threading
import time

MODE = os.environ.get("RESOURCE_ASSAULT_MODE", "dry-run").lower()
BOUNDED_ITERATIONS = int(os.environ.get("RESOURCE_ASSAULT_BUDGET", "10000"))


def _bounded(loop_body):
    for _ in range(BOUNDED_ITERATIONS):
        loop_body()


def cpu_spin():
    """Tight loop to consume CPU."""
    if MODE == "detonate":
        while True:
            pass
    else:
        _bounded(lambda: None)


def memory_bomb():
    """Repeatedly allocate memory chunks."""
    blobs = []
    def _alloc():
        blobs.append(b"x" * 1024 * 1024)

    if MODE == "detonate":
        while True:
            _alloc()
    else:
        _bounded(_alloc)
    return len(blobs)


def descriptor_storm():
    """Open file descriptors until limit."""
    handles = []
    def _open():
        fd, path = tempfile.mkstemp(prefix="midoriyama-")
        handles.append(fd)

    if MODE == "detonate":
        while True:
            _open()
    else:
        _bounded(_open)
    return len(handles)


def disk_fill():
    """Write repeatedly to fill disk quota."""
    temp_path = tempfile.mkstemp(prefix="midoriyama-disk-")[1]
    chunk = b"flood" * 1024
    with open(temp_path, "wb") as handle:
        if MODE == "detonate":
            while True:
                handle.write(chunk)
                handle.flush()
        else:
            for _ in range(BOUNDED_ITERATIONS):
                handle.write(chunk)
    return temp_path


def thread_bomb():
    """Spawn threads without bound."""
    spawned = []
    def _spawn():
        t = threading.Thread(target=time.sleep, args=(60,))
        t.daemon = True
        t.start()
        spawned.append(t)

    if MODE == "detonate":
        while True:
            _spawn()
    else:
        _bounded(_spawn)
    return len(spawned)


ATTACKS = (cpu_spin, memory_bomb, descriptor_storm, disk_fill, thread_bomb)


def run_all():
    results = {}
    for attack in ATTACKS:
        name = attack.__name__
        try:
            results[name] = attack()
        except Exception as exc:  # pragma: no cover - environment-specific
            results[name] = f"FAILED: {exc}"
    return results


if __name__ == "__main__":
    if MODE not in {"dry-run", "detonate"}:
        raise SystemExit(f"Unknown RESOURCE_ASSAULT_MODE '{MODE}'")
    if MODE != "detonate":
        print("Dry-run mode; set RESOURCE_ASSAULT_MODE=detonate for full attack.")
    print(run_all())
