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

    try:
        if MODE == "detonate":
            while True:
                _alloc()
        else:
            _bounded(_alloc)
    finally:
        blobs.clear()
    return len(blobs)


def descriptor_storm():
    """Open file descriptors until limit."""
    handles = []
    paths = []
    def _open():
        fd, path = tempfile.mkstemp(prefix="midoriyama-")
        handles.append(fd)
        paths.append(path)

    try:
        if MODE == "detonate":
            while True:
                _open()
        else:
            _bounded(_open)
    finally:
        for fd in handles:
            os.close(fd)
        for path in paths:
            try:
                os.remove(path)
            except OSError:
                # Best-effort cleanup: ignore failures when removing temp files.
                pass
    return len(handles)


def disk_fill():
    """Write repeatedly to fill disk quota."""
    def _cleanup(target: str) -> bool:
        try:
            os.remove(target)
            return True
        except OSError:
            return False

    cleaned = False
    temp_path = tempfile.mkstemp(prefix="midoriyama-disk-")[1]
    chunk = b"flood" * 1024
    try:
        with open(temp_path, "wb") as handle:
            if MODE == "detonate":
                while True:
                    handle.write(chunk)
                    handle.flush()
            else:
                for _ in range(BOUNDED_ITERATIONS):
                    handle.write(chunk)
    finally:
        cleaned = _cleanup(temp_path)
    return {"path": temp_path, "cleaned": cleaned}


def thread_bomb():
    """Spawn threads without bound."""
    spawned = []
    def _spawn():
        t = threading.Thread(target=time.sleep, args=(60,), daemon=True)
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
        except (OSError, RuntimeError, MemoryError) as exc:  # pragma: no cover - environment-specific
            results[name] = f"FAILED: {exc}"
    return results


if __name__ == "__main__":
    if MODE not in {"dry-run", "detonate"}:
        raise SystemExit(f"Unknown RESOURCE_ASSAULT_MODE '{MODE}'")
    if MODE != "detonate":
        print("Dry-run mode; set RESOURCE_ASSAULT_MODE=detonate for full attack.")
    print(run_all())
