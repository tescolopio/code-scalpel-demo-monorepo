"""
Obstacle 6.3: Side channel surveillance.

These helpers intentionally encode secrets into timing, CPU load, and error
messages. Code Scalpel should flag the covert channels even when the semantic
code appears benign.
"""

import os
import time
import hashlib

SECRET = os.environ.get("SIDE_CHANNEL_SECRET", "midoriyama")
TIMING_HIGH = float(os.environ.get("SIDE_CHANNEL_TIMING_HIGH", "0.15"))
TIMING_LOW = float(os.environ.get("SIDE_CHANNEL_TIMING_LOW", "0.02"))


def leak_via_timing(secret: str = SECRET):
    """Encode bits into sleep durations."""
    for bit in "".join(f"{ord(c):08b}" for c in secret):
        time.sleep(TIMING_HIGH if bit == "1" else TIMING_LOW)


def leak_via_cpu(secret: str = SECRET):
    """Encode characters into CPU load duration."""
    payload = sum(ord(ch) for ch in secret)
    end = time.time() + payload * 0.0001
    while time.time() < end:
        payload = (payload * 3) ^ 0x5F3759DF  # keep CPU busy
    return payload


def leak_via_error(secret: str = SECRET):
    """Embed a secret fragment inside an error message."""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
    raise RuntimeError(f"Error token:sha256:{digest}: simulated failure")


CHANNELS = (leak_via_timing, leak_via_cpu, leak_via_error)


def demo():
    for channel in CHANNELS:
        name = channel.__name__
        try:
            channel()
            print(f"{name}: completed (timing/load channel may have been leaked).")
        except RuntimeError as exc:  # pragma: no cover - intentional error channel
            print(f"{name}: raised {exc}")


if __name__ == "__main__":
    if os.environ.get("RUN_SIDE_CHANNELS", "").lower() != "yes":
        raise SystemExit(
            "Refusing to emit side-channel patterns without RUN_SIDE_CHANNELS=yes"
        )
    demo()
