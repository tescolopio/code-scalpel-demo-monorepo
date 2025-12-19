"""
Obstacle 6.4: Path explosion precipice.

The branching below grows exponentially with DEPTH, stressing symbolic execution.
The default depth is conservative; increase PATH_EXPLOSION_DEPTH to observe
timeouts and partial exploration behavior.
"""

import os
import random

DEPTH = int(os.environ.get("PATH_EXPLOSION_DEPTH", "12"))
SEED_MAX = 2 ** 16
BITMASK_32 = (1 << 32) - 1


def branching_state_machine(seed: int, depth: int = DEPTH) -> int:
    """Recursive branching that doubles paths each level."""
    if depth == 0:
        return seed

    if seed & 1:
        # Odd path: mutate via Collatz-style rule
        next_seed = seed * 3 + 1
    else:
        # Even path: invert bits and add a twist (bounded to 32 bits)
        next_seed = ((~seed) & BITMASK_32) ^ depth

    # Two divergent recursive branches: path count doubles every call
    left = branching_state_machine(next_seed ^ depth, depth - 1)
    right = branching_state_machine(next_seed + depth, depth - 1)
    return left ^ right


def explode_paths(runs: int = 3):
    """
    Trigger multiple independent explosions to amplify path count.

    Complexity: branching_state_machine is O(2**depth). Depth > 20 will produce
    millions of paths and should be avoided unless the sandbox enforces strict
    time/space limits.
    """
    results = []
    for _ in range(runs):
        seed = random.randint(1, SEED_MAX)
        results.append(branching_state_machine(seed, depth=DEPTH))
    return results


if __name__ == "__main__":
    if os.environ.get("RUN_PATH_EXPLOSION", "").lower() != "yes":
        raise SystemExit(
            "Path explosion demo disabled. Set RUN_PATH_EXPLOSION=yes to run."
        )
    print(explode_paths())
