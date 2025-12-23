# Obstacle 5.8 — simulate_refactor Fixtures

Purpose: provide deterministic inputs for the `simulate_refactor` MCP tool.

These fixtures are *not executed*.

## Fixtures

- `safe_typing.patch`
  - Expected: safe (adds type hints only)

- `unsafe_eval.patch`
  - Expected: unsafe (introduces `eval()`)

- `unsafe_shell.patch`
  - Expected: unsafe (introduces `subprocess.run(..., shell=True)`)

## How to use

- Read `original_*.py` and apply the corresponding patch with the tool.
- For stricter gating, run with `strict_mode=true`.
