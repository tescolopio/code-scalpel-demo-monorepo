# Mount Midoriyama – Ultimate Sandbox & Symbolic Limits

This directory contains the Stage 6 torture tests described in `Code_Scalpel_Ninja_Warrior_Torture_Tests.md`. Each artifact targets one obstacle and is designed to be executed or statically analyzed inside a hardened sandbox. Do **not** run these outside a constrained environment.

## Artifacts

- `sandbox_escape.py` – escape attempts across filesystem, network, process, shared memory, and symlink vectors (Obstacle 6.1).
- `resource_exhaustion.py` – CPU, memory, descriptor, disk, and thread bombs with guard rails so they are only exercised intentionally (Obstacle 6.2).
- `side_channel.py` – timing/load/error-based covert channels with configurable secrets (Obstacle 6.3).
- `path_explosion.py` – deliberately branching control flow to trigger symbolic execution path explosion (Obstacle 6.4).
- `constraint_solver_torture.smt2` – adversarial SMT constraints that should time out gracefully (Obstacle 6.5).
- `adversarial_agent.md` – scripted multi-step adversarial change sequence that must not bypass policy enforcement (Obstacle 6.6).

## Usage

1. Run from the repository root (or adjust paths accordingly).
2. Point Code Scalpel (or your sandbox harness) at this directory and run under strict limits.

   **Examples (from repo root):**

   ```bash
   # Change into the directory then scan
   cd torture-tests/mount-midoriyama
   code-scalpel run .

   # Or stay at root and pass the target
   code-scalpel run torture-tests/mount-midoriyama
   ```

   With config:

   ```yaml
   # code-scalpel.yml
   targets:
     - path: torture-tests/mount-midoriyama
       mode: sandboxed
   ```

   ```bash
   code-scalpel run --config code-scalpel.yml
   ```

   Generic harness example:

   ```bash
   my-sandbox-harness \
     --workdir "$(pwd)/torture-tests/mount-midoriyama" \
     --cpu-limit 2 \
     --memory-limit 512M
   ```

3. Execute or symbolically analyze each artifact individually under sandbox limits.
4. Capture evidence per the torture-test doc: result, confidence/uncertainty, performance metrics, and hashes.

Expected passes and failure modes are documented inline within each artifact to keep the tests self-contained.
