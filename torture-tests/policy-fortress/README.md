# Stage 5: The Policy Fortress Torture Tests

Guardrail and policy bypass fixtures derived from the **Code_Scalpel_Ninja_Warrior_Torture_Tests** document (Stage 5: The Policy Fortress, obstacles 5.1–5.7). These files are intentionally adversarial; they should be analyzed by Code Scalpel (or any policy engine) to verify that guardrails cannot be bypassed through encoding tricks, indirection, configuration changes, or social engineering.

## How to use these fixtures

- Point Code Scalpel at the files in this directory and assert the Expected Detection notes in the table below.
- The files are standalone; no external services are required to analyze them.
- Obstacle 5.1 is annotated with `STEP` comments to mimic the multi-commit erosion pattern. Treat each step as a separate diff when running incremental checks.

| Obstacle | Fixture | Focus | Expected Detection |
| --- | --- | --- | --- |
| 5.1 Incremental Erosion | `obstacle-5.1-incremental-erosion.py` | Cumulative vulnerability across small changes | Detect cumulative admin escalation created by the combination of helper, data-flow redirect, fail-open handler, config toggle, and final wiring |
| 5.2 Encoding Evasion Suite | `obstacle-5.2-encoding-evasion.py` | Encoded payloads and nested decoding | Decode base64/Unicode/hex/URL/HTML layers and flag the underlying SQL/path traversal/XSS patterns |
| 5.3 Transitive Dependency Attack | `obstacle-5.3-transitive-dependency-attack.py` | Forbidden action through indirection | Track `/etc/passwd` from assignment through sanitize/write helpers and block at the final file write |
| 5.4 Semantic Equivalence Bypass | `obstacle-5.4-semantic-equivalence-bypass.py` | Same outcome with different syntax | Treat TRUNCATE/DELETE and shell variants as equivalent destructive operations subject to the same policy |
| 5.5 Configuration Override | `obstacle-5.5-configuration-override.py` | Policy disablement via config/env | Detect that environment/config merges disable enforcement and flag the attempted eval when policy is off |
| 5.6 Social Engineering Simulation | `obstacle-5.6-social-engineering.py` | Prompt-injection in code/comments | Ignore manipulative comments/strings and apply policies based on behavior only |
| 5.7 Change Budget Exhaustion | `obstacle-5.7-change-budget-exhaustion.py` | Blast radius and line-count evasions | Count all added lines (including “auto-generated” blocks) and flag the hidden `os.system` execution that sneaks in among filler changes |

These fixtures are written to be concise but cover the essential bypass vectors described in Stage 5. Use them as regression inputs when tuning policy rules or auditing AI agent behavior.
