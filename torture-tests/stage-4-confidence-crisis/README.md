# Stage 4: The Confidence Crisis

Uncertainty quantification torture tests for Code Scalpel, built from an internal Code Scalpel specification. Each obstacle is isolated in its own folder with:

- Minimal code samples that exercise the obstacle
- Ground-truth or ambiguity expectations
- Execution and evidence notes tailored to Code Scalpel output (confidence, limitations, contradictions)

## Obstacles and expected outcomes

| Obstacle | Artifacts | Expected Outcome (pass) |
| --- | --- | --- |
| 4.1 Calibration Test | `obstacle-4.1-calibration-test/*` | Report confidence buckets that align with ground truth (no high-confidence wrong answers; calibration error < 10%) |
| 4.2 Adversarial Naming | `obstacle-4.2-adversarial-naming/*` | Base findings on behavior, not names/comments; flag misleading “sanitize” that does nothing and avoid penalizing safe-but-scary names |
| 4.3 Duplicate Function Dilemma | `obstacle-4.3-duplicate-function-dilemma/*` | Acknowledge multiple `validate` targets and avoid high-confidence answers without disambiguation |
| 4.4 Incomplete Information Acknowledgment | `obstacle-4.4-incomplete-information-ack/*` | Explicitly list unanalyzed dependencies/runtime data and lower confidence instead of claiming certainty |
| 4.5 Confidence Decay Test | `obstacle-4.5-confidence-decay/*` | Decrease confidence monotonically across the inference chain A→B→C→D; highest confidence only at the direct vulnerability |
| 4.6 Contradiction Detector | `obstacle-4.6-contradiction-detector/*` | Detect conflicting evidence, prefer code behavior over comments, and surface contradictions with reduced confidence |

See each obstacle folder for the exact artifacts and evidence to collect per the master torture-test specification.
