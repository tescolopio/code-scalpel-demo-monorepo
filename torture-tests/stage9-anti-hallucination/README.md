# Stage 9: Anti-Hallucination Gauntlet

This stage contains tests specifically designed to catch AI agent hallucinations
when using code analysis tools. Each obstacle represents a common failure mode
where an LLM might make confident-but-wrong assertions without proper tooling.

## Obstacles

### 9.1 - Semantic Equivalence Trap
Test that semantically equivalent code gets the same security verdict.
An LLM might hallucinate different risk levels for:
- `if x: return a else: return b` vs `return a if x else b`
- Loop vs comprehension
- Class method vs standalone function

### 9.2 - Decoy Sanitizer Matrix
Systematic false positive/negative testing with:
- Real sanitizers that work
- Decoy sanitizers that don't sanitize
- Partial sanitizers (escape some but not all)
- Over-sanitizers (escape too much, breaking functionality)

### 9.3 - Cross-Language Consistency
Same vulnerability pattern in Python, JavaScript, TypeScript, Java.
All should be detected with similar confidence.

### 9.4 - Negative Inference Validation
Tests for invalid backward reasoning:
- "Function A is safe" does NOT mean "Function B that calls A is safe"
- "This path is clean" does NOT mean "all paths are clean"

### 9.5 - Quantitative Precision Matrix
Formal precision/recall/F1 measurement with:
- True Positives (vulnerabilities correctly flagged)
- True Negatives (safe code correctly cleared)
- False Positives (safe code incorrectly flagged)
- False Negatives (vulnerabilities missed)

### 9.6 - Confidence Consistency
Same vulnerability, different coding styles:
- Inline vs extracted function
- Sync vs async
- Class method vs module function
- With/without type hints

All should report consistent confidence scores.

### 9.7 - Hallucination Honeypots
Code patterns that commonly cause LLM hallucinations:
- Comments describing non-existent code
- Variable names suggesting wrong types
- Import aliases that hide true module identity
- Docstrings from copied code (wrong context)
