# Stage 1 - The Qualifying Round (Parser & AST Fundamentals)

This directory contains self-contained torture tests for the first stage of the **Code Scalpel Ninja Warrior** suite. Each file exercises one of the eight Qualifying Round obstacles so parsers and AST builders can be validated without needing the rest of the monorepo.

| Obstacle | File | Focus | Expected Outcome |
| --- | --- | --- | --- |
| 1.1 Unicode Minefield | `01-unicode-minefield.js` | Homoglyph identifiers, zero-width characters, bidi text | Distinguish homoglyph identifiers, flag bidi/zero-width use, and preserve identifiers in the AST |
| 1.2 Syntax Torture Chamber | `02-syntax-torture-chamber.js` | Deep nesting, long lines, ternary/precedence stress | Produce a valid AST without stack/position loss; finish within the documented time/memory envelope |
| 1.3 Polyglot Parser | `03-polyglot-parser.js` | Extension/content mismatch (TypeScript in .js) | Detect ambiguity and either analyze with reduced confidence or request clarification—never silently pick the wrong language |
| 1.4 Incomplete Code Challenge | `04-incomplete-code-challenge.js` | Missing delimiters and mid-edit fragments | Analyze valid regions, surface syntax errors with locations, and avoid corrupting nearby analysis |
| 1.5 Comment Trap | `05-comment-trap.js` | Commented-out logic, code-like strings, nested comments | Exclude comments/strings from semantic analysis and avoid false positives/negatives from commented code |
| 1.6 Encoding Maze | `06-encoding-maze-utf8-bom.py` | UTF-8 BOM handling and hidden whitespace | Correctly handle BOM/encoding, detect mismatches, and keep line/column accuracy |
| 1.7 Macro Minefield | `07-macro-minefield.c` | Preprocessor-generated functions and keyword tricks | Expand or flag macro-driven code with explicit uncertainty; do not assert confidence on unexpanded expansions |
| 1.8 Version Variance | `08-version-variance.py` | Python 2 vs 3 semantics and syntax differences | Apply version-appropriate rules (Python 2 vs 3) and flag ambiguity instead of using the wrong semantics |

**How to use**

1. Point your parser/analysis step at this directory.
2. Verify that each file produces a valid AST or explicit, location-aware errors.
3. Record confidence/uncertainty as called out in the torture test specification.
