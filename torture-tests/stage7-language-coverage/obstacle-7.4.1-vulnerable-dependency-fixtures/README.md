# Obstacle 7.4.1 — Vulnerable Dependency Fixtures

Purpose: provide **ground-truth dependency manifests** that should trigger findings in the `scan_dependencies` MCP tool.

These fixtures are *not executed*.

## How to use

- NPM:
  - Scan: `vulnerable.package.json`
  - Control: `fixed.package.json`

- Python:
  - Scan: `vulnerable.requirements.txt`
  - Control: `fixed.requirements.txt`

- Maven:
  - Scan: `vulnerable.pom.xml`
  - Control: `fixed.pom.xml`

## Expected outcomes (high level)

- Vulnerable manifests should usually produce 1+ vulnerabilities from OSV.
- Fixed manifests should produce fewer (ideally 0).

Note: OSV results can change over time as advisories are added/updated.
