# Audit Trail Test Suite

Comprehensive test suite for Code Scalpel's **Audit Trail** feature - tamper-resistant, cryptographically-signed logging of all security events for compliance and forensics.

## Overview

The Audit Trail provides:
- **HMAC-SHA256 signing** of all events
- **Tamper detection** via integrity verification
- **JSON-lines format** for easy parsing and streaming
- **Event type classification** for different security events
- **Severity levels** for prioritization

## Test Files

| File | Purpose | Test Count |
|------|---------|------------|
| `audit_trail_framework.py` | Core framework with AuditLog, signing, verification | - |
| `test_event_recording.py` | Event schema, JSON-lines format, signature attachment | 15 |
| `test_hmac_signing.py` | HMAC-SHA256 signing, secret management, canonical JSON | 18 |
| `test_tamper_detection.py` | Tampering detection, corruption handling, error reporting | 23 |
| `test_event_types.py` | All event types and severity levels | 23 |
| `test_edge_cases.py` | Concurrency, large payloads, special characters, errors | 24 |

**Total: 103 test cases**

## Event Types

### Required Event Types

| Event Type | Description | Typical Severity |
|------------|-------------|------------------|
| `POLICY_EVALUATION` | Policy was evaluated | LOW-MEDIUM |
| `POLICY_VIOLATION` | Security policy violated | HIGH-CRITICAL |
| `POLICY_OVERRIDE_APPROVED` | Override approved by authorized user | HIGH |
| `TAMPER_DETECTED` | Log tampering was detected | CRITICAL |

### Additional Event Types

| Event Type | Description |
|------------|-------------|
| `AGENT_SESSION_START` | Agent session started |
| `AGENT_SESSION_END` | Agent session ended |
| `FILE_ACCESS` | File access attempt |
| `CODE_EDIT` | Code was modified |
| `SANDBOX_VIOLATION` | Sandbox security violation |
| `SECRET_DETECTED` | Secret/credential detected |

## Severity Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `LOW` | Informational | Routine evaluations, session events |
| `MEDIUM` | Warning | Findings that need review |
| `HIGH` | Security concern | Policy violations, overrides |
| `CRITICAL` | Immediate action required | Tampering, secrets, sandbox violations |

## Security Properties

### HMAC-SHA256 Signing

Every log entry is signed using HMAC-SHA256:

```python
signature = "hmac-sha256:" + hmac.new(
    secret_key,
    canonical_json(event),
    hashlib.sha256
).hexdigest()
```

### Canonical JSON

Events are canonicalized before signing:
- Sorted keys (`sort_keys=True`)
- No whitespace (`separators=(',', ':')`)
- UTF-8 encoding

### Tamper Detection

```python
try:
    audit_log.verify_integrity()
except TamperDetectedError as e:
    print(f"Tampering on line {e.line_number}")
    print(f"Expected: {e.expected_sig}")
    print(f"Actual: {e.actual_sig}")
```

## Running Tests

### Run All Tests

```bash
cd torture-tests/audit-trail

# Run individual test files
python test_event_recording.py
python test_hmac_signing.py
python test_tamper_detection.py
python test_event_types.py
python test_edge_cases.py

# Run all tests
for f in test_*.py; do python "$f"; done
```

### Expected Output

```
======================================================================
AUDIT TRAIL EVENT RECORDING TESTS
======================================================================

✓ PASS: [SCHEMA-001] Event has required fields
✓ PASS: [SCHEMA-002] Timestamp format
✓ PASS: [SCHEMA-003] Event ID is UUID
...

Results: 15 passed, 0 failed
======================================================================
```

## Configuration

### Secret Key

Set the HMAC secret via environment variable:

```bash
export SCALPEL_AUDIT_SECRET="your-secret-key"
```

If not set, a default secret is used (suitable for testing only).

## Log Format

Events are stored in JSON-lines format:

```json
{"timestamp":"2025-12-20T10:30:00.000+00:00","event_id":"uuid-here","event_type":"POLICY_VIOLATION","severity":"HIGH","details":{"policy":"no-sql-injection","file":"api.py","line":42},"signature":"hmac-sha256:abc123..."}
{"timestamp":"2025-12-20T10:30:01.000+00:00","event_id":"uuid-here","event_type":"POLICY_EVALUATION","severity":"LOW","details":{"policies_checked":5},"signature":"hmac-sha256:def456..."}
```

## Integration Example

```python
from audit_trail_framework import AuditLog, TamperDetectedError

# Initialize
audit_log = AuditLog("/var/log/scalpel/audit.log")

# Record a violation
audit_log.record_event(
    event_type="POLICY_VIOLATION",
    severity="HIGH",
    details={
        "policy_name": "no-raw-sql",
        "file_path": "src/api/users.py",
        "line_number": 42,
        "violation_type": "SQL_INJECTION"
    }
)

# Verify integrity
try:
    audit_log.verify_integrity()
    print("Log integrity verified")
except TamperDetectedError as e:
    print(f"ALERT: Tampering detected on line {e.line_number}")
```

## Test Categories

### Event Recording Tests (15)
- Event schema validation
- Timestamp format (ISO 8601 UTC)
- UUID generation
- JSON-lines format
- Signature attachment

### HMAC Signing Tests (18)
- Algorithm verification
- Deterministic signing
- Secret key management
- Canonical JSON
- Timing-safe comparison

### Tamper Detection Tests (23)
- Data modification detection
- Signature tampering
- Multi-event tampering
- Log corruption handling
- Error detail reporting

### Event Types Tests (23)
- All required event types
- Additional event types
- Severity levels
- Filtering by type/severity

### Edge Cases Tests (24)
- Concurrent access
- Large payloads
- Special characters
- File system errors
- Time-based filtering
