#!/usr/bin/env python3
"""
=============================================================================
AUDIT TRAIL EVENT TYPES AND SEVERITY TESTS
=============================================================================

PURPOSE: Test all event types and severity levels.
These tests verify that:

1. All required event types are supported
2. All severity levels are correctly handled
3. Event type-specific behavior is correct
4. Severity level ordering and filtering works
5. Event type validation (if applicable)

REQUIRED EVENT TYPES:
- POLICY_EVALUATION: Policy was evaluated (may or may not have issues)
- POLICY_VIOLATION: Policy was violated (security issue found)
- POLICY_OVERRIDE_APPROVED: Override was approved by authorized user
- TAMPER_DETECTED: Log tampering was detected

SEVERITY LEVELS (ascending):
- LOW: Informational
- MEDIUM: Warning
- HIGH: Security concern
- CRITICAL: Immediate action required

=============================================================================
"""
import json
import os
import tempfile
from datetime import datetime, timezone

from audit_trail_framework import (
    AuditLog, AuditEvent, EventType, Severity,
    TamperDetectedError
)


# =============================================================================
# POLICY_EVALUATION EVENT TESTS
# =============================================================================

def test_policy_evaluation_event():
    """
    TEST: POLICY_EVALUATION events are recorded correctly.

    This event type is used when a policy is evaluated, regardless
    of whether a violation was found.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={
                "policy_name": "no-raw-sql",
                "file_path": "src/api/users.py",
                "result": "PASS",
                "evaluation_time_ms": 2.5
            }
        )

        assert event.event_type == "POLICY_EVALUATION"
        assert event.severity == "LOW"
        assert event.details["result"] == "PASS"

    finally:
        os.unlink(log_path)


def test_policy_evaluation_with_findings():
    """
    TEST: POLICY_EVALUATION with findings is recorded correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="MEDIUM",
            details={
                "policy_name": "no-raw-sql",
                "file_path": "src/api/users.py",
                "result": "FINDINGS",
                "findings": [
                    {"line": 42, "message": "Possible SQL injection"},
                    {"line": 87, "message": "Unparameterized query"}
                ]
            }
        )

        assert event.event_type == "POLICY_EVALUATION"
        assert len(event.details["findings"]) == 2

    finally:
        os.unlink(log_path)


def test_policy_evaluation_batch():
    """
    TEST: Batch policy evaluations are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={
                "batch_id": "batch-123",
                "policies_evaluated": 15,
                "files_scanned": 42,
                "total_time_ms": 350.5,
                "summary": {
                    "passed": 12,
                    "failed": 3,
                    "skipped": 0
                }
            }
        )

        assert event.details["policies_evaluated"] == 15

    finally:
        os.unlink(log_path)


# =============================================================================
# POLICY_VIOLATION EVENT TESTS
# =============================================================================

def test_policy_violation_event():
    """
    TEST: POLICY_VIOLATION events are recorded correctly.

    This event type is used when a security policy is violated.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "policy_name": "no-raw-sql",
                "violation_type": "SQL_INJECTION",
                "file_path": "src/api/users.py",
                "line_number": 42,
                "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "recommendation": "Use parameterized queries"
            }
        )

        assert event.event_type == "POLICY_VIOLATION"
        assert event.severity == "HIGH"
        assert event.details["violation_type"] == "SQL_INJECTION"

    finally:
        os.unlink(log_path)


def test_policy_violation_critical():
    """
    TEST: Critical policy violations are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="CRITICAL",
            details={
                "policy_name": "no-secrets-in-code",
                "violation_type": "SECRET_EXPOSURE",
                "file_path": "config/settings.py",
                "line_number": 15,
                "secret_type": "API_KEY",
                "masked_value": "sk-****...****abc"
            }
        )

        assert event.severity == "CRITICAL"
        assert event.details["secret_type"] == "API_KEY"

    finally:
        os.unlink(log_path)


def test_policy_violation_multiple_locations():
    """
    TEST: Violation with multiple locations is recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "policy_name": "no-command-injection",
                "violation_type": "COMMAND_INJECTION",
                "locations": [
                    {"file": "src/utils.py", "line": 23},
                    {"file": "src/utils.py", "line": 45},
                    {"file": "src/runner.py", "line": 12}
                ]
            }
        )

        assert len(event.details["locations"]) == 3

    finally:
        os.unlink(log_path)


# =============================================================================
# POLICY_OVERRIDE_APPROVED EVENT TESTS
# =============================================================================

def test_policy_override_approved_event():
    """
    TEST: POLICY_OVERRIDE_APPROVED events are recorded correctly.

    This event type is used when an authorized user approves
    an override of a policy violation.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_OVERRIDE_APPROVED",
            severity="HIGH",
            details={
                "policy_name": "no-raw-sql",
                "original_violation_id": "event-123",
                "override_reason": "False positive - using parameterized query",
                "approver": "security-admin@company.com",
                "approval_method": "CLI_FLAG",
                "expires_at": "2025-12-31T23:59:59Z"
            }
        )

        assert event.event_type == "POLICY_OVERRIDE_APPROVED"
        assert event.details["approver"] == "security-admin@company.com"

    finally:
        os.unlink(log_path)


def test_policy_override_with_ticket():
    """
    TEST: Override with ticket reference is recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_OVERRIDE_APPROVED",
            severity="MEDIUM",
            details={
                "policy_name": "require-tests",
                "override_reason": "Hotfix - tests will be added in follow-up",
                "approver": "tech-lead@company.com",
                "ticket_reference": "JIRA-1234",
                "follow_up_required": True
            }
        )

        assert event.details["ticket_reference"] == "JIRA-1234"

    finally:
        os.unlink(log_path)


def test_policy_override_permanent():
    """
    TEST: Permanent override (no expiration) is recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_OVERRIDE_APPROVED",
            severity="LOW",
            details={
                "policy_name": "naming-convention",
                "override_reason": "Legacy code - exempt from new rules",
                "approver": "cto@company.com",
                "permanent": True,
                "scope": ["src/legacy/**/*.py"]
            }
        )

        assert event.details["permanent"] == True

    finally:
        os.unlink(log_path)


# =============================================================================
# TAMPER_DETECTED EVENT TESTS
# =============================================================================

def test_tamper_detected_event():
    """
    TEST: TAMPER_DETECTED events are recorded correctly.

    This event type is used when log tampering is detected.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="TAMPER_DETECTED",
            severity="CRITICAL",
            details={
                "detection_method": "SIGNATURE_MISMATCH",
                "affected_line": 42,
                "expected_signature": "hmac-sha256:abc123...",
                "actual_signature": "hmac-sha256:def456...",
                "alert_sent": True
            }
        )

        assert event.event_type == "TAMPER_DETECTED"
        assert event.severity == "CRITICAL"
        assert event.details["detection_method"] == "SIGNATURE_MISMATCH"

    finally:
        os.unlink(log_path)


def test_tamper_detected_corruption():
    """
    TEST: Log corruption detection is recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="TAMPER_DETECTED",
            severity="CRITICAL",
            details={
                "detection_method": "INVALID_JSON",
                "affected_line": 15,
                "parse_error": "Unexpected token",
                "incident_id": "INC-2025-001"
            }
        )

        assert event.details["detection_method"] == "INVALID_JSON"

    finally:
        os.unlink(log_path)


# =============================================================================
# ADDITIONAL EVENT TYPE TESTS
# =============================================================================

def test_agent_session_start_event():
    """
    TEST: AGENT_SESSION_START events are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="AGENT_SESSION_START",
            severity="LOW",
            details={
                "session_id": "sess-abc123",
                "agent_type": "code-assistant",
                "user": "developer@company.com",
                "workspace": "/home/dev/project"
            }
        )

        assert event.event_type == "AGENT_SESSION_START"

    finally:
        os.unlink(log_path)


def test_agent_session_end_event():
    """
    TEST: AGENT_SESSION_END events are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="AGENT_SESSION_END",
            severity="LOW",
            details={
                "session_id": "sess-abc123",
                "duration_seconds": 3600,
                "actions_performed": 42,
                "files_modified": 5
            }
        )

        assert event.event_type == "AGENT_SESSION_END"

    finally:
        os.unlink(log_path)


def test_file_access_event():
    """
    TEST: FILE_ACCESS events are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="FILE_ACCESS",
            severity="LOW",
            details={
                "file_path": "/etc/passwd",
                "access_type": "READ",
                "allowed": False,
                "reason": "Outside allowed paths"
            }
        )

        assert event.event_type == "FILE_ACCESS"

    finally:
        os.unlink(log_path)


def test_code_edit_event():
    """
    TEST: CODE_EDIT events are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="CODE_EDIT",
            severity="LOW",
            details={
                "file_path": "src/api/users.py",
                "edit_type": "INSERT",
                "lines_added": 15,
                "lines_removed": 3,
                "diff_hash": "sha256:abc123..."
            }
        )

        assert event.event_type == "CODE_EDIT"

    finally:
        os.unlink(log_path)


def test_sandbox_violation_event():
    """
    TEST: SANDBOX_VIOLATION events are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="SANDBOX_VIOLATION",
            severity="CRITICAL",
            details={
                "violation_type": "NETWORK_ACCESS",
                "target": "malicious-site.com:443",
                "blocked": True,
                "process": "python"
            }
        )

        assert event.event_type == "SANDBOX_VIOLATION"
        assert event.severity == "CRITICAL"

    finally:
        os.unlink(log_path)


def test_secret_detected_event():
    """
    TEST: SECRET_DETECTED events are recorded.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="SECRET_DETECTED",
            severity="CRITICAL",
            details={
                "secret_type": "AWS_ACCESS_KEY",
                "file_path": "config.py",
                "line_number": 12,
                "masked_value": "AKIA****...****WXYZ",
                "action_taken": "BLOCKED"
            }
        )

        assert event.event_type == "SECRET_DETECTED"

    finally:
        os.unlink(log_path)


# =============================================================================
# SEVERITY LEVEL TESTS
# =============================================================================

def test_all_severity_levels():
    """
    TEST: All severity levels are supported.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

        for severity in severities:
            event = audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity=severity,
                details={"severity_test": severity}
            )
            assert event.severity == severity

        events = audit_log.get_events()
        assert len(events) == 4

    finally:
        os.unlink(log_path)


def test_severity_filtering():
    """
    TEST: Events can be filtered by severity.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record events with different severities
        audit_log.record_event("POLICY_EVALUATION", "LOW", {"id": 1})
        audit_log.record_event("POLICY_EVALUATION", "LOW", {"id": 2})
        audit_log.record_event("POLICY_VIOLATION", "HIGH", {"id": 3})
        audit_log.record_event("POLICY_VIOLATION", "CRITICAL", {"id": 4})

        low = audit_log.get_events(severity="LOW")
        high = audit_log.get_events(severity="HIGH")
        critical = audit_log.get_events(severity="CRITICAL")

        assert len(low) == 2
        assert len(high) == 1
        assert len(critical) == 1

    finally:
        os.unlink(log_path)


def test_combined_type_and_severity_filter():
    """
    TEST: Events can be filtered by both type and severity.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record mixed events
        audit_log.record_event("POLICY_EVALUATION", "LOW", {"id": 1})
        audit_log.record_event("POLICY_EVALUATION", "HIGH", {"id": 2})
        audit_log.record_event("POLICY_VIOLATION", "HIGH", {"id": 3})
        audit_log.record_event("POLICY_VIOLATION", "CRITICAL", {"id": 4})

        # Filter by type
        evaluations = audit_log.get_events(event_type="POLICY_EVALUATION")
        violations = audit_log.get_events(event_type="POLICY_VIOLATION")

        assert len(evaluations) == 2
        assert len(violations) == 2

        # Filter by severity
        high_events = audit_log.get_events(severity="HIGH")
        assert len(high_events) == 2

    finally:
        os.unlink(log_path)


# =============================================================================
# EVENT TYPE ENUM TESTS
# =============================================================================

def test_event_type_enum_values():
    """
    TEST: EventType enum has all required values.
    """
    required_types = [
        "POLICY_EVALUATION",
        "POLICY_VIOLATION",
        "POLICY_OVERRIDE_APPROVED",
        "TAMPER_DETECTED"
    ]

    for event_type in required_types:
        assert hasattr(EventType, event_type), \
            f"Missing event type: {event_type}"
        assert EventType[event_type].value == event_type


def test_severity_enum_values():
    """
    TEST: Severity enum has all required values.
    """
    required_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    for severity in required_severities:
        assert hasattr(Severity, severity), \
            f"Missing severity: {severity}"
        assert Severity[severity].value == severity


def test_event_type_enum_string_conversion():
    """
    TEST: EventType enum converts to/from strings correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record using enum value
        event = audit_log.record_event(
            event_type=EventType.POLICY_VIOLATION.value,
            severity=Severity.HIGH.value,
            details={}
        )

        # Should be stored as string
        events = audit_log.get_events()
        assert events[0].event_type == "POLICY_VIOLATION"

    finally:
        os.unlink(log_path)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_event_type_tests():
    """Run all event type and severity tests."""
    tests = [
        ("EVAL-001", "Policy evaluation event", test_policy_evaluation_event),
        ("EVAL-002", "Policy evaluation with findings", test_policy_evaluation_with_findings),
        ("EVAL-003", "Policy evaluation batch", test_policy_evaluation_batch),
        ("VIOL-001", "Policy violation event", test_policy_violation_event),
        ("VIOL-002", "Critical policy violation", test_policy_violation_critical),
        ("VIOL-003", "Violation multiple locations", test_policy_violation_multiple_locations),
        ("OVERRIDE-001", "Policy override approved", test_policy_override_approved_event),
        ("OVERRIDE-002", "Override with ticket", test_policy_override_with_ticket),
        ("OVERRIDE-003", "Permanent override", test_policy_override_permanent),
        ("TAMPER-001", "Tamper detected event", test_tamper_detected_event),
        ("TAMPER-002", "Corruption detection", test_tamper_detected_corruption),
        ("SESSION-001", "Agent session start", test_agent_session_start_event),
        ("SESSION-002", "Agent session end", test_agent_session_end_event),
        ("ACCESS-001", "File access event", test_file_access_event),
        ("EDIT-001", "Code edit event", test_code_edit_event),
        ("SANDBOX-001", "Sandbox violation event", test_sandbox_violation_event),
        ("SECRET-001", "Secret detected event", test_secret_detected_event),
        ("SEV-001", "All severity levels", test_all_severity_levels),
        ("SEV-002", "Severity filtering", test_severity_filtering),
        ("SEV-003", "Combined type and severity filter", test_combined_type_and_severity_filter),
        ("ENUM-001", "EventType enum values", test_event_type_enum_values),
        ("ENUM-002", "Severity enum values", test_severity_enum_values),
        ("ENUM-003", "EventType enum string conversion", test_event_type_enum_string_conversion),
    ]

    print("=" * 70)
    print("AUDIT TRAIL EVENT TYPES AND SEVERITY TESTS")
    print("=" * 70)
    print()

    passed = 0
    failed = 0

    for test_id, name, test_fn in tests:
        try:
            test_fn()
            print(f"✓ PASS: [{test_id}] {name}")
            passed += 1
        except AssertionError as e:
            print(f"✗ FAIL: [{test_id}] {name}")
            print(f"  Reason: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ ERROR: [{test_id}] {name}")
            print(f"  Exception: {type(e).__name__}: {e}")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return passed, failed


if __name__ == "__main__":
    run_event_type_tests()
