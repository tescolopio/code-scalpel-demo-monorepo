#!/usr/bin/env python3
"""
=============================================================================
AUDIT TRAIL EVENT RECORDING TESTS
=============================================================================

PURPOSE: Test event recording functionality and schema validation.
These tests verify that:

1. Events are recorded with correct schema
2. Timestamps are in ISO 8601 format (UTC)
3. Event IDs are unique UUIDs
4. All required fields are present
5. HMAC signatures are attached to every event
6. Events are appended to log file correctly
7. JSON-lines format is maintained

=============================================================================
"""
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from audit_trail_framework import (
    AuditLog, AuditEvent, EventType, Severity,
    AuditTestCase, AuditTrailTestRunner
)


# =============================================================================
# EVENT SCHEMA TESTS
# =============================================================================

def test_event_has_required_fields():
    """
    TEST: Every recorded event must have all required fields.

    Required fields:
    - timestamp: ISO 8601 format
    - event_id: UUID
    - event_type: String
    - severity: String
    - details: Object
    - signature: HMAC-SHA256 signature
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={"test": "value"}
        )

        # Verify required fields
        assert event.timestamp is not None, "Missing timestamp"
        assert event.event_id is not None, "Missing event_id"
        assert event.event_type is not None, "Missing event_type"
        assert event.severity is not None, "Missing severity"
        assert event.details is not None, "Missing details"
        assert event.signature is not None, "Missing signature"

        # Verify signature format
        assert event.signature.startswith("hmac-sha256:"), \
            f"Invalid signature format: {event.signature}"

    finally:
        os.unlink(log_path)


def test_timestamp_format():
    """
    TEST: Timestamps must be ISO 8601 format in UTC.

    Expected format: "2025-12-19T14:30:00.000+00:00"
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={}
        )

        # Parse the timestamp to verify format
        try:
            parsed = datetime.fromisoformat(event.timestamp)
            assert parsed.tzinfo is not None, "Timestamp must include timezone"
        except ValueError as e:
            raise AssertionError(f"Invalid timestamp format: {event.timestamp}") from e

    finally:
        os.unlink(log_path)


def test_event_id_is_uuid():
    """
    TEST: Event IDs must be valid UUIDs.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={}
        )

        # Verify UUID format
        try:
            uuid.UUID(event.event_id)
        except ValueError as e:
            raise AssertionError(f"Invalid UUID format: {event.event_id}") from e

    finally:
        os.unlink(log_path)


def test_event_ids_are_unique():
    """
    TEST: Each event must have a unique ID.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        ids = set()

        for i in range(100):
            event = audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"iteration": i}
            )
            assert event.event_id not in ids, \
                f"Duplicate event ID: {event.event_id}"
            ids.add(event.event_id)

    finally:
        os.unlink(log_path)


def test_details_preserved():
    """
    TEST: Event details must be preserved exactly as provided.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        details = {
            "policy_name": "no-raw-sql",
            "file_path": "src/api/users.py",
            "code_hash": "sha256:abc123def456",
            "line_number": 42,
            "nested": {
                "key": "value",
                "list": [1, 2, 3]
            }
        }

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details=details
        )

        assert event.details == details, \
            f"Details mismatch: {event.details} != {details}"

    finally:
        os.unlink(log_path)


# =============================================================================
# LOG FILE FORMAT TESTS
# =============================================================================

def test_json_lines_format():
    """
    TEST: Log file must use JSON-lines format (one JSON object per line).
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record multiple events
        for i in range(5):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        # Read and verify format
        with open(log_path, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 5, f"Expected 5 lines, got {len(lines)}"

        for i, line in enumerate(lines):
            try:
                obj = json.loads(line.strip())
                assert isinstance(obj, dict), f"Line {i+1} is not a JSON object"
            except json.JSONDecodeError as e:
                raise AssertionError(f"Line {i+1} is not valid JSON: {e}")

    finally:
        os.unlink(log_path)


def test_events_appended_not_overwritten():
    """
    TEST: New events must be appended, not overwrite existing events.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record first batch
        for i in range(3):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"batch": 1, "index": i}
            )

        # Create new AuditLog instance (simulating restart)
        audit_log2 = AuditLog(log_path)

        # Record second batch
        for i in range(2):
            audit_log2.record_event(
                event_type="POLICY_VIOLATION",
                severity="HIGH",
                details={"batch": 2, "index": i}
            )

        # Verify all events are present
        events = audit_log2.get_events()
        assert len(events) == 5, f"Expected 5 events, got {len(events)}"

        # Verify both batches are present
        batch1 = [e for e in events if e.details.get("batch") == 1]
        batch2 = [e for e in events if e.details.get("batch") == 2]
        assert len(batch1) == 3, f"Expected 3 events from batch 1, got {len(batch1)}"
        assert len(batch2) == 2, f"Expected 2 events from batch 2, got {len(batch2)}"

    finally:
        os.unlink(log_path)


def test_log_file_creation():
    """
    TEST: Log file and parent directories are created if they don't exist.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "subdir", "nested", "audit.log")

        audit_log = AuditLog(log_path)
        audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={}
        )

        assert os.path.exists(log_path), "Log file was not created"
        assert audit_log.get_event_count() == 1


# =============================================================================
# SIGNATURE ATTACHMENT TESTS
# =============================================================================

def test_signature_attached_to_every_event():
    """
    TEST: Every recorded event must have an HMAC signature.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record various events
        event_types = [
            ("POLICY_EVALUATION", "LOW"),
            ("POLICY_VIOLATION", "HIGH"),
            ("POLICY_OVERRIDE_APPROVED", "HIGH"),
            ("TAMPER_DETECTED", "CRITICAL"),
        ]

        for event_type, severity in event_types:
            event = audit_log.record_event(
                event_type=event_type,
                severity=severity,
                details={"type": event_type}
            )
            assert event.signature is not None, \
                f"Missing signature for {event_type}"
            assert event.signature.startswith("hmac-sha256:"), \
                f"Invalid signature format for {event_type}: {event.signature}"

    finally:
        os.unlink(log_path)


def test_signature_format():
    """
    TEST: Signatures must follow format "hmac-sha256:<64 hex chars>".
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={}
        )

        sig = event.signature
        assert sig.startswith("hmac-sha256:"), "Missing hmac-sha256 prefix"

        hex_part = sig.split(":")[1]
        assert len(hex_part) == 64, f"Expected 64 hex chars, got {len(hex_part)}"

        # Verify it's valid hex
        try:
            int(hex_part, 16)
        except ValueError:
            raise AssertionError(f"Invalid hex in signature: {hex_part}")

    finally:
        os.unlink(log_path)


def test_signature_in_log_file():
    """
    TEST: Signatures must be present in the log file.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={}
        )

        with open(log_path, 'r') as f:
            line = f.readline()
            event = json.loads(line)

        assert "signature" in event, "Signature not in log file"
        assert event["signature"].startswith("hmac-sha256:"), \
            "Invalid signature format in log file"

    finally:
        os.unlink(log_path)


# =============================================================================
# EVENT RETRIEVAL TESTS
# =============================================================================

def test_get_all_events():
    """
    TEST: get_events() returns all events when no filters applied.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        for i in range(10):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        events = audit_log.get_events()
        assert len(events) == 10, f"Expected 10 events, got {len(events)}"

    finally:
        os.unlink(log_path)


def test_filter_by_event_type():
    """
    TEST: get_events() filters by event_type correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record mixed events
        for i in range(5):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )
        for i in range(3):
            audit_log.record_event(
                event_type="POLICY_VIOLATION",
                severity="HIGH",
                details={"index": i}
            )

        evals = audit_log.get_events(event_type="POLICY_EVALUATION")
        violations = audit_log.get_events(event_type="POLICY_VIOLATION")

        assert len(evals) == 5, f"Expected 5 evaluations, got {len(evals)}"
        assert len(violations) == 3, f"Expected 3 violations, got {len(violations)}"

    finally:
        os.unlink(log_path)


def test_filter_by_severity():
    """
    TEST: get_events() filters by severity correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record events with different severities
        severities = ["LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for sev in severities:
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity=sev,
                details={"severity": sev}
            )

        low = audit_log.get_events(severity="LOW")
        high = audit_log.get_events(severity="HIGH")
        critical = audit_log.get_events(severity="CRITICAL")

        assert len(low) == 2, f"Expected 2 LOW events, got {len(low)}"
        assert len(high) == 1, f"Expected 1 HIGH event, got {len(high)}"
        assert len(critical) == 1, f"Expected 1 CRITICAL event, got {len(critical)}"

    finally:
        os.unlink(log_path)


def test_get_event_count():
    """
    TEST: get_event_count() returns correct count.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        assert audit_log.get_event_count() == 0, "Empty log should have 0 events"

        for i in range(7):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={}
            )

        assert audit_log.get_event_count() == 7, \
            f"Expected 7 events, got {audit_log.get_event_count()}"

    finally:
        os.unlink(log_path)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_event_recording_tests():
    """Run all event recording tests."""
    tests = [
        ("SCHEMA-001", "Event has required fields", test_event_has_required_fields),
        ("SCHEMA-002", "Timestamp format", test_timestamp_format),
        ("SCHEMA-003", "Event ID is UUID", test_event_id_is_uuid),
        ("SCHEMA-004", "Event IDs are unique", test_event_ids_are_unique),
        ("SCHEMA-005", "Details preserved", test_details_preserved),
        ("FORMAT-001", "JSON-lines format", test_json_lines_format),
        ("FORMAT-002", "Events appended not overwritten", test_events_appended_not_overwritten),
        ("FORMAT-003", "Log file creation", test_log_file_creation),
        ("SIG-001", "Signature attached to every event", test_signature_attached_to_every_event),
        ("SIG-002", "Signature format", test_signature_format),
        ("SIG-003", "Signature in log file", test_signature_in_log_file),
        ("RETRIEVE-001", "Get all events", test_get_all_events),
        ("RETRIEVE-002", "Filter by event type", test_filter_by_event_type),
        ("RETRIEVE-003", "Filter by severity", test_filter_by_severity),
        ("RETRIEVE-004", "Get event count", test_get_event_count),
    ]

    print("=" * 70)
    print("AUDIT TRAIL EVENT RECORDING TESTS")
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
    run_event_recording_tests()
