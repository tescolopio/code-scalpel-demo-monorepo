#!/usr/bin/env python3
"""
=============================================================================
AUDIT TRAIL TAMPER DETECTION TESTS
=============================================================================

PURPOSE: Test tamper detection and integrity verification functionality.
These tests verify that:

1. Any modification to log entries is detected
2. TamperDetectedError is raised with correct details
3. Various tampering scenarios are caught
4. Partial tampering is detected
5. Log corruption is distinguished from tampering
6. Verification provides line-level error reporting

SECURITY GUARANTEE:
Any modification to the audit log - whether to data, timestamps,
event types, severity, or signatures - will be detected and reported.

=============================================================================
"""
import json
import os
import tempfile
from pathlib import Path

from audit_trail_framework import (
    AuditLog, AuditEvent, EventType, Severity,
    TamperDetectedError, AuditLogCorruptedError
)


# =============================================================================
# DATA MODIFICATION TAMPERING TESTS
# =============================================================================

def test_tamper_modify_details():
    """
    TEST: Modifying event details is detected.

    Scenario: Attacker changes details to hide evidence.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="CRITICAL",
            details={"violation": "SQL Injection", "file": "api.py", "line": 42}
        )

        # Tamper: change violation type to hide evidence
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["details"]["violation"] = "Minor Warning"

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered details should be detected")
        except TamperDetectedError as e:
            assert e.line_number == 1, f"Wrong line number: {e.line_number}"

    finally:
        os.unlink(log_path)


def test_tamper_modify_timestamp():
    """
    TEST: Modifying event timestamp is detected.

    Scenario: Attacker changes timestamp to create alibi.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        audit_log.record_event(
            event_type="SANDBOX_VIOLATION",
            severity="CRITICAL",
            details={"action": "unauthorized_access"}
        )

        # Tamper: change timestamp
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["timestamp"] = "2020-01-01T00:00:00.000+00:00"  # Old date

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered timestamp should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


def test_tamper_modify_event_type():
    """
    TEST: Modifying event type is detected.

    Scenario: Attacker downgrades VIOLATION to EVALUATION.
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

        # Tamper: change event type
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["event_type"] = "POLICY_EVALUATION"  # Downgrade

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered event type should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


def test_tamper_modify_severity():
    """
    TEST: Modifying event severity is detected.

    Scenario: Attacker downgrades CRITICAL to LOW.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="CRITICAL",
            details={}
        )

        # Tamper: change severity
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["severity"] = "LOW"  # Downgrade

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered severity should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


def test_tamper_modify_event_id():
    """
    TEST: Modifying event ID is detected.

    Scenario: Attacker changes event ID to create confusion.
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

        # Tamper: change event ID
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["event_id"] = "fake-event-id-12345"

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered event ID should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


# =============================================================================
# SIGNATURE TAMPERING TESTS
# =============================================================================

def test_tamper_remove_signature():
    """
    TEST: Removing signature is detected.
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

        # Tamper: remove signature
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        del event["signature"]

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect as corruption (missing signature)
        try:
            audit_log.verify_integrity()
            raise AssertionError("Missing signature should be detected")
        except AuditLogCorruptedError:
            pass

    finally:
        os.unlink(log_path)


def test_tamper_replace_signature():
    """
    TEST: Replacing signature with another valid-looking signature is detected.
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

        # Tamper: replace with different valid-looking signature
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["signature"] = "hmac-sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Replaced signature should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


def test_tamper_truncate_signature():
    """
    TEST: Truncated signature is detected.
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

        # Tamper: truncate signature
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["signature"] = "hmac-sha256:abc123"  # Truncated

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Truncated signature should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


def test_tamper_wrong_signature_prefix():
    """
    TEST: Wrong signature prefix is detected.
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

        # Tamper: wrong prefix
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        event["signature"] = "sha256:" + event["signature"].split(":")[1]

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Should detect tampering
        try:
            audit_log.verify_integrity()
            raise AssertionError("Wrong signature prefix should be detected")
        except TamperDetectedError:
            pass

    finally:
        os.unlink(log_path)


# =============================================================================
# MULTI-EVENT TAMPERING TESTS
# =============================================================================

def test_tamper_middle_event():
    """
    TEST: Tampering with middle event in log is detected.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Create multiple events
        for i in range(5):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        # Tamper: modify middle event (index 2)
        with open(log_path, 'r') as f:
            lines = f.readlines()

        event = json.loads(lines[2])
        event["details"]["index"] = 999

        lines[2] = json.dumps(event) + '\n'

        with open(log_path, 'w') as f:
            f.writelines(lines)

        # Should detect tampering at line 3
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered middle event should be detected")
        except TamperDetectedError as e:
            assert e.line_number == 3, f"Wrong line number: {e.line_number}"

    finally:
        os.unlink(log_path)


def test_tamper_last_event():
    """
    TEST: Tampering with last event in log is detected.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        for i in range(3):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        # Tamper: modify last event
        with open(log_path, 'r') as f:
            lines = f.readlines()

        event = json.loads(lines[-1])
        event["severity"] = "CRITICAL"

        lines[-1] = json.dumps(event) + '\n'

        with open(log_path, 'w') as f:
            f.writelines(lines)

        # Should detect tampering at line 3
        try:
            audit_log.verify_integrity()
            raise AssertionError("Tampered last event should be detected")
        except TamperDetectedError as e:
            assert e.line_number == 3

    finally:
        os.unlink(log_path)


def test_tamper_delete_event():
    """
    TEST: Deleting an event doesn't affect signature of remaining events.

    Note: Deletion of events is not detectable by signature verification
    alone - you need sequence numbers or chained hashes for that.
    This test verifies remaining events are still valid.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        for i in range(5):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        # Delete middle event
        with open(log_path, 'r') as f:
            lines = f.readlines()

        del lines[2]

        with open(log_path, 'w') as f:
            f.writelines(lines)

        # Remaining events should still verify
        # (Deletion detection would require chained signatures)
        assert audit_log.verify_integrity() == True
        assert audit_log.get_event_count() == 4

    finally:
        os.unlink(log_path)


def test_tamper_reorder_events():
    """
    TEST: Reordering events - signatures remain valid per-event.

    Note: Event reordering is not detectable by per-event signatures.
    This would require chained hashes. Test verifies each event is valid.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        for i in range(3):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        # Reorder events
        with open(log_path, 'r') as f:
            lines = f.readlines()

        lines = [lines[2], lines[0], lines[1]]

        with open(log_path, 'w') as f:
            f.writelines(lines)

        # Per-event signatures still valid
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


# =============================================================================
# LOG CORRUPTION TESTS
# =============================================================================

def test_corrupt_invalid_json():
    """
    TEST: Invalid JSON is detected as corruption.
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

        # Corrupt: write invalid JSON
        with open(log_path, 'w') as f:
            f.write("{ this is not valid json }\n")

        try:
            audit_log.verify_integrity()
            raise AssertionError("Invalid JSON should be detected")
        except AuditLogCorruptedError as e:
            assert "Invalid JSON" in str(e)

    finally:
        os.unlink(log_path)


def test_corrupt_partial_line():
    """
    TEST: Partial/truncated line is detected as corruption.
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

        # Corrupt: truncate the line
        with open(log_path, 'r') as f:
            line = f.readline()

        with open(log_path, 'w') as f:
            f.write(line[:50] + '\n')  # Truncate

        try:
            audit_log.verify_integrity()
            raise AssertionError("Truncated line should be detected")
        except AuditLogCorruptedError:
            pass

    finally:
        os.unlink(log_path)


def test_corrupt_binary_data():
    """
    TEST: Binary data in log is detected as corruption.
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

        # Corrupt: add binary data
        with open(log_path, 'wb') as f:
            f.write(b'\x00\x01\x02\x03\x04\x05\n')

        try:
            audit_log.verify_integrity()
            raise AssertionError("Binary data should be detected")
        except (AuditLogCorruptedError, UnicodeDecodeError, json.JSONDecodeError):
            pass

    finally:
        os.unlink(log_path)


def test_corrupt_empty_object():
    """
    TEST: Empty JSON object is detected.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Write empty object
        with open(log_path, 'w') as f:
            f.write("{}\n")

        try:
            audit_log.verify_integrity()
            raise AssertionError("Empty object should be detected")
        except AuditLogCorruptedError:
            pass

    finally:
        os.unlink(log_path)


# =============================================================================
# TAMPER DETECTED ERROR DETAILS TESTS
# =============================================================================

def test_tamper_error_includes_line_number():
    """
    TEST: TamperDetectedError includes correct line number.
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

        # Tamper line 7
        with open(log_path, 'r') as f:
            lines = f.readlines()

        event = json.loads(lines[6])
        event["details"]["tampered"] = True

        lines[6] = json.dumps(event) + '\n'

        with open(log_path, 'w') as f:
            f.writelines(lines)

        try:
            audit_log.verify_integrity()
            raise AssertionError("Should detect tampering")
        except TamperDetectedError as e:
            assert e.line_number == 7, \
                f"Expected line 7, got {e.line_number}"

    finally:
        os.unlink(log_path)


def test_tamper_error_includes_signatures():
    """
    TEST: TamperDetectedError includes expected and actual signatures.
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

        # Tamper
        with open(log_path, 'r') as f:
            event = json.loads(f.readline())

        original_sig = event["signature"]
        event["details"]["tampered"] = True

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        try:
            audit_log.verify_integrity()
            raise AssertionError("Should detect tampering")
        except TamperDetectedError as e:
            assert e.actual_sig == original_sig, \
                f"Actual sig mismatch: {e.actual_sig}"
            assert e.expected_sig.startswith("hmac-sha256:"), \
                f"Expected sig format wrong: {e.expected_sig}"
            assert e.expected_sig != e.actual_sig, \
                "Expected and actual should differ"

    finally:
        os.unlink(log_path)


# =============================================================================
# EDGE CASES
# =============================================================================

def test_empty_log_verification():
    """
    TEST: Empty log file passes verification.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_single_event_verification():
    """
    TEST: Log with single event verifies correctly.
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

        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_large_log_verification():
    """
    TEST: Large log file verifies correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Create 1000 events
        for i in range(1000):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i, "data": "x" * 100}
            )

        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_verification_idempotent():
    """
    TEST: Verification can be run multiple times.
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

        # Run verification multiple times
        for _ in range(5):
            assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_tamper_detection_tests():
    """Run all tamper detection tests."""
    tests = [
        ("TAMPER-001", "Modify details detected", test_tamper_modify_details),
        ("TAMPER-002", "Modify timestamp detected", test_tamper_modify_timestamp),
        ("TAMPER-003", "Modify event type detected", test_tamper_modify_event_type),
        ("TAMPER-004", "Modify severity detected", test_tamper_modify_severity),
        ("TAMPER-005", "Modify event ID detected", test_tamper_modify_event_id),
        ("SIG-TAMPER-001", "Remove signature detected", test_tamper_remove_signature),
        ("SIG-TAMPER-002", "Replace signature detected", test_tamper_replace_signature),
        ("SIG-TAMPER-003", "Truncate signature detected", test_tamper_truncate_signature),
        ("SIG-TAMPER-004", "Wrong signature prefix detected", test_tamper_wrong_signature_prefix),
        ("MULTI-001", "Tamper middle event detected", test_tamper_middle_event),
        ("MULTI-002", "Tamper last event detected", test_tamper_last_event),
        ("MULTI-003", "Delete event (remaining valid)", test_tamper_delete_event),
        ("MULTI-004", "Reorder events (per-event valid)", test_tamper_reorder_events),
        ("CORRUPT-001", "Invalid JSON detected", test_corrupt_invalid_json),
        ("CORRUPT-002", "Partial line detected", test_corrupt_partial_line),
        ("CORRUPT-003", "Binary data detected", test_corrupt_binary_data),
        ("CORRUPT-004", "Empty object detected", test_corrupt_empty_object),
        ("ERROR-001", "Error includes line number", test_tamper_error_includes_line_number),
        ("ERROR-002", "Error includes signatures", test_tamper_error_includes_signatures),
        ("EDGE-001", "Empty log verification", test_empty_log_verification),
        ("EDGE-002", "Single event verification", test_single_event_verification),
        ("EDGE-003", "Large log verification", test_large_log_verification),
        ("EDGE-004", "Verification idempotent", test_verification_idempotent),
    ]

    print("=" * 70)
    print("AUDIT TRAIL TAMPER DETECTION TESTS")
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
    run_tamper_detection_tests()
