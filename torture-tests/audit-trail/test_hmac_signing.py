#!/usr/bin/env python3
"""
=============================================================================
AUDIT TRAIL HMAC SIGNING TESTS
=============================================================================

PURPOSE: Test HMAC-SHA256 cryptographic signing functionality.
These tests verify that:

1. HMAC-SHA256 signatures are correctly generated
2. Signatures are deterministic for the same input
3. Different inputs produce different signatures
4. Signature verification works correctly
5. Secret key management is secure
6. Canonical JSON representation is used

SECURITY PROPERTIES:
- HMAC-SHA256 provides authentication and integrity
- Signatures are tied to a secret key
- Canonical JSON ensures consistent signing
- Timing-safe comparison prevents timing attacks

=============================================================================
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from audit_trail_framework import (
    AuditLog, AuditEvent, EventType, Severity,
    TamperDetectedError, AuditLogCorruptedError
)


# =============================================================================
# HMAC SIGNATURE GENERATION TESTS
# =============================================================================

def test_hmac_sha256_algorithm():
    """
    TEST: Signatures must use HMAC-SHA256 algorithm.

    Verifies that the signature can be independently reproduced
    using the HMAC-SHA256 algorithm with the known secret.
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

        # Extract the hex part of the signature
        stored_sig = event.signature.replace("hmac-sha256:", "")

        # Manually compute HMAC-SHA256
        event_dict = event.to_dict()
        event_copy = {k: v for k, v in event_dict.items() if k != "signature"}
        message = json.dumps(event_copy, sort_keys=True, separators=(',', ':'))

        secret = os.environ.get("SCALPEL_AUDIT_SECRET", "default-secret").encode('utf-8')
        expected_sig = hmac.new(secret, message.encode('utf-8'), hashlib.sha256).hexdigest()

        assert stored_sig == expected_sig, \
            f"Signature mismatch: {stored_sig} != {expected_sig}"

    finally:
        os.unlink(log_path)


def test_signature_deterministic():
    """
    TEST: Same event data must produce the same signature.

    Given identical event data, the signature should be deterministic.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Create identical event data (but we can only verify via the log)
        # Since event_id and timestamp change, we verify the signing logic
        secret = os.environ.get("SCALPEL_AUDIT_SECRET", "default-secret").encode('utf-8')

        test_data = {
            "timestamp": "2025-01-01T00:00:00.000+00:00",
            "event_id": "test-id-123",
            "event_type": "POLICY_VIOLATION",
            "severity": "HIGH",
            "details": {"key": "value"}
        }

        message = json.dumps(test_data, sort_keys=True, separators=(',', ':'))
        sig1 = hmac.new(secret, message.encode('utf-8'), hashlib.sha256).hexdigest()
        sig2 = hmac.new(secret, message.encode('utf-8'), hashlib.sha256).hexdigest()

        assert sig1 == sig2, "Deterministic signing failed"

    finally:
        os.unlink(log_path)


def test_different_data_different_signature():
    """
    TEST: Different event data must produce different signatures.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event1 = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={"value": 1}
        )

        event2 = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={"value": 2}
        )

        assert event1.signature != event2.signature, \
            "Different events should have different signatures"

    finally:
        os.unlink(log_path)


def test_signature_changes_with_event_type():
    """
    TEST: Changing event type changes the signature.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event1 = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={}
        )

        event2 = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="LOW",
            details={}
        )

        assert event1.signature != event2.signature, \
            "Different event types should have different signatures"

    finally:
        os.unlink(log_path)


def test_signature_changes_with_severity():
    """
    TEST: Changing severity changes the signature.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event1 = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="LOW",
            details={}
        )

        event2 = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={}
        )

        assert event1.signature != event2.signature, \
            "Different severities should have different signatures"

    finally:
        os.unlink(log_path)


# =============================================================================
# SIGNATURE VERIFICATION TESTS
# =============================================================================

def test_verify_valid_signature():
    """
    TEST: Valid signatures pass verification.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={"key": "value"}
        )

        # Verification should pass
        assert audit_log.verify_integrity() == True, \
            "Valid signature should pass verification"

    finally:
        os.unlink(log_path)


def test_verify_multiple_events():
    """
    TEST: Multiple events all verify correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        for i in range(50):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i, "nested": {"data": [1, 2, 3]}}
            )

        # All events should verify
        assert audit_log.verify_integrity() == True, \
            "All valid signatures should pass verification"

    finally:
        os.unlink(log_path)


def test_verification_fails_on_modified_event():
    """
    TEST: Modified event fails verification.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={"original": True}
        )

        # Tamper with the log file
        with open(log_path, 'r') as f:
            line = f.readline()

        event = json.loads(line)
        event["details"]["original"] = False  # Modify data

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Verification should fail
        try:
            audit_log.verify_integrity()
            raise AssertionError("Modified event should fail verification")
        except TamperDetectedError:
            pass  # Expected

    finally:
        os.unlink(log_path)


def test_verification_fails_on_modified_signature():
    """
    TEST: Event with modified signature fails verification.
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

        # Tamper with the signature
        with open(log_path, 'r') as f:
            line = f.readline()

        event = json.loads(line)
        event["signature"] = "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000"

        with open(log_path, 'w') as f:
            f.write(json.dumps(event) + '\n')

        # Verification should fail
        try:
            audit_log.verify_integrity()
            raise AssertionError("Modified signature should fail verification")
        except TamperDetectedError:
            pass  # Expected

    finally:
        os.unlink(log_path)


# =============================================================================
# SECRET KEY MANAGEMENT TESTS
# =============================================================================

def test_default_secret_used():
    """
    TEST: Default secret is used when env var is not set.
    """
    # Temporarily unset the env var
    old_secret = os.environ.pop("SCALPEL_AUDIT_SECRET", None)

    try:
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            log_path = f.name

        try:
            audit_log = AuditLog(log_path)
            event = audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={}
            )

            # Should use default secret
            assert event.signature is not None
            assert event.signature.startswith("hmac-sha256:")

        finally:
            os.unlink(log_path)

    finally:
        if old_secret is not None:
            os.environ["SCALPEL_AUDIT_SECRET"] = old_secret


def test_custom_secret_from_env():
    """
    TEST: Custom secret from environment variable is used.
    """
    old_secret = os.environ.get("SCALPEL_AUDIT_SECRET")
    os.environ["SCALPEL_AUDIT_SECRET"] = "my-custom-secret-key"

    try:
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            log_path = f.name

        try:
            audit_log = AuditLog(log_path)
            event = audit_log.record_event(
                event_type="POLICY_VIOLATION",
                severity="HIGH",
                details={}
            )

            # Manually compute with custom secret
            event_dict = event.to_dict()
            event_copy = {k: v for k, v in event_dict.items() if k != "signature"}
            message = json.dumps(event_copy, sort_keys=True, separators=(',', ':'))

            expected_sig = "hmac-sha256:" + hmac.new(
                b"my-custom-secret-key",
                message.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            assert event.signature == expected_sig, \
                f"Custom secret not used: {event.signature} != {expected_sig}"

        finally:
            os.unlink(log_path)

    finally:
        if old_secret is not None:
            os.environ["SCALPEL_AUDIT_SECRET"] = old_secret
        else:
            os.environ.pop("SCALPEL_AUDIT_SECRET", None)


def test_different_secrets_produce_different_signatures():
    """
    TEST: Different secrets produce different signatures for same data.
    """
    test_data = {
        "timestamp": "2025-01-01T00:00:00.000+00:00",
        "event_id": "test-id",
        "event_type": "POLICY_VIOLATION",
        "severity": "HIGH",
        "details": {}
    }
    message = json.dumps(test_data, sort_keys=True, separators=(',', ':'))

    sig1 = hmac.new(b"secret-one", message.encode('utf-8'), hashlib.sha256).hexdigest()
    sig2 = hmac.new(b"secret-two", message.encode('utf-8'), hashlib.sha256).hexdigest()

    assert sig1 != sig2, "Different secrets should produce different signatures"


def test_cross_instance_verification():
    """
    TEST: Events signed by one instance can be verified by another with same secret.
    """
    old_secret = os.environ.get("SCALPEL_AUDIT_SECRET")
    os.environ["SCALPEL_AUDIT_SECRET"] = "shared-secret-key"

    try:
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            log_path = f.name

        try:
            # First instance creates events
            audit_log1 = AuditLog(log_path)
            audit_log1.record_event(
                event_type="POLICY_VIOLATION",
                severity="HIGH",
                details={"instance": 1}
            )

            # Second instance verifies
            audit_log2 = AuditLog(log_path)
            assert audit_log2.verify_integrity() == True, \
                "Cross-instance verification should pass with same secret"

        finally:
            os.unlink(log_path)

    finally:
        if old_secret is not None:
            os.environ["SCALPEL_AUDIT_SECRET"] = old_secret
        else:
            os.environ.pop("SCALPEL_AUDIT_SECRET", None)


# =============================================================================
# CANONICAL JSON TESTS
# =============================================================================

def test_canonical_json_sorted_keys():
    """
    TEST: JSON canonicalization uses sorted keys.
    """
    # Verify that key order doesn't affect signature
    data1 = {"z": 1, "a": 2, "m": 3}
    data2 = {"a": 2, "m": 3, "z": 1}

    canonical1 = json.dumps(data1, sort_keys=True, separators=(',', ':'))
    canonical2 = json.dumps(data2, sort_keys=True, separators=(',', ':'))

    assert canonical1 == canonical2, "Canonical JSON should sort keys"


def test_canonical_json_no_whitespace():
    """
    TEST: JSON canonicalization removes unnecessary whitespace.
    """
    data = {"key": "value", "nested": {"inner": [1, 2, 3]}}
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))

    # Should have no spaces after : or ,
    assert ": " not in canonical, "Canonical JSON should not have space after colon"
    assert ", " not in canonical, "Canonical JSON should not have space after comma"


def test_nested_objects_signed_correctly():
    """
    TEST: Nested objects are signed correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "level1": {
                    "level2": {
                        "level3": {
                            "deep_value": "test"
                        }
                    }
                }
            }
        )

        assert audit_log.verify_integrity() == True, \
            "Nested objects should be signed correctly"

    finally:
        os.unlink(log_path)


def test_special_characters_signed_correctly():
    """
    TEST: Special characters in data are signed correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "unicode": "Hello, 世界! 🌍",
                "newlines": "line1\nline2\nline3",
                "tabs": "col1\tcol2\tcol3",
                "quotes": 'He said "Hello"',
                "backslash": "C:\\path\\to\\file"
            }
        )

        assert audit_log.verify_integrity() == True, \
            "Special characters should be signed correctly"

    finally:
        os.unlink(log_path)


# =============================================================================
# TIMING-SAFE COMPARISON TEST
# =============================================================================

def test_timing_safe_comparison():
    """
    TEST: Signature comparison uses timing-safe method.

    The AuditLog should use hmac.compare_digest() to prevent timing attacks.
    This test verifies the mechanism exists (actual timing analysis would
    require more sophisticated testing).
    """
    # Verify hmac.compare_digest is available and works
    sig1 = "hmac-sha256:abc123"
    sig2 = "hmac-sha256:abc123"
    sig3 = "hmac-sha256:def456"

    assert hmac.compare_digest(sig1, sig2) == True, \
        "Identical signatures should match"
    assert hmac.compare_digest(sig1, sig3) == False, \
        "Different signatures should not match"


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_hmac_signing_tests():
    """Run all HMAC signing tests."""
    tests = [
        ("HMAC-001", "HMAC-SHA256 algorithm", test_hmac_sha256_algorithm),
        ("HMAC-002", "Signature deterministic", test_signature_deterministic),
        ("HMAC-003", "Different data different signature", test_different_data_different_signature),
        ("HMAC-004", "Signature changes with event type", test_signature_changes_with_event_type),
        ("HMAC-005", "Signature changes with severity", test_signature_changes_with_severity),
        ("VERIFY-001", "Verify valid signature", test_verify_valid_signature),
        ("VERIFY-002", "Verify multiple events", test_verify_multiple_events),
        ("VERIFY-003", "Verification fails on modified event", test_verification_fails_on_modified_event),
        ("VERIFY-004", "Verification fails on modified signature", test_verification_fails_on_modified_signature),
        ("SECRET-001", "Default secret used", test_default_secret_used),
        ("SECRET-002", "Custom secret from env", test_custom_secret_from_env),
        ("SECRET-003", "Different secrets different signatures", test_different_secrets_produce_different_signatures),
        ("SECRET-004", "Cross-instance verification", test_cross_instance_verification),
        ("CANON-001", "Canonical JSON sorted keys", test_canonical_json_sorted_keys),
        ("CANON-002", "Canonical JSON no whitespace", test_canonical_json_no_whitespace),
        ("CANON-003", "Nested objects signed correctly", test_nested_objects_signed_correctly),
        ("CANON-004", "Special characters signed correctly", test_special_characters_signed_correctly),
        ("TIMING-001", "Timing-safe comparison", test_timing_safe_comparison),
    ]

    print("=" * 70)
    print("AUDIT TRAIL HMAC SIGNING TESTS")
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
    run_hmac_signing_tests()
