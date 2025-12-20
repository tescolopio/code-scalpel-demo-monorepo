#!/usr/bin/env python3
"""
=============================================================================
AUDIT TRAIL EDGE CASES AND ERROR HANDLING TESTS
=============================================================================

PURPOSE: Test edge cases, error conditions, and robustness.
These tests verify that:

1. Concurrent access is handled correctly
2. Large payloads are supported
3. Special characters don't break signing
4. File system errors are handled gracefully
5. Memory efficiency for large logs
6. Time-based filtering works correctly
7. Error recovery scenarios

=============================================================================
"""
import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path

from audit_trail_framework import (
    AuditLog, AuditEvent, EventType, Severity,
    TamperDetectedError, AuditLogCorruptedError
)


# =============================================================================
# CONCURRENT ACCESS TESTS
# =============================================================================

def test_concurrent_writes():
    """
    TEST: Multiple threads can write to the log concurrently.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        num_threads = 10
        events_per_thread = 50
        errors = []

        def write_events(thread_id):
            try:
                for i in range(events_per_thread):
                    audit_log.record_event(
                        event_type="POLICY_EVALUATION",
                        severity="LOW",
                        details={"thread": thread_id, "index": i}
                    )
            except Exception as e:
                errors.append((thread_id, e))

        threads = []
        for t in range(num_threads):
            thread = threading.Thread(target=write_events, args=(t,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0, f"Concurrent write errors: {errors}"

        # Verify all events were written
        count = audit_log.get_event_count()
        expected = num_threads * events_per_thread
        assert count == expected, f"Expected {expected} events, got {count}"

        # All signatures should be valid
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_concurrent_read_write():
    """
    TEST: Reading and writing can happen concurrently.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)
        errors = []
        stop_flag = threading.Event()

        def writer():
            try:
                for i in range(100):
                    audit_log.record_event(
                        event_type="POLICY_EVALUATION",
                        severity="LOW",
                        details={"index": i}
                    )
            except Exception as e:
                errors.append(("writer", e))
            finally:
                stop_flag.set()

        def reader():
            try:
                while not stop_flag.is_set():
                    audit_log.get_events()
                    time.sleep(0.01)
            except Exception as e:
                errors.append(("reader", e))

        writer_thread = threading.Thread(target=writer)
        reader_thread = threading.Thread(target=reader)

        writer_thread.start()
        reader_thread.start()

        writer_thread.join()
        reader_thread.join()

        assert len(errors) == 0, f"Concurrent access errors: {errors}"

    finally:
        os.unlink(log_path)


def test_thread_pool_writes():
    """
    TEST: Thread pool can write events efficiently.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        def write_event(index):
            return audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": index}
            )

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(write_event, i) for i in range(100)]
            results = [f.result() for f in futures]

        assert len(results) == 100
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


# =============================================================================
# LARGE PAYLOAD TESTS
# =============================================================================

def test_large_details_payload():
    """
    TEST: Large details payloads are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Create a large payload (~1MB)
        large_data = {
            "large_string": "x" * (1024 * 1024),  # 1MB string
            "nested": {"key": "value"}
        }

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details=large_data
        )

        assert event.signature is not None
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_deeply_nested_details():
    """
    TEST: Deeply nested details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Create deeply nested structure (50 levels)
        nested = {"value": "deepest"}
        for i in range(50):
            nested = {"level": i, "nested": nested}

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details=nested
        )

        assert event.signature is not None
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_large_array_in_details():
    """
    TEST: Large arrays in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Create a large array
        large_array = list(range(10000))

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={"array": large_array}
        )

        assert event.details["array"] == large_array
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_many_events_log_file():
    """
    TEST: Log file with many events works correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Write 5000 events
        for i in range(5000):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        assert audit_log.get_event_count() == 5000
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


# =============================================================================
# SPECIAL CHARACTER TESTS
# =============================================================================

def test_unicode_in_details():
    """
    TEST: Unicode characters in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "message": "Error: 错误信息 🚨",
                "file": "модуль.py",
                "emoji": "🔥💻🐛",
                "arabic": "مرحبا بالعالم",
                "japanese": "こんにちは世界"
            }
        )

        assert event.details["message"] == "Error: 错误信息 🚨"
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_control_characters_in_details():
    """
    TEST: Control characters in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "newlines": "line1\nline2\nline3",
                "tabs": "col1\tcol2\tcol3",
                "carriage": "test\rreturn",
                "null_char": "before\x00after"
            }
        )

        assert "\n" in event.details["newlines"]
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_json_special_chars_in_details():
    """
    TEST: JSON special characters in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_VIOLATION",
            severity="HIGH",
            details={
                "quotes": 'He said "Hello"',
                "backslash": "C:\\path\\to\\file",
                "mixed": '{"nested": "json"}',
                "brackets": "[array, elements]"
            }
        )

        assert '"' in event.details["quotes"]
        assert "\\" in event.details["backslash"]
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_empty_string_values():
    """
    TEST: Empty string values are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={
                "empty": "",
                "whitespace": "   ",
                "nested_empty": {"key": ""}
            }
        )

        assert event.details["empty"] == ""
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


# =============================================================================
# FILE SYSTEM ERROR HANDLING TESTS
# =============================================================================

def test_log_directory_created():
    """
    TEST: Log directory is created if it doesn't exist.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "deep", "nested", "path", "audit.log")

        audit_log = AuditLog(log_path)
        audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={}
        )

        assert os.path.exists(log_path)


def test_log_file_permissions():
    """
    TEST: Log file can be written with correct permissions.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={}
        )

        # File should be readable and writable
        assert os.access(log_path, os.R_OK)
        assert os.access(log_path, os.W_OK)

    finally:
        os.unlink(log_path)


def test_nonexistent_log_verification():
    """
    TEST: Verifying a nonexistent log file returns True (empty log).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "nonexistent.log")

        audit_log = AuditLog(log_path)

        # Should not raise, empty log is valid
        assert audit_log.verify_integrity() == True


def test_log_recovery_after_partial_write():
    """
    TEST: Log can recover from partial write scenarios.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Write some valid events
        for i in range(5):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"index": i}
            )

        # Simulate partial write (truncated line)
        with open(log_path, 'a') as f:
            f.write('{"incomplete":')

        # get_events should skip invalid lines
        events = audit_log.get_events()
        assert len(events) == 5

    finally:
        os.unlink(log_path)


# =============================================================================
# TIME-BASED FILTERING TESTS
# =============================================================================

def test_filter_events_since_timestamp():
    """
    TEST: Events can be filtered by timestamp.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        # Record events
        event1 = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={"id": 1}
        )

        time.sleep(0.1)  # Small delay

        event2 = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={"id": 2}
        )

        # Filter since first event (should get both)
        events = audit_log.get_events(since=event1.timestamp)
        assert len(events) == 2

        # Filter since second event (should get 1)
        events = audit_log.get_events(since=event2.timestamp)
        assert len(events) == 1

    finally:
        os.unlink(log_path)


def test_filter_future_timestamp():
    """
    TEST: Filtering with future timestamp returns no events.
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

        # Future timestamp
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        events = audit_log.get_events(since=future)
        assert len(events) == 0

    finally:
        os.unlink(log_path)


def test_timestamp_ordering():
    """
    TEST: Events are returned in timestamp order.
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

        # Verify ordering (should be chronological)
        for i in range(1, len(events)):
            assert events[i].timestamp >= events[i-1].timestamp

    finally:
        os.unlink(log_path)


# =============================================================================
# CLEAR AND RESET TESTS
# =============================================================================

def test_clear_log():
    """
    TEST: Log can be cleared.
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

        assert audit_log.get_event_count() == 10

        audit_log.clear()

        assert audit_log.get_event_count() == 0
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_write_after_clear():
    """
    TEST: Events can be written after clearing.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        for i in range(5):
            audit_log.record_event(
                event_type="POLICY_EVALUATION",
                severity="LOW",
                details={"batch": 1, "index": i}
            )

        audit_log.clear()

        for i in range(3):
            audit_log.record_event(
                event_type="POLICY_VIOLATION",
                severity="HIGH",
                details={"batch": 2, "index": i}
            )

        assert audit_log.get_event_count() == 3
        events = audit_log.get_events()
        assert all(e.event_type == "POLICY_VIOLATION" for e in events)

    finally:
        os.unlink(log_path)


# =============================================================================
# DATA TYPE EDGE CASES
# =============================================================================

def test_numeric_values_in_details():
    """
    TEST: Various numeric types in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={
                "integer": 42,
                "float": 3.14159,
                "negative": -100,
                "zero": 0,
                "large": 10**20,
                "small": 1e-10
            }
        )

        assert event.details["integer"] == 42
        assert event.details["float"] == 3.14159
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_boolean_values_in_details():
    """
    TEST: Boolean values in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={
                "true_val": True,
                "false_val": False,
                "nested": {"flag": True}
            }
        )

        assert event.details["true_val"] == True
        assert event.details["false_val"] == False
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_null_values_in_details():
    """
    TEST: Null values in details are handled correctly.
    """
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
        log_path = f.name

    try:
        audit_log = AuditLog(log_path)

        event = audit_log.record_event(
            event_type="POLICY_EVALUATION",
            severity="LOW",
            details={
                "null_val": None,
                "nested": {"optional": None}
            }
        )

        assert event.details["null_val"] is None
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


def test_empty_details():
    """
    TEST: Empty details object is handled correctly.
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

        assert event.details == {}
        assert audit_log.verify_integrity() == True

    finally:
        os.unlink(log_path)


# =============================================================================
# TEST RUNNER
# =============================================================================

def run_edge_case_tests():
    """Run all edge case tests."""
    tests = [
        ("CONCURRENT-001", "Concurrent writes", test_concurrent_writes),
        ("CONCURRENT-002", "Concurrent read/write", test_concurrent_read_write),
        ("CONCURRENT-003", "Thread pool writes", test_thread_pool_writes),
        ("LARGE-001", "Large details payload", test_large_details_payload),
        ("LARGE-002", "Deeply nested details", test_deeply_nested_details),
        ("LARGE-003", "Large array in details", test_large_array_in_details),
        ("LARGE-004", "Many events log file", test_many_events_log_file),
        ("CHARS-001", "Unicode in details", test_unicode_in_details),
        ("CHARS-002", "Control characters in details", test_control_characters_in_details),
        ("CHARS-003", "JSON special chars in details", test_json_special_chars_in_details),
        ("CHARS-004", "Empty string values", test_empty_string_values),
        ("FS-001", "Log directory created", test_log_directory_created),
        ("FS-002", "Log file permissions", test_log_file_permissions),
        ("FS-003", "Nonexistent log verification", test_nonexistent_log_verification),
        ("FS-004", "Recovery after partial write", test_log_recovery_after_partial_write),
        ("TIME-001", "Filter events since timestamp", test_filter_events_since_timestamp),
        ("TIME-002", "Filter future timestamp", test_filter_future_timestamp),
        ("TIME-003", "Timestamp ordering", test_timestamp_ordering),
        ("CLEAR-001", "Clear log", test_clear_log),
        ("CLEAR-002", "Write after clear", test_write_after_clear),
        ("TYPES-001", "Numeric values in details", test_numeric_values_in_details),
        ("TYPES-002", "Boolean values in details", test_boolean_values_in_details),
        ("TYPES-003", "Null values in details", test_null_values_in_details),
        ("TYPES-004", "Empty details", test_empty_details),
    ]

    print("=" * 70)
    print("AUDIT TRAIL EDGE CASES AND ERROR HANDLING TESTS")
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
    run_edge_case_tests()
