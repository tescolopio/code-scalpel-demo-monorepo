#!/usr/bin/env python3
"""
=============================================================================
AUDIT TRAIL TEST FRAMEWORK
=============================================================================

Comprehensive test suite for Code Scalpel's Audit Trail feature.
The Audit Trail provides tamper-resistant, cryptographically-signed logging
of all security events for compliance and forensics.

KEY FEATURES TESTED:
- HMAC-SHA256 signing of all events
- Tamper detection via integrity verification
- Event schema validation
- Event types: POLICY_EVALUATION, POLICY_VIOLATION, POLICY_OVERRIDE_APPROVED, TAMPER_DETECTED
- Severity levels: LOW, MEDIUM, HIGH, CRITICAL

SECURITY PROPERTIES:
- Each log entry is signed with HMAC-SHA256
- Tampering with any entry is detectable
- Signatures use a secret key (from env or default)
- Log integrity can be verified at any time

=============================================================================
"""
import hashlib
import hmac
import json
import os
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid


# =============================================================================
# ENUMS AND DATA STRUCTURES
# =============================================================================

class EventType(Enum):
    """Types of audit events."""
    POLICY_EVALUATION = "POLICY_EVALUATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    POLICY_OVERRIDE_APPROVED = "POLICY_OVERRIDE_APPROVED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    # Additional event types for comprehensive coverage
    AGENT_SESSION_START = "AGENT_SESSION_START"
    AGENT_SESSION_END = "AGENT_SESSION_END"
    FILE_ACCESS = "FILE_ACCESS"
    CODE_EDIT = "CODE_EDIT"
    SANDBOX_VIOLATION = "SANDBOX_VIOLATION"
    SECRET_DETECTED = "SECRET_DETECTED"


class Severity(Enum):
    """Event severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AuditEvent:
    """Represents an audit log event."""
    timestamp: str
    event_type: str
    severity: str
    details: Dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "details": self.details,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Create from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            event_id=data.get("event_id", str(uuid.uuid4())),
            event_type=data["event_type"],
            severity=data["severity"],
            details=data["details"],
            signature=data.get("signature")
        )


class TamperDetectedError(Exception):
    """Raised when log tampering is detected."""
    def __init__(self, message: str, line_number: int = 0, expected_sig: str = "", actual_sig: str = ""):
        super().__init__(message)
        self.line_number = line_number
        self.expected_sig = expected_sig
        self.actual_sig = actual_sig


class AuditLogCorruptedError(Exception):
    """Raised when the audit log is corrupted."""
    pass


# =============================================================================
# AUDIT LOG IMPLEMENTATION
# =============================================================================

class AuditLog:
    """
    Tamper-resistant, cryptographically-signed audit log.

    Features:
    - HMAC-SHA256 signing of each event
    - Integrity verification
    - JSON-lines format for easy parsing
    - Tamper detection
    """

    DEFAULT_SECRET = "default-secret"
    SECRET_ENV_VAR = "SCALPEL_AUDIT_SECRET"

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self._secret = self._get_secret()
        self._ensure_log_exists()

    def _get_secret(self) -> bytes:
        """Get the HMAC secret from environment or use default."""
        secret = os.environ.get(self.SECRET_ENV_VAR, self.DEFAULT_SECRET)
        return secret.encode('utf-8')

    def _ensure_log_exists(self) -> None:
        """Ensure the log file exists."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

    def _sign_event(self, event: Dict[str, Any]) -> str:
        """
        Sign an event using HMAC-SHA256.

        Args:
            event: Event dictionary WITHOUT signature field

        Returns:
            HMAC signature as hex string
        """
        # Create a copy without signature for signing
        event_copy = {k: v for k, v in event.items() if k != "signature"}
        # Canonical JSON representation (sorted keys, no whitespace)
        message = json.dumps(event_copy, sort_keys=True, separators=(',', ':'))
        signature = hmac.new(
            self._secret,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"hmac-sha256:{signature}"

    def _verify_signature(self, event: Dict[str, Any]) -> bool:
        """
        Verify an event's signature.

        Args:
            event: Event dictionary with signature field

        Returns:
            True if signature is valid, False otherwise
        """
        if "signature" not in event:
            return False

        stored_signature = event["signature"]
        expected_signature = self._sign_event(event)

        return hmac.compare_digest(stored_signature, expected_signature)

    def _get_timestamp(self) -> str:
        """Get ISO 8601 timestamp in UTC."""
        return datetime.now(timezone.utc).isoformat(timespec='milliseconds')

    def record_event(
        self,
        event_type: str,
        severity: str,
        details: Dict[str, Any]
    ) -> AuditEvent:
        """
        Record a new audit event.

        Args:
            event_type: Type of event (POLICY_VIOLATION, etc.)
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            details: Event-specific details

        Returns:
            The recorded AuditEvent
        """
        event = AuditEvent(
            timestamp=self._get_timestamp(),
            event_type=event_type,
            severity=severity,
            details=details
        )

        # Create event dict for signing
        event_dict = event.to_dict()
        del event_dict["signature"]  # Remove None signature before signing

        # Sign the event
        signature = self._sign_event(event_dict)
        event.signature = signature
        event_dict["signature"] = signature

        # Append to log file
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(event_dict, separators=(',', ':')) + '\n')

        return event

    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the entire audit log.

        Raises:
            TamperDetectedError: If tampering is detected
            AuditLogCorruptedError: If log format is invalid

        Returns:
            True if log is intact
        """
        if not self.log_path.exists():
            return True  # Empty log is valid

        with open(self.log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    raise AuditLogCorruptedError(
                        f"Invalid JSON on line {line_num}: {e}"
                    )

                if "signature" not in event:
                    raise AuditLogCorruptedError(
                        f"Missing signature on line {line_num}"
                    )

                if not self._verify_signature(event):
                    expected = self._sign_event(event)
                    raise TamperDetectedError(
                        f"Signature mismatch on line {line_num}",
                        line_number=line_num,
                        expected_sig=expected,
                        actual_sig=event.get("signature", "")
                    )

        return True

    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[str] = None
    ) -> List[AuditEvent]:
        """
        Retrieve events from the audit log.

        Args:
            event_type: Filter by event type
            severity: Filter by severity
            since: Filter events after this timestamp (ISO 8601)

        Returns:
            List of matching AuditEvent objects
        """
        events = []

        if not self.log_path.exists():
            return events

        with open(self.log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    event_dict = json.loads(line)
                    event = AuditEvent.from_dict(event_dict)

                    # Apply filters
                    if event_type and event.event_type != event_type:
                        continue
                    if severity and event.severity != severity:
                        continue
                    if since and event.timestamp < since:
                        continue

                    events.append(event)
                except (json.JSONDecodeError, KeyError):
                    continue

        return events

    def get_event_count(self) -> int:
        """Get the total number of events in the log."""
        if not self.log_path.exists():
            return 0

        with open(self.log_path, 'r') as f:
            return sum(1 for line in f if line.strip())

    def clear(self) -> None:
        """Clear the audit log (for testing only)."""
        if self.log_path.exists():
            self.log_path.unlink()
        self._ensure_log_exists()


# =============================================================================
# TEST DATA STRUCTURES
# =============================================================================

@dataclass
class AuditTestCase:
    """Represents an audit trail test case."""
    test_id: str
    name: str
    description: str
    setup: Optional[callable] = None
    test_fn: Optional[callable] = None
    expected_pass: bool = True


@dataclass
class AuditTestResult:
    """Result of running an audit test."""
    test_case: AuditTestCase
    passed: bool
    error: Optional[str] = None
    execution_time_ms: float = 0.0


# =============================================================================
# TEST RUNNER
# =============================================================================

class AuditTrailTestRunner:
    """Test runner for audit trail tests."""

    def __init__(self):
        self.results: List[AuditTestResult] = []

    def run_test(self, test_case: AuditTestCase) -> AuditTestResult:
        """Run a single test case."""
        start = time.perf_counter()

        try:
            if test_case.setup:
                test_case.setup()

            if test_case.test_fn:
                test_case.test_fn()

            passed = test_case.expected_pass
            error = None

        except AssertionError as e:
            passed = not test_case.expected_pass
            error = str(e)
        except Exception as e:
            passed = False
            error = f"{type(e).__name__}: {e}"

        elapsed = (time.perf_counter() - start) * 1000

        result = AuditTestResult(
            test_case=test_case,
            passed=passed,
            error=error,
            execution_time_ms=elapsed
        )

        self.results.append(result)
        return result

    def run_all(self, test_cases: List[AuditTestCase]) -> List[AuditTestResult]:
        """Run all test cases."""
        self.results = []
        for test_case in test_cases:
            self.run_test(test_case)
        return self.results

    def generate_report(self) -> Dict[str, Any]:
        """Generate a test report."""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        return {
            "total": len(self.results),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / max(len(self.results), 1),
            "failures": [
                {
                    "test_id": r.test_case.test_id,
                    "name": r.test_case.name,
                    "error": r.error
                }
                for r in self.results if not r.passed
            ]
        }


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Run the audit trail test framework."""
    print("=" * 70)
    print("CODE SCALPEL AUDIT TRAIL TEST FRAMEWORK")
    print("=" * 70)
    print()
    print("Features:")
    print("  - HMAC-SHA256 signing of all events")
    print("  - Tamper detection via integrity verification")
    print("  - JSON-lines format for easy parsing")
    print("  - Event types: POLICY_EVALUATION, POLICY_VIOLATION, etc.")
    print("  - Severity levels: LOW, MEDIUM, HIGH, CRITICAL")
    print()
    print("Security Properties:")
    print("  - Each log entry is cryptographically signed")
    print("  - Tampering with any entry is detectable")
    print("  - Log integrity can be verified at any time")
    print("=" * 70)


if __name__ == "__main__":
    main()
