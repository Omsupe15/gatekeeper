"""Violation Diagnostic Categorizer and Builders.

Formats actionable discrepancy records across Network Egress, Filesystem Boundary,
and Process Execution security dimensions.
"""

from typing import List
from core.schema.arbitration import SecurityDimension, SeverityLevel, ViolationRecord


def create_network_violation(
    endpoint: str,
    reason: str,
    severity: str = SeverityLevel.CRITICAL.value,
) -> ViolationRecord:
    """Create a structured ViolationRecord for unauthorized network egress."""
    return ViolationRecord(
        dimension=SecurityDimension.NETWORK,
        severity=severity,
        description=f"Unauthorized network egress to {endpoint}: {reason}",
        offending_artifact=endpoint,
    )


def create_credential_violation(
    path: str,
    severity: str = SeverityLevel.CRITICAL.value,
) -> ViolationRecord:
    """Create a structured ViolationRecord for credential or secret access."""
    return ViolationRecord(
        dimension=SecurityDimension.FILESYSTEM,
        severity=severity,
        description=(
            f"Unauthorized filesystem access to sensitive credential store or secret: {path} "
            "(contract invariant violated: accesses_user_credentials=False)"
        ),
        offending_artifact=path,
    )


def create_prefix_violation(
    path: str,
    operation: str,
    allowed_prefixes: List[str],
    severity: str = SeverityLevel.WARNING.value,
) -> ViolationRecord:
    """Create a structured ViolationRecord for directory prefix boundary violations."""
    prefixes_str = ", ".join(f"'{p}'" for p in allowed_prefixes) if allowed_prefixes else "none"
    return ViolationRecord(
        dimension=SecurityDimension.FILESYSTEM,
        severity=severity,
        description=(
            f"Unauthorized {operation} operation on path: {path} "
            f"(outside permitted directory prefixes: [{prefixes_str}])"
        ),
        offending_artifact=path,
    )


def create_process_violation(
    binary: str,
    reason: str,
    severity: str = SeverityLevel.WARNING.value,
) -> ViolationRecord:
    """Create a structured ViolationRecord for unauthorized spawned binary."""
    return ViolationRecord(
        dimension=SecurityDimension.PROCESS,
        severity=severity,
        description=f"Spawned unauthorized executable binary '{binary}': {reason}",
        offending_artifact=binary,
    )


def create_timeout_violation(
    timeout_seconds: float = 20.0,
    severity: str = SeverityLevel.CRITICAL.value,
) -> ViolationRecord:
    """Create a structured ViolationRecord when sandbox execution times out."""
    return ViolationRecord(
        dimension=SecurityDimension.PROCESS,
        severity=severity,
        description=(
            f"Sandbox execution exceeded maximum timeout limit of {timeout_seconds:.1f}s "
            "(potential timing-bomb evasion or hanging lifecycle script)"
        ),
        offending_artifact=f"timeout_{int(timeout_seconds)}s",
    )
