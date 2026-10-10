"""Backward-compatibility module re-exporting arbitration models and lifecycle states."""

from core.schema.arbitration import (
    SecurityDimension,
    SeverityLevel,
    ViolationRecord,
    DriftResult,
)
from core.schema.state import ExecutionState, VerdictState

__all__ = [
    "SecurityDimension",
    "SeverityLevel",
    "ViolationRecord",
    "DriftResult",
    "ExecutionState",
    "VerdictState",
]
