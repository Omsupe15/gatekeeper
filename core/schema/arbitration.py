"""Differential Arbitration & Drift Result Models.

Defines the mathematical vector discrepancy output, individual violation records,
and security evaluation dimensions.
"""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class SecurityDimension(str, Enum):
    """Evaluation dimensions for runtime behavioral drift."""
    NETWORK = "Network Egress"
    FILESYSTEM = "Filesystem Boundary"
    PROCESS = "Process Execution"


class SeverityLevel(str, Enum):
    """Violation severity levels."""
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class ViolationRecord(BaseModel):
    """Specific discrepancy detected between EBC contract and kernel telemetry."""

    dimension: SecurityDimension
    severity: str = Field(
        ...,
        description="Severity rating: WARNING or CRITICAL",
    )
    description: str = Field(
        ...,
        description="Human-readable violation summary",
    )
    offending_artifact: str = Field(
        ...,
        description="Raw path, IP, or binary that triggered the violation",
    )


class DriftResult(BaseModel):
    """Multi-axis mathematical drift result computed by the arbitrator engine."""

    composite_drift_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Weighted composite score: D = 0.45(D_net) + 0.35(D_fs) + 0.20(D_proc)",
    )
    network_drift: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Network dimension drift score in [0.0, 1.0]",
    )
    filesystem_drift: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Filesystem dimension drift score in [0.0, 1.0]",
    )
    process_drift: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Process execution dimension drift score in [0.0, 1.0]",
    )
    is_quarantined: bool = Field(
        ...,
        description="True if composite_drift_score >= 0.40",
    )
    violations: List[ViolationRecord] = Field(
        default_factory=list,
        description="List of specific violations contributing to drift",
    )
