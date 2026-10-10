from enum import Enum
from pydantic import BaseModel, Field
from typing import List


class SecurityDimension(str, Enum):
    NETWORK = "Network Egress"
    FILESYSTEM = "Filesystem Boundary"
    PROCESS = "Process Execution"


class VerdictState(str, Enum):
    ALLOW = "ALLOW"             # Exit Code 0: Runtime aligns with intent
    QUARANTINE = "QUARANTINE"   # Exit Code 1: Drift >= threshold detected
    ERROR = "ERROR"             # Exit Code 2: System or configuration failure


class ExecutionState(str, Enum):
    IDLE = "IDLE"
    INGESTING = "INGESTING"
    SYNTHESIZING_CONTRACT = "SYNTHESIZING_CONTRACT"
    SANDBOXING = "SANDBOXING"
    ARBITRATING = "ARBITRATING"
    ATTRIBUTING_FORENSICS = "ATTRIBUTING_FORENSICS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ViolationRecord(BaseModel):
    dimension: SecurityDimension
    severity: str = Field(default="CRITICAL", description="Severity rating: WARNING or CRITICAL")
    description: str = Field(description="Human-readable violation summary")
    offending_artifact: str = Field(description="Raw path, IP, or binary that triggered the violation")


class DriftResult(BaseModel):
    composite_drift_score: float = Field(ge=0.0, le=1.0)
    network_drift: float = Field(default=0.0, ge=0.0, le=1.0)
    filesystem_drift: float = Field(default=0.0, ge=0.0, le=1.0)
    process_drift: float = Field(default=0.0, ge=0.0, le=1.0)
    is_quarantined: bool
    violations: List[ViolationRecord] = Field(default_factory=list)
