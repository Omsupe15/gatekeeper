"""System State Machine & Verdict Enums.

Defines the explicit, deterministic execution states and POSIX-compliant
verdict exit codes enforced throughout Gatekeeper execution.
"""

from enum import Enum


class ExecutionState(str, Enum):
    """Deterministic states of the Gatekeeper scanner execution lifecycle."""
    IDLE = "IDLE"
    INGESTING = "INGESTING"
    SYNTHESIZING_CONTRACT = "SYNTHESIZING_CONTRACT"
    SANDBOXING = "SANDBOXING"
    ARBITRATING = "ARBITRATING"
    ATTRIBUTING_FORENSICS = "ATTRIBUTING_FORENSICS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VerdictState(str, Enum):
    """Final arbitration verdict and CI/CD gating outcome."""
    ALLOW = "ALLOW"             # Exit Code 0: Runtime aligns with intent
    QUARANTINE = "QUARANTINE"   # Exit Code 1: Drift >= 0.40 detected
    ERROR = "ERROR"             # Exit Code 2: System or configuration failure

    @property
    def exit_code(self) -> int:
        """Standard POSIX exit code associated with this verdict."""
        if self == VerdictState.ALLOW:
            return 0
        if self == VerdictState.QUARANTINE:
            return 1
        return 2
