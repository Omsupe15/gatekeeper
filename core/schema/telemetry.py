"""Kernel Telemetry & Observation Models.

Captures and normalizes low-level system call activity intercepted via strace
inside Bubblewrap container namespaces.
"""

from typing import Set
from pydantic import BaseModel, Field


class ObservedKernelTrace(BaseModel):
    """Telemetry captured from low-level Linux kernel syscall interception.

    Uses `Set[str]` for file operations, network endpoints, and binaries to
    guarantee O(1) set operations during differential comparison and eliminate
    duplicate syscall noise.
    """

    files_read: Set[str] = Field(
        default_factory=set,
        description="Set of file paths resolved via openat syscalls with read flags",
    )
    files_written: Set[str] = Field(
        default_factory=set,
        description="Set of file paths resolved via openat syscalls with write flags",
    )
    network_endpoints: Set[str] = Field(
        default_factory=set,
        description="Set of IP:Port endpoints captured from connect syscalls",
    )
    spawned_binaries: Set[str] = Field(
        default_factory=set,
        description="Set of executable basenames captured from execve syscalls",
    )
    syscalls: Set[str] = Field(
        default_factory=set,
        description="Set of syscall names observed in the strace log",
    )
    flagged_syscalls: Set[str] = Field(
        default_factory=set,
        description="Observed syscall names present in the suspicious syscall cache",
    )
    timed_out: bool = Field(
        default=False,
        description="Whether the sandbox execution reached the 20-second timeout limit",
    )
    execution_duration_ms: float = Field(
        default=0.0,
        description="Total duration in milliseconds spent inside the kernel sandbox",
    )
