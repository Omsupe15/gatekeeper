from pydantic import BaseModel, Field
from typing import Set


class ObservedKernelTrace(BaseModel):
    """
    Captured low-level Linux kernel telemetry emitted during Bubblewrap sandbox execution.
    """
    files_read: Set[str] = Field(
        default_factory=set,
        description="Set of file paths resolved via openat syscalls with read flags"
    )
    files_written: Set[str] = Field(
        default_factory=set,
        description="Set of file paths resolved via openat syscalls with write flags"
    )
    network_endpoints: Set[str] = Field(
        default_factory=set,
        description="Set of IP:Port endpoints captured from connect syscalls"
    )
    spawned_binaries: Set[str] = Field(
        default_factory=set,
        description="Set of executable basenames captured from execve syscalls"
    )
    timed_out: bool = Field(
        default=False,
        description="Whether the sandbox execution reached the timeout limit"
    )
    execution_duration_ms: float = Field(
        default=0.0,
        description="Total duration in milliseconds spent inside the kernel sandbox"
    )
