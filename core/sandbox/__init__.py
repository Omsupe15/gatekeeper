"""Gatekeeper Sandbox Subsystem (Block 4: Kernel Isolation & Syscall Tracing).

Provides containerized and namespace process isolation using Bubblewrap and Docker,
with low-level system call interception using strace. Emits structured telemetry for downstream drift arbitration.
"""

from __future__ import annotations

from sandbox.bwrap import (
    DEFAULT_BWRAP_BIN,
    DEFAULT_CPU_LIMIT,
    DEFAULT_DOCKER_BIN,
    DEFAULT_MEMORY_LIMIT,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_USER,
    BubblewrapSandbox,
    BubblewrapUnavailableError,
    BwrapRunner,
    DockerSandbox,
    DockerUnavailableError,
    ExecutionResult,
    KernelSandbox,
    SandboxConfig,
    SandboxError,
    SandboxRunner,
    SandboxTimeoutError,
    SecurityViolationError,
    build_bwrap_args,
    build_docker_run_args,
    is_bwrap_available,
    is_docker_available,
    run_in_sandbox,
    validate_host_path,
)
from sandbox.log_parser import (
    extract_observed_trace,
    extract_observed_trace_model,
    parse_line,
    parse_trace,
    parse_trace_file,
)
from sandbox.tracer import (
    SandboxReport,
    SyscallTracer,
    run_trace,
    trace_execution,
)

__all__ = [
    # Sandbox runner & configuration
    "DockerSandbox",
    "BubblewrapSandbox",
    "KernelSandbox",
    "SandboxRunner",
    "BwrapRunner",
    "SandboxConfig",
    "ExecutionResult",
    "run_in_sandbox",
    "build_docker_run_args",
    "build_bwrap_args",
    "is_docker_available",
    "is_bwrap_available",
    "validate_host_path",
    # Tracing orchestrator & reports
    "SyscallTracer",
    "SandboxReport",
    "trace_execution",
    "run_trace",
    # Log parser
    "parse_trace",
    "parse_trace_file",
    "parse_line",
    "extract_observed_trace",
    "extract_observed_trace_model",
    # Exceptions
    "SandboxError",
    "DockerUnavailableError",
    "BubblewrapUnavailableError",
    "SecurityViolationError",
    "SandboxTimeoutError",
    # Constants
    "DEFAULT_SANDBOX_IMAGE",
    "DEFAULT_DOCKER_BIN",
    "DEFAULT_BWRAP_BIN",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_MEMORY_LIMIT",
    "DEFAULT_CPU_LIMIT",
    "DEFAULT_PIDS_LIMIT",
    "DEFAULT_USER",
]
