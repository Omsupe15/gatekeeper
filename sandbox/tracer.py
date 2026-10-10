"""Syscall tracing orchestrator for Gatekeeper sandbox.

Executes untrusted scripts within an isolated Docker container wrapped with strace
to intercept low-level kernel system calls:
  - openat (Filesystem boundary inspection)
  - connect (Network socket egress inspection)
  - execve (Process and sub-shell execution tracking)

Emits standardized, structured telemetry reports consumable by Gatekeeper's arbitrator.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple

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
    DockerSandbox,
    ExecutionResult,
    KernelSandbox,
    SandboxConfig,
    build_bwrap_args,
    is_bwrap_available,
    is_docker_available,
    validate_host_path,
)
from sandbox.log_parser import extract_observed_trace, parse_trace


@dataclasses.dataclass
class SandboxReport:
    """Standardized report returned by the sandbox subsystem for arbitration."""
    status: str  # "completed", "timeout", "docker_unavailable", "bwrap_unavailable", "execution_failed", "trace_failed"
    exit_code: Optional[int]
    timed_out: bool
    trace_complete: bool
    events: List[Dict[str, Any]]
    telemetry: Dict[str, Any]  # Matches ObservedKernelTrace schema
    stdout: str
    stderr: str
    trace_path: Optional[str]
    errors: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to JSON-serializable dictionary."""
        data = dataclasses.asdict(self)
        # Ensure sets in telemetry are converted to sorted lists for serialization
        if "telemetry" in data and isinstance(data["telemetry"], dict):
            tel = data["telemetry"]
            for key in ("files_read", "files_written", "network_endpoints", "spawned_binaries"):
                if key in tel and isinstance(tel[key], (set, list)):
                    tel[key] = sorted(list(tel[key]))
        return data

    def to_observed_kernel_trace(self) -> Dict[str, Any]:
        """Return the telemetry dictionary formatted for the arbitrator."""
        from sandbox.log_parser import validate_observed_trace
        self.telemetry = validate_observed_trace(self.telemetry)
        return self.telemetry

    def to_observed_kernel_trace_model(self) -> Any:
        """Return the telemetry formatted as a core.schema.telemetry.ObservedKernelTrace instance."""
        from core.schema.telemetry import ObservedKernelTrace
        return ObservedKernelTrace(**self.telemetry)

    def to_model(self) -> Any:
        """Alias for to_observed_kernel_trace_model."""
        return self.to_observed_kernel_trace_model()



class SyscallTracer:
    """Orchestrator that combines kernel isolation (Bubblewrap or Docker) with strace syscall interception."""

    def __init__(
        self,
        backend: str = "auto",
        image: str = DEFAULT_SANDBOX_IMAGE,
        docker_bin: str = DEFAULT_DOCKER_BIN,
        bwrap_bin: str = DEFAULT_BWRAP_BIN,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        cpu_limit: str = DEFAULT_CPU_LIMIT,
        pids_limit: int = DEFAULT_PIDS_LIMIT,
        container_user: Optional[str] = DEFAULT_USER,
    ) -> None:
        self.backend = backend
        self.image = image
        self.docker_bin = docker_bin
        self.bwrap_bin = bwrap_bin
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.container_user = container_user

    def get_active_backend(self, override: Optional[str] = None) -> str:
        """Determine whether to use Bubblewrap or Docker for execution tracing."""
        b = (override or self.backend or "auto").lower()
        if b == "bwrap":
            return "bwrap"
        elif b == "docker":
            return "docker"
        else:  # "auto"
            if is_bwrap_available(self.bwrap_bin):
                return "bwrap"
            return "docker"

    def run_and_trace(
        self,
        script_path: str,
        workspace_dir: str,
        timeout: Optional[float] = None,
        writable_output_dir: Optional[str] = None,
        trace_strace_args: Optional[List[str]] = None,
        backend_override: Optional[str] = None,
    ) -> SandboxReport:
        """Run the script in the sandbox under strace and return a structured report."""
        effective_timeout = timeout if timeout is not None else self.timeout_seconds
        start_time = time.perf_counter()

        chosen_backend = self.get_active_backend(backend_override)

        # Step 1: Verify backend availability
        if chosen_backend == "bwrap" and not is_bwrap_available(self.bwrap_bin):
            return SandboxReport(
                status="bwrap_unavailable",
                exit_code=None,
                timed_out=False,
                trace_complete=False,
                events=[],
                telemetry=extract_observed_trace([], timed_out=False, execution_duration_ms=0.0),
                stdout="",
                stderr="Bubblewrap is not available or unprivileged user namespaces are unsupported.",
                trace_path=None,
                errors=["Bubblewrap CLI missing or user namespaces unsupported. Cannot establish kernel isolation."],
            )
        elif chosen_backend == "docker" and not is_docker_available(self.docker_bin):
            return SandboxReport(
                status="docker_unavailable",
                exit_code=None,
                timed_out=False,
                trace_complete=False,
                events=[],
                telemetry=extract_observed_trace([], timed_out=False, execution_duration_ms=0.0),
                stdout="",
                stderr="Docker is not available or Docker daemon is not running.",
                trace_path=None,
                errors=["Docker daemon unreachable or docker CLI missing. Cannot establish kernel isolation."],
            )

        # Step 2: Validate input paths
        try:
            valid_workspace = validate_host_path(workspace_dir, must_exist=True)
            valid_script = validate_host_path(script_path, must_exist=True)
        except Exception as e:
            return SandboxReport(
                status="execution_failed",
                exit_code=None,
                timed_out=False,
                trace_complete=False,
                events=[],
                telemetry=extract_observed_trace([], timed_out=False, execution_duration_ms=0.0),
                stdout="",
                stderr=str(e),
                trace_path=None,
                errors=[f"Host path validation error: {e}"],
            )

        # Step 3: Set up dedicated temporary trace output directory outside workspace
        trace_dir = tempfile.mkdtemp(prefix="sysdrift_trace_")
        trace_file_host = os.path.join(trace_dir, "strace.log")

        if chosen_backend == "bwrap":
            cfg = SandboxConfig(
                backend="bwrap",
                bwrap_bin=self.bwrap_bin,
                writable_output_dir=writable_output_dir,
            )
            bwrap_cmd = build_bwrap_args(
                script_path=valid_script,
                workspace_dir=valid_workspace,
                config=cfg,
            )
            strace_cmd = [
                "strace",
                "-f",
                "-s",
                "512",
                "-e",
                "trace=open,openat,openat2,creat,connect,execve,execveat",
                "-o",
                trace_file_host,
                "--",
            ] + bwrap_cmd
            if trace_strace_args:
                strace_cmd = trace_strace_args

            timed_out = False
            stdout_text = ""
            stderr_text = ""
            exit_code: Optional[int] = None
            errors: List[str] = []

            try:
                proc = subprocess.run(
                    strace_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=effective_timeout,
                    text=True,
                    check=False,
                )
                exit_code = proc.returncode
                stdout_text = proc.stdout or ""
                stderr_text = proc.stderr or ""
                status = "completed" if exit_code == 0 else "execution_failed"
            except subprocess.TimeoutExpired as te:
                timed_out = True
                status = "timeout"
                stdout_text = te.stdout or "" if isinstance(te.stdout, str) else ""
                stderr_text = te.stderr or "" if isinstance(te.stderr, str) else ""
                errors.append(f"Execution timed out after {effective_timeout}s")
            except Exception as e:
                status = "execution_failed"
                stderr_text = str(e)
                errors.append(f"Subprocess invocation failure: {e}")

            exec_res = ExecutionResult(
                status=status,
                exit_code=exit_code,
                stdout=stdout_text,
                stderr=stderr_text,
                timed_out=timed_out,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
                errors=errors,
            )

        else:  # Docker
            container_trace_file = "/sysdrift_trace/strace.log"
            try:
                rel_script = os.path.relpath(valid_script, valid_workspace)
                if not rel_script.startswith("..") and not os.path.isabs(rel_script):
                    container_script = f"/workspace/{rel_script.replace(os.sep, '/')}"
                else:
                    container_script = "/sysdrift_runner/runner.sh"
            except ValueError:
                container_script = "/sysdrift_runner/runner.sh"

            strace_cmd = [
                "strace",
                "-f",
                "-s",
                "512",
                "-e",
                "trace=open,openat,openat2,creat,connect,execve,execveat",
                "-o",
                container_trace_file,
                "--",
                "/bin/sh",
                container_script,
            ]
            if trace_strace_args:
                strace_cmd = trace_strace_args

            cfg = SandboxConfig(
                image=self.image,
                docker_bin=self.docker_bin,
                timeout_seconds=effective_timeout,
                memory_limit=self.memory_limit,
                cpu_limit=self.cpu_limit,
                pids_limit=self.pids_limit,
                network="none",
                read_only_rootfs=True,
                drop_all_caps=True,
                no_new_privileges=False,  # ptrace inside container requires standard privilege boundary
                container_user=None,      # strace requires root or matching user inside container
                writable_output_dir=writable_output_dir,
                read_only_workspace=True,
                custom_docker_args=["--cap-add", "SYS_PTRACE"],
            )

            runner = DockerSandbox(config=cfg)
            extra_mounts = [(trace_dir, "/sysdrift_trace", "rw")]

            exec_res = runner.run(
                script_path=valid_script,
                workspace_dir=valid_workspace,
                timeout=effective_timeout,
                extra_mounts=extra_mounts,
                command_override=strace_cmd,
            )

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 4: Inspect trace output
        errors = list(exec_res.errors)
        events: List[Dict[str, Any]] = []
        trace_complete = False

        if os.path.exists(trace_file_host) and os.path.getsize(trace_file_host) > 0:
            try:
                with open(trace_file_host, "r", encoding="utf-8", errors="replace") as f:
                    trace_content = f.read()

                # Check for strace permission or attachment failures in trace output
                if "ptrace" in trace_content.lower() and "operation not permitted" in trace_content.lower():
                    errors.append("strace ptrace failed: Operation not permitted inside container.")
                    trace_complete = False
                elif "strace: command not found" in exec_res.stderr or "strace: not found" in exec_res.stderr:
                    errors.append("strace binary not found on host or container image.")
                    trace_complete = False
                else:
                    events = parse_trace(trace_content)
                    trace_complete = True
            except Exception as pe:
                errors.append(f"Failed to read or parse trace file: {pe}")
                trace_complete = False
        else:
            # Trace file was not created or empty
            if exec_res.timed_out:
                errors.append("Trace incomplete: Sandbox execution timed out.")
            elif "strace: not found" in exec_res.stderr or "strace: command not found" in exec_res.stderr:
                errors.append("strace is not installed in the target container image or host.")
            elif exec_res.exit_code == 127:
                errors.append("Command or strace executable not found (exit code 127).")
            else:
                errors.append("Trace file was missing or empty after execution.")
            trace_complete = False

        # Determine overall report status
        if exec_res.timed_out:
            status = "timeout"
        elif exec_res.status in ("docker_unavailable", "bwrap_unavailable"):
            status = exec_res.status
        elif not trace_complete:
            status = "trace_failed"
        elif exec_res.exit_code != 0:
            status = "execution_failed"
        else:
            status = "completed"

        telemetry = extract_observed_trace(
            events=events,
            timed_out=exec_res.timed_out,
            execution_duration_ms=duration_ms,
        )

        return SandboxReport(
            status=status,
            exit_code=exec_res.exit_code,
            timed_out=exec_res.timed_out,
            trace_complete=trace_complete,
            events=events,
            telemetry=telemetry,
            stdout=exec_res.stdout,
            stderr=exec_res.stderr,
            trace_path=trace_file_host if os.path.exists(trace_file_host) else None,
            errors=errors,
        )


def trace_execution(
    script_path: str,
    workspace_dir: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    image: str = DEFAULT_SANDBOX_IMAGE,
    writable_output_dir: Optional[str] = None,
    backend: str = "auto",
) -> SandboxReport:
    """Public convenience function to trace script execution and generate a standardized report."""
    tracer = SyscallTracer(backend=backend, image=image, timeout_seconds=timeout)
    return tracer.run_and_trace(
        script_path=script_path,
        workspace_dir=workspace_dir,
        writable_output_dir=writable_output_dir,
    )


def run_package(
    package_dir: str,
    lifecycle_script: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    image: str = DEFAULT_SANDBOX_IMAGE,
    writable_output_dir: Optional[str] = None,
    backend: str = "auto",
) -> SandboxReport:
    """Execute an approved package lifecycle script without reading package metadata.

    The caller is responsible for analyzing README and package metadata before this
    handoff. The sandbox only validates that the selected script belongs to the
    mounted package directory, then traces its isolated execution.
    """
    valid_package_dir = validate_host_path(package_dir, must_exist=True)
    script_candidate = lifecycle_script
    if not os.path.isabs(script_candidate):
        script_candidate = os.path.join(valid_package_dir, script_candidate)
    valid_script = validate_host_path(script_candidate, must_exist=True)

    try:
        if os.path.commonpath((valid_package_dir, valid_script)) != valid_package_dir:
            raise ValueError("Lifecycle script must be inside the package directory.")
    except ValueError as exc:
        raise ValueError("Lifecycle script must be inside the package directory.") from exc

    return trace_execution(
        script_path=valid_script,
        workspace_dir=valid_package_dir,
        timeout=timeout,
        image=image,
        writable_output_dir=writable_output_dir,
        backend=backend,
    )


# Backward compatibility alias
run_trace = trace_execution
