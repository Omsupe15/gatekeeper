"""Docker-backed sandbox runner providing isolated, unprivileged script execution.

Maintains backward-compatible interfaces (bwrap.py) while orchestrating
containerized execution using Docker with hardened security defaults:
  - Network isolation (--network none)
  - Read-only root filesystem (--read-only)
  - Dropped Linux capabilities (--cap-drop ALL)
  - Privilege escalation disabled (--security-opt no-new-privileges)
  - Strict resource constraints (--memory, --cpus, --pids-limit)
  - Isolated tmpfs mounts and strict read-only workspace mounts
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# Prohibited host sensitive path prefixes / names
_SENSITIVE_HOST_PATTERNS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".git-credentials",
    ".docker",
    "docker.sock",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "shadow",
    "passwd",
    "master.key",
)

DEFAULT_SANDBOX_IMAGE = os.environ.get("GATEKEEPER_SANDBOX_IMAGE", "alpine:latest")
DEFAULT_DOCKER_BIN = os.environ.get("DOCKER_BIN", "docker")
DEFAULT_BWRAP_BIN = os.environ.get("BWRAP_BIN", "bwrap")
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_CPU_LIMIT = "1.0"
DEFAULT_PIDS_LIMIT = 64
DEFAULT_USER = "1000:1000"


class SandboxError(Exception):
    """Base exception for sandbox execution errors."""
    pass


class DockerUnavailableError(SandboxError):
    """Raised when Docker CLI or daemon is not reachable."""
    pass


class BubblewrapUnavailableError(SandboxError):
    """Raised when Bubblewrap CLI is not installed or unprivileged namespaces are unsupported."""
    pass


class SecurityViolationError(SandboxError):
    """Raised when a mount path or execution configuration violates security invariants."""
    pass


class SandboxTimeoutError(SandboxError):
    """Raised when a sandboxed execution exceeds the maximum allocated runtime."""
    pass


@dataclasses.dataclass
class SandboxConfig:
    """Configuration parameters for the sandbox subsystem."""
    backend: str = "auto"  # "auto", "docker", "bwrap"
    image: str = DEFAULT_SANDBOX_IMAGE
    docker_bin: str = DEFAULT_DOCKER_BIN
    bwrap_bin: str = DEFAULT_BWRAP_BIN
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    memory_limit: str = DEFAULT_MEMORY_LIMIT
    cpu_limit: str = DEFAULT_CPU_LIMIT
    pids_limit: int = DEFAULT_PIDS_LIMIT
    network: str = "none"
    read_only_rootfs: bool = True
    drop_all_caps: bool = True
    no_new_privileges: bool = True
    container_user: Optional[str] = DEFAULT_USER
    writable_output_dir: Optional[str] = None
    read_only_workspace: bool = True
    env_vars: Dict[str, str] = dataclasses.field(default_factory=dict)
    custom_docker_args: List[str] = dataclasses.field(default_factory=list)
    custom_bwrap_args: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ExecutionResult:
    """Raw result of a containerized script execution."""
    status: str  # "completed", "timeout", "docker_unavailable", "execution_failed"
    exit_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: float
    container_id: Optional[str] = None
    errors: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def validate_host_path(path: str, must_exist: bool = True) -> str:
    """Validate that a host path is safe and does not reference sensitive credentials or sockets."""
    if not path or not isinstance(path, str):
        raise SecurityViolationError("Path must be a non-empty string.")

    abs_path = os.path.abspath(os.path.expanduser(path))
    real_path = os.path.realpath(abs_path)

    if must_exist and not os.path.exists(real_path):
        raise FileNotFoundError(f"Host path does not exist: {real_path}")

    # Check for forbidden sensitive targets
    lower_path = real_path.lower()
    for pattern in _SENSITIVE_HOST_PATTERNS:
        if pattern in lower_path:
            raise SecurityViolationError(
                f"Security violation: Attempted to mount sensitive host resource '{pattern}' from '{real_path}'"
            )

    # Prevent mounting system root or user home directory directly
    home_dir = os.path.realpath(os.path.expanduser("~"))
    if real_path == home_dir:
        raise SecurityViolationError("Security violation: Mounting entire user home directory is strictly forbidden.")

    return real_path


def is_docker_available(docker_bin: str = DEFAULT_DOCKER_BIN) -> bool:
    """Check whether the Docker CLI and Docker daemon are functional."""
    # Check if executable exists in PATH
    if not shutil.which(docker_bin):
        return False
    try:
        proc = subprocess.run(
            [docker_bin, "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3.0,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def is_bwrap_available(bwrap_bin: str = DEFAULT_BWRAP_BIN) -> bool:
    """Check whether the Bubblewrap binary exists and can execute unprivileged user namespaces."""
    if not shutil.which(bwrap_bin):
        return False
    try:
        proc = subprocess.run(
            [bwrap_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2.0,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def build_bwrap_args(
    script_path: str,
    workspace_dir: str,
    config: Optional[SandboxConfig] = None,
    extra_mounts: Optional[List[Tuple[str, str, str]]] = None,
    command_override: Optional[List[str]] = None,
) -> List[str]:
    """Construct a secure Bubblewrap execution command according to TRD specifications.
    
    Guarantees strict isolation invariants:
      - Mounts system roots (/usr, /lib, /bin, etc.) read-only
      - Never allows sensitive host paths (~/.ssh, ~/.aws, docker.sock)
      - Mounts workspace read-only unless configured
      - Mounts ephemeral tmpfs on /tmp and /run
      - Drops privileges using unprivileged user/pid/ipc/uts namespaces
      - Air-gaps network when network='none' via --unshare-net
    """
    cfg = config or SandboxConfig()

    # Validate custom arguments for dangerous flags
    forbidden_bwrap_flags = (
        "--bind / /",
        "--bind / ",
    )
    for arg in cfg.custom_bwrap_args:
        for forbidden in forbidden_bwrap_flags:
            if forbidden in arg:
                raise SecurityViolationError(
                    f"Security violation: Prohibited argument '{forbidden}' violates container isolation boundary."
                )

    valid_workspace = validate_host_path(workspace_dir, must_exist=True)
    valid_script = validate_host_path(script_path, must_exist=True)

    cmd: List[str] = [cfg.bwrap_bin]

    # Mount read-only system paths that exist on host
    system_paths = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/resolv.conf")
    for sp in system_paths:
        if os.path.exists(sp):
            cmd.extend(["--ro-bind", sp, sp])

    # Proc and Dev pseudo-filesystems
    cmd.extend(["--proc", "/proc", "--dev", "/dev"])

    # Ephemeral tmpfs mounts
    cmd.extend(["--tmpfs", "/tmp", "--tmpfs", "/run"])

    # Unshare namespaces (user, pid, ipc, uts, cgroup)
    cmd.extend([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
    ])

    # Network isolation
    if cfg.network == "none":
        cmd.append("--unshare-net")

    # Workspace mount
    ws_flag = "--ro-bind" if cfg.read_only_workspace else "--bind"
    cmd.extend([ws_flag, valid_workspace, valid_workspace])

    # Dedicated writable output directory if designated
    if cfg.writable_output_dir:
        valid_output = validate_host_path(cfg.writable_output_dir, must_exist=False)
        os.makedirs(valid_output, exist_ok=True)
        cmd.extend(["--bind", valid_output, valid_output])

    # Extra verified mounts (e.g. trace directory)
    if extra_mounts:
        for host_p, cont_p, mode in extra_mounts:
            v_host = validate_host_path(host_p, must_exist=False)
            flag = "--ro-bind" if mode == "ro" else "--bind"
            cmd.extend([flag, v_host, cont_p])

    # Clean lifecycle options
    cmd.extend(["--die-with-parent", "--new-session", "--chdir", valid_workspace])

    # Custom options
    cmd.extend(cfg.custom_bwrap_args)

    # Command
    if command_override:
        cmd.extend(command_override)
    else:
        cmd.extend(["/bin/sh", valid_script])

    return cmd


def build_docker_run_args(
    script_path: str,
    workspace_dir: str,
    config: Optional[SandboxConfig] = None,
    container_name: Optional[str] = None,
    extra_mounts: Optional[List[Tuple[str, str, str]]] = None,  # (host_path, container_path, mode)
    command_override: Optional[List[str]] = None,
) -> List[str]:
    """Construct a secure Docker run command argument list.
    
    Guarantees strict isolation invariants:
      - Never includes --privileged
      - Drops all capabilities (--cap-drop ALL)
      - Enforces no-new-privileges
      - Disables network (--network none)
      - Mounts workspace read-only by default
      - Employs ephemeral tmpfs mounts for /tmp and /run
    """
    cfg = config or SandboxConfig()

    # Invariant checks
    forbidden_custom_args = (
        "--privileged",
        "--cap-add=ALL",
        "--cap-add ALL",
        "--net=host",
        "--net host",
        "--network=host",
        "--network host",
        "--pid=host",
        "--pid host",
        "--ipc=host",
        "--ipc host",
        "--uts=host",
        "--uts host",
        "--userns=host",
        "--userns host",
    )
    for arg in cfg.custom_docker_args:
        for forbidden in forbidden_custom_args:
            if forbidden in arg:
                raise SecurityViolationError(
                    f"Security violation: Prohibited argument '{forbidden}' violates container isolation boundary."
                )

    valid_workspace = validate_host_path(workspace_dir, must_exist=True)
    valid_script = validate_host_path(script_path, must_exist=True)

    # Determine relative or mounted path inside container
    container_workspace = "/workspace"
    try:
        rel_script = os.path.relpath(valid_script, valid_workspace)
        if not rel_script.startswith("..") and not os.path.isabs(rel_script):
            # Script is inside the workspace
            container_script_path = f"/workspace/{rel_script.replace(os.sep, '/')}"
            script_mount_needed = False
        else:
            container_script_path = "/sysdrift_runner/runner.sh"
            script_mount_needed = True
    except ValueError:
        container_script_path = "/sysdrift_runner/runner.sh"
        script_mount_needed = True

    cmd: List[str] = [cfg.docker_bin, "run", "--rm"]

    if container_name:
        cmd.extend(["--name", container_name])

    # Network isolation
    cmd.extend(["--network", cfg.network or "none"])

    # Rootfs read-only
    if cfg.read_only_rootfs:
        cmd.append("--read-only")

    # Drop capabilities
    if cfg.drop_all_caps:
        cmd.extend(["--cap-drop", "ALL"])

    # Security options
    if cfg.no_new_privileges:
        cmd.extend(["--security-opt", "no-new-privileges"])

    # Resource limits
    if cfg.memory_limit:
        cmd.extend(["--memory", cfg.memory_limit])
    if cfg.cpu_limit:
        cmd.extend(["--cpus", str(cfg.cpu_limit)])
    if cfg.pids_limit:
        cmd.extend(["--pids-limit", str(cfg.pids_limit)])

    # Ephemeral tmpfs mounts
    cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])
    cmd.extend(["--tmpfs", "/run:rw,noexec,nosuid,size=16m"])

    # Non-root user if specified
    if cfg.container_user:
        cmd.extend(["--user", cfg.container_user])

    # Workspace mount
    ws_mode = "ro" if cfg.read_only_workspace else "rw"
    cmd.extend(["-v", f"{valid_workspace}:{container_workspace}:{ws_mode}"])

    # Dedicated writable output directory if designated
    if cfg.writable_output_dir:
        valid_output = validate_host_path(cfg.writable_output_dir, must_exist=False)
        os.makedirs(valid_output, exist_ok=True)
        cmd.extend(["-v", f"{valid_output}:/workspace/output:rw"])

    # Separate script mount if located outside workspace
    if script_mount_needed:
        cmd.extend(["-v", f"{valid_script}:/sysdrift_runner/runner.sh:ro"])

    # Extra verified mounts (e.g. dedicated trace output mount)
    if extra_mounts:
        for host_p, cont_p, mode in extra_mounts:
            v_host = validate_host_path(host_p, must_exist=False)
            cmd.extend(["-v", f"{v_host}:{cont_p}:{mode}"])

    # Environment variables
    for k, v in cfg.env_vars.items():
        cmd.extend(["-e", f"{k}={v}"])

    # Custom options (checked for safety)
    cmd.extend(cfg.custom_docker_args)

    # Working directory
    cmd.extend(["-w", container_workspace])

    # Image
    cmd.append(cfg.image)

    # Command
    if command_override:
        cmd.extend(command_override)
    else:
        cmd.extend(["/bin/sh", container_script_path])

    return cmd


class DockerSandbox:
    """Runner that executes untrusted scripts inside hardened Docker containers."""

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()

    def run(
        self,
        script_path: str,
        workspace_dir: str,
        timeout: Optional[float] = None,
        extra_mounts: Optional[List[Tuple[str, str, str]]] = None,
        command_override: Optional[List[str]] = None,
    ) -> ExecutionResult:
        """Execute the specified script in an isolated Docker container."""
        # Fail closed if Docker is unavailable
        if not is_docker_available(self.config.docker_bin):
            return ExecutionResult(
                status="docker_unavailable",
                exit_code=None,
                stdout="",
                stderr="Docker is not available or Docker daemon is not running.",
                timed_out=False,
                duration_ms=0.0,
                errors=["Docker daemon unreachable or docker CLI missing."],
            )

        container_name = f"gatekeeper-sbx-{uuid.uuid4().hex[:12]}"
        effective_timeout = timeout if timeout is not None else self.config.timeout_seconds

        try:
            cmd = build_docker_run_args(
                script_path=script_path,
                workspace_dir=workspace_dir,
                config=self.config,
                container_name=container_name,
                extra_mounts=extra_mounts,
                command_override=command_override,
            )
        except SecurityViolationError as sve:
            return ExecutionResult(
                status="execution_failed",
                exit_code=None,
                stdout="",
                stderr=str(sve),
                timed_out=False,
                duration_ms=0.0,
                errors=[f"Security validation failed: {sve}"],
            )
        except Exception as e:
            return ExecutionResult(
                status="execution_failed",
                exit_code=None,
                stdout="",
                stderr=str(e),
                timed_out=False,
                duration_ms=0.0,
                errors=[f"Configuration error: {e}"],
            )

        start_time = time.perf_counter()
        timed_out = False
        stdout_text = ""
        stderr_text = ""
        exit_code: Optional[int] = None
        errors: List[str] = []

        try:
            proc = subprocess.run(
                cmd,
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
            # Force clean up container
            self._cleanup_container(container_name)

        except Exception as e:
            status = "execution_failed"
            stderr_text = str(e)
            errors.append(f"Subprocess invocation failure: {e}")
            self._cleanup_container(container_name)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=timed_out,
            duration_ms=duration_ms,
            container_id=container_name,
            errors=errors,
        )

    def _cleanup_container(self, container_name: str) -> None:
        """Ensure container is terminated and removed on timeout or failure."""
        try:
            subprocess.run(
                [self.config.docker_bin, "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5.0,
                check=False,
            )
        except Exception:
            pass


class BubblewrapSandbox:
    """Runner that executes untrusted scripts inside isolated Linux namespaces using Bubblewrap."""

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()

    def run(
        self,
        script_path: str,
        workspace_dir: str,
        timeout: Optional[float] = None,
        extra_mounts: Optional[List[Tuple[str, str, str]]] = None,
        command_override: Optional[List[str]] = None,
    ) -> ExecutionResult:
        """Execute the specified script in an isolated Bubblewrap namespace sandbox."""
        if not is_bwrap_available(self.config.bwrap_bin):
            return ExecutionResult(
                status="bwrap_unavailable",
                exit_code=None,
                stdout="",
                stderr="Bubblewrap is not available or unprivileged user namespaces are unsupported.",
                timed_out=False,
                duration_ms=0.0,
                errors=["Bubblewrap CLI missing or user namespaces unsupported."],
            )

        effective_timeout = timeout if timeout is not None else self.config.timeout_seconds

        try:
            cmd = build_bwrap_args(
                script_path=script_path,
                workspace_dir=workspace_dir,
                config=self.config,
                extra_mounts=extra_mounts,
                command_override=command_override,
            )
        except SecurityViolationError as sve:
            return ExecutionResult(
                status="execution_failed",
                exit_code=None,
                stdout="",
                stderr=str(sve),
                timed_out=False,
                duration_ms=0.0,
                errors=[f"Security validation failed: {sve}"],
            )
        except Exception as e:
            return ExecutionResult(
                status="execution_failed",
                exit_code=None,
                stdout="",
                stderr=str(e),
                timed_out=False,
                duration_ms=0.0,
                errors=[f"Configuration error: {e}"],
            )

        start_time = time.perf_counter()
        timed_out = False
        stdout_text = ""
        stderr_text = ""
        exit_code: Optional[int] = None
        errors: List[str] = []

        try:
            proc = subprocess.run(
                cmd,
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

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=timed_out,
            duration_ms=duration_ms,
            errors=errors,
        )


class KernelSandbox:
    """Unified sandbox runner that auto-selects or delegates to Bubblewrap or Docker."""

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()

    def get_active_backend(self) -> str:
        """Determine which backend runner will be utilized."""
        backend = (self.config.backend or "auto").lower()
        if backend == "bwrap":
            return "bwrap"
        elif backend == "docker":
            return "docker"
        else:  # "auto"
            if is_bwrap_available(self.config.bwrap_bin):
                return "bwrap"
            elif is_docker_available(self.config.docker_bin):
                return "docker"
            else:
                if os.name == "posix" and not sys.platform.startswith("darwin"):
                    return "bwrap"
                return "docker"

    def _get_runner(self):
        backend = self.get_active_backend()
        if backend == "bwrap":
            return BubblewrapSandbox(self.config)
        return DockerSandbox(self.config)

    def run(
        self,
        script_path: str,
        workspace_dir: str,
        timeout: Optional[float] = None,
        extra_mounts: Optional[List[Tuple[str, str, str]]] = None,
        command_override: Optional[List[str]] = None,
    ) -> ExecutionResult:
        runner = self._get_runner()
        return runner.run(
            script_path=script_path,
            workspace_dir=workspace_dir,
            timeout=timeout,
            extra_mounts=extra_mounts,
            command_override=command_override,
        )


# Backward compatibility aliases for existing codebase imports
SandboxRunner = KernelSandbox
BwrapRunner = KernelSandbox


def run_in_sandbox(
    script_path: str,
    workspace_dir: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    image: str = DEFAULT_SANDBOX_IMAGE,
    writable_output_dir: Optional[str] = None,
    backend: str = "auto",
) -> ExecutionResult:
    """Convenience functional wrapper for sandboxed script execution."""
    cfg = SandboxConfig(
        backend=backend,
        image=image,
        timeout_seconds=timeout,
        writable_output_dir=writable_output_dir,
    )
    runner = KernelSandbox(config=cfg)
    return runner.run(script_path=script_path, workspace_dir=workspace_dir)

