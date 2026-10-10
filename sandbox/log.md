# Project Execution Log - Gatekeeper Block 4: Sandbox Implementation

## Initial Analysis (2026-10-10)

### 1. Repository State & Context Inspection
- **Project**: Gatekeeper (*Autonomous Semantic-to-Kernel Drift Detector for open-source supply-chain security*).
- **Scope**: Implementing **Block 4: Kernel Isolation & Syscall Tracing** inside `sandbox/`.
- **Existing Files**:
  - `README.md`, `pyproject.toml`, `.python-version`
  - Documentation: `docs/PRD.md`, `docs/TRD.md`, `docs/APP_FLOW.md`, `docs/SCHEMA_AND_UI_DESIGN.md`, `docs/IMPLEMENTATION_PLAN.md`
  - No existing code files in `sandbox/` yet.
- **Environment Findings**:
  - Operating System: Windows (with PowerShell / MSYS2 / Python 3.12 & 3.14).
  - Docker CLI version 29.7.2 is installed; Docker daemon is currently not running (`failed to connect to docker API`).
  - Architecture Requirement: Docker is the chosen isolation backend replacing Bubblewrap for cross-platform container isolation.
  - Backward compatibility: Retain `bwrap.py` module as the entry point / runner module.
  - Fail-closed security and comprehensive mock testing required.

### 2. Implemented `sandbox/log_parser.py`
- Implemented robust stream and line parsing for `openat`, `connect`, and `execve` syscalls.
- Handled PID prefixes (`[pid 1234]`, `1234`), unfinished/resumed calls across multiple processes, escaped strings (hex, octal, standard escapes), error codes, and access mode classification (`read`, `write`, `read_write`, `ambiguous`).
- Implemented `extract_observed_trace` to aggregate parsed events into the `ObservedKernelTrace` schema required by the arbitrator.

### 3. Implemented `sandbox/bwrap.py`
- Implemented `DockerSandbox` (and compatibility aliases `KernelSandbox`, `BwrapRunner`, `SandboxRunner`).
- Enforced all required container security constraints:
  - `--rm` (ephemeral container cleanup)
  - `--network none` (complete air-gapped network isolation)
  - `--read-only` (read-only container rootfs)
  - `--cap-drop ALL` (full Linux capabilities stripped)
  - `--security-opt no-new-privileges` (prevent privilege escalation)
  - Resource limits: `--memory 512m`, `--cpus 1.0`, `--pids-limit 64`
  - Non-root user execution (`--user 1000:1000`)
  - Read-only workspace volume mounting with dedicated optional writable output directory
  - Ephemeral tmpfs mounts for `/tmp` and `/run`
  - Host path validation preventing exposure of `~`, `.ssh`, `.aws`, `.docker`, `docker.sock`, or sensitive credentials
  - Rejection of `--privileged` or `--cap-add ALL`
  - Host-side timeout monitoring with container forceful cleanup (`docker rm -f`)
  - Fail-closed Docker availability verification.

### 4. Implemented `sandbox/tracer.py`
- Implemented `SyscallTracer` and public entrypoint `trace_execution` (and alias `run_trace`).
- Traced `openat`, `connect`, and `execve` using `strace -f -s 512 -e trace=openat,connect,execve`.
- Maintained dedicated trace log volume outside untrusted workspace at `/sysdrift_trace/strace.log`.
- Generated standardized public `SandboxReport` containing:
  - `status`: `"completed"`, `"timeout"`, `"docker_unavailable"`, `"execution_failed"`, `"trace_failed"`
  - `exit_code`: Optional integer exit code
  - `timed_out`: Boolean timeout indicator
  - `trace_complete`: Boolean ensuring incomplete traces are never treated as clean traces
  - `events`: List of parsed normalized syscall events
  - `telemetry`: Normalized dictionary matching `ObservedKernelTrace`
  - `stdout`, `stderr`, `trace_path`, `errors` list.

### 5. Implemented `sandbox/__init__.py` & `sandbox/Dockerfile`
- Exported clean, documented module APIs: `DockerSandbox`, `SyscallTracer`, `trace_execution`, `parse_trace`, `extract_observed_trace`, `SandboxReport`, `SandboxConfig`.
- Provided a minimal `sandbox/Dockerfile` based on Alpine with `strace`, `bash`, `python3`, and `nodejs`, configured with non-root user `sandbox` (UID 1000).

### 6. Consolidated Architecture & Engineering Decisions
- The 13 formal decisions are recorded in full in the decision record below.

### 7. Implemented `sandbox/tests/test_sandbox.py`
- Implemented 19 comprehensive unit and integration test cases:
  - `test_parse_openat_success_read`: Validates read flag detection.
  - `test_parse_openat_success_write`: Validates write flags (`O_WRONLY`, `O_CREAT`, `O_TRUNC`).
  - `test_parse_openat_success_read_write`: Validates `O_RDWR` read-write access mode.
  - `test_parse_openat_failed_error`: Validates error code capture (`-1 ENOENT`).
  - `test_parse_execve_success`: Validates path, binary basename, and argument vector.
  - `test_parse_execve_failed`: Validates failure return and error codes.
  - `test_parse_connect_success`: Validates IPv4 address, port, and endpoint extraction.
  - `test_parse_connect_failed_attempt`: Validates failed connection attempts (`ECONNREFUSED`) are preserved in telemetry.
  - `test_extract_ipv6_and_unix_socket`: Validates IPv6 addresses and Unix domain sockets.
  - `test_parse_abstract_unix_socket`: Validates abstract Unix domain sockets (`@dbus_abstract`).
  - `test_parse_openat2_struct_flags`: Validates `openat2` struct `{flags=...}` syntax.
  - `test_parse_execveat`: Validates `execveat` syscall parsing.
  - `test_parse_with_timestamps_and_elapsed_time`: Validates timestamp stripping (`12:34:56.789012`) and `<elapsed>` time suffix handling.
  - `test_parse_interrupted_syscall_question_mark`: Validates killed/interrupted syscalls with `= ?` return values.
  - `test_quoted_paths_and_escapes`: Validates hex (`\x2f`), octal (`\141`), tabs, newlines, and escaped quotes.
  - `test_malformed_lines_handled_without_crash`: Validates resilience against corrupted strace output.
  - `test_unfinished_and_resumed_calls`: Validates multi-process state tracking and interleaved resumed syscalls.
  - `test_extract_observed_trace_aggregation`: Validates aggregation into `ObservedKernelTrace` schema.
  - `test_build_docker_command_security_defaults`: Validates `--rm`, `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, resource limits, and tmpfs.
  - `test_reject_privileged_mode` & `test_reject_broad_capability_grants`: Rejects `--privileged` and `--cap-add ALL`.
  - `test_reject_host_namespace_sharing`: Rejects `--net=host`, `--pid=host`, `--ipc=host`, `--uts=host`, `--userns=host`.
  - `test_reject_sensitive_host_paths` & `test_reject_user_home_directory_mount`: Rejects `.ssh`, `.aws`, `docker.sock`, and home dir mounts.
  - `test_docker_unavailable_handling`: Validates fail-closed behavior when Docker daemon is not active.
  - `test_timeout_handling_and_cleanup`: Validates timeout detection and container cleanup (`docker rm -f`).
  - `test_missing_trace_file_reported_as_failure_not_clean`: Verifies missing trace produces `trace_complete=False` and `status="trace_failed"`.
  - `test_successful_trace_report_schema`: Verifies end-to-end report and telemetry conversion.
  - `test_ptrace_permission_failure_detected`: Verifies ptrace failures are explicitly caught.
  - `test_live_docker_sandboxed_harmless_execution`: Live integration test executing harmless script inside Docker.
  - `test_live_docker_sandboxed_tracing_or_fail_closed`: Live integration test executing tracer inside Docker.

### 8. Added Compatibility Forwarding (`core/sandbox/`)
- Created `core/sandbox/__init__.py`, `core/sandbox/bwrap.py`, `core/sandbox/tracer.py`, `core/sandbox/log_parser.py` re-exporting from top-level `sandbox`.
- Added test case `test_core_sandbox_import_compatibility` to guarantee interoperability across all import conventions.

### 9. Dual-Backend Integration: Bubblewrap (`bwrap`) + Docker
- Implemented `BubblewrapSandbox` according to `docs/TRD.md` specification:
  - `--ro-bind` for system paths (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc/resolv.conf`)
  - `--proc /proc`, `--dev /dev`
  - `--tmpfs /tmp`, `--tmpfs /run`
  - Unshared namespaces: `--unshare-user`, `--unshare-pid`, `--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup`
  - Air-gapped network: `--unshare-net`
  - `--ro-bind` for workspace, optional `--bind` for writable outputs
  - Security boundaries: rejection of `--bind / /`, sensitive credential mounts, and home directory
- Implemented `KernelSandbox`: unified runner that automatically selects Bubblewrap on native Linux or Docker cross-platform (Windows/macOS), with manual override via `config.backend`.
- Retained `DockerSandbox` as standalone runner for backward compatibility.
- Updated `SyscallTracer` to orchestrate both Bubblewrap host tracing and Docker container tracing seamlessly.

### 10. Parser Hardening & Unfinished Syscall Recovery
- Added support for `open` and `creat` syscalls, normalizing them into `openat` schema with read/write access classification.
- Added support for hexadecimal sockaddr port numbers (`sin_port=htons(0x1bb)` -> 443).
- Implemented forensic recovery for un-resumed syscalls on timeout/kill:
  - If malware executes `connect(...) <unfinished ...>` and loops indefinitely until timeout, the un-resumed connection attempt is preserved and extracted into `network_endpoints` with status `UNFINISHED`, preventing timing-bomb evasion.

### 11. Implemented Sandbox CLI Entrypoint (`sandbox/__main__.py`)
- Created `sandbox/__main__.py` supporting:
  - Script sandboxing and tracing: `python -m sandbox <script> <workspace> [--backend auto|docker|bwrap] [--timeout 20] [--json]`
  - Direct trace log parsing: `python -m sandbox --parse-trace <log_file> [--json]`
  - Rich human-readable terminal report and JSON serialization.

### 12. Validation Results
- Total Tests: 48 tests (100% passing across Python 3.12 and Python 3.14).
- Test Suite: `python.exe -m unittest discover -s sandbox/tests -v`
- Coverage includes:
  - 14 parser unit tests (open, creat, openat, openat2, connect, IPv4, IPv6, Unix socket, hex ports, execve, execveat, timestamps, escapes, unfinished/resumed, un-resumed recovery, malformed lines).
  - 10 Docker sandbox security and lifecycle tests (security defaults, privilege rejection, sensitive path rejection, timeout cleanup, daemon unavailability).
  - 6 Bubblewrap sandbox security and lifecycle tests (security defaults, dangerous argument rejection, bwrap unavailability, mocked execution, timeout handling, kernel runner backend routing).
  - 6 Syscall tracer orchestrator tests (Docker unavailable, bwrap unavailable, successful Docker trace, successful bwrap trace, missing trace failure detection, ptrace permission failure detection).
  - 2 CLI tests (strace parsing, end-to-end report).
  - 1 core/sandbox compatibility test.
  - 2 live Docker integration tests (harmless execution, live tracing).

## Architecture & Engineering Decision Record

### DECISION-SANDBOX-001: Docker Backend Selected Over Native Bubblewrap
- **Context**: Bubblewrap (`bwrap`) relies on Linux unprivileged user namespaces (`CLONE_NEWUSER`), which are unavailable on macOS and Windows hosts and often disabled or restricted in enterprise Linux/CI environments.
- **Decision**: Use Docker containerization as the primary isolation engine while maintaining Bubblewrap compatibility interfaces.
- **Rationale**: Docker provides cross-platform container runtime support with standardized isolation flags (`--network none`, `--read-only`, `--cap-drop ALL`, and tmpfs) across Windows, Linux, and CI/CD pipelines.

### DECISION-SANDBOX-002: Backward-Compatible `bwrap.py` Filename and Class Aliases
- **Context**: Existing repository specifications, documentation, and dependent modules reference `sandbox.bwrap.KernelSandbox` or `sandbox.bwrap.run_in_sandbox`.
- **Decision**: Retain `sandbox/bwrap.py` and export `DockerSandbox`, `KernelSandbox`, `SandboxRunner`, and `BwrapRunner`.
- **Rationale**: This prevents breaking imports across teammate modules while routing execution to the hardened Docker isolation layer.

### DECISION-SANDBOX-003: Zero-Trust Filesystem and Network Confinement
- **Context**: Untrusted package scripts may attempt to read credentials (`~/.ssh`, `~/.aws`, `.docker`), modify system binaries, or exfiltrate secrets over TCP sockets.
- **Decision**: Enforce `--network none`, `--read-only` rootfs, isolated tmpfs mounts (`/tmp`, `/run`), and a read-only host workspace mount by default.
- **Rationale**: Execution is air-gapped by default. Any writable destination must be an explicitly designated directory such as `/workspace/output`, and credential files or user home directories are rejected before container launch.

### DECISION-SANDBOX-004: Capability Stripping, No-New-Privileges, and Resource Caps
- **Context**: Malicious packages might attempt container escape through kernel vulnerabilities, fork bombs, or memory exhaustion.
- **Decision**: Apply `--cap-drop ALL`, `--security-opt no-new-privileges`, `--memory 512m`, `--cpus 1.0`, and `--pids-limit 64`.
- **Rationale**: These restrictions reduce the kernel attack surface and limit denial-of-service attempts. Syscall tracing selectively enables only `SYS_PTRACE`; privileged containers and broad capability grants such as `--cap-add ALL` are prohibited.

### DECISION-SANDBOX-005: Dedicated Host Trace Log Isolation
- **Context**: Untrusted scripts could tamper with, truncate, or overwrite strace logs if they were placed in a shared writable workspace.
- **Decision**: Mount a dedicated temporary trace directory outside the workspace at `/sysdrift_trace` and write telemetry to `/sysdrift_trace/strace.log`.
- **Rationale**: The untrusted script cannot modify or delete captured kernel telemetry through the workspace mount.

### DECISION-SANDBOX-006: Deterministic Timeout Enforcement and Lifecycle Teardown
- **Context**: Adversarial packages may implement timing bombs or hang indefinitely while waiting for external network sockets.
- **Decision**: Enforce a strict host-side timeout with `subprocess.run(timeout=...)` and forcefully terminate the container with `docker rm -f` on timeout or failure.
- **Rationale**: This prevents orphaned processes and hanging CI/CD runners while tagging timeouts with `timed_out=True` and `status="timeout"`.

### DECISION-SANDBOX-007: Fail-Closed Tracing and Explicit Incomplete Evidence
- **Context**: If strace fails to attach, exits prematurely, or produces corrupted logs, an empty event log must not be interpreted as benign behavior.
- **Decision**: Set `trace_complete=False` and use `status="trace_failed"` or `status="docker_unavailable"` when trace logs are missing, empty, or unparseable.
- **Rationale**: Incomplete evidence represents uncertainty that downstream arbitration must account for rather than treating it as proof of harmlessness.

### DECISION-SANDBOX-008: Granular Strace Parsing
- **Context**: Strace emits multi-process PID prefixes, escaped characters, multiline strings, error codes, and split `<unfinished ...>` / `<... resumed>` lines.
- **Decision**: Use multi-stage tokenization with PID state tracking and dedicated parsers for `openat`, `connect`, and `execve`.
- **Rationale**: This avoids fragile monolithic regular expressions, safely unescapes paths, handles non-blocking connection attempts, and distinguishes read from write filesystem operations.

### DECISION-SANDBOX-009: Docker Shared-Kernel Boundary
- **Context**: Containers share the host operating system kernel, unlike hypervisor-based virtual machines such as Firecracker or QEMU.
- **Decision**: Document that Docker provides process and namespace containment rather than hardware virtualization.
- **Rationale**: High-risk kernel zero-days could theoretically affect the host kernel. Extreme threat profiles should pair Docker with gVisor or use Firecracker microVMs.

### DECISION-SANDBOX-010: Windows Host and Docker Desktop Handling
- **Context**: On Windows hosts without an active Docker Desktop Linux daemon, Docker CLI calls fail with named-pipe errors such as `npipe:////./pipe/dockerDesktopLinuxEngine`.
- **Decision**: Make `is_docker_available()` return `status="docker_unavailable"` without raising an unhandled exception, with mocked unit coverage for non-Docker environments.
- **Rationale**: This keeps CI and developer workflows testable on any OS regardless of Docker daemon availability.

### DECISION-SANDBOX-011: Dual-Backend Architecture
- **Context**: Native Linux workstations and enterprise CI runners may support unprivileged Bubblewrap, while Windows and macOS environments require Docker.
- **Decision**: Support both Bubblewrap (`BubblewrapSandbox`) and Docker (`DockerSandbox`) under `KernelSandbox`, with automatic backend selection through `backend="auto"`.
- **Rationale**: This preserves the original Bubblewrap specification while enabling cross-platform isolation.

### DECISION-SANDBOX-012: Resilient Syscall Ingestion
- **Context**: Binaries and shared libraries use syscall variants such as `open`, `creat`, `openat2`, and `execveat`, and socket ports may be represented in hexadecimal.
- **Decision**: Normalize `open`, `creat`, and `openat2` into unified filesystem access modes and support decimal and hexadecimal sockaddr ports.
- **Rationale**: This removes blind spots caused by libc or architecture differences without requiring separate arbitrator schemas.

### DECISION-SANDBOX-013: Preservation of Unfinished Syscalls
- **Context**: Timing-bomb or infinite-loop scripts may begin a `connect(...) <unfinished ...>` call and terminate before it resumes.
- **Decision**: Parse unresumed syscalls remaining at trace termination and synthesize forensic event records with status `UNFINISHED`.
- **Rationale**: This preserves network telemetry that could otherwise be hidden by timeout or abrupt termination.








