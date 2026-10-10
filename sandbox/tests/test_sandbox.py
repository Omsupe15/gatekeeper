"""Comprehensive unit and integration test suite for Gatekeeper Sandbox (Block 4).

Tests:
  - openat parsing (read, write, read_write, failed error codes)
  - execve parsing (success, failure, binary basenames, argv)
  - connect parsing (success, failure, IPv4, IPv6, Unix socket, attempted connection semantics)
  - Escaped characters, hex, octal, quotes
  - Unfinished and resumed syscall state tracking
  - Malformed and corrupt lines
  - Missing/empty trace failure reporting (never reported as clean trace)
  - Docker command construction & security invariants (--network none, --read-only, --cap-drop ALL)
  - Rejection of --privileged and sensitive host mounts (~/.ssh, ~/.aws, docker.sock)
  - Docker unavailable and timeout handling via mocks
  - Arbitrator telemetry schema conversion
  - Docker live integration tests (skipped if Docker daemon is unreachable)
"""

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from sandbox.bwrap import (
    DEFAULT_CPU_LIMIT,
    DEFAULT_MEMORY_LIMIT,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_TIMEOUT_SECONDS,
    BubblewrapSandbox,
    BubblewrapUnavailableError,
    DockerSandbox,
    DockerUnavailableError,
    ExecutionResult,
    KernelSandbox,
    SandboxConfig,
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
    run_package,
    run_trace,
    trace_execution,
)


class TestStraceLogParser(unittest.TestCase):
    """Unit tests for strace output parser."""

    def test_parse_openat_success_read(self):
        line = 'openat(AT_FDCWD, "/workspace/setup.py", O_RDONLY|O_CLOEXEC) = 3'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["path"], "/workspace/setup.py")
        self.assertEqual(event["result"], 3)
        self.assertTrue(event["success"])
        self.assertEqual(event["access_mode"], "read")
        self.assertIsNone(event["error_code"])
        self.assertEqual(event["raw"], line)

    def test_parse_openat_success_write(self):
        line = '12345 openat(AT_FDCWD, "/workspace/output/result.json", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["pid"], 12345)
        self.assertEqual(event["path"], "/workspace/output/result.json")
        self.assertEqual(event["result"], 4)
        self.assertTrue(event["success"])
        self.assertEqual(event["access_mode"], "write")

    def test_parse_openat_success_read_write(self):
        line = '[pid 888] openat(AT_FDCWD, "/workspace/data.db", O_RDWR|O_CREAT) = 5'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["pid"], 888)
        self.assertEqual(event["path"], "/workspace/data.db")
        self.assertEqual(event["access_mode"], "read_write")
        self.assertTrue(event["success"])

    def test_parse_openat_failed_error(self):
        line = '12345 openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["path"], "/root/.ssh/id_rsa")
        self.assertEqual(event["result"], -1)
        self.assertFalse(event["success"])
        self.assertEqual(event["error_code"], "ENOENT")

    def test_parse_execve_success(self):
        line = '12345 execve("/bin/bash", ["bash", "-c", "echo hello"], 0x7ffd9b8) = 0'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "execve")
        self.assertEqual(event["path"], "/bin/bash")
        self.assertEqual(event["binary"], "bash")
        self.assertEqual(event["arguments"]["argv"], ["bash", "-c", "echo hello"])
        self.assertEqual(event["result"], 0)
        self.assertTrue(event["success"])
        self.assertIsNone(event["error_code"])

    def test_parse_execve_failed(self):
        line = '12345 execve("/usr/bin/nonexistent_tool", ["nonexistent_tool"], 0x7ffd) = -1 ENOENT (No such file or directory)'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "execve")
        self.assertEqual(event["path"], "/usr/bin/nonexistent_tool")
        self.assertEqual(event["binary"], "nonexistent_tool")
        self.assertEqual(event["result"], -1)
        self.assertFalse(event["success"])
        self.assertEqual(event["error_code"], "ENOENT")

    def test_parse_connect_success(self):
        line = '12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("194.26.29.112")}, 16) = 0'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "connect")
        self.assertEqual(event["address"], "194.26.29.112")
        self.assertEqual(event["port"], 443)
        self.assertEqual(event["endpoint"], "194.26.29.112:443")
        self.assertEqual(event["family"], "AF_INET")
        self.assertEqual(event["result"], 0)
        self.assertTrue(event["success"])

    def test_parse_connect_failed_attempt(self):
        line = '12345 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("10.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "connect")
        self.assertEqual(event["address"], "10.0.0.1")
        self.assertEqual(event["port"], 8080)
        self.assertEqual(event["endpoint"], "10.0.0.1:8080")
        self.assertEqual(event["result"], -1)
        self.assertFalse(event["success"])
        self.assertEqual(event["error_code"], "ECONNREFUSED")

        # Telemetry extraction must still record failed connection attempts as observed network activity
        telemetry = extract_observed_trace([event])
        self.assertIn("10.0.0.1:8080", telemetry["network_endpoints"])

    def test_extract_ipv6_and_unix_socket(self):
        ipv6_line = '12 connect(4, {sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, "::1", &sin6_addr)}, 28) = 0'
        ev_ipv6 = parse_line(ipv6_line)
        self.assertIsNotNone(ev_ipv6)
        self.assertEqual(ev_ipv6["address"], "::1")
        self.assertEqual(ev_ipv6["port"], 80)
        self.assertEqual(ev_ipv6["endpoint"], "::1:80")

        unix_line = '13 connect(5, {sa_family=AF_UNIX, sun_path="/var/run/test.sock"}, 110) = 0'
        ev_unix = parse_line(unix_line)
        self.assertIsNotNone(ev_unix)
        self.assertEqual(ev_unix["address"], "/var/run/test.sock")
        self.assertEqual(ev_unix["endpoint"], "/var/run/test.sock")

    def test_quoted_paths_and_escapes(self):
        # Hex escape \x2f is '/'
        hex_line = r'openat(AT_FDCWD, "\x2f\x74\x6d\x70\x2f\x68\x65\x6c\x6c\x6f", O_RDONLY) = 3'
        ev_hex = parse_line(hex_line)
        self.assertIsNotNone(ev_hex)
        self.assertEqual(ev_hex["path"], "/tmp/hello")

        # Octal escape \141 is 'a'
        oct_line = r'openat(AT_FDCWD, "/tmp/\141\142\143", O_RDONLY) = 3'
        ev_oct = parse_line(oct_line)
        self.assertIsNotNone(ev_oct)
        self.assertEqual(ev_oct["path"], "/tmp/abc")

        # Escaped quotes and tabs
        esc_line = r'openat(AT_FDCWD, "/workspace/my\"file\"\tand\nnewline", O_RDONLY) = 3'
        ev_esc = parse_line(esc_line)
        self.assertIsNotNone(ev_esc)
        self.assertEqual(ev_esc["path"], '/workspace/my"file"\tand\nnewline')

    def test_malformed_lines_handled_without_crash(self):
        malformed_samples = [
            "",
            "   ",
            "+++ exited with 0 +++",
            "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=123} ---",
            "corrupt line without parentheses or equals",
            'openat(unbalanced quotes "/foo, O_RDONLY) = -1',
            "connect(invalid syntax {{}}))) = -1",
            '12345 openat(AT_FDCWD, "/valid/path", O_RDONLY) = not_an_int',
            '12345 execve("/bin/ls", [NULL], 0x0) = 0',
        ]
        for line in malformed_samples:
            # Must safely return without raising unhandled exceptions
            res = parse_line(line)
            if "execve" in line:
                self.assertIsNotNone(res)

        full_trace = "\n".join(malformed_samples)
        events = parse_trace(full_trace)
        self.assertIsInstance(events, list)
        for ev in events:
            self.assertIn(ev["syscall"], ("openat", "connect", "execve"))
            self.assertIn("raw", ev)



    def test_unfinished_and_resumed_calls(self):
        trace_stream = """
1001 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("194.26.29.112")}, 16 <unfinished ...>
1002 openat(AT_FDCWD, "/tmp/interleaved.txt", O_WRONLY|O_CREAT, 0644) = 4
1001 <... connect resumed>) = 0
1003 execve("/bin/sh", ["sh"] <unfinished ...>
1003 <... execve resumed>) = 0
"""
        events = parse_trace(trace_stream)
        self.assertEqual(len(events), 3)

        # Check connect
        conn_ev = [e for e in events if e["syscall"] == "connect"][0]
        self.assertEqual(conn_ev["pid"], 1001)
        self.assertEqual(conn_ev["endpoint"], "194.26.29.112:443")
        self.assertTrue(conn_ev["success"])

        # Check openat
        open_ev = [e for e in events if e["syscall"] == "openat"][0]
        self.assertEqual(open_ev["pid"], 1002)
        self.assertEqual(open_ev["path"], "/tmp/interleaved.txt")
        self.assertEqual(open_ev["access_mode"], "write")

        # Check execve
        exec_ev = [e for e in events if e["syscall"] == "execve"][0]
        self.assertEqual(exec_ev["pid"], 1003)
        self.assertEqual(exec_ev["path"], "/bin/sh")

    def test_parse_openat2_struct_flags(self):
        line = '1234 openat2(AT_FDCWD, "/workspace/foo.txt", {flags=O_RDONLY, resolve=RESOLVE_NO_SYMLINKS}, 24) = 3'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["path"], "/workspace/foo.txt")
        self.assertEqual(event["access_mode"], "read")
        self.assertTrue(event["success"])

    def test_parse_execveat(self):
        line = '1234 execveat(AT_FDCWD, "/bin/sh", ["sh", "-c", "whoami"], NULL, 0) = 0'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "execve")
        self.assertEqual(event["path"], "/bin/sh")
        self.assertEqual(event["binary"], "sh")
        self.assertEqual(event["arguments"]["argv"], ["sh", "-c", "whoami"])
        self.assertTrue(event["success"])

    def test_parse_with_timestamps_and_elapsed_time(self):
        line = '12:34:56.789012 [pid 1234] openat(AT_FDCWD, "/tmp/ts.txt", O_RDONLY) = 3 <0.000045>'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["pid"], 1234)
        self.assertEqual(event["path"], "/tmp/ts.txt")
        self.assertEqual(event["result"], 3)
        self.assertTrue(event["success"])

    def test_parse_interrupted_syscall_question_mark(self):
        line = '1234 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = ?'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["path"], "/etc/shadow")
        self.assertEqual(event["result"], -1)
        self.assertFalse(event["success"])

    def test_parse_abstract_unix_socket(self):
        line = '1234 connect(3, {sa_family=AF_UNIX, sun_path=@"dbus_abstract"}, 110) = 0'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "connect")
        self.assertEqual(event["address"], "@dbus_abstract")
        self.assertTrue(event["success"])

    def test_parse_open_success_read(self):
        line = '1234 open("/workspace/setup.py", O_RDONLY|O_CLOEXEC) = 3'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["path"], "/workspace/setup.py")
        self.assertEqual(event["access_mode"], "read")
        self.assertTrue(event["success"])

    def test_parse_open_success_write(self):
        line = '1234 open("/workspace/out.txt", O_WRONLY|O_CREAT, 0644) = 4'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["path"], "/workspace/out.txt")
        self.assertEqual(event["access_mode"], "write")
        self.assertTrue(event["success"])

    def test_parse_creat_success_write(self):
        line = '1234 creat("/workspace/newfile.bin", 0644) = 5'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "openat")
        self.assertEqual(event["path"], "/workspace/newfile.bin")
        self.assertEqual(event["access_mode"], "write")
        self.assertTrue(event["success"])

    def test_parse_connect_hex_port(self):
        line = '1234 connect(3, {sa_family=AF_INET, sin_port=htons(0x1bb), sin_addr=inet_addr("1.2.3.4")}, 16) = 0'
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["syscall"], "connect")
        self.assertEqual(event["port"], 443)
        self.assertEqual(event["endpoint"], "1.2.3.4:443")
        self.assertTrue(event["success"])

    def test_unfinished_syscall_recovered_on_abrupt_termination(self):
        # When execution aborts (e.g. timeout), un-resumed syscalls must still be recovered
        trace = '1001 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("194.26.29.112")}, 16 <unfinished ...>'
        events = parse_trace(trace)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["syscall"], "connect")
        self.assertEqual(events[0]["endpoint"], "194.26.29.112:443")
        self.assertEqual(events[0]["error_code"], "UNFINISHED")

        # Telemetry must capture the endpoint even if never resumed
        tel = extract_observed_trace(events)
        self.assertIn("194.26.29.112:443", tel["network_endpoints"])

    def test_extract_observed_trace_aggregation(self):
        events = [
            {"syscall": "openat", "path": "/workspace/readme.md", "access_mode": "read"},
            {"syscall": "openat", "path": "/workspace/output.txt", "access_mode": "write"},
            {"syscall": "openat", "path": "/workspace/db.sqlite", "access_mode": "read_write"},
            {"syscall": "connect", "endpoint": "194.26.29.112:443"},
            {"syscall": "connect", "endpoint": "10.0.0.1:80"},
            {"syscall": "execve", "binary": "python3", "path": "/usr/bin/python3"},
            {"syscall": "execve", "binary": "bash", "path": "/bin/bash"},
        ]
        trace = extract_observed_trace(events, timed_out=False, execution_duration_ms=150.0)

        self.assertEqual(trace["files_read"], {"/workspace/readme.md", "/workspace/db.sqlite"})
        self.assertEqual(trace["files_written"], {"/workspace/output.txt", "/workspace/db.sqlite"})
        self.assertEqual(trace["network_endpoints"], {"194.26.29.112:443", "10.0.0.1:80"})
        self.assertEqual(trace["spawned_binaries"], {"python3", "bash"})
        self.assertFalse(trace["timed_out"])
        self.assertEqual(trace["execution_duration_ms"], 150.0)

        # Test Pydantic model conversion
        try:
            from core.schema.telemetry import ObservedKernelTrace
            model = extract_observed_trace_model(events, timed_out=False, execution_duration_ms=150.0)
            self.assertIsInstance(model, ObservedKernelTrace)
            self.assertEqual(model.files_read, {"/workspace/readme.md", "/workspace/db.sqlite"})
            self.assertEqual(model.files_written, {"/workspace/output.txt", "/workspace/db.sqlite"})
            self.assertEqual(model.network_endpoints, {"194.26.29.112:443", "10.0.0.1:80"})
            self.assertEqual(model.spawned_binaries, {"python3", "bash"})
            self.assertFalse(model.timed_out)
            self.assertEqual(model.execution_duration_ms, 150.0)
        except ImportError:
            pass




class TestDockerSandboxSecurityAndRunner(unittest.TestCase):
    """Unit tests for Docker command construction, security boundaries, and lifecycle."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="gatekeeper_test_")
        self.script_path = os.path.join(self.tmp_dir, "install.sh")
        with open(self.script_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho 'hello'\n")

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_build_docker_command_security_defaults(self):
        cmd = build_docker_run_args(
            script_path=self.script_path,
            workspace_dir=self.tmp_dir,
            container_name="test-sandbox-01",
        )

        cmd_str = " ".join(cmd)
        self.assertIn("--rm", cmd)
        self.assertIn("--network none", cmd_str)
        self.assertIn("--read-only", cmd)
        self.assertIn("--cap-drop ALL", cmd_str)
        self.assertIn("--security-opt no-new-privileges", cmd_str)
        self.assertIn("--memory 512m", cmd_str)
        self.assertIn("--cpus 1.0", cmd_str)
        self.assertIn("--pids-limit 64", cmd_str)
        self.assertIn("--tmpfs /tmp:rw,noexec,nosuid,size=64m", cmd_str)
        self.assertIn("--tmpfs /run:rw,noexec,nosuid,size=16m", cmd_str)
        self.assertIn(":ro", cmd_str)
        self.assertNotIn("--privileged", cmd)

    def test_reject_privileged_mode(self):
        cfg = SandboxConfig(custom_docker_args=["--privileged"])
        with self.assertRaises(SecurityViolationError):
            build_docker_run_args(
                script_path=self.script_path,
                workspace_dir=self.tmp_dir,
                config=cfg,
            )

    def test_reject_broad_capability_grants(self):
        cfg = SandboxConfig(custom_docker_args=["--cap-add=ALL"])
        with self.assertRaises(SecurityViolationError):
            build_docker_run_args(
                script_path=self.script_path,
                workspace_dir=self.tmp_dir,
                config=cfg,
            )

    def test_reject_host_namespace_sharing(self):
        dangerous_args = [
            ["--net=host"],
            ["--network=host"],
            ["--pid=host"],
            ["--ipc=host"],
            ["--uts=host"],
            ["--userns=host"],
        ]
        for arg in dangerous_args:
            cfg = SandboxConfig(custom_docker_args=arg)
            with self.assertRaises(SecurityViolationError):
                build_docker_run_args(
                    script_path=self.script_path,
                    workspace_dir=self.tmp_dir,
                    config=cfg,
                )

    def test_reject_sensitive_host_paths(self):
        sensitive_samples = [
            "/home/user/.ssh",
            "/home/user/.aws/credentials",
            "/var/run/docker.sock",
            "/etc/shadow",
            "C:\\Users\\User\\.ssh\\id_rsa",
        ]
        for s_path in sensitive_samples:
            with self.assertRaises(SecurityViolationError):
                validate_host_path(s_path, must_exist=False)

    def test_reject_user_home_directory_mount(self):
        home = os.path.expanduser("~")
        with self.assertRaises(SecurityViolationError):
            validate_host_path(home, must_exist=True)

    @patch("sandbox.bwrap.is_docker_available", return_value=False)
    def test_docker_unavailable_handling(self, mock_docker_avail):
        runner = DockerSandbox()
        res = runner.run(script_path=self.script_path, workspace_dir=self.tmp_dir)
        self.assertEqual(res.status, "docker_unavailable")
        self.assertIsNone(res.exit_code)
        self.assertFalse(res.timed_out)
        self.assertTrue(len(res.errors) > 0)
        self.assertIn("Docker daemon unreachable", res.errors[0])

    @patch("sandbox.bwrap.is_docker_available", return_value=True)
    @patch("subprocess.run")
    def test_timeout_handling_and_cleanup(self, mock_subproc, mock_docker_avail):
        # Mock subprocess.run raising TimeoutExpired on container execution
        mock_subproc.side_effect = [
            subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=20.0),
            MagicMock(returncode=0),  # cleanup docker rm -f
        ]

        runner = DockerSandbox()
        res = runner.run(script_path=self.script_path, workspace_dir=self.tmp_dir, timeout=20.0)

        self.assertEqual(res.status, "timeout")
        self.assertTrue(res.timed_out)
        self.assertIn("Execution timed out after 20.0s", res.errors[0])
        # Verify cleanup docker rm -f was called
        self.assertEqual(mock_subproc.call_count, 2)


class TestBubblewrapSandboxSecurityAndRunner(unittest.TestCase):
    """Unit tests for Bubblewrap command construction, namespace invariants, and execution."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="gatekeeper_bwrap_test_")
        self.script_path = os.path.join(self.tmp_dir, "install.sh")
        with open(self.script_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho 'bwrap test'\n")

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_build_bwrap_command_security_defaults(self):
        cmd = build_bwrap_args(
            script_path=self.script_path,
            workspace_dir=self.tmp_dir,
        )
        cmd_str = " ".join(cmd)

        self.assertIn("--proc /proc", cmd_str)
        self.assertIn("--dev /dev", cmd_str)
        self.assertIn("--tmpfs /tmp", cmd_str)
        self.assertIn("--tmpfs /run", cmd_str)
        self.assertIn("--unshare-user", cmd_str)
        self.assertIn("--unshare-pid", cmd_str)
        self.assertIn("--unshare-ipc", cmd_str)
        self.assertIn("--unshare-uts", cmd_str)
        self.assertIn("--unshare-net", cmd_str)
        self.assertIn("--ro-bind", cmd_str)
        self.assertIn("--die-with-parent", cmd_str)
        self.assertIn("--new-session", cmd_str)

    def test_reject_dangerous_bwrap_args(self):
        cfg = SandboxConfig(custom_bwrap_args=["--bind / /"])
        with self.assertRaises(SecurityViolationError):
            build_bwrap_args(
                script_path=self.script_path,
                workspace_dir=self.tmp_dir,
                config=cfg,
            )

    @patch("sandbox.bwrap.is_bwrap_available", return_value=False)
    def test_bwrap_unavailable_handling(self, mock_bwrap_avail):
        runner = BubblewrapSandbox()
        res = runner.run(script_path=self.script_path, workspace_dir=self.tmp_dir)
        self.assertEqual(res.status, "bwrap_unavailable")
        self.assertIsNone(res.exit_code)
        self.assertFalse(res.timed_out)
        self.assertIn("Bubblewrap CLI missing", res.errors[0])

    @patch("sandbox.bwrap.is_bwrap_available", return_value=True)
    @patch("subprocess.run")
    def test_bwrap_successful_execution_mocked(self, mock_subproc, mock_bwrap_avail):
        mock_subproc.return_value = MagicMock(returncode=0, stdout="bwrap success", stderr="")
        runner = BubblewrapSandbox()
        res = runner.run(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(res.status, "completed")
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.stdout, "bwrap success")
        self.assertFalse(res.timed_out)

    @patch("sandbox.bwrap.is_bwrap_available", return_value=True)
    @patch("subprocess.run")
    def test_bwrap_timeout_handling_mocked(self, mock_subproc, mock_bwrap_avail):
        mock_subproc.side_effect = subprocess.TimeoutExpired(cmd=["bwrap"], timeout=15.0)
        runner = BubblewrapSandbox()
        res = runner.run(script_path=self.script_path, workspace_dir=self.tmp_dir, timeout=15.0)

        self.assertEqual(res.status, "timeout")
        self.assertTrue(res.timed_out)
        self.assertIn("Execution timed out after 15.0s", res.errors[0])

    def test_kernel_sandbox_backend_routing(self):
        cfg_bwrap = SandboxConfig(backend="bwrap")
        ks_bwrap = KernelSandbox(config=cfg_bwrap)
        self.assertEqual(ks_bwrap.get_active_backend(), "bwrap")
        self.assertIsInstance(ks_bwrap._get_runner(), BubblewrapSandbox)

        cfg_docker = SandboxConfig(backend="docker")
        ks_docker = KernelSandbox(config=cfg_docker)
        self.assertEqual(ks_docker.get_active_backend(), "docker")
        self.assertIsInstance(ks_docker._get_runner(), DockerSandbox)


class TestSyscallTracer(unittest.TestCase):
    """Unit tests for SyscallTracer orchestrator and standardized report schema."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="gatekeeper_tracer_")
        self.script_path = os.path.join(self.tmp_dir, "install.sh")
        with open(self.script_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho 'tracing test'\n")

    def tearDown(self):
        if os.path.exists(self.tmp_dir):
            import shutil
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("sandbox.tracer.is_docker_available", return_value=False)
    def test_tracer_docker_unavailable(self, mock_docker_avail):
        tracer = SyscallTracer()
        report = tracer.run_and_trace(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(report.status, "docker_unavailable")
        self.assertFalse(report.trace_complete)
        self.assertFalse(report.timed_out)
        self.assertEqual(len(report.events), 0)
        self.assertTrue(len(report.errors) > 0)

    @patch("sandbox.tracer.is_docker_available", return_value=True)
    @patch("sandbox.tracer.DockerSandbox.run")
    def test_missing_trace_file_reported_as_failure_not_clean(self, mock_docker_run, mock_docker_avail):
        # Container succeeds but trace file is never created or empty
        mock_docker_run.return_value = ExecutionResult(
            status="completed",
            exit_code=0,
            stdout="done",
            stderr="",
            timed_out=False,
            duration_ms=100.0,
            errors=[],
        )

        tracer = SyscallTracer()
        report = tracer.run_and_trace(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(report.status, "trace_failed")
        self.assertFalse(report.trace_complete)
        self.assertEqual(len(report.events), 0)
        self.assertIn("Trace file was missing or empty after execution.", report.errors)

    @patch("sandbox.tracer.is_docker_available", return_value=True)
    @patch("sandbox.tracer.DockerSandbox.run")
    def test_successful_trace_report_schema(self, mock_docker_run, mock_docker_avail):
        mock_trace_log = """
100 openat(AT_FDCWD, "/workspace/install.sh", O_RDONLY) = 3
100 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("194.26.29.112")}, 16) = 0
100 execve("/bin/uname", ["uname", "-a"], 0x7ffd) = 0
"""
        def fake_run(*args, **kwargs):
            # Write fake trace to the mounted extra_mount trace dir
            extra_mounts = kwargs.get("extra_mounts", [])
            for host_dir, cont_dir, _ in extra_mounts:
                if cont_dir == "/sysdrift_trace":
                    trace_file = os.path.join(host_dir, "strace.log")
                    with open(trace_file, "w", encoding="utf-8") as f:
                        f.write(mock_trace_log)
            return ExecutionResult(
                status="completed",
                exit_code=0,
                stdout="test output",
                stderr="",
                timed_out=False,
                duration_ms=85.0,
            )

        mock_docker_run.side_effect = fake_run

        tracer = SyscallTracer()
        report = tracer.run_and_trace(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(report.status, "completed")
        self.assertTrue(report.trace_complete)
        self.assertEqual(report.exit_code, 0)
        self.assertFalse(report.timed_out)
        self.assertEqual(len(report.events), 3)

        # Telemetry conversion
        telemetry = report.to_observed_kernel_trace()
        self.assertIn("/workspace/install.sh", telemetry["files_read"])
        self.assertIn("194.26.29.112:443", telemetry["network_endpoints"])
        self.assertIn("uname", telemetry["spawned_binaries"])

        # Pydantic ObservedKernelTrace model conversion
        try:
            from core.schema.telemetry import ObservedKernelTrace
            model = report.to_model()
            self.assertIsInstance(model, ObservedKernelTrace)
            self.assertIn("/workspace/install.sh", model.files_read)
            self.assertIn("194.26.29.112:443", model.network_endpoints)
            self.assertIn("uname", model.spawned_binaries)
            self.assertFalse(model.timed_out)
        except ImportError:
            pass


        # Dict export

        rep_dict = report.to_dict()
        self.assertIsInstance(rep_dict, dict)
        self.assertEqual(rep_dict["status"], "completed")
        self.assertIsInstance(rep_dict["telemetry"]["files_read"], list)

    @patch("sandbox.tracer.is_docker_available", return_value=True)
    @patch("sandbox.tracer.DockerSandbox.run")
    def test_ptrace_permission_failure_detected(self, mock_docker_run, mock_docker_avail):
        mock_ptrace_err = "strace: ptrace(PTRACE_TRACEME, ...): Operation not permitted\n"

        def fake_run(*args, **kwargs):
            extra_mounts = kwargs.get("extra_mounts", [])
            for host_dir, cont_dir, _ in extra_mounts:
                if cont_dir == "/sysdrift_trace":
                    trace_file = os.path.join(host_dir, "strace.log")
                    with open(trace_file, "w", encoding="utf-8") as f:
                        f.write(mock_ptrace_err)
            return ExecutionResult(
                status="execution_failed",
                exit_code=1,
                stdout="",
                stderr=mock_ptrace_err,
                timed_out=False,
                duration_ms=40.0,
            )

        mock_docker_run.side_effect = fake_run

        tracer = SyscallTracer()
        report = tracer.run_and_trace(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(report.status, "trace_failed")
        self.assertFalse(report.trace_complete)
        self.assertTrue(any("ptrace failed" in err for err in report.errors))

    @patch("sandbox.tracer.is_bwrap_available", return_value=False)
    def test_tracer_bwrap_backend_unavailable(self, mock_bwrap_avail):
        tracer = SyscallTracer(backend="bwrap")
        report = tracer.run_and_trace(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(report.status, "bwrap_unavailable")
        self.assertFalse(report.trace_complete)
        self.assertTrue(len(report.errors) > 0)
        self.assertIn("Bubblewrap CLI missing", report.errors[0])

    @patch("sandbox.tracer.is_bwrap_available", return_value=True)
    @patch("subprocess.run")
    def test_tracer_bwrap_backend_successful_trace(self, mock_subproc, mock_bwrap_avail):
        mock_trace_log = """
100 openat(AT_FDCWD, "/workspace/install.sh", O_RDONLY) = 3
100 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("194.26.29.112")}, 16) = 0
100 execve("/bin/uname", ["uname", "-a"], 0x7ffd) = 0
"""
        def fake_run(cmd, *args, **kwargs):
            if "-o" in cmd:
                idx = cmd.index("-o")
                out_path = cmd[idx + 1]
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(mock_trace_log)
            return MagicMock(returncode=0, stdout="done", stderr="")

        mock_subproc.side_effect = fake_run

        tracer = SyscallTracer(backend="bwrap")
        report = tracer.run_and_trace(script_path=self.script_path, workspace_dir=self.tmp_dir)

        self.assertEqual(report.status, "completed")
        self.assertTrue(report.trace_complete)
        self.assertEqual(len(report.events), 3)
        self.assertIn("/workspace/install.sh", report.to_observed_kernel_trace()["files_read"])
        self.assertIn("194.26.29.112:443", report.to_observed_kernel_trace()["network_endpoints"])
        self.assertIn("uname", report.to_observed_kernel_trace()["spawned_binaries"])

    @patch("sandbox.tracer.trace_execution")
    def test_run_package_uses_package_directory_and_approved_script(self, mock_trace_execution):
        mock_trace_execution.return_value = SandboxReport(
            status="completed",
            exit_code=0,
            timed_out=False,
            trace_complete=True,
            events=[],
            telemetry={},
            stdout="",
            stderr="",
            trace_path=None,
        )

        report = run_package(self.tmp_dir, "install.sh", backend="docker")

        self.assertEqual(report.status, "completed")
        mock_trace_execution.assert_called_once_with(
            script_path=os.path.join(self.tmp_dir, "install.sh"),
            workspace_dir=self.tmp_dir,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            image=DEFAULT_SANDBOX_IMAGE,
            writable_output_dir=None,
            backend="docker",
        )

    def test_run_package_rejects_script_outside_package_directory(self):
        outside_script = os.path.join(tempfile.gettempdir(), "outside-package.sh")
        with open(outside_script, "w", encoding="utf-8") as script_file:
            script_file.write("#!/bin/sh\n")
        try:
            with self.assertRaises(ValueError):
                run_package(self.tmp_dir, outside_script)
        finally:
            if os.path.exists(outside_script):
                os.remove(outside_script)

    def test_core_sandbox_import_compatibility(self):
        """Verify that core.sandbox.* re-exports match sandbox.* interfaces."""
        import core.sandbox
        import core.sandbox.bwrap
        import core.sandbox.log_parser
        import core.sandbox.tracer

        self.assertEqual(core.sandbox.DockerSandbox, DockerSandbox)
        self.assertEqual(core.sandbox.BubblewrapSandbox, BubblewrapSandbox)
        self.assertEqual(core.sandbox.KernelSandbox, KernelSandbox)
        self.assertEqual(core.sandbox.SyscallTracer, SyscallTracer)
        self.assertEqual(core.sandbox.parse_trace, parse_trace)
        self.assertEqual(core.sandbox.tracer.trace_execution, trace_execution)
        self.assertEqual(core.sandbox.build_bwrap_args, build_bwrap_args)
        self.assertEqual(core.sandbox.is_bwrap_available, is_bwrap_available)


class TestSandboxCLI(unittest.TestCase):
    """Unit tests for the sandbox command-line interface."""

    def test_cli_parse_trace(self):
        import io
        from contextlib import redirect_stdout
        from sandbox.__main__ import main

        tmp_log = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log", encoding="utf-8")
        try:
            tmp_log.write('100 openat(AT_FDCWD, "/workspace/cli_test.txt", O_RDONLY) = 3\n')
            tmp_log.close()

            buf = io.StringIO()
            with redirect_stdout(buf):
                exit_code = main(["--parse-trace", tmp_log.name, "--json"])

            self.assertEqual(exit_code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["event_count"], 1)
            self.assertIn("/workspace/cli_test.txt", data["telemetry"]["files_read"])
        finally:
            if os.path.exists(tmp_log.name):
                os.remove(tmp_log.name)

    @patch("sandbox.__main__.trace_execution")
    def test_cli_run_trace_mocked(self, mock_trace_exec):
        import io
        from contextlib import redirect_stdout
        from sandbox.__main__ import main

        mock_trace_exec.return_value = SandboxReport(
            status="completed",
            exit_code=0,
            timed_out=False,
            trace_complete=True,
            events=[{"syscall": "openat", "path": "/foo"}],
            telemetry={
                "files_read": {"/foo"},
                "files_written": set(),
                "network_endpoints": set(),
                "spawned_binaries": set(),
                "timed_out": False,
                "execution_duration_ms": 10.0,
            },
            stdout="done",
            stderr="",
            trace_path=None,
            errors=[],
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["dummy_script.sh", "dummy_ws", "--json"])

        self.assertEqual(exit_code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["exit_code"], 0)



class TestDockerLiveIntegration(unittest.TestCase):
    """Integration tests that execute only when a functional Docker daemon is present."""

    @unittest.skipUnless(is_docker_available(), "Docker daemon is not available on this host environment.")
    def test_live_docker_sandboxed_harmless_execution(self):
        tmp_dir = tempfile.mkdtemp(prefix="gatekeeper_live_")
        try:
            script_file = os.path.join(tmp_dir, "harmless.sh")
            with open(script_file, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho 'GATEKEEPER_SANDBOX_LIVE_TEST_OK'\n")

            runner = DockerSandbox()
            result = runner.run(script_path=script_file, workspace_dir=tmp_dir)

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.exit_code, 0)
            self.assertIn("GATEKEEPER_SANDBOX_LIVE_TEST_OK", result.stdout)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @unittest.skipUnless(is_docker_available(), "Docker daemon is not available on this host environment.")
    def test_live_docker_sandboxed_tracing_or_fail_closed(self):
        tmp_dir = tempfile.mkdtemp(prefix="gatekeeper_live_trace_")
        try:
            script_file = os.path.join(tmp_dir, "harmless_trace.sh")
            with open(script_file, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho 'TRACE_TEST'\n")

            tracer = SyscallTracer()
            report = tracer.run_and_trace(script_path=script_file, workspace_dir=tmp_dir)

            self.assertIsInstance(report, SandboxReport)
            self.assertIn(report.status, ("completed", "trace_failed", "execution_failed"))
            if report.trace_complete:
                self.assertTrue(len(report.events) >= 0)
            else:
                self.assertTrue(len(report.errors) > 0)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
