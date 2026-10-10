"""Comprehensive unit and integration test suite for core.sandbox (Block 4).

Validates that core.sandbox re-exports and interfaces conform strictly to
TRD Block 4 requirements, schema contracts, and isolation boundaries.
"""

import os
import unittest
from unittest.mock import patch
from core.sandbox import (
    DockerSandbox,
    BubblewrapSandbox,
    KernelSandbox,
    SyscallTracer,
    SandboxReport,
    SandboxConfig,
    ExecutionResult,
    extract_observed_trace,
    extract_observed_trace_model,
    parse_line,
    parse_trace,
    parse_trace_file,
    trace_execution,
    run_trace,
    run_in_sandbox,
    build_docker_run_args,
    build_bwrap_args,
    is_docker_available,
    is_bwrap_available,
    validate_host_path,
)
from sandbox.tests.test_sandbox import (
    TestStraceLogParser,
    TestDockerSandboxSecurityAndRunner,
    TestBubblewrapSandboxSecurityAndRunner,
    TestSyscallTracer,
    TestSandboxCLI,
    TestDockerLiveIntegration,
)


class TestCoreSandboxModuleContracts(unittest.TestCase):
    """Verify that core.sandbox exports all required Block 4 symbols and conforms to schemas."""

    def test_all_block4_exports_present(self):
        expected_symbols = [
            "DockerSandbox",
            "BubblewrapSandbox",
            "KernelSandbox",
            "SyscallTracer",
            "SandboxReport",
            "SandboxConfig",
            "ExecutionResult",
            "extract_observed_trace",
            "extract_observed_trace_model",
            "parse_line",
            "parse_trace",
            "parse_trace_file",
            "trace_execution",
            "run_trace",
            "run_in_sandbox",
            "build_docker_run_args",
            "build_bwrap_args",
            "is_docker_available",
            "is_bwrap_available",
            "validate_host_path",
        ]
        import core.sandbox
        for sym in expected_symbols:
            self.assertTrue(hasattr(core.sandbox, sym), f"Missing symbol {sym} in core.sandbox")

    def test_core_sandbox_tracer_observed_kernel_trace_schema(self):
        """Verify that telemetry from core.sandbox aligns with core.schema.telemetry.ObservedKernelTrace."""
        from core.schema.telemetry import ObservedKernelTrace

        events = [
            {"syscall": "openat", "path": "/etc/passwd", "access_mode": "read"},
            {"syscall": "connect", "endpoint": "194.26.29.112:443"},
            {"syscall": "execve", "binary": "curl", "path": "/usr/bin/curl"},
        ]
        raw_telemetry = extract_observed_trace(events, timed_out=False, execution_duration_ms=42.5)
        model = extract_observed_trace_model(events, timed_out=False, execution_duration_ms=42.5)

        self.assertIsInstance(model, ObservedKernelTrace)
        self.assertEqual(model.files_read, {"/etc/passwd"})
        self.assertEqual(model.network_endpoints, {"194.26.29.112:443"})
        self.assertEqual(model.spawned_binaries, {"curl"})
        self.assertEqual(model.syscalls, {"openat", "connect", "execve"})
        self.assertEqual(model.flagged_syscalls, set())
        self.assertFalse(model.timed_out)
        self.assertEqual(model.execution_duration_ms, 42.5)

    @patch("sandbox.log_parser.load_syscall_cache", return_value={"ptrace"})
    def test_syscall_cache_flags_observed_syscall(self, mock_cache):
        """Verify parsed syscall names are matched against the suspicious cache."""
        telemetry = extract_observed_trace([{"syscall": "ptrace"}])

        self.assertEqual(telemetry["syscalls"], {"ptrace"})
        self.assertEqual(telemetry["flagged_syscalls"], {"ptrace"})

    def test_core_sandbox_bwrap_direct_import(self):
        """Verify direct import from core.sandbox.bwrap."""
        import core.sandbox.bwrap as bwrap_mod
        self.assertTrue(hasattr(bwrap_mod, "DockerSandbox"))
        self.assertTrue(hasattr(bwrap_mod, "BubblewrapSandbox"))
        self.assertTrue(hasattr(bwrap_mod, "KernelSandbox"))

    def test_core_sandbox_tracer_direct_import(self):
        """Verify direct import from core.sandbox.tracer."""
        import core.sandbox.tracer as tracer_mod
        self.assertTrue(hasattr(tracer_mod, "SyscallTracer"))
        self.assertTrue(hasattr(tracer_mod, "SandboxReport"))

    def test_core_sandbox_log_parser_direct_import(self):
        """Verify direct import from core.sandbox.log_parser."""
        import core.sandbox.log_parser as parser_mod
        self.assertTrue(hasattr(parser_mod, "parse_trace"))
        self.assertTrue(hasattr(parser_mod, "extract_observed_trace"))
