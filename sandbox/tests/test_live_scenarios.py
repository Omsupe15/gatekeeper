"""Live integration tests for Gatekeeper Kernel Sandbox layer.

Executes real scripts inside the Docker container sandbox (gatekeeper-sandbox:latest)
to verify live syscall interception, air-gapped network isolation, filesystem
confinement, timeout enforcement, and arbitrator telemetry schema output.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from sandbox.bwrap import (
    DockerSandbox,
    SandboxConfig,
    SecurityViolationError,
    build_docker_run_args,
    is_docker_available,
)
from sandbox.tracer import SyscallTracer, run_package, trace_execution


@unittest.skipUnless(is_docker_available(), "Docker daemon is not available on this host environment.")
class TestKernelSandboxLiveScenarios(unittest.TestCase):
    """End-to-end live testing of the kernel sandbox isolation and syscall tracing."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="gatekeeper_live_sandbox_")
        self.output_dir = os.path.join(self.tmp_dir, "output")
        os.makedirs(self.output_dir, exist_ok=True)
        self.image = "gatekeeper-sandbox:latest"

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_live_benign_lifecycle_script(self):
        """Verify benign build script: workspace read, output write, binary spawning."""
        readme_file = os.path.join(self.tmp_dir, "README.txt")
        with open(readme_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("Gatekeeper Benign Test Workspace\n")

        # Create benign script with Linux LF line endings
        script_file = os.path.join(self.tmp_dir, "build.sh")
        with open(script_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("#!/bin/sh\n"
                    "cat README.txt\n"
                    "echo 'Build complete' > /workspace/output/build.log\n"
                    "uname -a\n"
                    "date\n")

        tracer = SyscallTracer(image=self.image, timeout_seconds=15.0)
        report = tracer.run_and_trace(
            script_path=script_file,
            workspace_dir=self.tmp_dir,
            writable_output_dir=self.output_dir,
        )

        self.assertEqual(report.status, "completed")
        self.assertEqual(report.exit_code, 0)
        self.assertTrue(report.trace_complete)
        self.assertFalse(report.timed_out)

        telemetry = report.to_observed_kernel_trace()
        # Should record read of README.txt
        read_files = {os.path.basename(p) for p in telemetry["files_read"]}
        self.assertIn("README.txt", read_files)

        # Should record write to build.log
        written_files = {os.path.basename(p) for p in telemetry["files_written"]}
        self.assertIn("build.log", written_files)

        # Output file should actually exist on host
        host_output = os.path.join(self.output_dir, "build.log")
        self.assertTrue(os.path.exists(host_output))
        with open(host_output, "r", encoding="utf-8") as f:
            self.assertIn("Build complete", f.read())

        # No network connections attempted
        self.assertEqual(len(telemetry["network_endpoints"]), 0)

        # Spawns sh, uname, date
        self.assertTrue(len(telemetry["spawned_binaries"]) >= 1)
        self.assertIn("uname", telemetry["spawned_binaries"])

    def test_live_malicious_credential_and_network_exfiltration(self):
        """Verify attack payload: credential inspection + network socket connect."""
        script_file = os.path.join(self.tmp_dir, "malicious.sh")
        with open(script_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("#!/bin/sh\n"
                    "cat /etc/passwd > /dev/null 2>&1 || true\n"
                    "python3 -c \"import socket; s = socket.socket(); s.settimeout(2.0); s.connect(('194.26.29.112', 443))\" > /dev/null 2>&1 || true\n"
                    "uname -s\n")

        tracer = SyscallTracer(image=self.image, timeout_seconds=15.0)
        report = tracer.run_and_trace(
            script_path=script_file,
            workspace_dir=self.tmp_dir,
            writable_output_dir=self.output_dir,
        )

        self.assertEqual(report.status, "completed")
        self.assertTrue(report.trace_complete)

        telemetry = report.to_observed_kernel_trace()

        # Connect syscall to C2 IP must be intercepted by strace
        self.assertIn("194.26.29.112:443", telemetry["network_endpoints"])

        # Sensitive path read should be recorded
        self.assertTrue(any("/etc/passwd" in p for p in telemetry["files_read"]))

        # Spawning of python3 and uname recorded
        self.assertTrue("python3" in telemetry["spawned_binaries"] or "python" in telemetry["spawned_binaries"])
        self.assertIn("uname", telemetry["spawned_binaries"])

    def test_live_fake_popup_dynamic_code_simulation(self):
        """Verify a harmless popup simulation with dynamic code and blocked network access."""
        fixture_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "fake-popup", "fake_popup.sh")
        )
        script_file = os.path.join(self.tmp_dir, "fake_popup.sh")
        shutil.copyfile(fixture_path, script_file)

        tracer = SyscallTracer(image=self.image, timeout_seconds=10.0)
        report = tracer.run_and_trace(
            script_path=script_file,
            workspace_dir=self.tmp_dir,
            writable_output_dir=self.output_dir,
        )

        self.assertEqual(report.status, "completed")
        self.assertEqual(report.exit_code, 0)
        self.assertTrue(report.trace_complete)
        self.assertIn("[FAKE POPUP] Warning: simulated virus detected.", report.stdout)
        self.assertIn("Network attempt blocked as expected.", report.stdout)

        marker_path = os.path.join(self.output_dir, "fake_popup_marker.txt")
        self.assertTrue(os.path.exists(marker_path))
        with open(marker_path, "r", encoding="utf-8") as marker_file:
            self.assertEqual(marker_file.read(), "simulation complete\n")

        telemetry = report.to_observed_kernel_trace()
        self.assertIn("203.0.113.1:9", telemetry["network_endpoints"])
        self.assertTrue(any("fake_popup_marker.txt" in path for path in telemetry["files_written"]))
        self.assertIn("python3", telemetry["spawned_binaries"])

    def test_live_package_handoff_runs_approved_script(self):
        """Verify package execution through the README-analysis handoff boundary."""
        package_dir = os.path.join(self.tmp_dir, "package")
        os.makedirs(package_dir)
        os.makedirs(os.path.join(package_dir, "output"))
        fixture_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "fake-popup", "fake_popup.sh")
        )
        shutil.copyfile(fixture_path, os.path.join(package_dir, "lifecycle.sh"))

        report = run_package(
            package_dir=package_dir,
            lifecycle_script="lifecycle.sh",
            timeout=10.0,
            image=self.image,
            writable_output_dir=self.output_dir,
            backend="docker",
        )

        self.assertEqual(report.status, "completed")
        self.assertTrue(report.trace_complete)
        self.assertIn("[FAKE POPUP] Simulation complete.", report.stdout)
        self.assertIn("python3", report.telemetry["spawned_binaries"])

    def test_live_timeout_enforcement_and_container_cleanup(self):
        """Verify that hanging/infinite-loop scripts are forcefully killed on timeout."""
        script_file = os.path.join(self.tmp_dir, "stalling.sh")
        with open(script_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("#!/bin/sh\n"
                    "echo 'Entering stall...'\n"
                    "sleep 30\n"
                    "echo 'Finished'\n")

        # Strict 2-second timeout
        tracer = SyscallTracer(image=self.image, timeout_seconds=2.0)
        report = tracer.run_and_trace(
            script_path=script_file,
            workspace_dir=self.tmp_dir,
            writable_output_dir=self.output_dir,
        )

        self.assertEqual(report.status, "timeout")
        self.assertTrue(report.timed_out)
        self.assertIn("Entering stall...", report.stdout)
        self.assertNotIn("Finished", report.stdout)
        self.assertTrue(any("timed out" in err.lower() for err in report.errors))

    def test_live_network_isolation_strictly_enforced(self):
        """Verify that network traffic is physically dropped by container namespace."""
        script_file = os.path.join(self.tmp_dir, "net_probe.sh")
        with open(script_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("#!/bin/sh\n"
                    "python3 -c \"import socket; s = socket.socket(); s.connect(('1.1.1.1', 80))\"\n")

        runner = DockerSandbox(config=SandboxConfig(image=self.image, network="none"))
        result = runner.run(script_path=script_file, workspace_dir=self.tmp_dir)

        # Script execution should fail with Network unreachable
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(result.status, "execution_failed")
        self.assertIn("Network unreachable", result.stderr)

    def test_security_violation_rejection(self):
        """Verify that dangerous mount points and flags are rejected fail-closed."""
        script_file = os.path.join(self.tmp_dir, "test.sh")
        with open(script_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("#!/bin/sh\necho hi\n")

        # Direct argument builder raises SecurityViolationError
        cfg_privileged = SandboxConfig(image=self.image, custom_docker_args=["--privileged"])
        with self.assertRaises(SecurityViolationError):
            build_docker_run_args(
                script_path=script_file,
                workspace_dir=self.tmp_dir,
                config=cfg_privileged,
            )

        cfg_hostnet = SandboxConfig(image=self.image, custom_docker_args=["--net=host"])
        with self.assertRaises(SecurityViolationError):
            build_docker_run_args(
                script_path=script_file,
                workspace_dir=self.tmp_dir,
                config=cfg_hostnet,
            )

        # Runner gracefully halts and flags security violation in errors
        runner_privileged = DockerSandbox(config=cfg_privileged)
        res = runner_privileged.run(script_path=script_file, workspace_dir=self.tmp_dir)
        self.assertEqual(res.status, "execution_failed")
        self.assertTrue(any("Security validation failed" in err for err in res.errors))


if __name__ == "__main__":
    unittest.main()
