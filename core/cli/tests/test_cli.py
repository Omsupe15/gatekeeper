"""Unit and integration tests for Gatekeeper CLI subsystem (core/cli).

Verifies exit codes, CLI flags, JSON/SARIF reporters, UI rendering,
no-hook fast-paths, strict daemon requirement enforcement, and the decoupled PipelineCoordinator adapter.
"""

import json
from pathlib import Path
import pytest

from core.cli.main import PipelineCoordinator, analyze_target_package, run_cli
from core.sandbox.bwrap import is_bwrap_available, is_docker_available
from core.schema import (
    DriftResult,
    ExpectedBehaviorContract,
    ObservedKernelTrace,
    SecurityDimension,
    ThreatAttributionReport,
    ViolationRecord,
)


@pytest.fixture
def mock_quarantine_coordinator():
    """Fixture providing a mock coordinator simulating a quarantined package analysis."""
    contract = ExpectedBehaviorContract(
        package_name="malicious-telemetry",
        purpose="Offline canvas / utility helper",
        network_required=False,
        allowed_domains=[],
        allowed_read_prefixes=["/tmp"],
        allowed_write_prefixes=["/tmp"],
        allowed_binaries=["node", "bash"],
        accesses_user_credentials=False,
        risk_level_assessment="HIGH",
    )
    trace = ObservedKernelTrace(
        files_read={"~/.aws/credentials", "/etc/passwd"},
        files_written=set(),
        network_endpoints={"194.26.29.112:443"},
        spawned_binaries={"python3", "curl"},
        timed_out=False,
        execution_duration_ms=412.5,
    )
    violations = [
        ViolationRecord(
            dimension=SecurityDimension.NETWORK,
            severity="CRITICAL",
            description="Unauthorized outbound socket connection to 194.26.29.112:443",
            offending_artifact="194.26.29.112:443",
        ),
        ViolationRecord(
            dimension=SecurityDimension.FILESYSTEM,
            severity="CRITICAL",
            description="Unauthorized read on AWS credential store (~/.aws/credentials)",
            offending_artifact="~/.aws/credentials",
        ),
    ]
    drift = DriftResult(
        composite_drift_score=0.80,
        network_drift=1.0,
        filesystem_drift=1.0,
        process_drift=0.5,
        is_quarantined=True,
        violations=violations,
    )
    forensic = ThreatAttributionReport(
        threat_score=0.80,
        attack_category="Credential Harvester & Exfiltration Dropper",
        mitre_attack_tactics=["T1552.001 (Credentials in Files)", "T1071.001 (Web Protocols)"],
        culprit_code_snippet="python3 -c 'import socket,os; open(~/.aws/credentials)...'",
        executive_summary="Package declared offline utility intent but harvested credentials and connected to 194.26.29.112:443.",
        remediation_recommendations=[
            "Block package execution and quarantine build pipeline immediately.",
            "Rotate active AWS credentials on affected host system.",
        ],
    )

    class MockCoordinator:
        def analyze(self, package_dir: str, threshold: float = 0.40):
            return contract, trace, drift, forensic

    return MockCoordinator()


def test_cli_help(capsys):
    """Verifies --help flag exits cleanly with 0."""
    with pytest.raises(SystemExit) as exc_info:
        run_cli(["--help"])
    assert exc_info.value.code == 0


def test_cli_nonexistent_path():
    """Verifies that a non-existent target path returns exit code 2 (ERROR)."""
    exit_code = run_cli(["/nonexistent_package_path_12345"])
    assert exit_code == 2


def test_cli_allow_verdict(tmp_path):
    """Verifies that a benign package with no hooks returns exit code 0 (ALLOW)."""
    benign_dir = tmp_path / "benign-package"
    benign_dir.mkdir()
    (benign_dir / "package.json").write_text('{"name": "benign-package", "version": "1.0.0"}')

    exit_code = run_cli([str(benign_dir), "--format=terminal"])
    assert exit_code == 0


def test_cli_quarantine_verdict(tmp_path, mock_quarantine_coordinator):
    """Verifies that a quarantined package returns exit code 1 (QUARANTINE)."""
    malicious_dir = tmp_path / "malicious-telemetry"
    malicious_dir.mkdir()
    (malicious_dir / "package.json").write_text('{"name": "malicious-telemetry", "version": "1.0.0"}')

    exit_code = run_cli([str(malicious_dir), "--format=terminal"], coordinator=mock_quarantine_coordinator)
    assert exit_code == 1


def test_cli_json_export(tmp_path, capsys, mock_quarantine_coordinator):
    """Verifies structured JSON export output."""
    target_dir = tmp_path / "malicious-telemetry"
    target_dir.mkdir()

    output_file = tmp_path / "report.json"
    exit_code = run_cli(
        [str(target_dir), "--format=json", f"--output={output_file}"],
        coordinator=mock_quarantine_coordinator,
    )

    assert exit_code == 1
    assert output_file.exists()

    content = json.loads(output_file.read_text())
    assert content["verdict"] == "QUARANTINE"
    assert content["exit_code"] == 1
    assert content["composite_drift_score"] >= 0.40
    assert "contract" in content
    assert "observed_trace" in content
    assert "violations" in content


def test_cli_sarif_export(tmp_path, mock_quarantine_coordinator):
    """Verifies OASIS SARIF v2.1.0 report generation."""
    target_dir = tmp_path / "malicious-telemetry"
    target_dir.mkdir()

    output_file = tmp_path / "report.sarif"
    exit_code = run_cli(
        [str(target_dir), "--format=sarif", f"--output={output_file}"],
        coordinator=mock_quarantine_coordinator,
    )

    assert exit_code == 1
    assert output_file.exists()

    content = json.loads(output_file.read_text())
    assert content["version"] == "2.1.0"
    assert "$schema" in content
    assert len(content["runs"]) > 0
    run_data = content["runs"][0]
    assert run_data["tool"]["driver"]["name"] == "Gatekeeper"
    assert len(run_data["results"]) > 0


def test_cli_no_lifecycle_hook_fast_path(tmp_path):
    """Verifies fast-path exit 0 for packages with no install-time lifecycle hooks."""
    pkg_dir = tmp_path / "pure-library"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text(
        json.dumps({
            "name": "pure-library",
            "version": "1.0.0",
            "scripts": {
                "test": "jest",
                "lint": "eslint .",
            },
        })
    )

    exit_code = run_cli([str(pkg_dir), "--format=terminal"])
    assert exit_code == 0


def test_cli_pipeline_coordinator_adapter(tmp_path):
    """Verifies that PipelineCoordinator allows dependency injection without merge conflicts."""
    pkg_dir = tmp_path / "custom-pkg"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text('{"name": "custom-pkg"}')

    coordinator = PipelineCoordinator(
        has_hooks_fn=lambda path: False,
    )
    contract, trace, drift, forensic = coordinator.analyze(str(pkg_dir))
    assert drift.composite_drift_score == 0.00
    assert drift.is_quarantined is False
    assert forensic is None


def test_cli_strict_daemon_error_when_docker_offline(tmp_path):
    """Verifies that when a package contains lifecycle hooks and Docker is offline, Exit 2 (ERROR) is returned."""
    pkg_dir = tmp_path / "active-hook-pkg"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text(
        json.dumps({
            "name": "active-hook-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "touch build.log",
            },
        })
    )

    if not is_docker_available() and not is_bwrap_available():
        exit_code = run_cli([str(pkg_dir), "--format=terminal"])
        assert exit_code == 2


def test_cli_real_fixtures():
    """Verifies execution against repository fixtures in fixtures/."""
    if not is_docker_available() and not is_bwrap_available():
        pytest.skip("Docker or Bubblewrap is not available on this host for live sandbox tracing.")

    benign_path = Path("fixtures/benign-canvas")
    if benign_path.exists():
        exit_code = run_cli([str(benign_path), "--format=terminal"])
        assert exit_code == 0

    malicious_path = Path("fixtures/malicious-telemetry")
    if malicious_path.exists():
        exit_code = run_cli([str(malicious_path), "--format=terminal"])
        assert exit_code == 1
