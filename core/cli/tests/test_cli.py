"""
Unit and integration tests for Gatekeeper CLI subsystem (core/cli).
Verifies exit codes, CLI flags, JSON/SARIF reporters, and UI rendering.
"""

import json
import pytest
from core.cli.main import run_cli


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
    """Verifies that a benign package returns exit code 0 (ALLOW)."""
    benign_dir = tmp_path / "benign-package"
    benign_dir.mkdir()
    (benign_dir / "package.json").write_text('{"name": "benign-package", "version": "1.0.0"}')

    exit_code = run_cli([str(benign_dir), "--format=terminal"])
    assert exit_code == 0


def test_cli_quarantine_verdict(tmp_path):
    """Verifies that a malicious package fixture returns exit code 1 (QUARANTINE)."""
    malicious_dir = tmp_path / "malicious-telemetry"
    malicious_dir.mkdir()
    (malicious_dir / "package.json").write_text('{"name": "malicious-telemetry", "version": "1.0.0"}')

    exit_code = run_cli([str(malicious_dir), "--format=terminal"])
    assert exit_code == 1


def test_cli_json_export(tmp_path, capsys):
    """Verifies structured JSON export output."""
    target_dir = tmp_path / "malicious-telemetry"
    target_dir.mkdir()

    output_file = tmp_path / "report.json"
    exit_code = run_cli([str(target_dir), "--format=json", f"--output={output_file}"])

    assert exit_code == 1
    assert output_file.exists()

    content = json.loads(output_file.read_text())
    assert content["verdict"] == "QUARANTINE"
    assert content["exit_code"] == 1
    assert content["composite_drift_score"] >= 0.40
    assert "contract" in content
    assert "observed_trace" in content
    assert "violations" in content


def test_cli_sarif_export(tmp_path):
    """Verifies OASIS SARIF v2.1.0 report generation."""
    target_dir = tmp_path / "malicious-telemetry"
    target_dir.mkdir()

    output_file = tmp_path / "report.sarif"
    exit_code = run_cli([str(target_dir), "--format=sarif", f"--output={output_file}"])

    assert exit_code == 1
    assert output_file.exists()

    content = json.loads(output_file.read_text())
    assert content["version"] == "2.1.0"
    assert "$schema" in content
    assert len(content["runs"]) > 0
    run_data = content["runs"][0]
    assert run_data["tool"]["driver"]["name"] == "Gatekeeper"
    assert len(run_data["results"]) > 0
