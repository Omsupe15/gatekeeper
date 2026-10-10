"""Unit tests for Block 5: core/arbitrator.

Tests mathematical vector drift scoring, heuristics whitelisting, loopback DNS filtering,
sensitive credential targeting, process execution penalties, and quarantine thresholds.
"""

import pytest

from core.arbitrator import (
    DEFAULT_QUARANTINE_THRESHOLD,
    DriftArbitrator,
    calculate_drift,
    evaluate_filesystem_drift,
    evaluate_network_drift,
    evaluate_process_drift,
    extract_endpoint_host,
    is_loopback_endpoint,
    is_sensitive_path,
    is_system_binary,
    is_system_read_path,
    normalize_file_path,
)
from core.schema import (
    ExpectedBehaviorContract,
    ObservedKernelTrace,
    SecurityDimension,
    SeverityLevel,
)


# =====================================================================
# 1. Heuristics & Whitelist Filter Tests
# =====================================================================

def test_is_sensitive_path():
    """Verify detection of high-value credential stores and system secrets."""
    assert is_sensitive_path("~/.aws/credentials") is True
    assert is_sensitive_path("/home/user/.ssh/id_rsa") is True
    assert is_sensitive_path("/app/.env") is True
    assert is_sensitive_path("/etc/shadow") is True
    assert is_sensitive_path("/etc/passwd") is True
    assert is_sensitive_path("~/.kube/config") is True
    assert is_sensitive_path("~/.docker/config.json") is True
    assert is_sensitive_path("/home/user/.git-credentials") is True

    # Benign paths
    assert is_sensitive_path("/tmp/pkg/index.js") is False
    assert is_sensitive_path("/usr/lib/libc.so.6") is False
    assert is_sensitive_path("./dist/bundle.js") is False


def test_is_loopback_endpoint():
    """Verify loopback endpoints and local DNS resolvers are accurately detected."""
    assert is_loopback_endpoint("127.0.0.1:8080") is True
    assert is_loopback_endpoint("127.0.0.53:53") is True
    assert is_loopback_endpoint("127.0.0.1") is True
    assert is_loopback_endpoint("localhost:3000") is True
    assert is_loopback_endpoint("[::1]:80") is True
    assert is_loopback_endpoint("::1") is True

    # External targets
    assert is_loopback_endpoint("194.26.29.112:443") is False
    assert is_loopback_endpoint("8.8.8.8:53") is False
    assert is_loopback_endpoint("api.github.com:443") is False


def test_is_system_binary():
    """Verify system runtime loaders and interpreters are recognized."""
    assert is_system_binary("node") is True
    assert is_system_binary("/usr/bin/node") is True
    assert is_system_binary("python3") is True
    assert is_system_binary("/usr/bin/python") is True
    assert is_system_binary("bash") is True
    assert is_system_binary("/bin/sh") is True
    assert is_system_binary("bwrap") is True

    # Dangerous or unwhitelisted binaries
    assert is_system_binary("curl") is False
    assert is_system_binary("wget") is False
    assert is_system_binary("nc") is False
    assert is_system_binary("powershell") is False
    assert is_system_binary("whoami") is False


def test_is_system_read_path():
    """Verify OS runtime library mounts are classified as system read paths."""
    assert is_system_read_path("/usr/lib/x86_64-linux-gnu/libc.so") is True
    assert is_system_read_path("/lib64/ld-linux-x86-64.so.2") is True
    assert is_system_read_path("/etc/ld.so.cache") is True
    assert is_system_read_path("/etc/resolv.conf") is True
    assert is_system_read_path("/proc/cpuinfo") is True

    # Non-system paths
    assert is_system_read_path("/tmp/malicious.sh") is False
    assert is_system_read_path("/home/user/.aws/credentials") is False


# =====================================================================
# 2. Network Drift Dimension Tests (D_net)
# =====================================================================

def test_network_drift_clean():
    """Verify zero network drift when no external endpoints are contacted."""
    contract = ExpectedBehaviorContract(
        package_name="clean-pkg",
        purpose="Offline math utility",
        network_required=False,
    )
    trace = ObservedKernelTrace(
        network_endpoints=set(),
    )
    d_net, violations = evaluate_network_drift(contract, trace)
    assert d_net == 0.0
    assert len(violations) == 0


def test_loopback_and_dns_resolver_filtering():
    """Verify loopback and systemd-resolved (127.0.0.53:53) connections are filtered out."""
    contract = ExpectedBehaviorContract(
        package_name="clean-pkg",
        purpose="Offline utility",
        network_required=False,
    )
    trace = ObservedKernelTrace(
        network_endpoints={"127.0.0.1:8080", "127.0.0.53:53", "localhost:3000"},
    )
    d_net, violations = evaluate_network_drift(contract, trace)
    assert d_net == 0.0
    assert len(violations) == 0


def test_network_drift_triggers_quarantine_independently():
    """Verify unauthorized external connection triggers D_net=1.0 and critical violation."""
    contract = ExpectedBehaviorContract(
        package_name="math-lib",
        purpose="Math calculations",
        network_required=False,
    )
    trace = ObservedKernelTrace(
        network_endpoints={"194.26.29.112:443"},
    )
    d_net, violations = evaluate_network_drift(contract, trace)
    assert d_net == 1.0
    assert len(violations) == 1
    assert violations[0].dimension == SecurityDimension.NETWORK
    assert violations[0].severity == SeverityLevel.CRITICAL.value
    assert "194.26.29.112:443" in violations[0].offending_artifact


def test_network_drift_allowed_domains():
    """Verify connections to whitelisted domains are permitted when network_required=True."""
    contract = ExpectedBehaviorContract(
        package_name="puppeteer-downloader",
        purpose="Fetches browser binary",
        network_required=True,
        allowed_domains=["storage.googleapis.com", "*.npmjs.org"],
    )
    trace = ObservedKernelTrace(
        network_endpoints={"storage.googleapis.com:443", "registry.npmjs.org:443"},
    )
    d_net, violations = evaluate_network_drift(contract, trace)
    assert d_net == 0.0
    assert len(violations) == 0


def test_network_drift_unwhitelisted_domain():
    """Verify connection to unwhitelisted domain when network_required=True triggers D_net=1.0."""
    contract = ExpectedBehaviorContract(
        package_name="downloader",
        purpose="Fetches assets",
        network_required=True,
        allowed_domains=["storage.googleapis.com"],
    )
    trace = ObservedKernelTrace(
        network_endpoints={"evil-c2-server.com:443"},
    )
    d_net, violations = evaluate_network_drift(contract, trace)
    assert d_net == 1.0
    assert len(violations) == 1
    assert "evil-c2-server.com" in violations[0].description


# =====================================================================
# 3. Filesystem Drift Dimension Tests (D_fs)
# =====================================================================

def test_system_library_read_noise_filtered():
    """Verify reads on standard OS shared libraries generate zero filesystem drift."""
    contract = ExpectedBehaviorContract(
        package_name="clean-pkg",
        purpose="Clean library",
        network_required=False,
        allowed_read_prefixes=["/tmp"],
    )
    trace = ObservedKernelTrace(
        files_read={"/usr/lib/libc.so", "/etc/ld.so.cache", "/lib64/ld-linux.so.2"},
    )
    d_fs, violations, cred_leak = evaluate_filesystem_drift(contract, trace)
    assert d_fs == 0.0
    assert len(violations) == 0
    assert cred_leak is False


def test_credential_theft_triggers_quarantine_floor():
    """Verify touching credential stores without authorization forces D_fs=1.0 and flags credential leak."""
    contract = ExpectedBehaviorContract(
        package_name="stealer-pkg",
        purpose="Math utility",
        network_required=False,
        accesses_user_credentials=False,
    )
    trace = ObservedKernelTrace(
        files_read={"/home/user/.aws/credentials"},
    )
    d_fs, violations, cred_leak = evaluate_filesystem_drift(contract, trace)
    assert d_fs == 1.0
    assert cred_leak is True
    assert len(violations) == 1
    assert violations[0].dimension == SecurityDimension.FILESYSTEM
    assert violations[0].severity == SeverityLevel.CRITICAL.value
    assert ".aws/credentials" in violations[0].offending_artifact


def test_authorized_credential_access():
    """Verify that if accesses_user_credentials=True, credential accesses do not raise credential violation."""
    contract = ExpectedBehaviorContract(
        package_name="aws-cli-helper",
        purpose="Legitimately configures local AWS CLI profile",
        network_required=False,
        accesses_user_credentials=True,
        allowed_read_prefixes=["/home/user/.aws"],
    )
    trace = ObservedKernelTrace(
        files_read={"/home/user/.aws/credentials"},
    )
    d_fs, violations, cred_leak = evaluate_filesystem_drift(contract, trace)
    assert cred_leak is False
    assert d_fs == 0.0


def test_unauthorized_directory_write():
    """Verify unwhitelisted write operations trigger filesystem violations."""
    contract = ExpectedBehaviorContract(
        package_name="pkg",
        purpose="Local build",
        network_required=False,
        allowed_write_prefixes=["/tmp/build"],
    )
    trace = ObservedKernelTrace(
        files_written={"/etc/cron.d/malicious_cron"},
    )
    d_fs, violations, cred_leak = evaluate_filesystem_drift(contract, trace)
    assert d_fs > 0.0
    assert len(violations) == 1
    assert violations[0].severity == SeverityLevel.CRITICAL.value


# =====================================================================
# 4. Process Execution Drift Tests (D_proc)
# =====================================================================

def test_process_drift_clean_system_binaries():
    """Verify standard system interpreters (node, bash, python3) generate zero process drift."""
    contract = ExpectedBehaviorContract(
        package_name="clean-pkg",
        purpose="Build utility",
        network_required=False,
        allowed_binaries=[],
    )
    trace = ObservedKernelTrace(
        spawned_binaries={"node", "/bin/bash", "/usr/bin/python3", "sh"},
    )
    d_proc, violations = evaluate_process_drift(contract, trace)
    assert d_proc == 0.0
    assert len(violations) == 0


def test_process_drift_declared_binaries():
    """Verify binaries explicitly declared in contract.allowed_binaries produce zero drift."""
    contract = ExpectedBehaviorContract(
        package_name="native-pkg",
        purpose="Compiles native C addon",
        network_required=False,
        allowed_binaries=["gcc", "make", "touch"],
    )
    trace = ObservedKernelTrace(
        spawned_binaries={"node", "make", "/usr/bin/gcc", "touch"},
    )
    d_proc, violations = evaluate_process_drift(contract, trace)
    assert d_proc == 0.0
    assert len(violations) == 0


def test_process_drift_unauthorized_binaries_scaling():
    """Verify process drift formula: D_proc = min(1.0, |unauthorized| / 2)."""
    contract = ExpectedBehaviorContract(
        package_name="pkg",
        purpose="Simple utility",
        network_required=False,
        allowed_binaries=[],
    )
    # 1 unauthorized binary -> 1 / 2 = 0.5
    trace_one = ObservedKernelTrace(spawned_binaries={"whoami"})
    d_proc_1, violations_1 = evaluate_process_drift(contract, trace_one)
    assert d_proc_1 == 0.5
    assert len(violations_1) == 1

    # 2 unauthorized binaries -> 2 / 2 = 1.0
    trace_two = ObservedKernelTrace(spawned_binaries={"nc", "curl"})
    d_proc_2, violations_2 = evaluate_process_drift(contract, trace_two)
    assert d_proc_2 == 1.0
    assert len(violations_2) == 2
    assert all(v.severity == SeverityLevel.CRITICAL.value for v in violations_2)


# =====================================================================
# 5. Composite DriftArbitrator & Scenario Tests
# =====================================================================

def test_arbitrator_nominal_execution():
    """Verify nominal benign execution produces composite score 0.00 and ALLOW verdict."""
    contract = ExpectedBehaviorContract(
        package_name="benign-canvas",
        purpose="Compiles canvas helper",
        network_required=False,
        allowed_read_prefixes=["/tmp"],
        allowed_binaries=["touch"],
    )
    trace = ObservedKernelTrace(
        files_read={"/tmp/input.txt", "/usr/lib/libc.so"},
        spawned_binaries={"node", "touch"},
        network_endpoints={"127.0.0.1:8080"},
    )
    arbitrator = DriftArbitrator()
    result = arbitrator.arbitrate(contract, trace)

    assert result.composite_drift_score == 0.00
    assert result.network_drift == 0.0
    assert result.filesystem_drift == 0.0
    assert result.process_drift == 0.0
    assert result.is_quarantined is False
    assert len(result.violations) == 0


def test_arbitrator_network_quarantine_alone():
    """Verify unauthorized network access alone triggers quarantine (0.45 >= 0.40)."""
    contract = ExpectedBehaviorContract(
        package_name="offline-pkg",
        purpose="Offline math",
        network_required=False,
    )
    trace = ObservedKernelTrace(
        network_endpoints={"194.26.29.112:443"},
    )
    arbitrator = DriftArbitrator()
    result = arbitrator.arbitrate(contract, trace)

    assert result.network_drift == 1.0
    assert result.composite_drift_score == 0.45
    assert result.is_quarantined is True


def test_arbitrator_credential_theft_alone():
    """Verify credential access alone enforces the quarantine floor (composite >= 0.40)."""
    contract = ExpectedBehaviorContract(
        package_name="stealer-pkg",
        purpose="Harvester",
        network_required=False,
        accesses_user_credentials=False,
    )
    trace = ObservedKernelTrace(
        files_read={"~/.aws/credentials"},
    )
    arbitrator = DriftArbitrator()
    result = arbitrator.arbitrate(contract, trace)

    assert result.filesystem_drift == 1.0
    assert result.composite_drift_score >= 0.40
    assert result.is_quarantined is True


def test_arbitrator_malicious_telemetry_combined_attack():
    """Verify combined attack (AWS credentials + remote IP exfiltration) yields D >= 0.80."""
    contract = ExpectedBehaviorContract(
        package_name="malicious-telemetry",
        purpose="Offline canvas helper",
        network_required=False,
        accesses_user_credentials=False,
    )
    trace = ObservedKernelTrace(
        files_read={"~/.aws/credentials"},
        network_endpoints={"194.26.29.112:443"},
        spawned_binaries={"python3", "curl"},
    )
    arbitrator = DriftArbitrator()
    result = arbitrator.arbitrate(contract, trace)

    # D = 0.45(1.0) + 0.35(1.0) + 0.20(0.5) = 0.45 + 0.35 + 0.10 = 0.90 >= 0.80
    assert result.composite_drift_score >= 0.80
    assert result.is_quarantined is True
    assert len(result.violations) >= 2


def test_arbitrator_sandbox_timeout_penalty():
    """Verify execution timeout marks timing bomb violation and triggers quarantine."""
    contract = ExpectedBehaviorContract(
        package_name="sleep-evasion",
        purpose="Hanging script",
        network_required=False,
    )
    trace = ObservedKernelTrace(
        timed_out=True,
        execution_duration_ms=20005.0,
    )
    arbitrator = DriftArbitrator()
    result = arbitrator.arbitrate(contract, trace)

    assert result.is_quarantined is True
    assert any("timeout" in v.description.lower() for v in result.violations)


def test_calculate_drift_functional_wrapper():
    """Verify calculate_drift() functional wrapper matches DriftArbitrator."""
    contract = ExpectedBehaviorContract(
        package_name="test-pkg",
        purpose="Test",
        network_required=False,
    )
    trace = ObservedKernelTrace()
    result = calculate_drift(contract, trace)
    assert result.composite_drift_score == 0.00
    assert result.is_quarantined is False
