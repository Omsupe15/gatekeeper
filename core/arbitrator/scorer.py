"""Mathematical Vector Drift Scorer and Differential Arbitrator.

Implements the multi-axis drift formula:
    D = (0.45 * D_net) + (0.35 * D_fs) + (0.20 * D_proc)
and arbitrates ExpectedBehaviorContract against ObservedKernelTrace.
"""

import os
from typing import List, Set, Tuple

from core.arbitrator.heuristics import (
    extract_endpoint_host,
    is_loopback_endpoint,
    is_sensitive_path,
    is_system_binary,
    is_system_read_path,
    normalize_file_path,
)
from core.arbitrator.violations import (
    create_credential_violation,
    create_network_violation,
    create_prefix_violation,
    create_process_violation,
    create_timeout_violation,
)
from core.schema.arbitration import DriftResult, SeverityLevel, ViolationRecord
from core.schema.contract import ExpectedBehaviorContract
from core.schema.telemetry import ObservedKernelTrace

# Standard mathematical weighting formulation
WEIGHT_NETWORK: float = 0.45
WEIGHT_FILESYSTEM: float = 0.35
WEIGHT_PROCESS: float = 0.20
DEFAULT_QUARANTINE_THRESHOLD: float = 0.40

# High-risk binaries that warrant CRITICAL severity when spawned without declaration
HIGH_RISK_BINARIES: Set[str] = {
    "nc",
    "ncat",
    "netcat",
    "socat",
    "curl",
    "wget",
    "powershell",
    "pwsh",
    "whoami",
    "id",
}


def evaluate_network_drift(
    contract: ExpectedBehaviorContract,
    trace: ObservedKernelTrace,
) -> Tuple[float, List[ViolationRecord]]:
    """Evaluate network egress dimension (D_net in {0.0, 1.0})."""
    # 1. Filter loopback connections and local DNS resolvers
    external_endpoints = [
        ep for ep in trace.network_endpoints if not is_loopback_endpoint(ep)
    ]

    if not external_endpoints:
        return 0.0, []

    violations: List[ViolationRecord] = []

    # 2. Case: Contract does not permit network egress at all
    if not contract.network_required:
        for ep in external_endpoints:
            violations.append(
                create_network_violation(
                    endpoint=ep,
                    reason="contract invariant violated: network_required=False (air-gapped package attempted egress)",
                    severity=SeverityLevel.CRITICAL.value,
                )
            )
        return 1.0, violations

    # 3. Case: Network permitted, check allowed_domains whitelist
    if not contract.allowed_domains:
        for ep in external_endpoints:
            violations.append(
                create_network_violation(
                    endpoint=ep,
                    reason="contract invariant violated: allowed_domains whitelist is empty",
                    severity=SeverityLevel.CRITICAL.value,
                )
            )
        return 1.0, violations

    # Verify against allowed_domains
    normalized_allowed = {d.strip().lower() for d in contract.allowed_domains}
    unauthorized_endpoints: List[str] = []

    for ep in external_endpoints:
        host = extract_endpoint_host(ep).lower()
        matched = False
        for allowed in normalized_allowed:
            if host == allowed:
                matched = True
                break
            # Wildcard domain or suffix matching
            if allowed.startswith("*.") and host.endswith(allowed[2:]):
                matched = True
                break
            if host.endswith("." + allowed):
                matched = True
                break

        if not matched:
            unauthorized_endpoints.append(ep)
            violations.append(
                create_network_violation(
                    endpoint=ep,
                    reason=f"destination host '{host}' not present in allowed_domains: {list(normalized_allowed)}",
                    severity=SeverityLevel.CRITICAL.value,
                )
            )

    if unauthorized_endpoints:
        return 1.0, violations

    return 0.0, []


def evaluate_filesystem_drift(
    contract: ExpectedBehaviorContract,
    trace: ObservedKernelTrace,
) -> Tuple[float, List[ViolationRecord], bool]:
    """Evaluate filesystem boundary dimension (D_fs in [0.0, 1.0]).

    Returns:
        (d_fs, violations, has_unauthorized_credentials)
    """
    violations: List[ViolationRecord] = []
    has_unauthorized_credentials = False

    all_touched_files = set(trace.files_read) | set(trace.files_written)

    # 1. Sensitive Targets Audit (Credentials, tokens, shadow passwords)
    for path in all_touched_files:
        if is_sensitive_path(path):
            if not contract.accesses_user_credentials:
                has_unauthorized_credentials = True
                violations.append(
                    create_credential_violation(
                        path=path,
                        severity=SeverityLevel.CRITICAL.value,
                    )
                )

    # 2. Directory Prefix Audit
    # Read prefixes check (exclude standard system runtime libraries and sensitive paths already flagged)
    if contract.allowed_read_prefixes:
        norm_read_prefixes = [
            normalize_file_path(p) for p in contract.allowed_read_prefixes
        ]
        for path in trace.files_read:
            norm_path = normalize_file_path(path)
            if is_system_read_path(norm_path) or is_sensitive_path(norm_path):
                continue
            matched = any(
                norm_path == prefix or norm_path.startswith(prefix + "/")
                for prefix in norm_read_prefixes
            )
            if not matched:
                violations.append(
                    create_prefix_violation(
                        path=path,
                        operation="read",
                        allowed_prefixes=contract.allowed_read_prefixes,
                        severity=SeverityLevel.WARNING.value,
                    )
                )

    # Write prefixes check
    if contract.allowed_write_prefixes:
        norm_write_prefixes = [
            normalize_file_path(p) for p in contract.allowed_write_prefixes
        ]
        for path in trace.files_written:
            norm_path = normalize_file_path(path)
            if is_sensitive_path(norm_path):
                continue
            matched = any(
                norm_path == prefix or norm_path.startswith(prefix + "/")
                for prefix in norm_write_prefixes
            )
            if not matched:
                is_high_risk = any(
                    norm_path.startswith(p)
                    for p in ("/etc", "/usr", "/bin", "/root", "/boot")
                )
                violations.append(
                    create_prefix_violation(
                        path=path,
                        operation="write",
                        allowed_prefixes=contract.allowed_write_prefixes,
                        severity=SeverityLevel.CRITICAL.value
                        if is_high_risk
                        else SeverityLevel.WARNING.value,
                    )
                )

    # 3. Calculate D_fs score
    if has_unauthorized_credentials:
        d_fs = 1.0
    elif violations:
        # Proportional penalty based on unwhitelisted paths
        d_fs = min(1.0, len(violations) * 0.5)
    else:
        d_fs = 0.0

    return d_fs, violations, has_unauthorized_credentials


def evaluate_process_drift(
    contract: ExpectedBehaviorContract,
    trace: ObservedKernelTrace,
) -> Tuple[float, List[ViolationRecord]]:
    """Evaluate process execution dimension: D_proc = min(1.0, |Unauthorized Binaries| / 2)."""
    # Filter standard system loaders and execution runtimes (bash, node, python3, bwrap)
    observed = [
        b for b in trace.spawned_binaries if not is_system_binary(b)
    ]

    # Normalize allowed binaries
    allowed = {os.path.basename(b.strip()) for b in contract.allowed_binaries}

    unauthorized_binaries: List[str] = [
        b for b in observed if os.path.basename(b.strip()) not in allowed
    ]

    if not unauthorized_binaries:
        return 0.0, []

    violations: List[ViolationRecord] = []
    for binary in unauthorized_binaries:
        base = os.path.basename(binary.strip())
        is_critical = base in HIGH_RISK_BINARIES
        violations.append(
            create_process_violation(
                binary=binary,
                reason=f"binary not declared in contract.allowed_binaries: {contract.allowed_binaries}",
                severity=SeverityLevel.CRITICAL.value
                if is_critical
                else SeverityLevel.WARNING.value,
            )
        )

    # Formula: D_proc = min(1.0, |unauthorized| / 2.0)
    d_proc = min(1.0, len(unauthorized_binaries) / 2.0)
    return d_proc, violations


class DriftArbitrator:
    """Differential Arbitration Engine calculating multi-axis behavioral drift vectors."""

    def __init__(
        self,
        threshold: float = DEFAULT_QUARANTINE_THRESHOLD,
        weight_net: float = WEIGHT_NETWORK,
        weight_fs: float = WEIGHT_FILESYSTEM,
        weight_proc: float = WEIGHT_PROCESS,
    ) -> None:
        self.threshold = threshold
        self.weight_net = weight_net
        self.weight_fs = weight_fs
        self.weight_proc = weight_proc

    def arbitrate(
        self,
        contract: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
    ) -> DriftResult:
        """Arbitrate an ExpectedBehaviorContract against an ObservedKernelTrace."""
        d_net, net_violations = evaluate_network_drift(contract, trace)
        d_fs, fs_violations, has_credential_leak = evaluate_filesystem_drift(
            contract, trace
        )
        d_proc, proc_violations = evaluate_process_drift(contract, trace)

        all_violations = net_violations + fs_violations + proc_violations

        # Handle timing bomb / sandbox timeout penalty
        if trace.timed_out:
            all_violations.append(create_timeout_violation(20.0))
            d_proc = min(1.0, d_proc + 0.5)

        # Standard weighted composite formulation: D = 0.45(D_net) + 0.35(D_fs) + 0.20(D_proc)
        raw_composite = (
            (self.weight_net * d_net)
            + (self.weight_fs * d_fs)
            + (self.weight_proc * d_proc)
        )

        # Security Invariant (DECISION-ARB-001 & DECISION-ARB-004):
        # A single unauthorized credential read or timeout bomb must independently trigger quarantine.
        if has_credential_leak:
            raw_composite = max(raw_composite, self.threshold)
        if trace.timed_out:
            raw_composite = max(raw_composite, self.threshold)

        composite_score = min(1.0, max(0.0, round(raw_composite, 4)))
        is_quarantined = composite_score >= self.threshold

        return DriftResult(
            composite_drift_score=composite_score,
            network_drift=round(d_net, 4),
            filesystem_drift=round(d_fs, 4),
            process_drift=round(d_proc, 4),
            is_quarantined=is_quarantined,
            violations=all_violations,
        )

    def calculate_drift(
        self,
        contract: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
    ) -> DriftResult:
        """Convenience alias for arbitrate() to match application flow sequence specifications."""
        return self.arbitrate(contract, trace)


def calculate_drift(
    contract: ExpectedBehaviorContract,
    trace: ObservedKernelTrace,
    threshold: float = DEFAULT_QUARANTINE_THRESHOLD,
) -> DriftResult:
    """Functional convenience wrapper for drift arbitration."""
    arbitrator = DriftArbitrator(threshold=threshold)
    return arbitrator.arbitrate(contract, trace)
