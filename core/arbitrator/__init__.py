"""Block 5: Differential Drift Arbitration Engine.

Exports the DriftArbitrator class, mathematical scoring functions,
sensitive asset targets, system runtime noise filters, and violation categorizers.
"""

from core.arbitrator.heuristics import (
    LOOPBACK_IPS,
    SENSITIVE_TARGETS,
    SYSTEM_READ_PREFIXES,
    SYSTEM_RUNTIME_WHITELIST,
    extract_endpoint_host,
    is_loopback_endpoint,
    is_sensitive_path,
    is_system_binary,
    is_system_read_path,
    normalize_file_path,
)
from core.arbitrator.scorer import (
    DEFAULT_QUARANTINE_THRESHOLD,
    WEIGHT_FILESYSTEM,
    WEIGHT_NETWORK,
    WEIGHT_PROCESS,
    DriftArbitrator,
    calculate_drift,
    evaluate_filesystem_drift,
    evaluate_network_drift,
    evaluate_process_drift,
)
from core.arbitrator.violations import (
    create_credential_violation,
    create_network_violation,
    create_prefix_violation,
    create_process_violation,
    create_timeout_violation,
)

__all__ = [
    # Engine & functional interface
    "DriftArbitrator",
    "calculate_drift",
    # Evaluation functions
    "evaluate_network_drift",
    "evaluate_filesystem_drift",
    "evaluate_process_drift",
    # Weight constants
    "WEIGHT_NETWORK",
    "WEIGHT_FILESYSTEM",
    "WEIGHT_PROCESS",
    "DEFAULT_QUARANTINE_THRESHOLD",
    # Heuristics & whitelists
    "SENSITIVE_TARGETS",
    "SYSTEM_RUNTIME_WHITELIST",
    "LOOPBACK_IPS",
    "SYSTEM_READ_PREFIXES",
    "is_sensitive_path",
    "is_loopback_endpoint",
    "is_system_binary",
    "is_system_read_path",
    "extract_endpoint_host",
    "normalize_file_path",
    # Violation constructors
    "create_network_violation",
    "create_credential_violation",
    "create_prefix_violation",
    "create_process_violation",
    "create_timeout_violation",
]
