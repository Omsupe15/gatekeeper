"""Security Heuristics, Target Definitions, and Noise Whitelists.

Contains hardcoded sensitive target lists, system runtime whitelists,
and network resolver filters used for differential drift arbitration.
"""

import os
from typing import List, Set


SENSITIVE_TARGETS: List[str] = [
    ".ssh",
    ".aws",
    ".env",
    ".gnupg",
    ".git-credentials",
    "/etc/shadow",
    "/etc/passwd",
    ".kube/config",
    ".docker/config.json",
]

SYSTEM_RUNTIME_WHITELIST: Set[str] = {
    "bash",
    "sh",
    "bwrap",
    "node",
    "python3",
    "python",
    "ld-linux",
    "ld-linux-x86-64.so.2",
    "ld-musl-x86_64.so.1",
}

LOOPBACK_IPS: Set[str] = {
    "127.0.0.1",
    "127.0.0.53",
    "localhost",
    "::1",
    "0.0.0.0",
}

SYSTEM_READ_PREFIXES: List[str] = [
    "/lib",
    "/usr/lib",
    "/lib64",
    "/usr/share",
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/resolv.conf",
    "/proc",
    "/dev",
    "/sys",
    "/usr/bin",
    "/bin",
]


def normalize_file_path(path: str) -> str:
    """Normalize file path for consistent security prefix and token matching."""
    if not path:
        return ""
    clean = path.strip().replace("\\", "/")
    # Expand or normalize home directory prefix if present
    if clean.startswith("~/"):
        return clean
    return clean


def is_sensitive_path(path: str) -> bool:
    """Check if a file path targets high-value credential stores or system secrets."""
    normalized = normalize_file_path(path)
    for target in SENSITIVE_TARGETS:
        target_norm = target.replace("\\", "/")
        if target_norm in normalized:
            return True
        # Also check path segments
        segments = normalized.strip("/").split("/")
        if target_norm.strip("/") in segments:
            return True
    return False


def extract_endpoint_host(endpoint: str) -> str:
    """Extract host/IP portion from an endpoint string (e.g. '194.26.29.112:443' -> '194.26.29.112')."""
    if not endpoint:
        return ""
    endpoint = endpoint.strip()
    # IPv6 bracketed endpoint e.g. [::1]:8080
    if endpoint.startswith("["):
        end_bracket = endpoint.find("]")
        if end_bracket != -1:
            return endpoint[1:end_bracket]
    # If endpoint has multiple colons without brackets, it is a bare IPv6 address
    if endpoint.count(":") > 1:
        return endpoint
    # Standard IPv4 or hostname host:port
    if ":" in endpoint:
        return endpoint.rsplit(":", 1)[0]
    return endpoint


def is_loopback_endpoint(endpoint: str) -> bool:
    """Check if an endpoint represents local loopback or local systemd DNS resolver."""
    host = extract_endpoint_host(endpoint)
    if not host:
        return True
    if host in LOOPBACK_IPS:
        return True
    if host.startswith("127."):
        return True
    if host.startswith("::ffff:127."):
        return True
    return False


def is_system_binary(binary_name: str) -> bool:
    """Check if an executable basename is part of the standard system runtime whitelist."""
    if not binary_name:
        return False
    base = os.path.basename(binary_name.strip())
    return base in SYSTEM_RUNTIME_WHITELIST


def is_system_read_path(path: str) -> bool:
    """Check if a path read is standard system shared library or OS runtime metadata."""
    normalized = normalize_file_path(path)
    for prefix in SYSTEM_READ_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return True
    return False
