"""Strace log parser for Gatekeeper sandbox telemetry.

Extracts, normalizes, and validates kernel syscall events (openat, connect, execve)
from raw strace output streams, tracking multi-process/thread lifecycles,
unfinished/resumed calls, escaped strings, and error codes.
"""

from __future__ import annotations

import os
import re
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# Regex patterns for strace line structure and components
_PID_PREFIX_PATTERN = re.compile(r"^(?:\[pid\s+(\d+)\]|\s*(\d+))\s+(.*)$")
_RESUMED_PATTERN = re.compile(r"^<\.\.\.\s*([a-zA-Z0-9_]+)\s+resumed>(.*)$")
_UNFINISHED_SUFFIX = "<unfinished ...>"

# Syscall call signature matcher: name(args...) [= result [error_code (error_desc)]] [optional elapsed time <0.000123>]
_SYSCALL_CALL_PATTERN = re.compile(
    r"^([a-zA-Z0-9_]+)\((.*)\)\s*=\s*(-?[0-9xXa-fA-F]+|\?)(?:\s+([A-Z0-9_]+)(?:\s+\((.*?)\))?)?(?:\s+<[0-9\.]+>)?$"
)

# Openat argument extractors
_OPENAT_FLAG_READ = {"O_RDONLY"}
_OPENAT_FLAG_WRITE = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}


@lru_cache(maxsize=1)
def load_syscall_cache() -> Set[str]:
    """Load the repository's suspicious syscall cache once per process."""
    cache_path = Path(__file__).resolve().parents[1] / "config" / "syscall_cache.json"
    try:
        with cache_path.open("r", encoding="utf-8") as cache_file:
            payload = json.load(cache_file)
        values = payload.get("critical_syscalls", [])
        return {value.strip() for value in values if isinstance(value, str) and value.strip()}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def _safe_unescape(text: str) -> str:
    """Safely decode escaped strings from strace without raising exceptions."""
    if not text:
        return text

    def _replace_hex(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    def _replace_oct(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 8))
        except (ValueError, OverflowError):
            return match.group(0)

    # Standard escape replacements
    replacements = {
        r"\\": "\\",
        r'\"': '"',
        r"\'": "'",
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r"\b": "\b",
        r"\f": "\f",
        r"\v": "\v",
        r"\0": "\0",
    }
    
    # Replace hex \xHH
    result = re.sub(r"\\x([0-9a-fA-F]{2})", _replace_hex, text)
    # Replace octal \OOO
    result = re.sub(r"\\([0-7]{1,3})", _replace_oct, result)
    # Replace single-character escapes
    for escaped, char in replacements.items():
        result = result.replace(escaped, char)
        
    return result


def _clean_strace_line(raw_line: str) -> Tuple[Optional[int], str]:
    """Extract optional PID and clean line content by stripping timestamps and PID prefixes."""
    content = raw_line.strip()
    pid: Optional[int] = None

    # Step 1: Strip optional initial timestamp e.g. "12:34:56", "12:34:56.123456", "1712345678.123456", or "<0.000123>"
    ts_match = re.match(r"^(?:(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d+\.\d+|<[0-9\.]+>)\s+)(.*)$", content)
    if ts_match:
        content = ts_match.group(1).strip()

    # Step 2: Check for PID prefix e.g. "[pid 1234]" or "1234"
    pid_match = _PID_PREFIX_PATTERN.match(content)
    if pid_match:
        pid_str = pid_match.group(1) or pid_match.group(2)
        try:
            pid = int(pid_str)
        except ValueError:
            pid = None
        content = pid_match.group(3).strip()

    # Step 3: Check for secondary timestamp after PID e.g. "1234 12:34:56.789012 openat(...)"
    ts_match2 = re.match(r"^(?:(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d+\.\d+|<[0-9\.]+>)\s+)(.*)$", content)
    if ts_match2:
        content = ts_match2.group(1).strip()

    return pid, content


def _extract_quoted_string(text: str) -> Optional[str]:
    """Extract and unescape the first quoted string in text."""
    match = re.search(r'"((?:\\.|[^"\\])*)"', text)
    if match:
        return _safe_unescape(match.group(1))
    return None


def _extract_all_quoted_strings(text: str) -> List[str]:
    """Extract all quoted strings in text."""
    matches = re.findall(r'"((?:\\.|[^"\\])*)"', text)
    return [_safe_unescape(m) for m in matches]


def _parse_openat_event(
    raw_line: str,
    pid: Optional[int],
    args_str: str,
    result_code: int,
    error_code: Optional[str],
    syscall_name: str = "openat",
) -> Dict[str, Any]:
    """Parse an openat, openat2, open, or creat syscall line into a normalized event dict."""
    # Example openat: AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC
    # Example open: "/workspace/setup.py", O_RDONLY
    # Example creat: "/workspace/out.txt", 0644
    # Example openat2: AT_FDCWD, "/workspace/test.txt", {flags=O_RDONLY, resolve=RESOLVE_NO_SYMLINKS}, 24
    path = _extract_quoted_string(args_str) or ""
    flags_str = ""
    dirfd_str = "AT_FDCWD"

    if syscall_name == "creat":
        flags_str = "O_WRONLY|O_CREAT|O_TRUNC"
        dirfd_str = "AT_FDCWD"
    else:
        # Check struct {flags=...} first
        struct_flags_match = re.search(r"flags=([A-Z0-9_|]+)", args_str)
        if struct_flags_match:
            flags_str = struct_flags_match.group(1)
        else:
            # Tokenize by comma outside of quotes
            parts = re.findall(r'(?:[^\s,"]+|"(?:\\.|[^"\\])*")+', args_str)
            if parts and parts[0].startswith('"'):
                # open("/path", flags, ...)
                dirfd_str = "AT_FDCWD"
                if len(parts) >= 2:
                    flags_str = parts[1].strip()
            else:
                # openat(dirfd, "/path", flags, ...)
                if len(parts) >= 1:
                    dirfd_str = parts[0].strip()
                if len(parts) >= 3:
                    flags_str = parts[2].strip()
                elif len(parts) == 2 and parts[0].startswith('"'):
                    flags_str = parts[1].strip()

    # Determine read vs write access mode
    flag_tokens = set(re.findall(r"[A-Z0-9_]+", flags_str))
    has_write_flags = bool(flag_tokens & _OPENAT_FLAG_WRITE)
    has_rdwr = "O_RDWR" in flag_tokens
    has_rdonly = "O_RDONLY" in flag_tokens

    if has_rdwr:
        access_mode = "read_write"
    elif has_write_flags:
        access_mode = "write"
    elif has_rdonly or not flag_tokens:
        access_mode = "read"
    else:
        access_mode = "ambiguous"

    success = result_code >= 0

    return {
        "syscall": "openat",
        "pid": pid,
        "path": path,
        "access_mode": access_mode,
        "arguments": {
            "dirfd": dirfd_str,
            "flags": flags_str,
            "path": path,
        },
        "result": result_code,
        "success": success,
        "error_code": error_code if not success else None,
        "raw": raw_line,
    }


def _parse_connect_event(
    raw_line: str,
    pid: Optional[int],
    args_str: str,
    result_code: int,
    error_code: Optional[str],
) -> Dict[str, Any]:
    """Parse a connect syscall line into a normalized event dict."""
    # Example args_str: 3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("194.26.29.112")}, 16
    # Example IPv6: 3, {sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, "::1", &sin6_addr), ...}, 28
    # Example Unix: 3, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110
    # Example Abstract: 3, {sa_family=AF_UNIX, sun_path=@"/tmp/test.sock"}, 18
    
    # Extract file descriptor
    fd_match = re.match(r"^\s*(\d+)", args_str)
    fd = int(fd_match.group(1)) if fd_match else None

    # Family
    family_match = re.search(r"sa_family=([A-Z0-9_]+)", args_str)
    family = family_match.group(1) if family_match else "UNKNOWN"

    # Port (handles decimal and hexadecimal e.g. htons(443) or htons(0x1bb))
    port: Optional[int] = None
    port_match = re.search(r"sin(?:6)?_port=htons\((0x[0-9a-fA-F]+|\d+)\)", args_str)
    if port_match:
        raw_port = port_match.group(1)
        try:
            port = int(raw_port, 16) if raw_port.startswith(("0x", "0X")) else int(raw_port)
        except ValueError:
            port = None

    # IP / Address
    address: Optional[str] = None
    # Check inet_addr("...")
    inet_addr_match = re.search(r'inet_addr\("([^"]+)"\)', args_str)
    if inet_addr_match:
        address = inet_addr_match.group(1)
    else:
        # Check inet_pton(..., "...", ...)
        inet_pton_match = re.search(r'inet_pton\([^,]+,\s*"([^"]+)"', args_str)
        if inet_pton_match:
            address = inet_pton_match.group(1)
        else:
            # Check sun_path=@"..." or sun_path="/..." or sun_path=@/path
            sun_path_match = re.search(r'sun_path=(@?"?[^",\}]+"?|\S+)', args_str)
            if sun_path_match:
                raw_sun = sun_path_match.group(1).strip('"')
                if raw_sun.startswith('@"'):
                    raw_sun = "@" + _safe_unescape(raw_sun[2:].rstrip('"'))
                elif raw_sun.startswith('"'):
                    raw_sun = _safe_unescape(raw_sun.strip('"'))
                address = raw_sun
            else:
                # Fallback: check any quoted string in sockaddr struct
                quoted = _extract_quoted_string(args_str)
                if quoted:
                    address = quoted

    endpoint = f"{address}:{port}" if address and port is not None else (address or "unknown")

    # In network connect, EINPROGRESS is commonly returned on non-blocking connect and is an active attempt.
    # A failed connection (ECONNREFUSED, ENETUNREACH, etc.) is STILL an attempted connection.
    success = result_code == 0 or error_code == "EINPROGRESS"

    return {
        "syscall": "connect",
        "pid": pid,
        "endpoint": endpoint,
        "address": address,
        "port": port,
        "family": family,
        "arguments": {
            "fd": fd,
            "family": family,
            "address": address,
            "port": port,
        },
        "result": result_code,
        "success": success,
        "error_code": error_code if result_code != 0 else None,
        "raw": raw_line,
    }


def _parse_execve_event(
    raw_line: str,
    pid: Optional[int],
    args_str: str,
    result_code: int,
    error_code: Optional[str],
    syscall_name: str = "execve",
) -> Dict[str, Any]:
    """Parse an execve or execveat syscall line into a normalized event dict."""
    quoted_strings = _extract_all_quoted_strings(args_str)
    path = quoted_strings[0] if quoted_strings else ""
    binary = os.path.basename(path) if path else ""
    
    argv = quoted_strings[1:] if len(quoted_strings) > 1 else [binary] if binary else []

    success = result_code >= 0

    return {
        "syscall": "execve",
        "pid": pid,
        "path": path,
        "binary": binary,
        "arguments": {
            "path": path,
            "argv": argv,
        },
        "result": result_code,
        "success": success,
        "error_code": error_code if not success else None,
        "raw": raw_line,
    }


def _parse_generic_event(
    raw_line: str,
    pid: Optional[int],
    syscall_name: str,
    args_str: str,
    result_code: int,
    error_code: Optional[str],
) -> Dict[str, Any]:
    """Keep syscall names available for cache-based security checks."""
    success = result_code >= 0
    return {
        "syscall": syscall_name,
        "pid": pid,
        "arguments_raw": args_str,
        "result": result_code,
        "success": success,
        "error_code": error_code if not success else None,
        "raw": raw_line,
    }


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single standalone strace line.
    
    Returns a normalized event dict for openat, openat2, open, creat, connect,
    execve, execveat, or None if the line is irrelevant, unfinished, signal/exit, or malformed.
    """
    raw_line = line.rstrip("\r\n")
    if not raw_line:
        return None

    # Clean line and extract PID & timestamps
    pid, content = _clean_strace_line(raw_line)

    if not content or content.startswith("+++") or content.startswith("---") or content.endswith(_UNFINISHED_SUFFIX):
        return None

    # Match syscall invocation
    call_match = _SYSCALL_CALL_PATTERN.match(content)
    if not call_match:
        return None

    syscall_name = call_match.group(1)
    args_str = call_match.group(2)
    result_str = call_match.group(3)
    error_code = call_match.group(4)

    try:
        if result_str == "?":
            result_code = -1
        elif result_str.startswith("0x") or result_str.startswith("0X"):
            result_code = int(result_str, 16)
        else:
            result_code = int(result_str)
    except ValueError:
        result_code = -1

    if syscall_name in ("openat", "openat2", "open", "creat"):
        return _parse_openat_event(raw_line, pid, args_str, result_code, error_code, syscall_name=syscall_name)
    elif syscall_name == "connect":
        return _parse_connect_event(raw_line, pid, args_str, result_code, error_code)
    elif syscall_name in ("execve", "execveat"):
        return _parse_execve_event(raw_line, pid, args_str, result_code, error_code, syscall_name=syscall_name)

    return _parse_generic_event(raw_line, pid, syscall_name, args_str, result_code, error_code)


def parse_trace(trace_text: str) -> List[Dict[str, Any]]:
    """Parse a full strace log text buffer into a list of normalized events.
    
    Robustly tracks multi-process PID states, handles unfinished and resumed calls,
    preserves raw lines, extracts error codes, recovers un-resumed calls on timeout,
    and guarantees no crashing on malformed input.
    """
    events: List[Dict[str, Any]] = []
    if not trace_text or not trace_text.strip():
        return events

    # Map of (pid, syscall_name) -> partial call string
    unfinished_calls: Dict[Tuple[Optional[int], str], str] = {}

    for line in trace_text.splitlines():
        raw_line = line.rstrip("\r\n")
        if not raw_line:
            continue

        try:
            pid, content = _clean_strace_line(raw_line)
            if not content or content.startswith("+++") or content.startswith("---"):
                continue

            # Case 1: Unfinished syscall start
            if content.endswith(_UNFINISHED_SUFFIX):
                m = re.match(r"^([a-zA-Z0-9_]+)\((.*)\s+<unfinished \.\.\.>$", content)
                if m:
                    sys_name = m.group(1)
                    partial_args = m.group(2)
                    unfinished_calls[(pid, sys_name)] = partial_args
                continue

            # Case 2: Resumed syscall
            resumed_match = _RESUMED_PATTERN.match(content)
            if resumed_match:
                sys_name = resumed_match.group(1)
                resumed_tail = resumed_match.group(2).strip()
                
                # Retrieve buffered start
                key = (pid, sys_name)
                partial_args = unfinished_calls.pop(key, "")

                # Reconstruct full signature with safe argument joining
                sep = ""
                if partial_args and not partial_args.endswith(",") and not resumed_tail.startswith(")") and not resumed_tail.startswith(","):
                    sep = ", "
                combined_content = f"{sys_name}({partial_args}{sep}{resumed_tail}"
                
                call_match = _SYSCALL_CALL_PATTERN.match(combined_content)
                if call_match:
                    args_str = call_match.group(2)
                    result_str = call_match.group(3)
                    error_code = call_match.group(4)
                    try:
                        if result_str == "?":
                            result_code = -1
                        elif result_str.startswith("0x") or result_str.startswith("0X"):
                            result_code = int(result_str, 16)
                        else:
                            result_code = int(result_str)
                    except ValueError:
                        result_code = -1

                    if sys_name in ("openat", "openat2", "open", "creat"):
                        events.append(_parse_openat_event(raw_line, pid, args_str, result_code, error_code, syscall_name=sys_name))
                    elif sys_name == "connect":
                        events.append(_parse_connect_event(raw_line, pid, args_str, result_code, error_code))
                    elif sys_name in ("execve", "execveat"):
                        events.append(_parse_execve_event(raw_line, pid, args_str, result_code, error_code, syscall_name=sys_name))
                    else:
                        events.append(_parse_generic_event(raw_line, pid, sys_name, args_str, result_code, error_code))
                continue

            # Case 3: Complete single line
            event = parse_line(raw_line)
            if event:
                events.append(event)

        except Exception:
            # Never crash on malformed lines
            continue

    # Case 4: Recover any un-resumed syscalls (e.g. aborted due to timeout or termination)
    for (unf_pid, unf_sys), partial_args in unfinished_calls.items():
        try:
            if unf_sys in ("openat", "openat2", "open", "creat"):
                events.append(
                    _parse_openat_event(
                        f"{unf_sys}({partial_args} <unfinished ...>",
                        unf_pid,
                        partial_args,
                        -1,
                        "UNFINISHED",
                        syscall_name=unf_sys,
                    )
                )
            elif unf_sys == "connect":
                events.append(
                    _parse_connect_event(
                        f"connect({partial_args} <unfinished ...>",
                        unf_pid,
                        partial_args,
                        -1,
                        "UNFINISHED",
                    )
                )
            elif unf_sys in ("execve", "execveat"):
                events.append(
                    _parse_execve_event(
                        f"{unf_sys}({partial_args} <unfinished ...>",
                        unf_pid,
                        partial_args,
                        -1,
                        "UNFINISHED",
                        syscall_name=unf_sys,
                    )
                )
            else:
                events.append(
                    _parse_generic_event(
                        f"{unf_sys}({partial_args} <unfinished ...>",
                        unf_pid,
                        unf_sys,
                        partial_args,
                        -1,
                        "UNFINISHED",
                    )
                )
        except Exception:
            continue

    return events


def parse_trace_file(trace_path: str) -> List[Dict[str, Any]]:
    """Read a strace log file from disk and parse all syscall events."""
    if not os.path.exists(trace_path):
        return []
    try:
        with open(trace_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return parse_trace(content)
    except Exception:
        return []


def _normalize_string_set(value: Any, field_name: str) -> Set[str]:
    """Normalize a field into a unique, non-empty set of strings."""
    if value is None:
        return set()
    if isinstance(value, str):
        raise ValueError(f"{field_name} must be an iterable of strings, not a single string.")

    normalized: Set[str] = set()
    for item in value:
        if item is None:
            continue
        if not isinstance(item, str):
            raise ValueError(f"{field_name} items must all be strings.")
        cleaned = item.strip()
        if not cleaned:
            continue
        if field_name == "network_endpoints" and ":" not in cleaned and not cleaned.startswith("/") and not cleaned.startswith("."):
            raise ValueError(f"{field_name} contains an invalid endpoint: {cleaned!r}")
        normalized.add(cleaned)
    return normalized


def validate_observed_trace(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize raw sandbox telemetry before it is used downstream."""
    if payload is None:
        raise ValueError("Telemetry payload cannot be empty.")
    if not isinstance(payload, dict):
        raise ValueError("Telemetry payload must be a dictionary.")

    normalized: Dict[str, Any] = {}
    for field_name in (
        "files_read",
        "files_written",
        "network_endpoints",
        "spawned_binaries",
        "syscalls",
        "flagged_syscalls",
    ):
        normalized[field_name] = _normalize_string_set(payload.get(field_name, set()), field_name)

    timed_out = payload.get("timed_out", False)
    if not isinstance(timed_out, bool):
        raise ValueError("timed_out must be a boolean value.")
    normalized["timed_out"] = timed_out

    execution_duration_ms = payload.get("execution_duration_ms", 0.0)
    try:
        duration_value = float(execution_duration_ms)
    except (TypeError, ValueError) as exc:
        raise ValueError("execution_duration_ms must be numeric.") from exc
    if duration_value < 0:
        raise ValueError("execution_duration_ms must be non-negative.")
    normalized["execution_duration_ms"] = duration_value

    return normalized


def extract_observed_trace(
    events: List[Dict[str, Any]],
    timed_out: bool = False,
    execution_duration_ms: float = 0.0,
) -> Dict[str, Any]:
    """Aggregate parsed events into an ObservedKernelTrace telemetry payload.
    
    Returns a dictionary structure compatible with Gatekeeper's ObservedKernelTrace schema:
      - files_read: set of file paths opened with read access
      - files_written: set of file paths opened with write access
      - network_endpoints: set of attempted network endpoints ("ip:port" or address)
      - spawned_binaries: set of executable basenames
            - syscalls: all syscall names observed in the log
            - flagged_syscalls: observed names present in the suspicious syscall cache
            - timed_out: boolean timeout flag
      - execution_duration_ms: execution runtime duration in milliseconds
    """
    files_read: Set[str] = set()
    files_written: Set[str] = set()
    network_endpoints: Set[str] = set()
    spawned_binaries: Set[str] = set()
    syscalls: Set[str] = set()
    flagged_syscalls: Set[str] = set()
    syscall_cache = load_syscall_cache()
    for ev in events:
        syscall = ev.get("syscall")
        if syscall:
            syscalls.add(syscall)
            if syscall in syscall_cache:
                flagged_syscalls.add(syscall)
        if syscall == "openat":
            path = ev.get("path")
            access_mode = ev.get("access_mode")
            if path:
                if access_mode in ("read", "read_write"):
                    files_read.add(path)
                if access_mode in ("write", "read_write"):
                    files_written.add(path)

        elif syscall == "connect":
            endpoint = ev.get("endpoint")
            address = ev.get("address")
            if endpoint and endpoint != "unknown":
                network_endpoints.add(endpoint)
            elif address:
                network_endpoints.add(address)

        elif syscall == "execve":
            binary = ev.get("binary")
            path = ev.get("path")
            if binary:
                spawned_binaries.add(binary)
            elif path:
                spawned_binaries.add(os.path.basename(path))

    payload = {
        "files_read": files_read,
        "files_written": files_written,
        "network_endpoints": network_endpoints,
        "spawned_binaries": spawned_binaries,
        "syscalls": syscalls,
        "flagged_syscalls": flagged_syscalls,
        "timed_out": timed_out,
        "execution_duration_ms": execution_duration_ms,
    }
    return validate_observed_trace(payload)


def extract_observed_trace_model(
    events: List[Dict[str, Any]],
    timed_out: bool = False,
    execution_duration_ms: float = 0.0,
) -> Any:
    """Aggregate parsed events into an ObservedKernelTrace Pydantic model instance."""
    raw = extract_observed_trace(
        events=events,
        timed_out=timed_out,
        execution_duration_ms=execution_duration_ms,
    )
    from core.schema.telemetry import ObservedKernelTrace
    return ObservedKernelTrace(**raw)

