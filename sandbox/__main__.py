"""Command-line interface for the Gatekeeper sandbox subsystem.

Usage:
  # Trace script execution in isolated sandbox:
  python -m sandbox <script_path> <workspace_dir> [--backend auto|docker|bwrap] [--timeout 20] [--json]

  # Parse existing strace output log:
  python -m sandbox --parse-trace /path/to/strace.log [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from sandbox.bwrap import DEFAULT_SANDBOX_IMAGE, DEFAULT_TIMEOUT_SECONDS
from sandbox.log_parser import extract_observed_trace, parse_trace_file
from sandbox.tracer import trace_execution


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gatekeeper-sandbox",
        description="Gatekeeper Kernel Isolation & Syscall Tracing Subsystem (Block 4)",
    )
    parser.add_argument(
        "script",
        nargs="?",
        help="Path to the untrusted installer/lifecycle script to execute",
    )
    parser.add_argument(
        "workspace",
        nargs="?",
        help="Path to the workspace root directory to mount into the sandbox",
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "docker", "bwrap"],
        default="auto",
        help="Isolation backend to employ (auto, docker, bwrap). Default: auto",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Execution timeout in seconds. Default: {DEFAULT_TIMEOUT_SECONDS}s",
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_SANDBOX_IMAGE,
        help=f"Container image for Docker backend. Default: {DEFAULT_SANDBOX_IMAGE}",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional dedicated host directory for writable sandbox outputs",
    )
    parser.add_argument(
        "--parse-trace",
        metavar="LOG_FILE",
        help="Directly parse an existing strace log file and output observed kernel trace",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit output formatted as JSON",
    )

    args = parser.parse_args(argv)

    # Mode 1: Directly parse strace log
    if args.parse_trace:
        if not os.path.exists(args.parse_trace):
            print(f"Error: Trace log not found: {args.parse_trace}", file=sys.stderr)
            return 1
        events = parse_trace_file(args.parse_trace)
        telemetry = extract_observed_trace(events)
        serializable = {
            "event_count": len(events),
            "telemetry": {
                "files_read": sorted(list(telemetry["files_read"])),
                "files_written": sorted(list(telemetry["files_written"])),
                "network_endpoints": sorted(list(telemetry["network_endpoints"])),
                "spawned_binaries": sorted(list(telemetry["spawned_binaries"])),
                "timed_out": telemetry["timed_out"],
                "execution_duration_ms": telemetry["execution_duration_ms"],
            },
        }
        if args.json:
            print(json.dumps(serializable, indent=2))
        else:
            print(f"Parsed {len(events)} syscall events from {args.parse_trace}:")
            print(f"  Files Read: {len(telemetry['files_read'])}")
            print(f"  Files Written: {len(telemetry['files_written'])}")
            print(f"  Network Endpoints: {len(telemetry['network_endpoints'])}")
            print(f"  Spawned Binaries: {sorted(list(telemetry['spawned_binaries']))}")
        return 0

    # Mode 2: Run and trace script
    if not args.script or not args.workspace:
        parser.print_help(sys.stderr)
        return 1

    report = trace_execution(
        script_path=args.script,
        workspace_dir=args.workspace,
        timeout=args.timeout,
        image=args.image,
        writable_output_dir=args.output_dir,
        backend=args.backend,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"=== Sandbox Execution Report ===")
        print(f"Status: {report.status}")
        print(f"Exit Code: {report.exit_code}")
        print(f"Timed Out: {report.timed_out}")
        print(f"Trace Complete: {report.trace_complete}")
        print(f"Events Intercepted: {len(report.events)}")
        tel = report.to_observed_kernel_trace()
        print(f"Observed Telemetry:")
        print(f"  - Files Read ({len(tel['files_read'])}): {sorted(list(tel['files_read']))[:5]}")
        print(f"  - Files Written ({len(tel['files_written'])}): {sorted(list(tel['files_written']))[:5]}")
        print(f"  - Network Endpoints ({len(tel['network_endpoints'])}): {sorted(list(tel['network_endpoints']))}")
        print(f"  - Spawned Binaries ({len(tel['spawned_binaries'])}): {sorted(list(tel['spawned_binaries']))}")
        if report.errors:
            print(f"Errors:")
            for err in report.errors:
                print(f"  - {err}")

    return 0 if (report.status == "completed" and report.exit_code == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
