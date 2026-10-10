"""Entrypoint CLI Dispatcher & Pipeline Coordinator for Gatekeeper.

Coordinates static extraction, AI contract synthesis, kernel tracing, vector arbitration, and UI rendering.
Implements a decoupled PipelineCoordinator adapter pattern to prevent integration merge conflicts.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, List, Optional, Tuple

from core.ai_engine.agents import ContractSynthesizer
from core.ai_engine.client import OllamaClient
from core.ai_engine.forensic_agent import ForensicAgent
from core.arbitrator.scorer import DriftArbitrator
from core.cli.reporters import generate_json_report, generate_sarif_report, write_report_to_file
from core.cli.ui import (
    create_status_spinner,
    get_console,
    print_banner,
    render_allow_card,
    render_comparison_matrix,
    render_error_card,
    render_forensic_panel,
    render_quarantine_card,
)
from core.extractor import extract_context, has_lifecycle_hooks
from core.sandbox.bwrap import is_bwrap_available, is_docker_available
from core.sandbox.tracer import SyscallTracer
from core.schema import (
    DriftResult,
    ExpectedBehaviorContract,
    ObservedKernelTrace,
    ThreatAttributionReport,
)


class PipelineCoordinator:
    """Decoupled Pipeline Coordinator.

    Orchestrates static extraction (Block 3), AI contract synthesis (Block 2),
    kernel sandboxing (Block 4), differential arbitration (Block 5),
    and AI forensic threat attribution (Block 2).
    """

    def __init__(
        self,
        extractor_fn=extract_context,
        has_hooks_fn=has_lifecycle_hooks,
        ollama_client: Optional[OllamaClient] = None,
        synthesizer: Optional[ContractSynthesizer] = None,
        tracer: Optional[SyscallTracer] = None,
        arbitrator: Optional[DriftArbitrator] = None,
        forensic_agent: Optional[ForensicAgent] = None,
        require_live_services: bool = True,
    ) -> None:
        self.extractor_fn = extractor_fn
        self.has_hooks_fn = has_hooks_fn
        self.ollama_client = ollama_client
        self.synthesizer = synthesizer
        self.tracer = tracer
        self.arbitrator = arbitrator
        self.forensic_agent = forensic_agent
        self.require_live_services = require_live_services

    def analyze(
        self,
        package_dir: str,
        threshold: float = 0.40,
    ) -> Tuple[ExpectedBehaviorContract, ObservedKernelTrace, DriftResult, Optional[ThreatAttributionReport]]:
        """Executes the end-to-end security analysis for a package directory."""
        package_path = os.path.abspath(package_dir)
        package_name = os.path.basename(package_path) or "target-package"

        # Step 1: Check for install-time lifecycle hooks (Block 3)
        try:
            has_hooks = self.has_hooks_fn(package_path)
        except Exception:
            has_hooks = False

        # Fast-Path: Package has no install-time lifecycle hooks
        # Build-time execution is not required; immediate ALLOW verdict (< 50ms)
        if not has_hooks:
            contract = ExpectedBehaviorContract(
                package_name=package_name,
                purpose="Package contains no install-time lifecycle hooks (Nominal / Clean)",
                network_required=False,
                allowed_domains=[],
                allowed_read_prefixes=["."],
                allowed_write_prefixes=[],
                allowed_binaries=[],
                accesses_user_credentials=False,
                risk_level_assessment="LOW",
            )
            trace = ObservedKernelTrace(
                files_read=set(),
                files_written=set(),
                network_endpoints=set(),
                spawned_binaries=set(),
                timed_out=False,
                execution_duration_ms=0.0,
            )
            drift_result = DriftResult(
                composite_drift_score=0.00,
                network_drift=0.0,
                filesystem_drift=0.0,
                process_drift=0.0,
                is_quarantined=False,
                violations=[],
            )
            return contract, trace, drift_result, None

        # Step 2: Extraction of context and runner script
        extraction_ctx = self.extractor_fn(package_path)
        if extraction_ctx is None:
            contract = ExpectedBehaviorContract(
                package_name=package_name,
                purpose="Package contains no install-time lifecycle hooks (Nominal / Clean)",
                network_required=False,
                allowed_domains=[],
                allowed_read_prefixes=["."],
                allowed_write_prefixes=[],
                allowed_binaries=[],
                accesses_user_credentials=False,
                risk_level_assessment="LOW",
            )
            trace = ObservedKernelTrace(
                files_read=set(),
                files_written=set(),
                network_endpoints=set(),
                spawned_binaries=set(),
                timed_out=False,
                execution_duration_ms=0.0,
            )
            drift_result = DriftResult(
                composite_drift_score=0.00,
                network_drift=0.0,
                filesystem_drift=0.0,
                process_drift=0.0,
                is_quarantined=False,
                violations=[],
            )
            return contract, trace, drift_result, None

        # Step 3: Validate live daemon requirements if strictly required
        client = self.ollama_client or OllamaClient()
        if self.require_live_services and self.synthesizer is None:
            if not client.check_health_sync():
                raise RuntimeError(
                    f"Ollama daemon is offline or unreachable at {client.base_url}. "
                    "Gatekeeper strictly requires a live Ollama instance for contract synthesis."
                )

        if self.require_live_services and self.tracer is None:
            if not is_docker_available() and not is_bwrap_available():
                raise RuntimeError(
                    "Docker daemon is offline or unreachable (and Bubblewrap is not supported on this host). "
                    "Gatekeeper strictly requires an active Docker/Bubblewrap environment to trace lifecycle execution."
                )

        # Step 4: AI Expected Behavior Contract Synthesis (Block 2)
        synthesizer = self.synthesizer or ContractSynthesizer(client=client)
        contract = synthesizer.synthesize_sync(extraction_ctx)

        # Step 5: Sandboxed Kernel Execution & Syscall Interception (Block 4)
        tracer = self.tracer or SyscallTracer()
        runner_path = str(extraction_ctx.runner_script_path) if extraction_ctx.runner_script_path else None
        if not runner_path or not os.path.exists(runner_path):
            raise RuntimeError(
                f"Runner script path '{runner_path}' does not exist for sandboxed execution."
            )

        report = tracer.run_and_trace(runner_path, package_path)

        if report.status == "docker_unavailable":
            raise RuntimeError(
                "Docker daemon is offline or unreachable. "
                "Gatekeeper strictly requires an active Docker/Bubblewrap environment to trace lifecycle execution."
            )

        if not report.trace_complete and report.status == "execution_failed" and not report.raw_trace_file:
            raise RuntimeError(
                f"Kernel syscall tracing failed inside sandbox: {report.stderr or report.errors}"
            )

        trace = report.to_observed_kernel_trace_model()

        # Step 6: Differential Vector Arbitration (Block 5)
        arbitrator = self.arbitrator or DriftArbitrator(threshold=threshold)
        drift_result = arbitrator.arbitrate(contract, trace)

        # Step 7: Post-Trace AI Forensic Threat Attribution (Block 2)
        forensic_report = None
        if drift_result.is_quarantined:
            forensic_agent = self.forensic_agent or ForensicAgent(client=client)
            forensic_report = forensic_agent.analyze_incident_sync(
                ebc=contract,
                trace=trace,
                drift=drift_result,
                context=extraction_ctx,
            )

        return contract, trace, drift_result, forensic_report


# Global coordinator instance
default_coordinator = PipelineCoordinator()


def analyze_target_package(
    package_dir: str,
    threshold: float = 0.40,
    c=None,
    coordinator: Optional[PipelineCoordinator] = None,
) -> Tuple[ExpectedBehaviorContract, ObservedKernelTrace, DriftResult, Optional[ThreatAttributionReport]]:
    """Analyzes a target package directory using the PipelineCoordinator adapter."""
    coord = coordinator or default_coordinator
    return coord.analyze(package_dir, threshold=threshold)


def run_cli(
    args: Optional[List[str]] = None,
    coordinator: Optional[PipelineCoordinator] = None,
) -> int:
    """Main CLI function dispatcher. Returns POSIX exit code:
    0: ALLOW (Pass)
    1: QUARANTINE (Drift detected)
    2: ERROR (Invalid usage or path error)
    """
    parser = argparse.ArgumentParser(
        prog="gatekeeper",
        description="Gatekeeper: Autonomous Semantic-to-Kernel Drift Detector for Open-Source Supply Chain Security",
    )
    parser.add_argument(
        "subcommand_or_path",
        nargs="?",
        default=".",
        help="Subcommand ('run', 'audit') or path to target package directory",
    )
    parser.add_argument(
        "target_path",
        nargs="?",
        default=None,
        help="Target package directory (when using subcommand like 'run ./path')",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "sarif"],
        default="terminal",
        help="Output report format (default: terminal)",
    )
    parser.add_argument(
        "-o", "--output",
        help="File path to write JSON or SARIF report output",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.40,
        help="Drift score quarantine threshold (default: 0.40)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable Rich ANSI color formatting",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Gatekeeper v0.1.0",
    )

    parsed = parser.parse_args(args)

    c = get_console(no_color=parsed.no_color)

    # Determine target package path
    if parsed.subcommand_or_path in ["run", "audit", "scan"]:
        package_dir = parsed.target_path or "."
    else:
        package_dir = parsed.subcommand_or_path

    package_dir = os.path.abspath(package_dir)

    # Check path existence
    if not os.path.exists(package_dir):
        if parsed.format == "terminal":
            print_banner(c)
            render_error_card(f"Target path does not exist: '{package_dir}'", c)
        return 2

    # Execute Analysis
    try:
        if parsed.format == "terminal":
            print_banner(c)
            with create_status_spinner("Analyzing package & executing kernel sandbox trace...", c):
                contract, trace, drift_result, forensic_report = analyze_target_package(
                    package_dir, threshold=parsed.threshold, c=c, coordinator=coordinator
                )

            render_comparison_matrix(contract, trace, c)

            if drift_result.is_quarantined:
                render_quarantine_card(drift_result, c)
                if forensic_report:
                    render_forensic_panel(forensic_report, c)
                return 1
            else:
                render_allow_card(drift_result, c)
                return 0

        elif parsed.format == "json":
            contract, trace, drift_result, forensic_report = analyze_target_package(
                package_dir, threshold=parsed.threshold, c=c, coordinator=coordinator
            )
            report_str = generate_json_report(package_dir, contract, trace, drift_result, forensic_report)
            if parsed.output:
                write_report_to_file(report_str, parsed.output)
                if parsed.verbose:
                    c.print(f"[bold green]JSON report written to '{parsed.output}'[/bold green]")
            else:
                sys.stdout.write(report_str + "\n")

            return 1 if drift_result.is_quarantined else 0

        elif parsed.format == "sarif":
            contract, trace, drift_result, forensic_report = analyze_target_package(
                package_dir, threshold=parsed.threshold, c=c, coordinator=coordinator
            )
            report_str = generate_sarif_report(package_dir, drift_result, forensic_report)
            if parsed.output:
                write_report_to_file(report_str, parsed.output)
                if parsed.verbose:
                    c.print(f"[bold green]SARIF report written to '{parsed.output}'[/bold green]")
            else:
                sys.stdout.write(report_str + "\n")

            return 1 if drift_result.is_quarantined else 0

    except Exception as e:
        if parsed.format == "terminal":
            render_error_card(str(e), c)
        else:
            sys.stderr.write(f"Error: {e}\n")
        return 2

    return 2


def main() -> None:
    """CLI entrypoint function invoked by `gatekeeper` script command."""
    exit_code = run_cli()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
