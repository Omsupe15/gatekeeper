"""
Rich Terminal UI & Presentation System for Gatekeeper CLI.
Implements brand visual identity, comparison matrix, quarantine cards, and AI forensic panels.
"""

import sys
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.status import Status

# Fix Windows console encoding for Unicode box characters and emoji
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


from core.schema import (
    ExpectedBehaviorContract,
    ObservedKernelTrace,
    DriftResult,
    ThreatAttributionReport,
)


# Color Palette Constants
COLOR_CYAN = "#00F0FF"      # Cyber Neon Cyan
COLOR_GREEN = "#00FF88"     # Emerald Green
COLOR_RED = "#FF0055"       # Crimson Alert
COLOR_AMBER = "#FFB703"     # Amber Gold
COLOR_PURPLE = "#8A2BE2"    # AI Purple
COLOR_SLATE = "#161B22"     # Obsidian Slate
COLOR_WHITE = "#F0F6FC"     # High-Vis White
COLOR_MUTED = "#8B949E"     # Muted Steel

console = Console(legacy_windows=False)


def get_console(no_color: bool = False) -> Console:
    """Returns a Console instance configured for stdout."""
    if no_color:
        return Console(no_color=True, legacy_windows=False)
    return console



def print_banner(c: Optional[Console] = None) -> None:
    """Renders the Gatekeeper ASCII header banner."""
    c = c or console
    banner_text = """[bold #00F0FF]
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  ██████╗   █████╗  ████████╗███████╗██╗  ██╗███████╗███████╗██████╗ ███████╗██████╗    │
│ ██╔════╝  ██╔══██╗ ╚══██╔══╝██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗   │
│ ██║  ███╗ ███████║    ██║   █████╗  █████═╝ █████╗  █████╗  ██████╔╝█████╗  ██████╔╝   │
│ ██║   ██║ ██╔══██║    ██║   ██╔══╝  ██╔═██╗ ██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗   │
│ ╚██████╔╝ ██║  ██║    ██║   ███████╗██║ ╚██╗███████╗███████╗██║     ███████╗██║  ██║   │
│  ╚═════╝  ╚═╝  ╚═╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   │
│                                                                                        │
│  [+] AUTONOMOUS SEMANTIC-TO-KERNEL DRIFT DETECTOR FOR SUPPLY CHAIN SECURITY            │
│  [*] STATUS: ACTIVE SCANNER    [•] CORE: QWEN2.5-CODER:7B    [#] SANDBOX: BWRAP+STRACE │
└────────────────────────────────────────────────────────────────────────────────────────┘[/bold #00F0FF]"""
    c.print(banner_text)


def create_status_spinner(status_msg: str, c: Optional[Console] = None) -> Status:
    """Creates a Rich status spinner for dynamic execution steps."""
    c = c or console
    return c.status(f"[bold {COLOR_CYAN}]{status_msg}[/bold {COLOR_CYAN}]", spinner="dots")


def render_comparison_matrix(
    contract: ExpectedBehaviorContract,
    trace: ObservedKernelTrace,
    c: Optional[Console] = None,
) -> None:
    """
    Renders side-by-side comparison table contrasting AI Declared Contract vs Observed Kernel Trace.
    """
    c = c or console
    table = Table(
        title="[bold #00F0FF]BEHAVIORAL COMPARISON MATRIX (DECLARED VS. OBSERVED)[/bold #00F0FF]",
        border_style=COLOR_SLATE,
        header_style=f"bold {COLOR_WHITE}",
        show_lines=True,
    )
    table.add_column("Security Property", style=f"bold {COLOR_WHITE}", width=25)
    table.add_column("SLM Contract (Declared)", width=32)
    table.add_column("Kernel Intercept (Observed)", width=35)

    # 1. Network Sockets
    if contract.network_required:
        contract_net = f"[{COLOR_GREEN}]True (Allowed: {', '.join(contract.allowed_domains) or 'Any'})[/{COLOR_GREEN}]"
    else:
        contract_net = f"[{COLOR_GREEN}]False (Air-gapped)[/{COLOR_GREEN}]"

    if trace.network_endpoints:
        endpoints_str = ", ".join(trace.network_endpoints)
        if not contract.network_required:
            trace_net = f"[bold {COLOR_RED}]{endpoints_str} (UNAUTHORIZED)[/bold {COLOR_RED}]"
        else:
            trace_net = f"[{COLOR_GREEN}]{endpoints_str}[/{COLOR_GREEN}]"
    else:
        trace_net = f"[{COLOR_MUTED}]No network connections captured[/{COLOR_MUTED}]"

    table.add_row("Network Sockets", contract_net, trace_net)

    # 2. Credential Access
    if contract.accesses_user_credentials:
        contract_cred = f"[{COLOR_AMBER}]True (Explicitly Permitted)[/{COLOR_AMBER}]"
    else:
        contract_cred = f"[{COLOR_GREEN}]False (Denied)[/{COLOR_GREEN}]"

    sensitive_found = [
        f for f in (trace.files_read | trace.files_written)
        if any(s in f for s in [".ssh", ".aws", ".env", ".kube/config", "/etc/shadow", "/etc/passwd"])
    ]
    if sensitive_found:
        trace_cred = f"[bold {COLOR_RED}]{', '.join(sensitive_found)} (UNAUTHORIZED)[/bold {COLOR_RED}]"
    else:
        trace_cred = f"[{COLOR_MUTED}]No credential store accessed[/{COLOR_MUTED}]"

    table.add_row("Credential Access", contract_cred, trace_cred)

    # 3. Spawned Binaries
    allowed_bin = ", ".join(contract.allowed_binaries) or "Standard runtimes"
    contract_bin = f"[{COLOR_MUTED}]{allowed_bin}[/{COLOR_MUTED}]"

    if trace.spawned_binaries:
        binaries_str = ", ".join(trace.spawned_binaries)
        trace_bin = f"[{COLOR_WHITE}]{binaries_str}[/{COLOR_WHITE}]"
    else:
        trace_bin = f"[{COLOR_MUTED}]No external binaries spawned[/{COLOR_MUTED}]"

    table.add_row("Spawned Binaries", contract_bin, trace_bin)

    # 4. Target Working Directory / Duration
    contract_dir = f"[{COLOR_MUTED}]Isolated Sandbox Environment[/{COLOR_MUTED}]"
    trace_dir = f"[{COLOR_MUTED}]Runtime: {trace.execution_duration_ms:.1f}ms (Timed out: {trace.timed_out})[/{COLOR_MUTED}]"
    table.add_row("Execution Metrics", contract_dir, trace_dir)

    c.print(table)


def render_quarantine_card(result: DriftResult, c: Optional[Console] = None) -> None:
    """Renders Crimson Red Quarantine Alert panel when D >= threshold."""
    c = c or console

    violations_text = []
    for v in result.violations:
        violations_text.append(f"  • [bold {COLOR_RED}]{v.dimension.value.upper()}:[/bold {COLOR_RED}] {v.description}")
        violations_text.append(f"    [dim {COLOR_MUTED}](Offending Artifact: {v.offending_artifact})[/dim {COLOR_MUTED}]")

    violations_block = "\n".join(violations_text) if violations_text else "  • Critical behavioral divergence observed across security boundaries."

    body = f"""[bold {COLOR_RED}]CRITICAL BEHAVIORAL DRIFT DETECTED: Score {result.composite_drift_score:.2f} / 1.00[/bold {COLOR_RED}]

[bold {COLOR_AMBER}]Observed Violations:[/bold {COLOR_AMBER}]
{violations_block}
"""
    panel = Panel(
        body,
        title=f"[bold {COLOR_RED}]VERDICT: QUARANTINE (EXIT CODE 1)[/bold {COLOR_RED}]",
        border_style=COLOR_RED,
        padding=(1, 2),
    )
    c.print(panel)


def render_forensic_panel(report: ThreatAttributionReport, c: Optional[Console] = None) -> None:
    """Renders AI Forensic Threat Attribution panel detailing attack vector and MITRE tags."""
    c = c or console

    mitre_badges = " ".join([f"[reverse {COLOR_PURPLE}] {t} [/]" for t in report.mitre_attack_tactics]) or "N/A"


    remediations = "\n".join([f"  {idx+1}. {r}" for idx, r in enumerate(report.remediation_recommendations)]) or "  1. Block package execution in CI/CD pipelines."

    body = f"""[bold {COLOR_CYAN}]Attack Category:[/bold {COLOR_CYAN}]  {report.attack_category}
[bold {COLOR_CYAN}]MITRE ATT&CK:[/bold {COLOR_CYAN}]     {mitre_badges}

[bold {COLOR_CYAN}]Culprit Code Snippet:[/bold {COLOR_CYAN}]
[dim {COLOR_WHITE}]{report.culprit_code_snippet or 'Code snippet not isolated.'}[/dim {COLOR_WHITE}]

[bold {COLOR_CYAN}]Forensic Summary:[/bold {COLOR_CYAN}]
{report.executive_summary}

[bold {COLOR_CYAN}]Remediation Recommendations:[/bold {COLOR_CYAN}]
{remediations}
"""
    panel = Panel(
        body,
        title=f"[bold {COLOR_CYAN}]🤖 AI FORENSIC THREAT ATTRIBUTION REPORT[/bold {COLOR_CYAN}]",
        border_style=COLOR_CYAN,
        padding=(1, 2),
    )
    c.print(panel)


def render_allow_card(result: DriftResult, c: Optional[Console] = None) -> None:
    """Renders Emerald Green Approval card when D < threshold."""
    c = c or console
    body = f"""[bold {COLOR_GREEN}]NOMINAL EXECUTION: Drift Score {result.composite_drift_score:.2f} / 1.00[/bold {COLOR_GREEN}]

All observed kernel actions (file operations, network egress, binary execution) align with
declared semantic intent. No unauthorized network connection or credential store access detected.
"""
    panel = Panel(
        body,
        title=f"[bold {COLOR_GREEN}]VERDICT: ALLOW (EXIT CODE 0)[/bold {COLOR_GREEN}]",
        border_style=COLOR_GREEN,
        padding=(1, 2),
    )
    c.print(panel)


def render_error_card(error_msg: str, c: Optional[Console] = None) -> None:
    """Renders Red Error panel for CLI/System errors."""
    c = c or console
    panel = Panel(
        f"[bold {COLOR_RED}]SYSTEM ERROR:[/bold {COLOR_RED}]\n{error_msg}",
        title=f"[bold {COLOR_RED}]VERDICT: ERROR (EXIT CODE 2)[/bold {COLOR_RED}]",
        border_style=COLOR_RED,
        padding=(1, 2),
    )
    c.print(panel)
