# Schema Design & UI/UX Design System

## Project: Gatekeeper (*Autonomous Semantic-to-Kernel Drift Detector*)

---

## 1. Schema Design & Pydantic Data Models

All data transformations in Gatekeeper are governed by strongly-typed **Pydantic v2** models. This guarantees runtime validation, auto-generated JSON schemas for Ollama constrained decoding, and lossless serialization across module boundaries.

### 1.1. Package Extraction & AST Models

```python
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Set
from enum import Enum

class EcosystemType(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    STANDALONE = "standalone"

class LifecycleHookType(str, Enum):
    PREINSTALL = "preinstall"
    INSTALL = "install"
    POSTINSTALL = "postinstall"
    SETUP_PY = "setup.py"
    STANDALONE_SHELL = "standalone_shell"

class ASTSuspiciousToken(BaseModel):
    token_type: str = Field(description="AST node type, e.g., CallExpression, ImportFrom")
    identifier: str = Field(description="Target function/module, e.g., child_process, socket, eval")
    line_number: int = Field(description="Line in script where token was discovered")
    snippet: str = Field(description="Code snippet surrounding the token")
    entropy_score: Optional[float] = Field(default=None, description="Calculated Shannon entropy for base64 strings")

class ExtractionContext(BaseModel):
    package_name: str
    version: str = "0.0.0"
    ecosystem: EcosystemType
    declared_description: str = Field(default="", description="Natural language description from manifest")
    repository_url: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    hook_type: LifecycleHookType
    hook_command: str = Field(description="Raw command declared in the manifest")
    source_code: str = Field(description="Extracted or assembled lifecycle script code")
    ast_tokens: List[ASTSuspiciousToken] = Field(default_factory=list)
    runner_script_path: str = Field(description="Path to the executable wrapper script for sandbox execution")
```

---

### 1.2. Behavioral Contract Schema (EBC)

This schema is serialized to JSON Schema and fed directly into Ollama's `format="json"` constrained decoding engine to guarantee that the local SLM generates compliant outputs.

```python
class ExpectedBehaviorContract(BaseModel):
    package_name: str = Field(
        description="Declared identifier of the package under evaluation"
    )
    purpose: str = Field(
        description="One-sentence technical summary of the legitimate functionality of this package"
    )
    network_required: bool = Field(
        description="Must be True ONLY if installation legitimately requires fetching remote assets"
    )
    allowed_domains: List[str] = Field(
        default_factory=list,
        description="Explicit whitelist of hostnames or IP subnets permitted for egress"
    )
    allowed_read_prefixes: List[str] = Field(
        default_factory=list,
        description="Directory prefixes the install script is legitimately permitted to read"
    )
    allowed_write_prefixes: List[str] = Field(
        default_factory=list,
        description="Directory prefixes the install script is legitimately permitted to write to"
    )
    allowed_binaries: List[str] = Field(
        default_factory=list,
        description="Explicit executable binary names permitted to be spawned during install"
    )
    accesses_user_credentials: bool = Field(
        default=False,
        description="Whether touching sensitive user credential stores (~/.ssh, ~/.aws) is legitimate"
    )
    risk_level_assessment: str = Field(
        default="LOW",
        description="AI initial risk rating based on static analysis: LOW, MEDIUM, or HIGH"
    )
```

---

### 1.3. Kernel Telemetry & Observation Models

```python
class ObservedKernelTrace(BaseModel):
    files_read: Set[str] = Field(
        default_factory=set,
        description="Set of file paths resolved via openat syscalls with read flags"
    )
    files_written: Set[str] = Field(
        default_factory=set,
        description="Set of file paths resolved via openat syscalls with write flags"
    )
    network_endpoints: Set[str] = Field(
        default_factory=set,
        description="Set of IP:Port endpoints captured from connect syscalls"
    )
    spawned_binaries: Set[str] = Field(
        default_factory=set,
        description="Set of executable basenames captured from execve syscalls"
    )
    timed_out: bool = Field(
        default=False,
        description="Whether the sandbox execution reached the 20-second timeout limit"
    )
    execution_duration_ms: float = Field(
        default=0.0,
        description="Total duration in milliseconds spent inside the kernel sandbox"
    )
```

---

### 1.4. Differential Arbitration & Threat Attribution Models

```python
class SecurityDimension(str, Enum):
    NETWORK = "Network Egress"
    FILESYSTEM = "Filesystem Boundary"
    PROCESS = "Process Execution"

class ViolationRecord(BaseModel):
    dimension: SecurityDimension
    severity: str = Field(description="Severity rating: WARNING or CRITICAL")
    description: str = Field(description="Human-readable violation summary")
    offending_artifact: str = Field(description="Raw path, IP, or binary that triggered the violation")

class DriftResult(BaseModel):
    composite_drift_score: float = Field(ge=0.0, le=1.0)
    network_drift: float = Field(ge=0.0, le=1.0)
    filesystem_drift: float = Field(ge=0.0, le=1.0)
    process_drift: float = Field(ge=0.0, le=1.0)
    is_quarantined: bool
    violations: List[ViolationRecord]

class ThreatAttributionReport(BaseModel):
    threat_score: float
    attack_category: str = Field(
        description="Identified attack vector, e.g., Credential Harvesting, Reverse Shell, Dropper"
    )
    mitre_attack_tactics: List[str] = Field(
        description="Mapped MITRE ATT&CK techniques, e.g., T1552.001, T1071.001"
    )
    culprit_code_snippet: str = Field(
        description="Identified line or statement in lifecycle code responsible for the violation"
    )
    executive_summary: str = Field(
        description="Plain-language forensic explanation detailing what the malware attempted to do"
    )
    remediation_recommendations: List[str] = Field(
        description="Actionable mitigation steps for DevSecOps and developers"
    )
```

---

## 2. System State Machine & Lifecycle Enums

Gatekeeper enforces an explicit, deterministic state machine throughout its execution:

```python
class ExecutionState(str, Enum):
    IDLE = "IDLE"
    INGESTING = "INGESTING"
    SYNTHESIZING_CONTRACT = "SYNTHESIZING_CONTRACT"
    SANDBOXING = "SANDBOXING"
    ARBITRATING = "ARBITRATING"
    ATTRIBUTING_FORENSICS = "ATTRIBUTING_FORENSICS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class VerdictState(str, Enum):
    ALLOW = "ALLOW"             # Exit Code 0: Runtime aligns with intent
    QUARANTINE = "QUARANTINE"   # Exit Code 1: Drift >= 0.40 detected
    ERROR = "ERROR"             # Exit Code 2: System or configuration failure
```

---

## 3. UI/UX Design System (Rich Terminal Interface)

Gatekeeper is designed as a **high-impact, cyber-security command-line tool**. The visual interface delivers instant cognitive clarity through clear color hierarchies, structured comparison tables, live spinners, and diagnostic alert cards.

### 3.1. Color Palette System

The CLI uses a tailored color palette implemented via the Python `rich` library, compatible with 256-color and 24-bit TrueColor terminals:

| Swatch | Name | Hex Code | ANSI Equivalent | UI Semantic Role |
| :---: | :--- | :--- | :--- | :--- |
| ![#00F0FF](https://via.placeholder.com/15/00F0FF/000000?text=+) | **Cyber Neon Cyan** | `#00F0FF` | Cyan (Bold) | Primary brand color, headers, banner accents, status spinners. |
| ![#00FF88](https://via.placeholder.com/15/00FF88/000000?text=+) | **Emerald Green** | `#00FF88` | Green (Bold) | Nominal execution, pass verdicts, allowed permissions, safe artifacts. |
| ![#FF0055](https://via.placeholder.com/15/FF0055/000000?text=+) | **Crimson Alert** | `#FF0055` | Red (Bold) | Critical drift detections, quarantine modals, unauthorized access. |
| ![#FFB703](https://via.placeholder.com/15/FFB703/000000?text=+) | **Amber Gold** | `#FFB703` | Yellow (Bold) | Warnings, medium-risk signals, runtime noise filtering. |
| ![#8A2BE2](https://via.placeholder.com/15/8A2BE2/000000?text=+) | **AI Purple** | `#8A2BE2` | Magenta | AI-specific processes (Ollama synthesis, cognitive reflection). |
| ![#161B22](https://via.placeholder.com/15/161B22/000000?text=+) | **Obsidian Slate** | `#161B22` | Bright Black | Card surface backgrounds, table borders, panel outlines. |
| ![#F0F6FC](https://via.placeholder.com/15/F0F6FC/000000?text=+) | **High-Vis White** | `#F0F6FC` | White (Bold) | Primary readable text, metrics, property names. |
| ![#8B949E](https://via.placeholder.com/15/8B949E/000000?text=+) | **Muted Steel** | `#8B949E` | White (Dim) | Secondary metadata, timestamps, directory paths. |

---

### 3.2. Terminal Layout Components

#### Component 1: The Live Progress Tracker
During execution, `rich.status` displays dynamic status spinners indicating the current state machine phase:

```text
  ⠋ [bold cyan]Step 1/4: Ingesting manifest and analyzing AST code trees...[/bold cyan]
  ⠙ [bold purple]Step 2/4: Synthesizing Expected Behavioral Contract via local SLM...[/bold purple]
  ⠹ [bold blue]Step 3/4: Executing inside unprivileged Bubblewrap namespace sandbox...[/bold blue]
  ⠸ [bold yellow]Step 4/4: Performing differential mathematical vector arbitration...[/bold yellow]
```

#### Component 2: Side-by-Side Comparison Matrix Table
Rendered using `rich.table.Table` with high-contrast column styling:

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Security Property           ┃ SLM Contract (Declared)       ┃ Kernel Intercept (Observed)   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Network Sockets             │ [green]False (Air-gapped)[/green]       │ [bold red]194.26.29.112:443 (TCP)[/bold red]   │
│ Credential Access           │ [green]False (Denied)[/green]           │ [bold red]~/.aws/credentials (Read)[/bold red] │
│ Spawned Binaries            │ [dim]node, touch[/dim]               │ [bold red]python3, curl[/bold red]            │
│ Target Working Directory    │ [dim]/tmp/pkg_sandbox[/dim]           │ [dim]/tmp/pkg_sandbox[/dim]           │
└─────────────────────────────┴───────────────────────────────┴───────────────────────────────┘
```

#### Component 3: Quarantine Alert Card (Critical Drift Verdict)
Rendered using `rich.panel.Panel` with a Crimson (`#FF0055`) border when $D \ge 0.40$:

```text
╭────────────────────────────── VERDICT: QUARANTINE (EXIT CODE 1) ──────────────────────────────╮
│                                                                                              │
│  [bold red]CRITICAL BEHAVIORAL DRIFT DETECTED: Score 0.80 / 1.00[/bold red]                             │
│                                                                                              │
│  [bold yellow]Observed Violations:[/bold yellow]                                                                  │
│  • [red]UNAUTHORIZED NETWORK:[/red] Outbound socket connection to 194.26.29.112:443               │
│    (Contract invariant violated: network_required=False)                                     │
│  • [red]UNAUTHORIZED FILESYSTEM ACCESS:[/red] Read attempt on /home/user/.aws/credentials         │
│    (Contract invariant violated: accesses_user_credentials=False)                           │
│                                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

#### Component 4: AI Forensic Threat Attribution Panel
Rendered directly beneath the Quarantine Alert card, detailing the AI's post-trace investigation:

```text
╭────────────────────── 🤖 AI FORENSIC THREAT ATTRIBUTION REPORT ───────────────────────────────╮
│                                                                                              │
│  [bold cyan]Attack Category:[/bold cyan]  Credential Harvester & Exfiltration Dropper                        │
│  [bold cyan]MITRE ATT&CK:[/bold cyan]     [reverse] T1552.001 (Credentials in Files) [/reverse] [reverse] T1071.001 (Web Protocols) [/reverse]   │
│                                                                                              │
│  [bold cyan]Culprit Code Snippet (Line 8):[/bold cyan]                                                         │
│  [dim]python3 -c 'import socket,os; open(os.path.expanduser("~/.aws/credentials")); ...'[/dim]        │
│                                                                                              │
│  [bold cyan]Forensic Summary:[/bold cyan]                                                                    │
│  The package declared itself as an offline mathematical utility ('fast-math-utils').         │
│  However, during lifecycle execution, it spawned an unmonitored Python process to harvest     │
│  cloud credentials from the user's home directory and transmit them to a remote IP address.  │
│                                                                                              │
│  [bold cyan]Remediation Recommendations:[/bold cyan]                                                        │
│  1. Immediately quarantine and block this package version across internal registries.       │
│  2. Rotate all active AWS access keys associated with the host workstation.                  │
│  3. Verify CI runner environment logs for unexpected egress to 194.26.29.112.                │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

#### Component 5: Nominal Approval Card (Pass Verdict)
Rendered with an Emerald Green (`#00FF88`) border when $D < 0.40$:

```text
╭───────────────────────────────── VERDICT: ALLOW (EXIT CODE 0) ────────────────────────────────╮
│                                                                                              │
│  [bold green]NOMINAL EXECUTION: Drift Score 0.00 / 1.00[/bold green]                                            │
│                                                                                              │
│  All observed kernel actions (file creation, local binary execution) align with declared    │
│  semantic intent. No unauthorized network egress or credential access detected.              │
│                                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

---

<div align="center">
  <sub>Gatekeeper Schemas & UI/UX • Confidential & Open-Source Engineering Specification</sub>
</div>
