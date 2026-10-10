# Technical Requirements Document (TRD)

## Project: Gatekeeper (*Autonomous Semantic-to-Kernel Drift Detector*)

---

## 1. System Overview & Technology Stack

Gatekeeper couples local neuro-symbolic open-weight language models with low-level Linux kernel isolation to deliver deterministic supply chain security. This document outlines the technical specifications, library dependencies, module architectures, directory structures, and subsystem interfaces.

### 1.1. Core Technology Stack & Library Matrix

| Layer / Subsystem | Technology / Library | Version | Architecture Role & Technical Rationale |
| :--- | :--- | :--- | :--- |
| **Language Runtime** | Python | `>= 3.10` | Core orchestration, typing system, async capabilities, and cross-module glue. |
| **Local AI Engine** | Ollama | `>= 0.3.0` | Local model server exposing OpenAI-compatible REST API on port `11434`; provides zero-latency GPU acceleration (CUDA, ROCm, Metal) and strict JSON schema constrained decoding. |
| **AI Model** | `qwen2.5-coder:7b` | `7B-Instruct (Q4_K_M)` | State-of-the-art open-weight model for AST reasoning, code intelligence, and structured JSON generation; sub-5GB VRAM footprint. |
| **Data Validation** | Pydantic v2 | `^2.7.0` | High-performance Rust-backed data modeling, schema export (`model_json_schema()`), and JSON validation (`model_validate_json()`). |
| **Static Code Parsing**| Tree-Sitter & Bindings | `^0.22.0` | Multi-language concrete syntax tree (CST) and AST generation for JavaScript, Python, and shell scripts without executing code. |
| **Namespace Isolation**| Bubblewrap (`bwrap`) | `>= 0.8.0` | Linux unprivileged namespace containerization (`CLONE_NEWNS`, `CLONE_NEWPID`), read-only mount bindings, and ephemeral `/tmp` allocation. |
| **Syscall Interception**| `strace` | `>= 5.16` | Filtered system call interception (`-e trace=openat,connect,execve`) with child process following (`-f`). (Planned roadmap transition to eBPF). |
| **HTTP Client** | HTTPX | `^0.27.0` | Asynchronous and synchronous HTTP client with connection pooling for local Ollama REST interactions. |
| **Terminal UI** | Rich | `^13.7.0` | Terminal presentation engine for live status spinners, ANSI comparison tables, forensic alert panels, and syntax-highlighted code diffs. |
| **Test Automation** | Pytest & Pytest-Asyncio| `^8.1.0` | Unit, integration, and behavioral test suite runner with fixture harnesses. |

---

## 2. Project Directory Structure

To ensure maintainability and strict architectural boundaries, Gatekeeper is organized into decoupled functional blocks. Every functional block contains its own dedicated `tests/` directory and an `ai_decisions.log` file capturing all architectural trade-offs, engineering decisions, and security invariants formulated during implementation.

```text
gatekeeper/
├── pyproject.toml                     # Poetry/pip build configuration & dependencies
├── README.md                          # Visual product overview & quickstart
├── docs/                              # Comprehensive engineering specifications
│   ├── PRD.md                         # Product Requirements Document
│   ├── TRD.md                         # Technical Requirements Document (this document)
│   ├── APP_FLOW.md                    # Subsystem Interaction & App Flow
│   ├── SCHEMA_AND_UI_DESIGN.md        # Data Schemas & Terminal UI/UX Design
│   └── IMPLEMENTATION_PLAN.md         # Phased Rollout & Parallelization Roadmap
│
├── core/
│   ├── schema/                        # BLOCK 1: Data Contracts & Type Definitions
│   │   ├── __init__.py
│   │   ├── contract.py                # ExpectedBehaviorContract Pydantic model
│   │   ├── telemetry.py               # Kernel syscall trace data structures
│   │   ├── forensics.py               # AI Threat Attribution & Incident report models
│   │   ├── ai_decisions.log           # AI architectural decisions for schema block
│   │   └── tests/
│   │       ├── __init__.py
│   │       └── test_schema.py         # Schema validation & serialization tests
│   │
│   ├── ai_engine/                     # BLOCK 2: Local AI & Multi-Agent Inference
│   │   ├── __init__.py
│   │   ├── client.py                  # HTTPX client for local Ollama daemon
│   │   ├── prompts.py                 # System prompts & schema injection templates
│   │   ├── agents.py                  # Intent Synthesizer & Adversarial Red-Team agents
│   │   ├── forensic_agent.py          # Post-trace AI Threat Attribution Explainer
│   │   ├── ai_decisions.log           # AI architectural decisions for inference block
│   │   └── tests/
│   │       ├── __init__.py
│   │       └── test_ai_engine.py      # Prompt formatting & mock Ollama response tests
│   │
│   ├── extractor/                     # BLOCK 3: Static Manifest & AST Code Extraction
│   │   ├── __init__.py
│   │   ├── manifest_parser.py         # package.json and setup.py metadata parser
│   │   ├── ast_inspector.py           # Tree-Sitter AST token and call-graph parser
│   │   ├── runner_builder.py          # Standalone execution script generator (.sh)
│   │   ├── ai_decisions.log           # AI architectural decisions for extractor block
│   │   └── tests/
│   │       ├── __init__.py
│   │       └── test_extractor.py      # Multi-ecosystem hook extraction tests
│   │
│   ├── sandbox/                       # BLOCK 4: Kernel Isolation & Syscall Tracing
│   │   ├── __init__.py
│   │   ├── bwrap.py                   # Bubblewrap mount & namespace runner
│   │   ├── tracer.py                  # strace filtered invocation & process monitor
│   │   ├── log_parser.py              # Regex/stream parser for openat, connect, execve
│   │   ├── ai_decisions.log           # AI architectural decisions for sandbox block
│   │   └── tests/
│   │       ├── __init__.py
│   │       └── test_sandbox.py        # Sandboxed execution & mock trace tests
│   │
│   ├── arbitrator/                    # BLOCK 5: Differential Drift Arbitration Engine
│   │   ├── __init__.py
│   │   ├── scorer.py                  # Mathematical multi-axis drift vector calculator
│   │   ├── heuristics.py              # Sensitive asset paths & system loader whitelists
│   │   ├── violations.py              # Violation formatting & discrepancy categorizer
│   │   ├── ai_decisions.log           # AI architectural decisions for arbitrator block
│   │   └── tests/
│   │       ├── __init__.py
│   │       └── test_arbitrator.py     # Drift scoring vector math tests
│   │
│   └── cli/                           # BLOCK 6: Presentation & CI/CD Gatekeeper
│       ├── __init__.py
│       ├── main.py                    # Entrypoint CLI command dispatcher
│       ├── ui.py                      # Rich terminal tables, spinners, and panels
│       ├── reporters.py               # JSON, SARIF, and terminal export formats
│       ├── ai_decisions.log           # AI architectural decisions for CLI block
│       └── tests/
│           ├── __init__.py
│           └── test_cli.py            # Exit code & CLI flag integration tests
│
└── fixtures/                          # Standardized Real-World Test Packages
    ├── benign-canvas/                 # Safe native compile helper (touch/make)
    ├── malicious-telemetry/           # AWS credential stealer with socket connect
    └── evasive-obfuscated/            # Base64 eval() reverse shell payload
```

---

## 3. Subsystem Technical Specifications & Folder-Level Architecture

### 3.1. Block 1: `core/schema/` (Data Contracts & Invariants)

#### Purpose & Responsibilities
Defines the immutable data structures used across all subsystems. Guarantees type safety between the generative AI output and deterministic kernel telemetry.

#### Module Specifications
- **`contract.py`**: Declares `ExpectedBehaviorContract` using Pydantic v2:
  - `package_name` *(str)*: Unique package name.
  - `purpose` *(str)*: Plain-text functional summary generated by the AI.
  - `network_required` *(bool)*: Boolean flag for remote HTTP/socket calls.
  - `allowed_domains` *(List[str])*: Destination hostnames or CIDRs.
  - `allowed_read_prefixes` / `allowed_write_prefixes` *(List[str])*: Allowed path prefixes.
  - `allowed_binaries` *(List[str])*: Authorized executables.
  - `accesses_user_credentials` *(bool)*: Whether accessing credential stores is legitimate.
- **`telemetry.py`**: Declares `ObservedKernelTrace`:
  - `files_read` *(Set[str])*: Paths extracted from `openat`.
  - `files_written` *(Set[str])*: Paths extracted from `openat` with `O_WRONLY`/`O_RDWR`.
  - `network_endpoints` *(Set[str])*: IP/Port tuples extracted from `connect`.
  - `spawned_binaries` *(Set[str])*: Executable basenames extracted from `execve`.
  - `execution_duration_ms` *(float)*: Runtime duration inside the sandbox.
- **`forensics.py`**: Declares `ThreatAttributionReport`:
  - `threat_score` *(float)*: Composite drift score.
  - `mitre_tactics` *(List[str])*: Relevant MITRE ATT&CK techniques.
  - `suspect_ast_nodes` *(List[str])*: Source code tokens corresponding to violation.
  - `executive_summary` *(str)*: AI-generated plain-language attack summary.
  - `remediation_steps` *(List[str])*: Actionable mitigation advice.

#### Structure of `core/schema/ai_decisions.log`
```text
[DECISION-SCHEMA-001] Pydantic v2 Selected over Marshmallow/Attrs
- Context: Need rapid compilation of JSON Schemas for local Ollama decoding.
- Decision: Use Pydantic v2 (pydantic.BaseModel.model_json_schema()).
- Rationale: Core Rust serialization engine provides 15x faster validation; native compatibility with Ollama's format="json".

[DECISION-SCHEMA-002] Set Datatypes for Observed Kernel Traces
- Context: Kernel syscall traces emit duplicate file opens and IP connects.
- Decision: Use Set[str] instead of List[str] in ObservedKernelTrace.
- Rationale: Guarantees O(1) set operations during differential comparison and removes deduplication overhead in the arbitrator.
```

---

### 3.2. Block 2: `core/ai_engine/` (Local AI & Multi-Agent Inference)

#### Purpose & Responsibilities
Orchestrates on-premises inference against the local Ollama daemon. Implements a multi-agent cognitive loop combining functional intent synthesis, adversarial red-teaming, and post-trace forensic attribution.

#### Multi-Agent Implementation Architecture
1. **`client.py`**:
   - Manages connection pools via `httpx.AsyncClient` targeting `http://localhost:11434`.
   - Health-checks the Ollama daemon and confirms `qwen2.5-coder:7b` is present.
   - Handles connection timeouts with automatic retries and fail-closed security defaults.
2. **`prompts.py`**:
   - Contains immutable prompt templates.
   - Enforces the **Air-Gapped Least Privilege System Prompt**:
     ```text
     You are an air-gapped security analyzer reviewing an open-source package installation script.
     Analyze the package metadata, dependencies, and lifecycle code.
     Synthesize a strict Expected Behavioral Contract (EBC) in JSON format.
     Grant permissions ONLY if explicit, unambiguous technical evidence exists.
     ```
3. **`agents.py`**:
   - **`IntentSynthesizerAgent`**: Analyzes package manifest, README, and dependencies to produce a draft contract.
   - **`AdversarialRedTeamAgent`**: Inspects code comments and strings for deceptive evasion or prompt injection tokens. If deception is detected, overrides draft contract permissions with strict defaults.
4. **`forensic_agent.py`**:
   - Activated only when arbitration detects a critical drift ($D \ge 0.40$).
   - Prompts the SLM with the captured syscall trace alongside the extracted source code to produce the `ThreatAttributionReport`.

#### Structure of `core/ai_engine/ai_decisions.log`
```text
[DECISION-AI-001] Strict Zero Temperature Configuration
- Context: LLM outputs must be reproducible and deterministic across identical packages.
- Decision: Force temperature=0.0 and top_p=1.0 in all Ollama API calls.
- Rationale: Eliminates probabilistic randomness in security boundary synthesis.

[DECISION-AI-002] Multi-Agent Separation of Intent vs. Code Inspection
- Context: Monolithic prompts conflate natural language intent with adversarial code tricks.
- Decision: Separate analysis into IntentSynthesizerAgent and AdversarialRedTeamAgent.
- Rationale: Prevents adversarial comments in source code from poisoning the perceived high-level intent.
```

---

### 3.3. Block 3: `core/extractor/` (Static Manifest & AST Code Extraction)

#### Purpose & Responsibilities
Passively discovers package build configurations and lifecycle hooks across NPM and Python ecosystems without executing any untrusted code.

#### Module Specifications
- **`manifest_parser.py`**:
  - Parses `package.json` for NPM (`preinstall`, `install`, `postinstall`, `dependencies`, `devDependencies`).
  - Parses `setup.py`, `setup.cfg`, and `pyproject.toml` for Python (`cmdclass`, custom `build_py`, `install` hooks).
- **`ast_inspector.py`**:
  - Utilizes Tree-Sitter grammars (`tree-sitter-javascript`, `tree-sitter-python`).
  - Identifies dangerous AST nodes:
    - JavaScript: `CallExpression` referencing `child_process.exec`, `eval()`, `fs.readFile`, `http.request`, `net.connect`.
    - Python: `ImportFrom` referencing `subprocess`, `socket`, `urllib`, `requests`, `os.system`.
  - Flags high-entropy strings and hex/base64 encoded payloads for adversarial review.
- **`runner_builder.py`**:
  - Converts inline manifest shell commands into a sanitized runner script (`.sysdrift_<hook>.sh`).
  - Prepends `#!/usr/bin/env bash` and sets executable bits (`0755`).

#### Structure of `core/extractor/ai_decisions.log`
```text
[DECISION-EXTRACT-001] Tree-Sitter over Native Python ast/esprima
- Context: Gatekeeper must parse multiple programming languages in polyglot projects.
- Decision: Standardize on Tree-Sitter with compiled language bindings.
- Rationale: Unified C-based AST interface across JavaScript, Python, and Shell; resistant to syntax crashes.

[DECISION-EXTRACT-002] Passive Extraction Sandbox Isolation
- Context: Some tools invoke `node -e` or `python setup.py --dry-run` to inspect metadata.
- Decision: Strictly prohibit runtime invocation during extraction; parse files purely as static text/AST.
- Rationale: Invoking Python or Node during inspection allows malicious packages to execute before sandboxing begins.
```

---

### 3.4. Block 4: `core/sandbox/` (Kernel Isolation & Syscall Tracing)

#### Purpose & Responsibilities
Executes untrusted lifecycle scripts inside an isolated Linux namespace container using Bubblewrap (`bwrap`) while capturing low-level system call telemetry via `strace`.

#### Module Specifications
- **`bwrap.py`**:
  - Constructs the Bubblewrap execution command with minimum privileges:
    ```bash
    bwrap \
      --ro-bind /usr /usr \
      --ro-bind /lib /lib \
      --ro-bind /lib64 /lib64 \
      --ro-bind /bin /bin \
      --ro-bind /etc/resolv.conf /etc/resolv.conf \
      --proc /proc \
      --dev /dev \
      --bind {working_dir} {working_dir} \
      --tmpfs /tmp \
      --unshare-pid \
      --unshare-user \
      --chdir {working_dir} \
      bash {script_path}
    ```
- **`tracer.py`**:
  - Prefixes the `bwrap` command with `strace`:
    ```bash
    strace -f -s 512 -e trace=openat,connect,execve -o {trace_log_path} -- <bwrap_cmd>
    ```
  - Runs with a strict `timeout=20` seconds via `subprocess.run()`.
  - Catches `TimeoutExpired` exceptions and marks execution as a potential timing-bomb evasion.
- **`log_parser.py`**:
  - Streams the `strace` output log and extracts telemetry using compiled regex patterns:
    - `openat`: Captures path from `openat\(AT_FDCWD,\s*"([^"]+)",\s*([A-Z_|]+)`.
    - `connect`: Captures address and port from `sin_addr=inet_addr\("([^"]+)"\),\s*sin_port=htons\((\d+)\)`.
    - `execve`: Captures executable path from `execve\("([^"]+)"`.

#### Structure of `core/sandbox/ai_decisions.log`
```text
[DECISION-SANDBOX-001] Bubblewrap Selected over Docker/Podman
- Context: CI/CD runners and developer workstations may not allow nested Docker-in-Docker or root daemon access.
- Decision: Use Bubblewrap (bwrap) as the primary isolation engine.
- Rationale: Operates completely unprivileged using Linux user namespaces (CLONE_NEWUSER); native installation via apt/dnf with zero background daemons.

[DECISION-SANDBOX-002] Selective Syscall Filtering (-e trace=openat,connect,execve)
- Context: Full strace capturing slows execution by 10x-50x due to context switching on read/write/stat calls.
- Decision: Restrict strace tracing strictly to openat, connect, and execve.
- Rationale: Reduces strace tracing overhead to < 2.5x while capturing 100% of the security-critical attack vectors.
```

---

### 3.5. Block 5: `core/arbitrator/` (Differential Drift Arbitration Engine)

#### Purpose & Responsibilities
Performs deterministic mathematical vector arbitration between the synthesized `ExpectedBehaviorContract` and the observed `ObservedKernelTrace`.

#### Mathematical Formulation & Module Specifications
- **`scorer.py`**:
  - Implements the multi-dimensional drift formula:
    $$D = (0.45 \cdot D_{\text{net}}) + (0.35 \cdot D_{\text{fs}}) + (0.20 \cdot D_{\text{proc}})$$
  - Where:
    - $D_{\text{net}} \in \{0.0, 1.0\}$: $1.0$ if non-loopback IPs connected when `contract.network_required == False` or target IP not in `contract.allowed_domains`.
    - $D_{\text{fs}} \in [0.0, 1.0]$: $1.0$ if sensitive targets touched or file paths outside `contract.allowed_read_prefixes`.
    - $D_{\text{proc}} \in [0.0, 1.0]$: $\min\left(1.0, \frac{|\text{Unauthorized Binaries}|}{2}\right)$.
- **`heuristics.py`**:
  - Hardcoded sensitive target list:
    ```python
    SENSITIVE_TARGETS = [
        ".ssh", ".aws", ".env", ".gnupg", ".git-credentials",
        "/etc/shadow", "/etc/passwd", ".kube/config", ".docker/config.json"
    ]
    ```
  - System runtime whitelist (noise reduction):
    ```python
    SYSTEM_RUNTIME_WHITELIST = {"bash", "sh", "bwrap", "node", "python3", "ld-linux"}
    ```
- **`violations.py`**:
  - Categorizes discrepancies into actionable diagnostic strings for terminal and SARIF presentation.

#### Structure of `core/arbitrator/ai_decisions.log`
```text
[DECISION-ARB-001] Weighted Asymmetry in Drift Formulation
- Context: Supply chain malware prioritizes network exfiltration and credential theft over binary spawning.
- Decision: Assign weights: Network (0.45), Filesystem (0.35), Process Spawn (0.20).
- Rationale: A single unauthorized network connection or credential read should independently trigger quarantine (threshold = 0.40).

[DECISION-ARB-002] Exclusion of Localhost and DNS Resolvers
- Context: System glibc and Node.js loaders routinely connect to 127.0.0.53:53 (systemd-resolved).
- Decision: Filter out 127.0.0.1 and 127.0.0.53 from external network drift calculations.
- Rationale: Prevents benign local DNS queries from being misclassified as malicious C2 outbound exfiltration.
```

---

### 3.6. Block 6: `cli/` (Presentation & CI/CD Gatekeeper)

#### Purpose & Responsibilities
Provides the user-facing CLI application, formats rich terminal dashboards, emits SARIF/JSON logs, and returns deterministic exit codes for CI/CD gating.

#### Module Specifications
- **`main.py`**:
  - Command-line argument parsing (`package_dir`, `--format=[terminal|json|sarif]`, `--threshold`, `--verbose`).
  - Top-level workflow coordinator connecting blocks 1 through 5.
- **`ui.py`**:
  - Constructs terminal dashboards using `rich.console`, `rich.table`, and `rich.panel`.
  - Color palette: Cyan (Status), Amber (Warning), Emerald Green (Pass), Crimson Red (Quarantine).
- **`reporters.py`**:
  - Formats output for automation:
    - Standard JSON report.
    - SARIF (OASIS Static Analysis Results Format) for GitHub Code Scanning tab integration.

#### Structure of `core/cli/ai_decisions.log`
```text
[DECISION-CLI-001] Strict POSIX Exit Code Contract
- Context: CI/CD build scripts rely on standard exit codes to halt automated pipelines.
- Decision: Exit code 0 for PASS (Nominal), Exit code 1 for QUARANTINE, Exit code 2 for CLI/System errors.
- Rationale: Guarantees zero friction when integrating Gatekeeper into GitHub Actions, GitLab CI, or Dockerfiles.

[DECISION-CLI-002] Dual Output Mode (Human Visual vs. Machine SARIF)
- Context: Developers need interactive terminal tables; CI runners need structured vulnerability uploads.
- Decision: Implement terminal rendering via Rich and structured SARIF v2.1.0 output via reporters.py.
- Rationale: Maximizes developer adoption locally while enabling native enterprise reporting in GitHub Security tabs.
```

---

<div align="center">
  <sub>Gatekeeper TRD • Confidential & Open-Source Engineering Specification</sub>
</div>
