# Gatekeeper: Project Explanation

This document explains Gatekeeper in plain language. It is meant for someone who is new to the repository and wants to understand what the project does, how the pieces fit together, and how to run it.

## 1. What Is Gatekeeper?

Gatekeeper is a security scanner for software packages.

Many packages run scripts while they are being installed. For example, an NPM package can run a `postinstall` script, and a Python package can run code through `setup.py` or a build backend. These scripts are powerful enough to read files, start programs, and make network connections.

That power is useful for legitimate build work, but it also creates a supply-chain security risk. A malicious package could try to:

- read SSH, AWS, or other credentials;
- connect to an unexpected server;
- download a second malware stage;
- launch a shell or another process; or
- change files outside its own workspace.

Gatekeeper asks a simple question:

> Does the package do what it claims to do?

It answers that question by comparing two things:

1. **Expected behavior**: what the package appears to need based on its metadata, source, and documentation.
2. **Observed behavior**: what the package actually attempts while it runs in a restricted sandbox.

If the observed behavior goes beyond the expected behavior, Gatekeeper reports drift and can quarantine the package.

## 2. The Main Idea

Gatekeeper uses three kinds of analysis together:

```text
Package files
    |
    v
Static extraction and local AI analysis
    |
    v
Expected Behavior Contract
    |
    +--------------------------+
    |                          |
    v                          v
Sandboxed execution       Syscall trace
    |                          |
    +------------+-------------+
                 v
          Drift arbitration
                 |
          ALLOW or QUARANTINE
```

The local AI is used to describe the package's expected behavior. It is not trusted to make the final decision. The final decision is based on structured contracts, observed telemetry, and deterministic arbitration rules.

## 3. What Happens During a Scan?

### Step 1: Find the package information

The extractor checks the target directory for common package files:

- `package.json` for NPM packages;
- `pyproject.toml`, `setup.py`, or `setup.cfg` for Python packages; and
- `install.sh`, `setup.sh`, or `build.sh` for standalone scripts.

It collects the package name, version, description, dependencies, and lifecycle command.

### Step 2: Find suspicious source behavior

The AST inspector examines source code without executing it. It can identify useful signals such as imports, network-related code, credential paths, high-entropy strings, and child-process activity.

This is not treated as proof by itself. It is context for the expected contract and later forensic reporting.

### Step 3: Build an Expected Behavior Contract

The AI engine can use a local Ollama model to turn package context into a structured contract. The contract describes:

- whether network access is required;
- which domains are allowed;
- which directories may be read;
- which directories may be written;
- which binaries may be started; and
- the initial risk level.

The contract is validated with Pydantic. If the AI service is unavailable or produces invalid output, the project has a zero-trust fallback that allows as little as possible.

### Step 4: Run the package in a sandbox

The sandbox runs the selected script without giving it normal access to the host machine. Gatekeeper supports two isolation backends:

- **Docker**: the normal cross-platform choice, especially on Windows and macOS through Docker Desktop.
- **Bubblewrap**: a native Linux option when unprivileged namespaces are available.

With `backend="auto"`, Gatekeeper selects a suitable backend for the host.

### Step 5: Record important system calls

The tracer records a focused set of system calls:

- `open`, `openat`, `openat2`, and `creat` for file access;
- `connect` for network connection attempts; and
- `execve` and `execveat` for started programs.

The parser normalizes these records into an `ObservedKernelTrace`. It also handles escaped paths, process IDs, error results, IPv4 and IPv6 addresses, Unix sockets, unfinished calls, and resumed calls.

### Common Syscalls That Can Flag Malicious Behavior

The syscall name alone does not prove that a package is malicious. Build tools often need to read files, create output files, connect to package registries, or start compiler processes. Gatekeeper flags behavior when it is unexpected for the package's contract, especially when several suspicious actions appear together.

| Syscall | What it means | Why it may be suspicious |
| --- | --- | --- |
| `open`, `openat`, `openat2` | Opens a file or directory. The parser records the path and whether the access is read, write, or read-write. | Reading `~/.ssh`, `~/.aws/credentials`, `.env`, `.kube/config`, `/etc/shadow`, or other files outside the package's allowed paths can indicate credential theft or host reconnaissance. |
| `creat` | Creates a file for writing. Gatekeeper normalizes it as a write operation. | Writing executables, shell scripts, startup files, or files outside the workspace can indicate payload installation or persistence. |
| `connect` | Attempts to connect a socket to an IP address, hostname-derived endpoint, port, or Unix socket. | An offline utility that connects to an unknown public IP, an unexpected port, or a local sensitive socket such as Docker's socket may be attempting exfiltration, command-and-control, or host access. Failed connections still count as attempts. |
| `execve` | Starts a program and provides its argument list. | Launching `curl`, `wget`, a shell, a scripting interpreter, or an unknown binary can be suspicious when it is not required by the package's declared build process. |
| `execveat` | Starts a program using a file descriptor or directory-relative path. | It can hide the exact launch path from a simple filename check, so an unexpected `execveat` is retained as process evidence. |

Examples of high-risk combinations include:

- `openat("~/.aws/credentials", O_RDONLY)` followed by `connect(...)` to an unapproved remote endpoint;
- `open` or `creat` writing a script or binary, followed by `execve` of that new file;
- `connect` to a remote server followed by `execve("/bin/sh", ...)` or another interpreter; and
- an unfinished `connect(...) <unfinished ...>` at timeout, which is preserved as an `UNFINISHED` network event rather than discarded.

The parser also keeps failed attempts such as `ECONNREFUSED` and `ENETUNREACH`. A failed connection can still reveal the package's intent. The arbitration layer then decides whether the path, endpoint, or executable violates the expected contract and whether the composite drift score reaches the quarantine threshold.

### Step 6: Compare expected and observed behavior

The arbitrator calculates drift in three areas:

- network behavior;
- filesystem behavior; and
- process behavior.

The result contains a composite score, individual scores, and human-readable violations. The default quarantine threshold is `0.40`.

### How the Drift Factor Is Calculated

Each dimension receives a score between `0.0` and `1.0`:

```text
D = (0.45 * D_net) + (0.35 * D_fs) + (0.20 * D_proc)
```

The dimensions are weighted differently because unexpected network access and sensitive file access are usually more dangerous than one extra helper process.

#### Network score: `D_net`

- `0.0` when there are no unexpected external connections.
- `1.0` when the contract forbids network access and the package attempts an external connection.
- `1.0` when network access is allowed but the destination is not in `allowed_domains`.
- Loopback connections are filtered as local activity.

A network score of `1.0` contributes `0.45` to the composite score. That alone is enough to pass the default quarantine threshold of `0.40`.

#### Filesystem score: `D_fs`

- `0.0` when all observed reads and writes fit the contract.
- `1.0` when the package accesses sensitive credentials without permission.
- Otherwise, each unapproved path contributes a penalty of `0.5`, capped at `1.0`.
- Sensitive paths include locations such as `.ssh`, `.aws`, `.env`, `.kube/config`, password files, and other protected targets.

An unauthorized credential read is treated as a security invariant violation. It independently forces quarantine, even if the weighted score would otherwise be below the threshold.

#### Process score: `D_proc`

- Standard runtime binaries are filtered to reduce normal build noise.
- Declared binaries in `allowed_binaries` do not add drift.
- An undeclared binary contributes `0.5` per binary, capped at `1.0`.
- High-risk tools such as `curl`, `wget`, `nc`, `socat`, PowerShell, `whoami`, and `id` receive critical-severity violation records when they are not declared.

#### Timeout behavior

A sandbox timeout adds a timeout violation and increases process drift by `0.5`. A timeout also independently forces quarantine because an infinite loop or timing bomb must not be treated as a clean result.

### How Gatekeeper Allows or Quarantines a Package

The decision process is:

1. Build the expected behavior contract.
2. Collect the observed kernel trace.
3. Calculate `D_net`, `D_fs`, and `D_proc`.
4. Combine them into the composite score `D`.
5. Compare `D` with the configured threshold, which defaults to `0.40`.

```text
if composite_drift_score >= threshold:
    QUARANTINE
else:
    ALLOW
```

Examples with the default threshold:

| Situation | Example score | Result |
| --- | ---: | --- |
| Declared local build, no unexpected activity | `0.00` | `ALLOW` |
| One undeclared helper process | `0.10` | `ALLOW`, with a warning |
| One unauthorized external network connection | `0.45` | `QUARANTINE` |
| Unauthorized credential access | At least `0.40` | `QUARANTINE` |
| Timeout or timing-bomb behavior | At least `0.40` | `QUARANTINE` |
| Several filesystem and process violations | `0.40` or higher | `QUARANTINE` |

The report includes the score, each dimension score, and the violations that caused it. A quarantined scan returns exit code `1`, which allows CI systems to stop the installation or build. An allowed scan returns exit code `0`. Invalid command usage or a missing target path returns exit code `2`.

Changing `--threshold` changes the sensitivity of the final comparison, but it does not remove the evidence or violation records from the report. Lower thresholds quarantine more behavior; higher thresholds allow more behavior before the final gate closes.

### Step 7: Produce a report

The CLI can display a Rich terminal report or write JSON and SARIF output. A quarantine report can include a forensic explanation, suspicious code context, MITRE ATT&CK tags, and recommended actions.

## 4. Repository Structure

```text
gatekeeper/
|
+-- core/
|   +-- ai_engine/
|   |   +-- client.py          Ollama HTTP client
|   |   +-- agents.py          Intent and adversarial analysis agents
|   |   +-- forensic_agent.py  Threat explanation support
|   |   +-- prompts.py         AI system and task prompts
|   |   +-- tests/             AI engine tests
|   |
|   +-- cli/
|   |   +-- main.py            Main pipeline and command-line entry point
|   |   +-- reporters.py       JSON and SARIF report generation
|   |   +-- ui.py              Rich terminal output
|   |   +-- tests/             CLI tests
|   |
|   +-- extractor/
|   |   +-- manifest_parser.py Package manifest parsing
|   |   +-- ast_inspector.py   Static source inspection
|   |   +-- runner_builder.py  Lifecycle script preparation
|   |   +-- tests/             Extractor tests
|   |
|   +-- schema/
|       +-- contract.py        Expected behavior contract
|       +-- extraction.py      Static extraction models
|       +-- telemetry.py       Observed kernel trace model
|       +-- arbitration.py     Drift and violation models
|       +-- forensics.py        Threat report model
|       +-- tests/              Schema tests
|
+-- sandbox/
|   +-- bwrap.py               Docker, Bubblewrap, and shared sandbox config
|   +-- tracer.py              Script execution and tracing orchestration
|   +-- log_parser.py          Strace parser and telemetry conversion
|   +-- __main__.py             Direct sandbox command-line interface
|   +-- Dockerfile              Optional sandbox image
|   +-- tests/                  Sandbox tests and live scenarios
|
+-- fixtures/                   Safe test packages and attack examples
+-- docs/                       Design and implementation documentation
+-- pyproject.toml              Dependencies and installed CLI commands
```

The `core/sandbox/` package contains compatibility forwarding modules for code that imports the sandbox through the `core` namespace. The implementation is kept in the top-level `sandbox/` package.

## 5. Security Defaults

The Docker sandbox is intentionally restrictive. Its default protections include:

- no network access;
- a read-only container root filesystem;
- a read-only workspace mount;
- isolated temporary filesystems for `/tmp` and `/run`;
- dropped Linux capabilities;
- `no-new-privileges`;
- a non-root container user;
- memory, CPU, and process limits;
- a strict host-side timeout; and
- forceful cleanup after timeout or failure.

Host path validation rejects mounts involving sensitive resources such as user home directories, `.ssh`, `.aws`, `.docker`, private keys, password files, and Docker sockets.

Trace data is written to a separate temporary trace location instead of the untrusted workspace. This prevents the tested script from changing its own forensic log.

The sandbox fails closed when Docker or tracing is unavailable. An unavailable or incomplete trace is reported as an error state, not as evidence that the package is harmless.

## 6. Using the Project

### Install the project

Python 3.10 or newer is required. From the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
```

### Scan a package

```bash
gatekeeper ./fixtures/benign-canvas
```

The equivalent module command is:

```bash
python -m core.cli.main ./fixtures/benign-canvas
```

### Select an output format

```bash
# Terminal report
gatekeeper ./fixtures/fake-popup --format terminal

# JSON report
gatekeeper ./fixtures/fake-popup --format json

# SARIF report for CI tools
gatekeeper ./fixtures/fake-popup --format sarif --output gatekeeper.sarif
```

### Change the quarantine threshold

```bash
gatekeeper ./fixtures/fake-popup --threshold 0.40
```

### Run the sandbox directly

```bash
python -m sandbox <script_path> <workspace_dir> --backend auto --timeout 20
```

Choose a backend explicitly when needed:

```bash
python -m sandbox <script_path> <workspace_dir> --backend docker
python -m sandbox <script_path> <workspace_dir> --backend bwrap
```

Parse an existing strace log:

```bash
python -m sandbox --parse-trace path/to/strace.log --json
```

## 7. Exit Codes

The main Gatekeeper CLI uses these exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | Allowed or no drift found |
| `1` | Quarantined, or execution failed |
| `2` | Invalid command usage or path error |

CI systems can use the exit code as a gate, while the JSON or SARIF report provides the details.

## 8. Local AI Configuration

The Ollama client uses these defaults:

- server: `http://localhost:11434`;
- model: `qwen2.5-coder:7b`; and
- request timeout: 30 seconds.

You can override the server and model with environment variables:

```bash
GATEKEEPER_OLLAMA_HOST=http://localhost:11434
GATEKEEPER_MODEL=qwen2.5-coder:7b
```

The model must already be available in Ollama. The project uses structured JSON responses and validates them against the Pydantic contract models.

## 9. Testing

Run all configured tests:

```bash
python -m pytest
```

Run the sandbox tests directly:

```bash
python -m unittest discover -s sandbox/tests -v
```

Tests include schema validation, parser cases, CLI behavior, security argument checks, timeout handling, unavailable-runtime behavior, and live sandbox scenarios. Live Docker tests require a running Docker Linux engine. Bubblewrap tests require a compatible Linux host when they are not mocked.

## 10. Fixtures

The repository includes small fixtures for repeatable testing:

- `fixtures/benign-canvas/`: a package intended to represent ordinary local build work;
- `fixtures/fake-popup/`: a suspicious standalone shell script; and
- `fixtures/malicious-telemetry/`: a malicious behavior scenario used by tests.

Do not run unknown package scripts directly on your host. Use an isolated environment.

## 11. Important Limitations

Gatekeeper is designed for install-time package checks, not continuous production monitoring.

Docker isolates processes and namespaces but still shares the host kernel. It is not the same as a virtual machine. Higher-risk analysis may require an additional boundary such as gVisor or a microVM.

The tracer observes connection endpoints and ports. It does not decrypt or inspect the contents of encrypted network traffic.

Linux tracing capabilities are required. Windows users generally need Docker Desktop's Linux engine or WSL2 for the sandbox path.

The repository contains both implemented components and design documents for planned expansion. The README and source code are the best references for the current command behavior.

## 12. More Documentation

- [Product requirements](PRD.md)
- [Technical requirements](TRD.md)
- [Application flow](APP_FLOW.md)
- [Schema and UI design](SCHEMA_AND_UI_DESIGN.md)
- [Implementation plan](IMPLEMENTATION_PLAN.md)
- [Sandbox execution and decision log](../sandbox/log.md)
