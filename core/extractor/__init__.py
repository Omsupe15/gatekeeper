"""Block 3: Static Manifest & AST Code Extraction.

Discovers package metadata, parses lifecycle script hooks (NPM, Python, Standalone),
inspects code ASTs for dangerous tokens and high-entropy strings, and compiles
hermetic runner scripts (.sysdrift_<hook>.sh) for sandbox tracing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from core.extractor.ast_inspector import (
    ASTInspector,
    calculate_shannon_entropy,
)
from core.extractor.manifest_parser import (
    ManifestParser,
    ParsedManifest,
)
from core.extractor.runner_builder import RunnerBuilder
from core.schema.extraction import (
    ASTSuspiciousToken,
    EcosystemType,
    ExtractionContext,
    LifecycleHookType,
)


def has_lifecycle_hooks(package_dir: str | Path) -> bool:
    """Checks whether a package contains executable lifecycle installation hooks.

    Fast check used by CLI orchestrator to take the < 50ms fast-path exit 0.
    """
    manifest = ManifestParser.parse_directory(package_dir)
    return manifest.has_lifecycle_hook


def extract_context(
    package_dir: str | Path,
    runner_output_dir: Optional[str | Path] = None,
    allow_empty: bool = False,
) -> Optional[ExtractionContext]:
    """Extracts normalized static metadata and AST context from an untrusted package directory.

    Args:
        package_dir: Target package directory path.
        runner_output_dir: Optional output directory for generated runner wrapper.
        allow_empty: If True, returns ExtractionContext even if no hook is present. Default False.

    Returns:
        ExtractionContext if lifecycle hooks are present (or allow_empty=True), else None.
    """
    pkg_path = Path(package_dir).resolve()
    manifest = ManifestParser.parse_directory(pkg_path)

    if not manifest.has_lifecycle_hook and not allow_empty:
        return None

    # Determine hook type (fallback to INSTALL if none detected but allow_empty is set)
    hook_type = manifest.hook_type or LifecycleHookType.INSTALL
    hook_command = manifest.hook_command or ""
    source_code = manifest.source_code or hook_command

    # 1. Build runner script if hook command exists
    runner_script_path = ""
    if hook_command:
        runner_path = RunnerBuilder.build_runner_script(
            package_dir=pkg_path,
            hook_type=hook_type,
            command=hook_command,
            output_dir=runner_output_dir,
        )
        runner_script_path = str(runner_path)

    # 2. Inspect AST for dangerous tokens and obfuscated strings
    ast_tokens = ASTInspector.inspect_code(source_code, filename=pkg_path.name)

    return ExtractionContext(
        package_name=manifest.package_name,
        version=manifest.version,
        ecosystem=manifest.ecosystem,
        declared_description=manifest.declared_description,
        repository_url=manifest.repository_url,
        dependencies=manifest.dependencies,
        hook_type=hook_type,
        hook_command=hook_command,
        source_code=source_code,
        ast_tokens=ast_tokens,
        runner_script_path=runner_script_path,
    )


__all__ = [
    "ManifestParser",
    "ParsedManifest",
    "ASTInspector",
    "calculate_shannon_entropy",
    "RunnerBuilder",
    "extract_context",
    "has_lifecycle_hooks",
]
