"""Manifest Parser for Gatekeeper Extractor Engine (Block 3).

Passively parses NPM and Python package manifests without executing untrusted code.
Extracts declared metadata, dependencies, and lifecycle execution hooks.
"""

from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.schema.extraction import EcosystemType, LifecycleHookType

# Built-in tomllib for Python 3.11+, fallback for older versions
try:
    import tomllib  # type: ignore
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


@dataclass
class ParsedManifest:
    """Normalized manifest metadata and lifecycle hook specifications."""

    package_name: str
    version: str = "0.0.0"
    ecosystem: EcosystemType = EcosystemType.STANDALONE
    declared_description: str = ""
    repository_url: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    has_lifecycle_hook: bool = False
    hook_type: Optional[LifecycleHookType] = None
    hook_command: str = ""
    source_code: str = ""


class ManifestParser:
    """Discovers and parses package manifests across NPM and Python ecosystems."""

    @classmethod
    def parse_directory(cls, package_dir: str | Path) -> ParsedManifest:
        """Parses a target directory and returns normalized manifest metadata.

        Args:
            package_dir: Path to the target package directory.

        Returns:
            ParsedManifest containing package metadata and lifecycle hook details.

        Raises:
            FileNotFoundError: If the target directory does not exist.
        """
        pkg_path = Path(package_dir).resolve()
        if not pkg_path.is_dir():
            raise FileNotFoundError(f"Target directory does not exist: {pkg_path}")

        # Priority 1: NPM (package.json)
        package_json_path = pkg_path / "package.json"
        if package_json_path.is_file():
            return cls._parse_package_json(package_json_path, pkg_path)

        # Priority 2: Python (pyproject.toml, setup.py, setup.cfg)
        pyproject_path = pkg_path / "pyproject.toml"
        setup_py_path = pkg_path / "setup.py"
        setup_cfg_path = pkg_path / "setup.cfg"

        if pyproject_path.is_file() or setup_py_path.is_file() or setup_cfg_path.is_file():
            return cls._parse_python_manifest(
                pkg_path, pyproject_path, setup_py_path, setup_cfg_path
            )

        # Priority 3: Standalone Shell Scripts
        for script_name in ["install.sh", "setup.sh", "build.sh"]:
            standalone_script = pkg_path / script_name
            if standalone_script.is_file():
                return cls._parse_standalone_script(standalone_script, pkg_path)

        # Fallback: Bare directory with no manifest
        return ParsedManifest(
            package_name=pkg_path.name or "unknown-package",
            version="0.0.0",
            ecosystem=EcosystemType.STANDALONE,
            declared_description="",
            has_lifecycle_hook=False,
        )

    @classmethod
    def _parse_package_json(cls, file_path: Path, pkg_path: Path) -> ParsedManifest:
        """Parses package.json for Node.js metadata and lifecycle scripts."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            # Corrupted or unparseable JSON
            return ParsedManifest(
                package_name=pkg_path.name,
                version="0.0.0",
                ecosystem=EcosystemType.NPM,
                declared_description=f"Malformed package.json: {exc}",
                has_lifecycle_hook=False,
            )

        name = data.get("name") or pkg_path.name
        version = data.get("version") or "0.0.0"
        description = data.get("description") or ""

        # Repository URL resolution
        repo = data.get("repository")
        repo_url = None
        if isinstance(repo, str):
            repo_url = repo
        elif isinstance(repo, dict):
            repo_url = repo.get("url")

        # Dependencies
        dependencies = list(data.get("dependencies", {}).keys())
        dev_deps = list(data.get("devDependencies", {}).keys())
        all_deps = sorted(list(set(dependencies + dev_deps)))

        # Lifecycle Hooks (NPM execution order: preinstall -> install -> postinstall)
        scripts = data.get("scripts", {})
        has_hook = False
        hook_type: Optional[LifecycleHookType] = None
        hook_command = ""
        source_code = ""

        hook_priority = [
            ("preinstall", LifecycleHookType.PREINSTALL),
            ("install", LifecycleHookType.INSTALL),
            ("postinstall", LifecycleHookType.POSTINSTALL),
        ]

        for hook_key, hook_enum in hook_priority:
            if hook_key in scripts and scripts[hook_key]:
                has_hook = True
                hook_type = hook_enum
                hook_command = str(scripts[hook_key]).strip()
                source_code = hook_command
                break

        return ParsedManifest(
            package_name=name,
            version=version,
            ecosystem=EcosystemType.NPM,
            declared_description=description,
            repository_url=repo_url,
            dependencies=all_deps,
            has_lifecycle_hook=has_hook,
            hook_type=hook_type,
            hook_command=hook_command,
            source_code=source_code,
        )

    @classmethod
    def _parse_python_manifest(
        cls,
        pkg_path: Path,
        pyproject_path: Path,
        setup_py_path: Path,
        setup_cfg_path: Path,
    ) -> ParsedManifest:
        """Parses pyproject.toml, setup.py, and setup.cfg for Python packages."""
        name = pkg_path.name
        version = "0.0.0"
        description = ""
        repo_url = None
        dependencies: List[str] = []

        # 1. Parse pyproject.toml if present
        if pyproject_path.is_file() and tomllib:
            try:
                with open(pyproject_path, "rb") as f:
                    toml_data = tomllib.load(f)
                proj = toml_data.get("project", {})
                name = proj.get("name") or name
                version = proj.get("version") or version
                description = proj.get("description") or description
                dependencies = proj.get("dependencies", [])
                urls = proj.get("urls", {})
                repo_url = urls.get("Repository") or urls.get("Source") or urls.get("Homepage")
            except Exception:
                pass

        # 2. Statically parse setup.py via AST (Passive: DO NOT execute setup.py)
        has_hook = False
        hook_type: Optional[LifecycleHookType] = None
        hook_command = ""
        source_code = ""

        if setup_py_path.is_file():
            try:
                with open(setup_py_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                source_code = content
                tree = ast.parse(content, filename=str(setup_py_path))

                # Look for custom cmdclass or setup invocation
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                        if func_name in ("setup", "Setup"):
                            has_hook = True
                            hook_type = LifecycleHookType.SETUP_PY
                            hook_command = "python3 setup.py build"
                            for kw in node.keywords:
                                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                    name = str(kw.value.value)
                                elif kw.arg == "version" and isinstance(kw.value, ast.Constant):
                                    version = str(kw.value.value)
                                elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                                    description = str(kw.value.value)
                            break

                # If setup.py contains top-level code or functions but no standard setup() call
                if not has_hook and len(content.strip()) > 0:
                    has_hook = True
                    hook_type = LifecycleHookType.SETUP_PY
                    hook_command = "python3 setup.py install"

            except Exception:
                # If AST parsing fails, mark setup.py hook present for cautious sandboxing
                has_hook = True
                hook_type = LifecycleHookType.SETUP_PY
                hook_command = "python3 setup.py build"

        return ParsedManifest(
            package_name=name,
            version=version,
            ecosystem=EcosystemType.PYPI,
            declared_description=description,
            repository_url=repo_url,
            dependencies=dependencies,
            has_lifecycle_hook=has_hook,
            hook_type=hook_type,
            hook_command=hook_command,
            source_code=source_code,
        )

    @classmethod
    def _parse_standalone_script(
        cls, script_path: Path, pkg_path: Path
    ) -> ParsedManifest:
        """Parses standalone shell scripts for non-managed projects."""
        try:
            with open(script_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            content = ""

        return ParsedManifest(
            package_name=pkg_path.name,
            version="1.0.0",
            ecosystem=EcosystemType.STANDALONE,
            declared_description="Standalone shell installation script",
            has_lifecycle_hook=True,
            hook_type=LifecycleHookType.STANDALONE_SHELL,
            hook_command=f"bash {script_path.name}",
            source_code=content,
        )
