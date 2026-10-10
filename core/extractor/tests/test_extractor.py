"""Unit tests for Gatekeeper Extractor Engine (core/extractor).

Validates static manifest parsing, AST token inspection, Shannon entropy calculation,
and hermetic runner script generation across NPM and Python ecosystems.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.extractor import (
    ASTInspector,
    ManifestParser,
    RunnerBuilder,
    calculate_shannon_entropy,
    extract_context,
    has_lifecycle_hooks,
)
from core.schema.extraction import EcosystemType, LifecycleHookType


def test_npm_manifest_parsing_with_postinstall(tmp_path: Path) -> None:
    """Verifies that an NPM package with a postinstall script is accurately parsed."""
    pkg_dir = tmp_path / "test-npm-pkg"
    pkg_dir.mkdir()
    package_json = {
        "name": "sample-pkg",
        "version": "1.2.0",
        "description": "Sample native compilation helper",
        "scripts": {
            "postinstall": "touch build.log",
        },
        "dependencies": {
            "chalk": "^4.1.0",
        },
    }
    (pkg_dir / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

    manifest = ManifestParser.parse_directory(pkg_dir)
    assert manifest.package_name == "sample-pkg"
    assert manifest.version == "1.2.0"
    assert manifest.ecosystem == EcosystemType.NPM
    assert manifest.has_lifecycle_hook is True
    assert manifest.hook_type == LifecycleHookType.POSTINSTALL
    assert manifest.hook_command == "touch build.log"
    assert "chalk" in manifest.dependencies


def test_npm_hook_precedence(tmp_path: Path) -> None:
    """Verifies execution hook priority order: preinstall > install > postinstall."""
    pkg_dir = tmp_path / "precedence-pkg"
    pkg_dir.mkdir()
    package_json = {
        "name": "precedence-pkg",
        "scripts": {
            "postinstall": "echo 3",
            "preinstall": "echo 1",
            "install": "echo 2",
        },
    }
    (pkg_dir / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

    manifest = ManifestParser.parse_directory(pkg_dir)
    assert manifest.has_lifecycle_hook is True
    assert manifest.hook_type == LifecycleHookType.PREINSTALL
    assert manifest.hook_command == "echo 1"


def test_package_without_hooks_fast_path(tmp_path: Path) -> None:
    """Verifies that a package without install scripts triggers the fast-path flag."""
    pkg_dir = tmp_path / "clean-pkg"
    pkg_dir.mkdir()
    package_json = {
        "name": "clean-pkg",
        "version": "2.0.0",
        "scripts": {
            "test": "jest",
            "build": "tsc",
        },
    }
    (pkg_dir / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

    assert has_lifecycle_hooks(pkg_dir) is False
    ctx = extract_context(pkg_dir)
    assert ctx is None


def test_python_setup_py_passive_ast_parsing(tmp_path: Path) -> None:
    """Verifies passive setup.py inspection without executing untrusted Python code."""
    pkg_dir = tmp_path / "py-pkg"
    pkg_dir.mkdir()
    setup_code = """
from setuptools import setup

setup(
    name="sample-python-lib",
    version="0.5.0",
    description="Python data processor",
)
"""
    (pkg_dir / "setup.py").write_text(setup_code, encoding="utf-8")

    manifest = ManifestParser.parse_directory(pkg_dir)
    assert manifest.ecosystem == EcosystemType.PYPI
    assert manifest.package_name == "sample-python-lib"
    assert manifest.version == "0.5.0"
    assert manifest.has_lifecycle_hook is True
    assert manifest.hook_type == LifecycleHookType.SETUP_PY


def test_python_pyproject_toml_parsing(tmp_path: Path) -> None:
    """Verifies parsing of pyproject.toml metadata."""
    pkg_dir = tmp_path / "pyproject-pkg"
    pkg_dir.mkdir()
    pyproject_content = """
[project]
name = "modern-py-lib"
version = "3.1.0"
description = "Modern Python Library"
dependencies = ["httpx>=0.20"]
"""
    (pkg_dir / "pyproject.toml").write_text(pyproject_content, encoding="utf-8")

    manifest = ManifestParser.parse_directory(pkg_dir)
    assert manifest.ecosystem == EcosystemType.PYPI
    assert manifest.package_name == "modern-py-lib"
    assert manifest.version == "3.1.0"


def test_ast_inspector_dangerous_token_detection() -> None:
    """Verifies AST detection of dangerous child processes and socket connections."""
    script_snippet = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.connect(('10.0.0.1', 8080))\n"
        "open('/home/user/.aws/credentials')\n"
    )

    tokens = ASTInspector.inspect_code(script_snippet, filename="sample.py")
    token_identifiers = {t.identifier for t in tokens}
    token_types = {t.token_type for t in tokens}

    assert any("socket" in ident for ident in token_identifiers)
    assert "CredentialAccess" in token_types


def test_shannon_entropy_calculation() -> None:
    """Verifies Shannon entropy detection for high-entropy strings."""
    # Low-entropy predictable text
    low_entropy_str = "aaaaabbbbbcccccdddddeeeee"
    h_low = calculate_shannon_entropy(low_entropy_str)
    assert h_low < 3.0

    # High-entropy random base64 string
    high_entropy_str = "aW1wb3J0IHNvY2tldDsgcz1zb2NrZXQuc29ja2V0KCk7IHM="
    h_high = calculate_shannon_entropy(high_entropy_str)
    assert h_high >= 4.0

    # Inspect code with high entropy string
    code_with_b64 = f"const payload = '{high_entropy_str}';"
    tokens = ASTInspector.inspect_code(code_with_b64)
    assert any(t.token_type == "HighEntropyString" for t in tokens)


def test_runner_builder_script_creation(tmp_path: Path) -> None:
    """Verifies synthesis of hermetic .sysdrift_<hook>.sh wrapper script."""
    pkg_dir = tmp_path / "runner-test"
    pkg_dir.mkdir()

    runner_path = RunnerBuilder.build_runner_script(
        package_dir=pkg_dir,
        hook_type=LifecycleHookType.POSTINSTALL,
        command="touch output.txt",
    )

    assert runner_path.exists()
    assert runner_path.name == ".sysdrift_postinstall.sh"

    content = runner_path.read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in content
    assert "set -e" in content
    assert "touch output.txt" in content

    # Test cleanup
    cleanup_success = RunnerBuilder.cleanup_runner_script(runner_path)
    assert cleanup_success is True
    assert not runner_path.exists()


def test_extract_context_end_to_end(tmp_path: Path) -> None:
    """Verifies complete end-to-end extraction yielding ExtractionContext."""
    pkg_dir = tmp_path / "e2e-pkg"
    pkg_dir.mkdir()
    package_json = {
        "name": "e2e-sample",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node -e 'require(\"child_process\").execSync(\"touch test.tmp\")'",
        },
    }
    (pkg_dir / "package.json").write_text(json.dumps(package_json), encoding="utf-8")

    ctx = extract_context(pkg_dir)
    assert ctx is not None
    assert ctx.package_name == "e2e-sample"
    assert ctx.ecosystem == EcosystemType.NPM
    assert ctx.hook_type == LifecycleHookType.POSTINSTALL
    assert "child_process" in ctx.hook_command
    assert Path(ctx.runner_script_path).exists()
    assert any("child_process" in t.identifier for t in ctx.ast_tokens)

    # Clean up runner script
    RunnerBuilder.cleanup_runner_script(ctx.runner_script_path)


def test_nonexistent_directory_raises_error() -> None:
    """Verifies FileNotFoundError on missing package directory."""
    with pytest.raises(FileNotFoundError):
        ManifestParser.parse_directory("/path/does/not/exist/at/all/99999")
