"""Package Extraction & AST Inspection Models.

Defines the static package extraction data structures, metadata contexts,
and Tree-Sitter AST token representations.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class EcosystemType(str, Enum):
    """Supported package ecosystem types."""
    NPM = "npm"
    PYPI = "pypi"
    STANDALONE = "standalone"


class LifecycleHookType(str, Enum):
    """Supported lifecycle execution hook points."""
    PREINSTALL = "preinstall"
    INSTALL = "install"
    POSTINSTALL = "postinstall"
    SETUP_PY = "setup.py"
    STANDALONE_SHELL = "standalone_shell"


class ASTSuspiciousToken(BaseModel):
    """Suspicious token detected during static AST analysis."""

    token_type: str = Field(
        ...,
        description="AST node type, e.g., CallExpression, ImportFrom",
    )
    identifier: str = Field(
        ...,
        description="Target function/module, e.g., child_process, socket, eval",
    )
    line_number: int = Field(
        ...,
        description="Line in script where token was discovered",
    )
    snippet: str = Field(
        ...,
        description="Code snippet surrounding the token",
    )
    entropy_score: Optional[float] = Field(
        default=None,
        description="Calculated Shannon entropy for base64 strings",
    )


class ExtractionContext(BaseModel):
    """Normalized metadata and static AST context extracted from an untrusted package."""

    package_name: str
    version: str = "0.0.0"
    ecosystem: EcosystemType
    declared_description: str = Field(
        default="",
        description="Natural language description from manifest",
    )
    readme_excerpt: str = Field(
        default="",
        description="Relevant, bounded excerpt from the package README",
    )
    repository_url: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    hook_type: LifecycleHookType
    hook_command: str = Field(
        ...,
        description="Raw command declared in the manifest",
    )
    source_code: str = Field(
        ...,
        description="Extracted or assembled lifecycle script code",
    )
    ast_tokens: List[ASTSuspiciousToken] = Field(default_factory=list)
    runner_script_path: str = Field(
        ...,
        description="Path to the executable wrapper script for sandbox execution",
    )
