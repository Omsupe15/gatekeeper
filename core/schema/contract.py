"""Behavioral Contract Schema (ExpectedBehaviorContract - EBC).

Defines the expected operational boundaries synthesized by the local AI engine
for network egress, filesystem access, and process execution.
"""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Initial risk rating based on static analysis."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ExpectedBehaviorContract(BaseModel):
    """Machine-enforceable behavioral contract for open-source package installation.

    Serialized to JSON Schema and fed directly into Ollama's constrained
    decoding engine (`format="json"`) to guarantee compliant outputs.
    """

    package_name: str = Field(
        ...,
        description="Declared identifier of the package under evaluation",
    )
    purpose: str = Field(
        ...,
        description="One-sentence technical summary of the legitimate functionality of this package",
    )
    network_required: bool = Field(
        ...,
        description="Must be True ONLY if installation legitimately requires fetching remote assets",
    )
    allowed_domains: List[str] = Field(
        default_factory=list,
        description="Explicit whitelist of hostnames or IP subnets permitted for egress",
    )
    allowed_read_prefixes: List[str] = Field(
        default_factory=list,
        description="Directory prefixes the install script is legitimately permitted to read",
    )
    allowed_write_prefixes: List[str] = Field(
        default_factory=list,
        description="Directory prefixes the install script is legitimately permitted to write to",
    )
    allowed_binaries: List[str] = Field(
        default_factory=list,
        description="Explicit executable binary names permitted to be spawned during install",
    )
    accesses_user_credentials: bool = Field(
        default=False,
        description="Whether touching sensitive user credential stores (~/.ssh, ~/.aws) is legitimate",
    )
    risk_level_assessment: str = Field(
        default="LOW",
        description="AI initial risk rating based on static analysis: LOW, MEDIUM, or HIGH",
    )

    @classmethod
    def zero_trust_fallback(
        cls,
        package_name: str,
        purpose: str = "Unverified package - zero-trust fail-closed fallback applied",
    ) -> "ExpectedBehaviorContract":
        """Construct a zero-trust, fail-closed contract instance.

        Used when the AI engine is unreachable or fails schema validation reflection,
        denying network, user credentials, and external binaries by default.
        """
        return cls(
            package_name=package_name,
            purpose=purpose,
            network_required=False,
            allowed_domains=[],
            allowed_read_prefixes=[],
            allowed_write_prefixes=[],
            allowed_binaries=[],
            accesses_user_credentials=False,
            risk_level_assessment=RiskLevel.HIGH.value,
        )
