"""Threat Attribution & Forensic Incident Report Models.

Defines the forensic analysis structure synthesized by the AI Forensic Explainer
agent when critical behavioral drift (D >= 0.40) is detected.
"""

from typing import List
from pydantic import BaseModel, Field, AliasChoices, ConfigDict


class ThreatAttributionReport(BaseModel):
    """Forensic report attributing observed kernel violations to source code.

    Includes mapped MITRE ATT&CK techniques, culprit code snippets, plain-language
    executive summaries, and remediation recommendations.
    """

    model_config = ConfigDict(populate_by_name=True)

    threat_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite drift score triggering the investigation",
    )
    attack_category: str = Field(
        ...,
        description="Identified attack vector, e.g., Credential Harvesting, Reverse Shell, Dropper",
    )
    mitre_attack_tactics: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("mitre_attack_tactics", "mitre_tactics"),
        description="Mapped MITRE ATT&CK techniques, e.g., T1552.001, T1071.001",
    )
    culprit_code_snippet: str = Field(
        default="",
        validation_alias=AliasChoices("culprit_code_snippet", "suspect_ast_nodes"),
        description="Identified line or statement in lifecycle code responsible for the violation",
    )
    executive_summary: str = Field(
        ...,
        description="Plain-language forensic explanation detailing what the malware attempted to do",
    )
    remediation_recommendations: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("remediation_recommendations", "remediation_steps"),
        description="Actionable mitigation steps for DevSecOps and developers",
    )

    @property
    def mitre_tactics(self) -> List[str]:
        """Backward-compatibility alias for mitre_attack_tactics."""
        return self.mitre_attack_tactics

    @property
    def suspect_ast_nodes(self) -> List[str]:
        """Backward-compatibility alias for suspect_ast_nodes (as a list)."""
        return [self.culprit_code_snippet] if self.culprit_code_snippet else []

    @property
    def remediation_steps(self) -> List[str]:
        """Backward-compatibility alias for remediation_recommendations."""
        return self.remediation_recommendations
