from pydantic import BaseModel, Field
from typing import List


class ThreatAttributionReport(BaseModel):
    """
    AI-generated threat attribution report detailing the attack vector, MITRE tactics, and remediation.
    """
    threat_score: float
    attack_category: str = Field(
        default="Unknown Malware Vector",
        description="Identified attack vector, e.g., Credential Harvester, Reverse Shell, Dropper"
    )
    mitre_attack_tactics: List[str] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK techniques, e.g., T1552.001, T1071.001"
    )
    culprit_code_snippet: str = Field(
        default="",
        description="Identified line or statement in lifecycle code responsible for the violation"
    )
    executive_summary: str = Field(
        default="",
        description="Plain-language forensic explanation detailing what the malware attempted to do"
    )
    remediation_recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable mitigation steps for DevSecOps and developers"
    )
