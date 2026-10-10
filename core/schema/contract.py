from pydantic import BaseModel, Field
from typing import List


class ExpectedBehaviorContract(BaseModel):
    """
    Expected Behavioral Contract (EBC) synthesized by the AI engine.
    Defines the strict operational boundaries for a package lifecycle execution.
    """
    package_name: str = Field(
        description="Declared identifier of the package under evaluation"
    )
    purpose: str = Field(
        default="",
        description="One-sentence technical summary of the legitimate functionality of this package"
    )
    network_required: bool = Field(
        default=False,
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
