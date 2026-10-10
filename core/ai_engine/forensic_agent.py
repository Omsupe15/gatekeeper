"""AI Forensic Threat Attribution & Incident Explainer Agent.

Activated when differential arbitration detects critical behavioral drift (D >= 0.40).
Correlates observed Linux kernel syscall violations with source code AST tokens,
identifies MITRE ATT&CK tactics, and produces actionable remediation reports.
"""

import json
import logging
from typing import Optional
from pydantic import ValidationError

from core.ai_engine.client import OllamaClient, OllamaError
from core.ai_engine.agents import extract_json_payload
from core.ai_engine.prompts import (
    FORENSIC_SYSTEM_PROMPT,
    format_forensic_prompt,
    format_reflection_prompt,
)
from core.schema.arbitration import DriftResult, SecurityDimension
from core.schema.contract import ExpectedBehaviorContract
from core.schema.extraction import ExtractionContext
from core.schema.forensics import ThreatAttributionReport
from core.schema.telemetry import ObservedKernelTrace

logger = logging.getLogger("sysdrift.ai_engine")


class ForensicAgent:
    """Post-trace cyber forensics incident responder agent."""

    def __init__(
        self,
        client: Optional[OllamaClient] = None,
        max_reflection_attempts: int = 2,
    ):
        self.client = client or OllamaClient()
        self.max_reflection_attempts = max_reflection_attempts

    async def analyze_incident(
        self,
        ebc: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
        drift: DriftResult,
        context: ExtractionContext,
    ) -> ThreatAttributionReport:
        """Synthesize a structured ThreatAttributionReport from trace violations and code tokens."""
        # 1. Check if Ollama is reachable
        is_healthy = await self.client.check_health()
        if not is_healthy:
            logger.warning(
                "Ollama daemon unreachable during forensic analysis. Emitting deterministic forensic fallback."
            )
            return self._create_deterministic_fallback(
                ebc=ebc, trace=trace, drift=drift, context=context
            )

        prompt = format_forensic_prompt(
            ebc=ebc,
            trace=trace,
            violations=drift.violations,
            context=context,
        )
        messages = [
            {"role": "system", "content": FORENSIC_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
            raw_response = await self.client.chat(messages=messages, format="json")
            return await self._validate_with_reflection(
                raw_response=raw_response,
                ebc=ebc,
                trace=trace,
                drift=drift,
                context=context,
            )
        except OllamaError as err:
            logger.error(
                "Ollama error during forensic threat attribution: %s. Emitting deterministic fallback.",
                err,
            )
            return self._create_deterministic_fallback(
                ebc=ebc, trace=trace, drift=drift, context=context
            )
        except Exception as err:
            logger.exception(
                "Unexpected failure during forensic analysis: %s. Emitting deterministic fallback.",
                err,
            )
            return self._create_deterministic_fallback(
                ebc=ebc, trace=trace, drift=drift, context=context
            )

    def analyze_incident_sync(
        self,
        ebc: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
        drift: DriftResult,
        context: ExtractionContext,
    ) -> ThreatAttributionReport:
        """Synchronously synthesize a structured ThreatAttributionReport."""
        is_healthy = self.client.check_health_sync()
        if not is_healthy:
            return self._create_deterministic_fallback(
                ebc=ebc, trace=trace, drift=drift, context=context
            )

        prompt = format_forensic_prompt(
            ebc=ebc,
            trace=trace,
            violations=drift.violations,
            context=context,
        )
        messages = [
            {"role": "system", "content": FORENSIC_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
            raw_response = self.client.chat_sync(messages=messages, format="json")
            return self._validate_with_reflection_sync(
                raw_response=raw_response,
                ebc=ebc,
                trace=trace,
                drift=drift,
                context=context,
            )
        except Exception:
            return self._create_deterministic_fallback(
                ebc=ebc, trace=trace, drift=drift, context=context
            )

    async def _validate_with_reflection(
        self,
        raw_response: str,
        ebc: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
        drift: DriftResult,
        context: ExtractionContext,
    ) -> ThreatAttributionReport:
        """Validate JSON against ThreatAttributionReport with self-healing reflection."""
        current_raw = extract_json_payload(raw_response)

        for attempt in range(self.max_reflection_attempts + 1):
            try:
                return ThreatAttributionReport.model_validate_json(current_raw)
            except (ValidationError, json.JSONDecodeError) as val_err:
                if attempt >= self.max_reflection_attempts:
                    logger.warning(
                        "Forensic report schema reflection exceeded retry limit. Emitting deterministic fallback."
                    )
                    return self._create_deterministic_fallback(
                        ebc=ebc, trace=trace, drift=drift, context=context
                    )

                logger.info(
                    "Forensic report self-healing reflection (attempt %d/%d)...",
                    attempt + 1,
                    self.max_reflection_attempts,
                )
                reflection_prompt = format_reflection_prompt(
                    raw_response=current_raw,
                    error_details=str(val_err),
                    schema_json=json.dumps(
                        ThreatAttributionReport.model_json_schema(), indent=2
                    ),
                )
                messages = [
                    {"role": "system", "content": FORENSIC_SYSTEM_PROMPT},
                    {"role": "user", "content": reflection_prompt},
                ]
                resp = await self.client.chat(messages=messages, format="json")
                current_raw = extract_json_payload(resp)

        return self._create_deterministic_fallback(
            ebc=ebc, trace=trace, drift=drift, context=context
        )

    def _validate_with_reflection_sync(
        self,
        raw_response: str,
        ebc: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
        drift: DriftResult,
        context: ExtractionContext,
    ) -> ThreatAttributionReport:
        """Synchronously validate JSON against ThreatAttributionReport."""
        current_raw = extract_json_payload(raw_response)
        try:
            return ThreatAttributionReport.model_validate_json(current_raw)
        except Exception:
            return self._create_deterministic_fallback(
                ebc=ebc, trace=trace, drift=drift, context=context
            )

    def _create_deterministic_fallback(
        self,
        ebc: ExpectedBehaviorContract,
        trace: ObservedKernelTrace,
        drift: DriftResult,
        context: ExtractionContext,
    ) -> ThreatAttributionReport:
        """Generate a deterministic forensic report directly from kernel violations without AI."""
        # 1. Determine attack category and MITRE tactics from violations
        mitre_tactics = []
        attack_categories = []

        has_network = any(
            v.dimension == SecurityDimension.NETWORK for v in drift.violations
        )
        has_filesystem = any(
            v.dimension == SecurityDimension.FILESYSTEM for v in drift.violations
        )
        has_process = any(
            v.dimension == SecurityDimension.PROCESS for v in drift.violations
        )

        if has_filesystem:
            attack_categories.append("Credential Harvesting & Sensitive File Access")
            mitre_tactics.append("T1552.001")  # Credentials In Files
        if has_network:
            attack_categories.append("Outbound Exfiltration / C2 Communication")
            mitre_tactics.append("T1071.001")  # Application Layer Protocol (Web)
        if has_process:
            attack_categories.append("Unauthorized Process Spawning / Shell Execution")
            mitre_tactics.append("T1059")  # Command and Scripting Interpreter

        if not attack_categories:
            attack_categories.append("Unspecified Runtime Behavioral Discrepancy")
            mitre_tactics.append("T1204")

        category_str = " | ".join(attack_categories)

        # 2. Identify culprit code snippet
        snippet = context.hook_command or "Lifecycle command execution"
        if context.ast_tokens:
            snippet = context.ast_tokens[0].snippet

        # 3. Formulate executive summary
        summary = (
            f"The package '{ebc.package_name}' breached declared behavioral bounds during execution. "
            f"Differential arbitration detected a composite drift score of {drift.composite_drift_score:.2f} "
            f"with {len(drift.violations)} critical security invariant violation(s)."
        )

        # 4. Actionable mitigation recommendations
        recommendations = [
            f"Immediately block and quarantine package version '{ebc.package_name}' across private registries.",
            "Verify CI/CD runner and workstation audit logs for unexpected network connections.",
            "Rotate any sensitive environment secrets or cloud credentials accessible to the build user.",
        ]

        return ThreatAttributionReport(
            threat_score=drift.composite_drift_score,
            attack_category=category_str,
            mitre_attack_tactics=mitre_tactics,
            culprit_code_snippet=snippet,
            executive_summary=summary,
            remediation_recommendations=recommendations,
        )
