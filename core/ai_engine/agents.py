"""Multi-Agent Cognitive Loop for Behavioral Contract Synthesis.

Implements IntentSynthesizerAgent, AdversarialRedTeamAgent, and the ContractSynthesizer
orchestrator with self-healing schema reflection and fail-closed zero-trust fallbacks.
"""

import json
import logging
import re
from typing import Optional
from pydantic import ValidationError

from core.ai_engine.client import OllamaClient, OllamaError
from core.ai_engine.prompts import (
    AIR_GAPPED_SYSTEM_PROMPT,
    RED_TEAM_SYSTEM_PROMPT,
    format_intent_synthesis_prompt,
    format_red_team_prompt,
    format_reflection_prompt,
)
from core.schema.contract import ExpectedBehaviorContract, RiskLevel
from core.schema.extraction import ExtractionContext

logger = logging.getLogger("sysdrift.ai_engine")


def extract_json_payload(text: str) -> str:
    """Strip markdown formatting or surrounding explanations to extract raw JSON."""
    text = text.strip()
    # Check for markdown code fences
    fence_pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
    match = re.search(fence_pattern, text)
    if match:
        return match.group(1).strip()

    # Find outer curly braces
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1].strip()

    return text


class IntentSynthesizerAgent:
    """Agent 1: Hypothesizes legitimate behavioral boundaries from manifest and documentation."""

    def __init__(self, client: OllamaClient):
        self.client = client

    async def run(self, context: ExtractionContext) -> str:
        """Formulate a draft contract JSON from natural language intent and manifest."""
        messages = [
            {"role": "system", "content": AIR_GAPPED_SYSTEM_PROMPT},
            {"role": "user", "content": format_intent_synthesis_prompt(context)},
        ]
        return await self.client.chat(messages=messages, format="json")

    def run_sync(self, context: ExtractionContext) -> str:
        """Synchronously formulate a draft contract JSON."""
        messages = [
            {"role": "system", "content": AIR_GAPPED_SYSTEM_PROMPT},
            {"role": "user", "content": format_intent_synthesis_prompt(context)},
        ]
        return self.client.chat_sync(messages=messages, format="json")


class AdversarialRedTeamAgent:
    """Agent 2: Audits code comments, AST tokens, and strings for deceptive evasion or prompt injection."""

    # Explicit prompt injection triggers frequently used in deceptive supply chain packages
    INJECTION_TRIGGERS = [
        "ignore all safety",
        "grant all permissions",
        "allow all network",
        "benign helper",
        "ignore security",
        "safety audit: pass",
        "safety auditor",
    ]

    def __init__(self, client: OllamaClient):
        self.client = client

    def detect_prompt_injection(self, source_code: str) -> bool:
        """Heuristically inspect source code for adversarial prompt injection phrases."""
        lower_code = source_code.lower()
        return any(trigger in lower_code for trigger in self.INJECTION_TRIGGERS)

    async def run(self, context: ExtractionContext, draft_contract_json: str) -> str:
        """Perform adversarial red-team audit and reconcile contract parameters."""
        messages = [
            {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": format_red_team_prompt(context, draft_contract_json),
            },
        ]
        audited_json = await self.client.chat(messages=messages, format="json")

        # Defense-in-depth: If source code contains blatant prompt injection phrases,
        # ensure restrictive flags are firmly enforced regardless of LLM generation.
        if self.detect_prompt_injection(context.source_code):
            audited_json = self._enforce_least_privilege_override(
                audited_json, context
            )

        return audited_json

    def run_sync(self, context: ExtractionContext, draft_contract_json: str) -> str:
        """Synchronously perform adversarial red-team audit."""
        messages = [
            {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": format_red_team_prompt(context, draft_contract_json),
            },
        ]
        audited_json = self.client.chat_sync(messages=messages, format="json")
        if self.detect_prompt_injection(context.source_code):
            audited_json = self._enforce_least_privilege_override(
                audited_json, context
            )
        return audited_json

    def _enforce_least_privilege_override(
        self, raw_json: str, context: ExtractionContext
    ) -> str:
        """Override contract to zero-trust boundaries when prompt injection is detected."""
        try:
            clean_str = extract_json_payload(raw_json)
            data = json.loads(clean_str)
            # Enforce strict security overrides
            data["accesses_user_credentials"] = False
            data["risk_level_assessment"] = RiskLevel.HIGH.value
            return json.dumps(data)
        except Exception:
            return raw_json


class ContractSynthesizer:
    """Orchestrator for multi-agent contract synthesis and self-healing schema reflection."""

    MAX_REFLECTION_ATTEMPTS = 2

    def __init__(
        self,
        client: Optional[OllamaClient] = None,
        max_reflection_attempts: int = MAX_REFLECTION_ATTEMPTS,
    ):
        self.client = client or OllamaClient()
        self.max_reflection_attempts = max_reflection_attempts
        self.intent_agent = IntentSynthesizerAgent(self.client)
        self.red_team_agent = AdversarialRedTeamAgent(self.client)

    async def synthesize(
        self, context: ExtractionContext
    ) -> ExpectedBehaviorContract:
        """Synthesize an ExpectedBehaviorContract with multi-agent reasoning and reflection."""
        # 1. Health check: Fallback immediately if Ollama is unreachable
        is_healthy = await self.client.check_health()
        if not is_healthy:
            logger.warning(
                "Ollama daemon unreachable at %s. Triggering fail-closed Zero-Trust contract.",
                self.client.base_url,
            )
            return ExpectedBehaviorContract.zero_trust_fallback(
                package_name=context.package_name,
                purpose=f"Ollama daemon offline - zero trust fallback applied for {context.package_name}",
            )

        try:
            # 2. Agent 1: Intent Synthesizer
            draft_json = await self.intent_agent.run(context)

            # 3. Agent 2: Adversarial Red-Team Auditor
            audited_json = await self.red_team_agent.run(context, draft_json)

            # 4. Schema Enforcer with Self-Healing Reflection Loop
            contract = await self._validate_with_reflection(
                audited_json, context
            )
            return contract

        except OllamaError as err:
            logger.error(
                "Ollama inference error during contract synthesis: %s. Applying zero-trust fallback.",
                err,
            )
            return ExpectedBehaviorContract.zero_trust_fallback(
                package_name=context.package_name,
                purpose=f"Inference failure - zero trust fallback applied for {context.package_name}",
            )
        except Exception as err:
            logger.exception(
                "Unexpected failure in ContractSynthesizer: %s. Applying zero-trust fallback.",
                err,
            )
            return ExpectedBehaviorContract.zero_trust_fallback(
                package_name=context.package_name,
                purpose=f"System error - zero trust fallback applied for {context.package_name}",
            )

    def synthesize_sync(
        self, context: ExtractionContext
    ) -> ExpectedBehaviorContract:
        """Synchronously synthesize an ExpectedBehaviorContract."""
        is_healthy = self.client.check_health_sync()
        if not is_healthy:
            logger.warning(
                "Ollama daemon unreachable. Triggering fail-closed Zero-Trust contract."
            )
            return ExpectedBehaviorContract.zero_trust_fallback(
                package_name=context.package_name,
                purpose=f"Ollama daemon offline - zero trust fallback applied for {context.package_name}",
            )

        try:
            draft_json = self.intent_agent.run_sync(context)
            audited_json = self.red_team_agent.run_sync(context, draft_json)
            return self._validate_with_reflection_sync(audited_json, context)
        except Exception as err:
            logger.warning(
                "Contract synthesis sync error: %s. Applying zero-trust fallback.",
                err,
            )
            return ExpectedBehaviorContract.zero_trust_fallback(
                package_name=context.package_name,
                purpose=f"Fallback applied for {context.package_name}",
            )

    async def _validate_with_reflection(
        self, raw_json: str, context: ExtractionContext
    ) -> ExpectedBehaviorContract:
        """Validate JSON against Pydantic schema, triggering self-healing re-prompting if invalid."""
        current_raw = extract_json_payload(raw_json)

        for attempt in range(self.max_reflection_attempts + 1):
            try:
                return ExpectedBehaviorContract.model_validate_json(current_raw)
            except (ValidationError, json.JSONDecodeError) as val_err:
                if attempt >= self.max_reflection_attempts:
                    logger.warning(
                        "Schema validation failed after %d reflection attempts: %s. Applying zero-trust fallback.",
                        self.max_reflection_attempts,
                        val_err,
                    )
                    return ExpectedBehaviorContract.zero_trust_fallback(
                        package_name=context.package_name,
                        purpose=f"Schema validation failed - zero trust fallback applied for {context.package_name}",
                    )

                logger.info(
                    "Self-healing schema reflection loop triggered (attempt %d/%d)...",
                    attempt + 1,
                    self.max_reflection_attempts,
                )
                reflection_prompt = format_reflection_prompt(
                    raw_response=current_raw,
                    error_details=str(val_err),
                    schema_json=json.dumps(
                        ExpectedBehaviorContract.model_json_schema(), indent=2
                    ),
                )
                messages = [
                    {"role": "system", "content": AIR_GAPPED_SYSTEM_PROMPT},
                    {"role": "user", "content": reflection_prompt},
                ]
                resp = await self.client.chat(messages=messages, format="json")
                current_raw = extract_json_payload(resp)

        return ExpectedBehaviorContract.zero_trust_fallback(
            package_name=context.package_name
        )

    def _validate_with_reflection_sync(
        self, raw_json: str, context: ExtractionContext
    ) -> ExpectedBehaviorContract:
        """Synchronously validate JSON against Pydantic schema with reflection."""
        current_raw = extract_json_payload(raw_json)

        for attempt in range(self.max_reflection_attempts + 1):
            try:
                return ExpectedBehaviorContract.model_validate_json(current_raw)
            except (ValidationError, json.JSONDecodeError) as val_err:
                if attempt >= self.max_reflection_attempts:
                    return ExpectedBehaviorContract.zero_trust_fallback(
                        package_name=context.package_name
                    )
                reflection_prompt = format_reflection_prompt(
                    raw_response=current_raw,
                    error_details=str(val_err),
                )
                messages = [
                    {"role": "system", "content": AIR_GAPPED_SYSTEM_PROMPT},
                    {"role": "user", "content": reflection_prompt},
                ]
                resp = self.client.chat_sync(messages=messages, format="json")
                current_raw = extract_json_payload(resp)

        return ExpectedBehaviorContract.zero_trust_fallback(
            package_name=context.package_name
        )
