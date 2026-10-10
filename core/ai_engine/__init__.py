"""Block 2: Local AI & Multi-Agent Inference Engine.

Exports Ollama client interfaces, immutable security prompt templates,
multi-agent contract synthesis, and post-trace forensic attribution agents.
"""

from core.ai_engine.client import (
    OllamaClient,
    OllamaError,
    OllamaConnectionError,
    OllamaTimeoutError,
)
from core.ai_engine.prompts import (
    AIR_GAPPED_SYSTEM_PROMPT,
    RED_TEAM_SYSTEM_PROMPT,
    FORENSIC_SYSTEM_PROMPT,
    format_intent_synthesis_prompt,
    format_red_team_prompt,
    format_reflection_prompt,
    format_forensic_prompt,
)
from core.ai_engine.agents import (
    IntentSynthesizerAgent,
    AdversarialRedTeamAgent,
    ContractSynthesizer,
    extract_json_payload,
)
from core.ai_engine.forensic_agent import ForensicAgent

__all__ = [
    # Ollama Client & Exceptions
    "OllamaClient",
    "OllamaError",
    "OllamaConnectionError",
    "OllamaTimeoutError",
    # Prompts & Formatting
    "AIR_GAPPED_SYSTEM_PROMPT",
    "RED_TEAM_SYSTEM_PROMPT",
    "FORENSIC_SYSTEM_PROMPT",
    "format_intent_synthesis_prompt",
    "format_red_team_prompt",
    "format_reflection_prompt",
    "format_forensic_prompt",
    # Cognitive Loop Agents
    "IntentSynthesizerAgent",
    "AdversarialRedTeamAgent",
    "ContractSynthesizer",
    "extract_json_payload",
    # Forensics Explainer
    "ForensicAgent",
]
