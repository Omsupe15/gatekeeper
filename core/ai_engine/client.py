"""Ollama REST API Client.

Provides asynchronous and synchronous client interfaces to communicate with
the local Ollama daemon on port 11434 with zero-temperature determinism and
strict JSON schema constrained decoding.
"""

import os
from typing import Any, Dict, List, Optional
import httpx


class OllamaError(Exception):
    """Base exception for all Ollama client interactions."""
    pass


class OllamaConnectionError(OllamaError):
    """Raised when the Ollama daemon is unreachable or connection is refused."""
    pass


class OllamaTimeoutError(OllamaError):
    """Raised when inference or network operation exceeds the allocated timeout."""
    pass


class OllamaClient:
    """Client for local on-premises Ollama inference engine."""

    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "qwen2.5-coder:7b"
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = (
            base_url
            or os.getenv("GATEKEEPER_OLLAMA_HOST")
            or self.DEFAULT_BASE_URL
        ).rstrip("/")
        self.model = (
            model
            or os.getenv("GATEKEEPER_MODEL")
            or self.DEFAULT_MODEL
        )
        self.timeout = timeout

    async def check_health(self) -> bool:
        """Check if the local Ollama daemon is reachable and responding."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(url)
                return response.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return False

    def check_health_sync(self) -> bool:
        """Synchronously check if the local Ollama daemon is reachable."""
        url = f"{self.base_url}/api/tags"
        try:
            with httpx.Client(timeout=3.0) as client:
                response = client.get(url)
                return response.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return False

    async def get_available_models(self) -> List[str]:
        """Fetch list of all models currently pulled into the local Ollama daemon."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    models = response.json().get("models", [])
                    return [m.get("name", "") for m in models if m.get("name")]
                return []
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return []

    async def resolve_active_model(self) -> str:
        """Resolve the best available model, falling back to installed variants if needed."""
        available = await self.get_available_models()
        if not available:
            return self.model

        # Exact match
        if self.model in available:
            return self.model

        # Base prefix match (e.g., qwen2.5-coder:7b vs qwen2.5-coder:3b-instruct-q8_0)
        prefix = self.model.split(":")[0]
        matching = [m for m in available if m.startswith(prefix)]
        if matching:
            return matching[0]

        # First available model as fallback
        return available[0]

    async def chat(
        self,
        messages: List[Dict[str, str]],
        format: Any = "json",
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Execute a structured chat completion against Ollama with zero temperature."""
        url = f"{self.base_url}/api/chat"
        opt = {
            "temperature": 0.0,
            "top_p": 1.0,
            **(options or {}),
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": opt,
        }
        if format:
            payload["format"] = format

        req_timeout = timeout or self.timeout
        try:
            async with httpx.AsyncClient(timeout=req_timeout) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    raise OllamaError(
                        f"Ollama API returned HTTP {response.status_code}: {response.text}"
                    )
                data = response.json()
                message = data.get("message", {})
                content = message.get("content", "")
                return content
        except httpx.ConnectError as e:
            raise OllamaConnectionError(
                f"Failed to connect to Ollama daemon at {self.base_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise OllamaTimeoutError(
                f"Ollama request timed out after {req_timeout}s: {e}"
            ) from e
        except httpx.RequestError as e:
            raise OllamaError(f"HTTP request to Ollama failed: {e}") from e

    def chat_sync(
        self,
        messages: List[Dict[str, str]],
        format: Any = "json",
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Synchronous wrapper for chat completion."""
        url = f"{self.base_url}/api/chat"
        opt = {
            "temperature": 0.0,
            "top_p": 1.0,
            **(options or {}),
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": opt,
        }
        if format:
            payload["format"] = format

        req_timeout = timeout or self.timeout
        try:
            with httpx.Client(timeout=req_timeout) as client:
                response = client.post(url, json=payload)
                if response.status_code != 200:
                    raise OllamaError(
                        f"Ollama API returned HTTP {response.status_code}: {response.text}"
                    )
                data = response.json()
                return data.get("message", {}).get("content", "")
        except httpx.ConnectError as e:
            raise OllamaConnectionError(
                f"Failed to connect to Ollama daemon at {self.base_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise OllamaTimeoutError(
                f"Ollama request timed out after {req_timeout}s: {e}"
            ) from e
        except httpx.RequestError as e:
            raise OllamaError(f"HTTP request to Ollama failed: {e}") from e

    async def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        format: Any = "json",
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Execute text generation against Ollama /api/generate with zero temperature."""
        url = f"{self.base_url}/api/generate"
        opt = {
            "temperature": 0.0,
            "top_p": 1.0,
            **(options or {}),
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": opt,
        }
        if system:
            payload["system"] = system
        if format:
            payload["format"] = format

        req_timeout = timeout or self.timeout
        try:
            async with httpx.AsyncClient(timeout=req_timeout) as client:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    raise OllamaError(
                        f"Ollama API returned HTTP {response.status_code}: {response.text}"
                    )
                return response.json().get("response", "")
        except httpx.ConnectError as e:
            raise OllamaConnectionError(
                f"Failed to connect to Ollama daemon at {self.base_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise OllamaTimeoutError(
                f"Ollama request timed out after {req_timeout}s: {e}"
            ) from e
        except httpx.RequestError as e:
            raise OllamaError(f"HTTP request to Ollama failed: {e}") from e
