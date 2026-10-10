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
    DEFAULT_MODEL = "qwen3:8b"
    DEFAULT_TIMEOUT = 120.0

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
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
        self._model_resolved = self.model != self.DEFAULT_MODEL
        self._health_status: Optional[bool] = None
        self._async_http_client: Optional[httpx.AsyncClient] = None
        self._sync_http_client: Optional[httpx.Client] = None
        self.timeout = (
            timeout
            if timeout is not None
            else float(os.getenv("GATEKEEPER_LLM_TIMEOUT", str(self.DEFAULT_TIMEOUT)))
        )

    async def check_health(self) -> bool:
        """Check if the local Ollama daemon is reachable and responding."""
        if self._health_status is not None:
            return self._health_status
        url = f"{self.base_url}/api/tags"
        try:
            response = await self._get_async_client().get(url, timeout=3.0)
            self._health_status = response.status_code == 200
            return self._health_status
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            self._health_status = False
            return False

    def check_health_sync(self) -> bool:
        """Synchronously check if the local Ollama daemon is reachable."""
        if self._health_status is not None:
            return self._health_status
        url = f"{self.base_url}/api/tags"
        try:
            response = self._get_sync_client().get(url, timeout=3.0)
            self._health_status = response.status_code == 200
            return self._health_status
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            self._health_status = False
            return False

    async def get_available_models(self) -> List[str]:
        """Fetch list of all models currently pulled into the local Ollama daemon."""
        url = f"{self.base_url}/api/tags"
        try:
            response = await self._get_async_client().get(url, timeout=5.0)
            if response.status_code == 200:
                models = response.json().get("models", [])
                return [m.get("name", "") for m in models if m.get("name")]
            return []
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return []

    def get_available_models_sync(self) -> List[str]:
        """Synchronously fetch list of all models currently pulled into the local Ollama daemon."""
        url = f"{self.base_url}/api/tags"
        try:
            response = self._get_sync_client().get(url, timeout=5.0)
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
            self._model_resolved = True
            return self.model

        # Exact match
        if self.model in available:
            self._model_resolved = True
            return self.model

        # Base prefix match (e.g., qwen2.5-coder:7b vs qwen2.5-coder:3b-instruct-q8_0)
        prefix = self.model.split(":")[0]
        matching = [m for m in available if m.startswith(prefix)]
        if matching:
            self.model = matching[0]
            self._model_resolved = True
            return matching[0]

        # First available model as fallback
        self.model = available[0]
        self._model_resolved = True
        return available[0]

    def resolve_active_model_sync(self) -> str:
        """Synchronously resolve best available model."""
        available = self.get_available_models_sync()
        if not available:
            self._model_resolved = True
            return self.model

        if self.model in available:
            self._model_resolved = True
            return self.model

        prefix = self.model.split(":")[0]
        matching = [m for m in available if m.startswith(prefix)]
        if matching:
            self.model = matching[0]
            self._model_resolved = True
            return matching[0]

        self.model = available[0]
        self._model_resolved = True
        return available[0]

    async def chat(
        self,
        messages: List[Dict[str, str]],
        format: Any = "json",
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Execute a structured chat completion against Ollama with zero temperature."""
        if not self._model_resolved:
            await self.resolve_active_model()

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
            response = await self._get_async_client().post(
                url, json=payload, timeout=req_timeout
            )
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
        if not self._model_resolved:
            self.resolve_active_model_sync()

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
            response = self._get_sync_client().post(
                url, json=payload, timeout=req_timeout
            )
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
            response = await self._get_async_client().post(
                url, json=payload, timeout=req_timeout
            )
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

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_http_client is None:
            self._sync_http_client = httpx.Client()
        return self._sync_http_client

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_http_client is None:
            self._async_http_client = httpx.AsyncClient()
        return self._async_http_client
