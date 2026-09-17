"""
LLM Provider Abstraction.

Provides a pluggable LLM interface so the model can be changed
without rewriting the application. Supports multiple providers
through a common interface.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from config.settings import Settings, LLMProvider, get_settings

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        response_format: Optional[str] = None,
    ) -> str:
        """Generate a response from the LLM.

        Args:
            system_prompt: System-level instructions.
            user_prompt: The user's prompt/request.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            response_format: Optional format hint ('json' for JSON output).

        Returns:
            The LLM's response text.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the LLM provider is configured and available."""
        ...


class GoogleLLMClient(LLMClient):
    """Google Gemini API client."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        self._api_key = api_key
        self._model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self._api_key)
        return self._client

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        response_format: Optional[str] = None,
    ) -> str:
        from google.genai import types

        client = self._get_client()

        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=temperature,
            max_output_tokens=max_tokens,
        )
        if response_format == "json":
            config.response_mime_type = "application/json"

        response = client.models.generate_content(
            model=self._model,
            contents=user_prompt,
            config=config,
        )
        return response.text

    def is_available(self) -> bool:
        return bool(self._api_key)


class OpenAILLMClient(LLMClient):
    """OpenAI API client (also supports Azure OpenAI)."""

    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: Optional[str] = None):
        self._api_key = api_key
        self._model = model
        self._base_url = base_url
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            kwargs: dict[str, Any] = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = OpenAI(**kwargs)
        return self._client

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        response_format: Optional[str] = None,
    ) -> str:
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format == "json":
            kwargs["response_format"] = {"type": "json_object"}

        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    def is_available(self) -> bool:
        return bool(self._api_key)


class AnthropicLLMClient(LLMClient):
    """Anthropic Claude API client."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self._api_key = api_key
        self._model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self._api_key)
        return self._client

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        response_format: Optional[str] = None,
    ) -> str:
        client = self._get_client()
        response = client.messages.create(
            model=self._model,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.content[0].text

    def is_available(self) -> bool:
        return bool(self._api_key)


class OllamaLLMClient(LLMClient):
    """Ollama local LLM client."""

    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self._model = model
        self._base_url = base_url

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        response_format: Optional[str] = None,
    ) -> str:
        import requests

        payload: dict[str, Any] = {
            "model": self._model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if response_format == "json":
            payload["format"] = "json"

        resp = requests.post(f"{self._base_url}/api/generate", json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json().get("response", "")

    def is_available(self) -> bool:
        try:
            import requests
            resp = requests.get(f"{self._base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False


def create_llm_client(settings: Optional[Settings] = None) -> LLMClient:
    """Factory function to create the appropriate LLM client based on settings.

    Args:
        settings: Application settings. Uses global settings if not provided.

    Returns:
        An initialized LLM client.

    Raises:
        ValueError: If the LLM provider is not configured properly.
    """
    if settings is None:
        settings = get_settings()

    api_key = settings.LLM_API_KEY or ""
    model = settings.LLM_MODEL

    if settings.LLM_PROVIDER == LLMProvider.GOOGLE:
        if not api_key:
            raise ValueError(
                "Google API key not set. Set API_KEY in your .env file. "
                "Get a key at https://aistudio.google.com/apikey"
            )
        return GoogleLLMClient(api_key=api_key, model=model)

    elif settings.LLM_PROVIDER == LLMProvider.OPENAI:
        if not api_key:
            raise ValueError("OpenAI API key not set. Set API_KEY in your .env file.")
        return OpenAILLMClient(api_key=api_key, model=model, base_url=settings.LLM_BASE_URL)

    elif settings.LLM_PROVIDER == LLMProvider.AZURE_OPENAI:
        if not api_key:
            raise ValueError("Azure OpenAI API key not set. Set API_KEY in your .env file.")
        if not settings.LLM_BASE_URL:
            raise ValueError("Azure OpenAI base URL not set. Set LLM_BASE_URL in your .env file.")
        return OpenAILLMClient(api_key=api_key, model=model, base_url=settings.LLM_BASE_URL)

    elif settings.LLM_PROVIDER == LLMProvider.ANTHROPIC:
        if not api_key:
            raise ValueError("Anthropic API key not set. Set API_KEY in your .env file.")
        return AnthropicLLMClient(api_key=api_key, model=model)

    elif settings.LLM_PROVIDER == LLMProvider.OLLAMA:
        base_url = settings.LLM_BASE_URL or "http://localhost:11434"
        return OllamaLLMClient(model=model, base_url=base_url)

    else:
        raise ValueError(f"Unsupported LLM provider: {settings.LLM_PROVIDER}")
