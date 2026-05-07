from __future__ import annotations

import json
import time
from typing import Optional

import requests

from autosecdev.settings import settings


class LLMClient:
    """
    Minimal LLM wrapper with retry logic.
    Default: Ollama (free local). Can be switched via AUTOSSECDEV_LLM_PROVIDER.
    """

    def __init__(self) -> None:
        self.provider = settings.llm_provider
        self.max_retries = 8  # Increased from 5 to 8
        self.initial_backoff = 2  # Increased from 1 to 2 seconds

    def complete(self, prompt: str, *, temperature: float = 0.0) -> str:
        try:
            if self.provider == "ollama":
                return self._complete_ollama(prompt=prompt, temperature=temperature)
            if self.provider == "openai":
                return self._complete_openai(prompt=prompt, temperature=temperature)
            if self.provider == "claude":
                return self._complete_claude(prompt=prompt, temperature=temperature)
            if self.provider == "gemini":
                return self._complete_gemini(prompt=prompt, temperature=temperature)
            # Research fallback: returns empty completion so pipeline stays runnable.
            return ""
        except Exception as e:
            # Log error for debugging
            import sys
            print(f"[LLM ERROR] Provider={self.provider}, Error: {str(e)}", file=sys.stderr)
            # Fail-open so agent pipeline can continue with deterministic fallbacks.
            return ""

    def _retry_with_backoff(self, func, *, max_retries: int = None, initial_backoff: float = None):
        """Retry a request with exponential backoff for rate limits."""
        max_retries = max_retries or self.max_retries
        backoff = initial_backoff or self.initial_backoff
        
        for attempt in range(max_retries + 1):
            try:
                return func()
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429 and attempt < max_retries:
                    # Rate limited, wait and retry
                    wait_time = backoff * (2 ** attempt)  # Exponential backoff: 2, 4, 8, 16, 32, 64, 128, 256s
                    import sys
                    print(f"[LLM RETRY] 429 Rate limited. Waiting {wait_time:.1f}s before retry {attempt + 1}/{max_retries}...", file=sys.stderr)
                    time.sleep(wait_time)
                    continue
                else:
                    raise

    def _complete_ollama(self, *, prompt: str, temperature: float) -> str:
        def _request():
            url = f"{settings.ollama_url}/api/generate"
            payload = {
                "model": settings.ollama_model,
                "prompt": prompt,
                "stream": False,
                "temperature": temperature,
            }
            r = requests.post(url, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            return str(data.get("response", "")).strip()
        return self._retry_with_backoff(_request)

    def _complete_openai(self, *, prompt: str, temperature: float) -> str:
        if not settings.openai_api_key:
            return ""
        def _request():
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {settings.openai_api_key}"}
            payload = {
                "model": settings.openai_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
            }
            r = requests.post(url, headers=headers, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            return str(data["choices"][0]["message"]["content"]).strip()
        return self._retry_with_backoff(_request)

    def _complete_claude(self, *, prompt: str, temperature: float) -> str:
        if not settings.anthropic_api_key:
            return ""
        def _request():
            url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            payload = {
                "model": settings.anthropic_model,
                "max_tokens": 1200,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
            r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=120)
            r.raise_for_status()
            data = r.json()
            content = data.get("content") or []
            if content and isinstance(content, list):
                # Anthropic returns list of blocks
                return str(content[0].get("text", "")).strip()
            return ""
        return self._retry_with_backoff(_request)

    def _complete_gemini(self, *, prompt: str, temperature: float) -> str:
        if not settings.gemini_api_key:
            return ""
        def _request():
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": temperature},
            }
            r = requests.post(url, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            candidates = data.get("candidates") or []
            if candidates and isinstance(candidates, list):
                content = candidates[0].get("content") or {}
                parts = content.get("parts") or []
                if parts and isinstance(parts, list):
                    return str(parts[0].get("text", "")).strip()
            return ""
        return self._retry_with_backoff(_request)

