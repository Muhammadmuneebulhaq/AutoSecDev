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
            if self.provider == "openrouter":
                return self._complete_openrouter(prompt=prompt, temperature=temperature)
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

    def _complete_openrouter(self, *, prompt: str, temperature: float) -> str:
        if not settings.openrouter_api_key:
            import sys
            print(f"[LLM ERROR] OpenRouter API key not set", file=sys.stderr)
            return ""
        if not settings.openrouter_model:
            import sys
            print(f"[LLM ERROR] OpenRouter model not set", file=sys.stderr)
            return ""
        def _request():
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {settings.openrouter_api_key}",
                "HTTP-Referer": "https://autosecdev.local",
            }
            payload = {
                "model": settings.openrouter_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
            }
            import sys
            print(f"[LLM DEBUG] OpenRouter request: model={settings.openrouter_model}, url={url}", file=sys.stderr)
            r = requests.post(url, headers=headers, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            print(f"[LLM DEBUG] OpenRouter response received", file=sys.stderr)
            return str(data["choices"][0]["message"]["content"]).strip()
        return self._retry_with_backoff(_request)

