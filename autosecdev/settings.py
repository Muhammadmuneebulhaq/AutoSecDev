from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

# Load .env file explicitly
from dotenv import load_dotenv
load_dotenv(override=True)


@dataclass(frozen=True)
class Settings:
    # LLM provider options: "ollama", "openai", "claude", "gemini" - NO DEFAULT
    llm_provider: str = os.getenv("AUTOSECDEV_LLM_PROVIDER") or ""

    # Ollama
    ollama_url: str = os.getenv("OLLAMA_URL") or ""
    ollama_model: str = os.getenv("OLLAMA_MODEL") or ""

    # OpenAI / Azure OpenAI
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL") or ""

    # Anthropic
    anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL") or ""

    # Google Gemini
    gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
    gemini_model: str = os.getenv("GEMINI_MODEL") or ""

    # Safety / runtime controls
    max_patch_iterations: int = int(os.getenv("AUTOSECDEV_MAX_PATCH_ITERATIONS", "3"))

    # RAG
    chroma_persist_dir: str = os.getenv("CHROMA_PERSIST_DIR", "data/chroma")
    chroma_collection: str = os.getenv("CHROMA_COLLECTION", "autosecdev_cwe_kb")


settings = Settings()


settings = Settings()

