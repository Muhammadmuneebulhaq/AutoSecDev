from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

# Load .env file explicitly
from dotenv import load_dotenv
load_dotenv(override=True)


@dataclass(frozen=True)
class Settings:
    # LLM provider options: "ollama", "openrouter" - NO DEFAULT
    llm_provider: str = os.getenv("AUTOSECDEV_LLM_PROVIDER") or ""

    # Ollama
    ollama_url: str = os.getenv("OLLAMA_URL") or ""
    ollama_model: str = os.getenv("OLLAMA_MODEL") or ""

    # OpenRouter (free models)
    openrouter_api_key: Optional[str] = os.getenv("OPENROUTER_API_KEY")
    openrouter_model: str = os.getenv("OPENROUTER_MODEL") or "meta-llama/llama-3-8b-instruct"

    # Safety / runtime controls
    max_patch_iterations: int = int(os.getenv("AUTOSECDEV_MAX_PATCH_ITERATIONS", "3"))

    # RAG
    chroma_persist_dir: str = os.getenv("CHROMA_PERSIST_DIR", "data/chroma")
    chroma_collection: str = os.getenv("CHROMA_COLLECTION", "autosecdev_cwe_kb")


settings = Settings()

