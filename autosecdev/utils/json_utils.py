from __future__ import annotations

import json
import re
from typing import Any, Optional


def extract_first_json_object(text: str) -> Optional[Any]:
    """
    Best-effort extraction of the first JSON object from a model response.
    Helps when the LLM wraps JSON in markdown/code fences.
    """
    if not text:
        return None

    # Remove common markdown wrappers.
    cleaned = text.strip()
    cleaned = re.sub(r"^```(json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()

    # Direct parse first.
    try:
        return json.loads(cleaned)
    except Exception:
        pass

    # Fallback: locate the first {...} block.
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None

