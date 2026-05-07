from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from autosecdev.settings import settings


@dataclass(frozen=True)
class CWEChunk:
    cwe_id: str
    title: str
    description: str
    extended_description: str

    @property
    def text(self) -> str:
        return f"{self.cwe_id}: {self.title}\n\n{self.description}\n\n{self.extended_description}".strip()


def _find_cwe_id(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"\bCWE-?\s*(\d{1,5})\b", text, flags=re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    return None


def _parse_cwe_from_xml(xml_path: Path, *, max_items: Optional[int] = None) -> List[CWEChunk]:
    """
    Best-effort CWE parsing from the CVEfixes-provided MITRE CWE XML.
    """
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    chunks: List[CWEChunk] = []
    for weakness in root.findall(".//Weakness"):
        # XML uses IDs like <Weakness ID="79"> ...
        cwe_id_raw = weakness.get("ID") or ""
        cwe_id = f"CWE-{cwe_id_raw}" if cwe_id_raw and not str(cwe_id_raw).startswith("CWE") else str(cwe_id_raw)
        name_el = weakness.find("Name")
        desc_el = weakness.find("Description")
        ext_el = weakness.find("ExtendedDescription")
        title = (name_el.text or "").strip() if name_el is not None and name_el.text else ""
        description = (desc_el.text or "").strip() if desc_el is not None and desc_el.text else ""
        extended_description = (ext_el.text or "").strip() if ext_el is not None and ext_el.text else ""

        if not cwe_id or not title:
            continue

        chunks.append(
            CWEChunk(
                cwe_id=cwe_id,
                title=title,
                description=description,
                extended_description=extended_description,
            )
        )
        if max_items is not None and len(chunks) >= max_items:
            break
    return chunks


class CWEChromaKB:
    def __init__(self) -> None:
        self.persist_dir = Path(settings.chroma_persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self._client = None
        self._collection = None
        self._enabled = True
        self._init_error: Optional[str] = None
        self._chroma_settings_cls = None

        try:
            # Lazy import so app startup does not fail on chromadb/opentelemetry conflicts.
            import chromadb  # type: ignore
            from chromadb.config import Settings as ChromaSettings  # type: ignore

            self._chroma_settings_cls = ChromaSettings
            self._client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=ChromaSettings(anonymized_telemetry=False),
            )
        except Exception as exc:
            self._enabled = False
            self._init_error = str(exc)

    def _collection_name(self) -> str:
        return settings.chroma_collection

    def _ensure_collection(self) -> None:
        if not self._enabled or self._client is None:
            return
        if self._collection is not None:
            return
        self._collection = self._client.get_or_create_collection(
            name=self._collection_name(),
            metadata={"hnsw:space": "cosine"},
        )

    def build_from_cvefixes_cwe_xml(self, xml_path: Path, *, max_items: Optional[int] = 272) -> None:
        self._ensure_collection()
        if not self._enabled or self._collection is None:
            return

        # If already built, don't rebuild.
        existing_count = self._collection.count()
        if existing_count and existing_count >= 200:
            return

        chunks = _parse_cwe_from_xml(xml_path, max_items=max_items)
        if not chunks:
            return

        ids = [c.cwe_id for c in chunks]
        documents = [c.text for c in chunks]
        metadatas = [{"cwe_id": c.cwe_id, "title": c.title} for c in chunks]

        self._collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

    def query(self, query_text: str, *, k: int = 3) -> List[Dict[str, str]]:
        self._ensure_collection()
        if not self._enabled or self._collection is None:
            return []
        res = self._collection.query(query_texts=[query_text], n_results=k)
        docs = []
        for doc, meta, dist in zip(res.get("documents", [[]])[0], res.get("metadatas", [[]])[0], res.get("distances", [[]])[0]):
            docs.append({"text": doc, "metadata": meta, "distance": str(dist)})
        return docs

    def get_cwe_ids(self) -> List[str]:
        self._ensure_collection()
        if not self._enabled or self._collection is None:
            return []
        # Chroma doesn't expose all ids cheaply; this is best-effort.
        try:
            res = self._collection.get(include=["metadatas"])
            metas = res.get("metadatas") or []
            ids = []
            for m in metas:
                if m and m.get("cwe_id"):
                    ids.append(str(m["cwe_id"]))
            return ids
        except Exception:
            return []

