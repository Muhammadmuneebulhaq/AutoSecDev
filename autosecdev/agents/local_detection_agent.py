from __future__ import annotations

"""
LocalDetectionAgent
===================
Uses the fine-tuned CodeBERT + LoRA model (SEQ_CLS) to classify code snippets
as vulnerable (label 1) or clean (label 0).

The agent mirrors the SASTAgent interface: it accepts a dict of {file_path: code}
and returns a SASTReport.  It still runs the heuristic fallback to produce
candidate findings (line numbers, CWE hints, descriptions) because the classifier
only gives a binary label per snippet — it does not locate lines or assign CWEs.
The classifier is then used to *confirm* or *dismiss* each candidate, replacing
the LLM confirmation step used by SASTAgent.
"""

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from autosecdev.schemas import SASTReport, VulnerabilityFinding

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MODEL_DIR = _REPO_ROOT / "Models" / "DetectionModel" / "codebert_lora_finetuned"


class LocalDetectionAgent:
    """
    Drop-in replacement for SASTAgent that uses the fine-tuned CodeBERT
    classifier instead of Bandit/Semgrep + LLM confirmation.

    Detection strategy
    ------------------
    1. Run the same heuristic pattern scanner as SASTAgent to get candidate
       findings with line numbers, CWE hints, and descriptions.
    2. For each candidate, extract the surrounding function block and run it
       through the CodeBERT classifier.
    3. Candidates classified as *vulnerable* (label 1) are confirmed; others
       are dismissed.
    4. If no heuristic candidates are found, run the classifier on the whole
       file to decide whether it is vulnerable at all.
    """

    def __init__(self, model_dir: Optional[str] = None) -> None:
        self._model_dir = Path(model_dir) if model_dir else _DEFAULT_MODEL_DIR
        self._model = None
        self._tokenizer = None
        self._device = None
        self._load_error: Optional[str] = None
        self._load_model()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        try:
            # Prevent torchvision from being imported (causes compatibility issues)
            import sys
            sys.modules['torchvision'] = None
            
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            
            base_model_name = "microsoft/codebert-base"
            print(f"[LocalDetection] Loading base model: {base_model_name}", file=sys.stderr)
            
            # Load tokenizer from base model (not from adapter dir which may have corrupted config)
            try:
                tokenizer = AutoTokenizer.from_pretrained(base_model_name)
            except Exception as e:
                print(f"[LocalDetection] Failed to load tokenizer from base model: {e}", file=sys.stderr)
                # Try loading from adapter dir as fallback
                tokenizer = AutoTokenizer.from_pretrained(str(self._model_dir))
            
            base_model = AutoModelForSequenceClassification.from_pretrained(
                base_model_name, num_labels=2, trust_remote_code=True
            )
            
            # Load LoRA adapter weights manually
            print(f"[LocalDetection] Loading LoRA adapter from: {self._model_dir}", file=sys.stderr)
            import json
            adapter_config_path = self._model_dir / "adapter_config.json"
            adapter_weights_path = self._model_dir / "adapter_model.safetensors"
            
            if not adapter_config_path.exists():
                raise FileNotFoundError(f"adapter_config.json not found at {self._model_dir}")
            
            # Load adapter using peft with version compatibility
            try:
                from peft import get_peft_model, PeftConfig
                config = PeftConfig.from_pretrained(str(self._model_dir))
                model = get_peft_model(base_model, config)
                
                # Load adapter weights
                if adapter_weights_path.exists():
                    from safetensors.torch import load_file
                    adapter_weights = load_file(str(adapter_weights_path))
                    # Merge adapter weights into model
                    for key, value in adapter_weights.items():
                        if key in model.state_dict():
                            model.state_dict()[key].copy_(value)
            except Exception as e:
                print(f"[LocalDetection] peft loading failed ({e}), trying direct load...", file=sys.stderr)
                # Fallback: load base model and adapter weights directly
                if adapter_weights_path.exists():
                    from safetensors.torch import load_file
                    adapter_weights = load_file(str(adapter_weights_path))
                    model = base_model
                    # Try to load weights directly
                    model.load_state_dict(adapter_weights, strict=False)
                else:
                    model = base_model
            
            model.eval()

            self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model = model.to(self._device)
            self._model = model
            self._tokenizer = tokenizer
            print(f"[LocalDetection] Model loaded on {self._device}", file=sys.stderr)
        except Exception as e:
            self._load_error = str(e)
            print(f"[LocalDetection ERROR] Failed to load model: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            print(f"[LocalDetection ERROR] Failed to load model: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    # ------------------------------------------------------------------
    # Public interface (mirrors SASTAgent.scan_files)
    # ------------------------------------------------------------------

    def scan_files(self, files: Dict[str, str]) -> SASTReport:
        all_findings: List[VulnerabilityFinding] = []

        for file_path, code in files.items():
            candidates = self._heuristic_candidates(code, original_file_path=file_path)

            if candidates:
                confirmed = self._classify_candidates(code, file_path, candidates)
            else:
                # No heuristic hits — run classifier on whole file to decide.
                confirmed = self._classify_whole_file(code, file_path)

            all_findings.extend(confirmed)

        return SASTReport(findings=all_findings)

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------

    def _classify_snippet(self, snippet: str) -> Tuple[int, float]:
        """
        Run the CodeBERT classifier on a code snippet.
        Returns (predicted_label, confidence) where label 1 = vulnerable.
        Falls back to (1, 0.5) if model is unavailable (fail-open).
        """
        if self._model is None or self._tokenizer is None:
            # Model failed to load — fail-open (treat as vulnerable).
            return 1, 0.5

        try:
            import torch

            # CodeBERT tokenizer may require list input; ensure compatibility
            try:
                inputs = self._tokenizer(
                    [snippet],  # Wrap in list for compatibility
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True,
                )
            except TypeError:
                # Fallback: try without list
                inputs = self._tokenizer(
                    snippet,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True,
                )
            
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
                label = int(torch.argmax(probs, dim=-1).item())
                confidence = float(probs[0][label].item())

            return label, confidence
        except Exception as e:
            print(f"[LocalDetection ERROR] Inference failed: {e}", file=sys.stderr)
            return 1, 0.5  # fail-open

    def _classify_candidates(
        self, code: str, file_path: str, candidates: List[Dict[str, Any]]
    ) -> List[VulnerabilityFinding]:
        """Confirm/dismiss each heuristic candidate using the classifier."""
        confirmed: List[VulnerabilityFinding] = []
        lines = code.splitlines()
        n = len(lines)

        for c in candidates:
            # Extract a window around the candidate line for context.
            ls = max(0, c["line_start"] - 1)
            le = min(n, c["line_end"] + 5)
            snippet = "\n".join(lines[ls:le])

            label, confidence = self._classify_snippet(snippet)
            is_confirmed = label == 1

            confirmed.append(
                VulnerabilityFinding(
                    file_path=c["file_path"],
                    line_start=c["line_start"],
                    line_end=c["line_end"],
                    cwe_id=c.get("cwe_id"),
                    severity=str(c.get("severity") or "unknown"),
                    description=c.get("description", "Vulnerability detected by local model"),
                    code_snippet=str(c.get("code_snippet") or snippet).strip(),
                    confirmed=is_confirmed,
                    tool_sources=["codebert-local"] + (c.get("tool_sources") or []),
                )
            )

        return confirmed

    def _classify_whole_file(self, code: str, file_path: str) -> List[VulnerabilityFinding]:
        """
        When no heuristic candidates exist, classify the whole file.
        If vulnerable, return a single file-level finding.
        """
        label, confidence = self._classify_snippet(code)
        if label != 1:
            return []

        return [
            VulnerabilityFinding(
                file_path=file_path,
                line_start=1,
                line_end=len(code.splitlines()),
                cwe_id=None,
                severity="unknown",
                description=(
                    f"Local CodeBERT model flagged this file as potentially vulnerable "
                    f"(confidence: {confidence:.2%}). Manual review recommended."
                ),
                code_snippet=code[:500].strip(),
                confirmed=True,
                tool_sources=["codebert-local"],
            )
        ]

    # ------------------------------------------------------------------
    # Heuristic candidate scanner (same as SASTAgent)
    # ------------------------------------------------------------------

    def _heuristic_candidates(self, code: str, *, original_file_path: str) -> List[Dict[str, Any]]:
        lines = code.splitlines()
        candidates: List[Dict[str, Any]] = []
        patterns = [
            (r"\beval\(", "Potential code execution via eval()", "CWE-78", "high"),
            (r"\bexec\(", "Potential code execution via exec()", "CWE-78", "high"),
            (r"subprocess\.(Popen|call|run)\(.*shell\s*=\s*True", "Shell injection risk with shell=True", "CWE-78", "high"),
            (r"pickle\.loads\(", "Unsafe deserialization with pickle.loads()", "CWE-502", "high"),
            (r"yaml\.load\(", "Unsafe YAML load may execute arbitrary code", "CWE-502", "high"),
            (r"hashlib\.md5\(", "Weak hash algorithm (MD5) for security context", "CWE-327", "medium"),
            (r"os\.system\(", "Shell command execution via os.system()", "CWE-78", "high"),
            (r"__import__\(", "Dynamic import may allow code injection", "CWE-78", "medium"),
            (r"open\(.*['\"]w['\"]", "File write operation — check for path traversal", "CWE-22", "medium"),
            (r"sqlite3\.connect\(", "Direct SQL connection — check for injection", "CWE-89", "medium"),
            (r"\.format\(.*request", "Potential injection via string formatting", "CWE-89", "medium"),
            (r"random\.(random|randint|choice)\(", "Weak PRNG for security context", "CWE-338", "low"),
        ]
        for idx, line in enumerate(lines, start=1):
            for pat, desc, cwe, sev in patterns:
                if re.search(pat, line):
                    candidates.append(
                        {
                            "file_path": original_file_path,
                            "line_start": idx,
                            "line_end": idx,
                            "cwe_id": cwe,
                            "severity": sev,
                            "description": desc,
                            "code_snippet": line.strip(),
                            "tool_sources": ["heuristic"],
                            "candidate_type": "heuristic-pattern",
                        }
                    )
        return candidates

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error
