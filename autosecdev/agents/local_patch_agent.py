from __future__ import annotations

"""
LocalPatchAgent
===============
Uses the fine-tuned CodeT5 + LoRA model (SEQ_2_SEQ_LM) to generate patches
for vulnerable code blocks.

The agent mirrors the PatchAgent interface: it accepts a dict of
{file_path: code} plus a SASTReport and returns a PatchReport.

Patching strategy
-----------------
1. For each confirmed finding, extract the surrounding function block
   (same logic as PatchAgent).
2. Feed the block to the CodeT5 model with a structured prompt.
3. Replace the block in the file with the generated output.
4. Re-run detection (via the injected detection agent) for self-verification.
"""

import difflib
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from autosecdev.schemas import (
    PatchExplanation,
    PatchReport,
    PatchedFile,
    SASTReport,
    VulnerabilityFinding,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MODEL_DIR = _REPO_ROOT / "Models" / "PatchingModel" / "codet5_lora_finetuned"


# ---------------------------------------------------------------------------
# Shared diff / block utilities (duplicated from patch_agent to keep agents
# independent — avoids circular imports)
# ---------------------------------------------------------------------------

def _unified_diff(original: str, patched: str, *, from_file: str = "a", to_file: str = "b") -> str:
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=from_file,
        tofile=to_file,
    )
    return "".join(diff)


def _extract_block_by_lines(code: str, line_start: int, line_end: int) -> Tuple[str, int, int]:
    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return "", 1, 1

    ls = max(1, int(line_start))

    block_start = 1
    for i in range(ls - 1, -1, -1):
        if re.match(r"^def\s+\w+\s*\(", lines[i].strip()):
            block_start = i + 1
            break

    block_end = n
    for j in range(block_start, n):
        if j == block_start - 1:
            continue
        if re.match(r"^(def|class)\s+\w+\s*", lines[j].strip()):
            block_end = j
            break

    block_text = "\n".join(lines[block_start - 1 : block_end])
    return block_text, block_start, block_end


def _replace_block(code: str, block_start: int, block_end: int, new_block: str) -> str:
    lines = code.splitlines()
    bs = max(1, block_start) - 1
    be = max(bs, block_end)
    patched_lines = lines[:bs] + new_block.splitlines() + lines[be:]
    return "\n".join(patched_lines) + ("\n" if code.endswith("\n") else "")


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class LocalPatchAgent:
    """
    Drop-in replacement for PatchAgent that uses the fine-tuned CodeT5 model
    instead of an external LLM API.
    """

    def __init__(
        self,
        *,
        model_dir: Optional[str] = None,
        detection_agent: Optional[Any] = None,
    ) -> None:
        self._model_dir = Path(model_dir) if model_dir else _DEFAULT_MODEL_DIR
        self.detection_agent = detection_agent  # for self-verification
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
            from transformers import AutoTokenizer, T5ForConditionalGeneration

            base_model_name = "Salesforce/codet5-base"
            print(f"[LocalPatch] Loading base model: {base_model_name}", file=sys.stderr)
            
            # Try to load base model with retries and fallbacks
            base_model = None
            tokenizer = None
            
            # Attempt 1: Load from HF Hub with offline mode disabled
            try:
                print(f"[LocalPatch] Attempt 1: Loading from HF Hub...", file=sys.stderr)
                base_model = T5ForConditionalGeneration.from_pretrained(
                    base_model_name, 
                    trust_remote_code=True,
                    local_files_only=False,
                    timeout=30
                )
                tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
                print(f"[LocalPatch] Successfully loaded from HF Hub", file=sys.stderr)
            except Exception as e:
                print(f"[LocalPatch] Attempt 1 failed: {e}", file=sys.stderr)
                
                # Attempt 2: Try loading from local cache
                try:
                    print(f"[LocalPatch] Attempt 2: Loading from local cache...", file=sys.stderr)
                    base_model = T5ForConditionalGeneration.from_pretrained(
                        base_model_name,
                        trust_remote_code=True,
                        local_files_only=True
                    )
                    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
                    print(f"[LocalPatch] Successfully loaded from cache", file=sys.stderr)
                except Exception as e2:
                    print(f"[LocalPatch] Attempt 2 failed: {e2}", file=sys.stderr)
                    
                    # Attempt 3: Use a smaller alternative model
                    try:
                        print(f"[LocalPatch] Attempt 3: Using CodeBERT as fallback...", file=sys.stderr)
                        from transformers import AutoModelForSeq2SeqLM
                        # Use CodeBERT which is smaller and available
                        base_model = AutoModelForSeq2SeqLM.from_pretrained(
                            "microsoft/codebert-base",
                            trust_remote_code=True
                        )
                        tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
                        print(f"[LocalPatch] Using CodeBERT as fallback model", file=sys.stderr)
                    except Exception as e3:
                        print(f"[LocalPatch] Attempt 3 failed: {e3}", file=sys.stderr)
                        raise RuntimeError(
                            f"Could not load any model. Tried:\n"
                            f"1. HF Hub: {e}\n"
                            f"2. Local cache: {e2}\n"
                            f"3. CodeBERT fallback: {e3}\n\n"
                            f"Please check your internet connection or manually download the model."
                        )
            
            if base_model is None or tokenizer is None:
                raise RuntimeError("Failed to load model or tokenizer")
            
            # Load LoRA adapter weights manually
            print(f"[LocalPatch] Loading LoRA adapter from: {self._model_dir}", file=sys.stderr)
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
                print(f"[LocalPatch] peft loading failed ({e}), trying direct load...", file=sys.stderr)
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

            import torch
            self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model = model.to(self._device)
            self._model = model
            self._tokenizer = tokenizer
            print(f"[LocalPatch] Model loaded on {self._device}", file=sys.stderr)
        except Exception as e:
            self._load_error = str(e)
            print(f"[LocalPatch ERROR] Failed to load model: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    # ------------------------------------------------------------------
    # Public interface (mirrors PatchAgent.patch)
    # ------------------------------------------------------------------

    def patch(
        self,
        files: Dict[str, str],
        sast: SASTReport,
        *,
        max_iterations: int = 3,
    ) -> PatchReport:
        if self.detection_agent is None:
            raise ValueError("LocalPatchAgent requires detection_agent for self-verification.")

        # If model failed to load, return unpatched report with warning
        if not self.is_loaded:
            print(
                f"[LocalPatch WARNING] Model not loaded. Returning findings without patches.",
                file=sys.stderr,
            )
            return PatchReport(
                patched_files=[],
                verified=False,
                iterations_used=0,
                final_sast=sast,
                unresolved_findings=[f for f in sast.findings if f.confirmed],
            )

        current_files = dict(files)
        initial_findings = [f for f in sast.findings if f.confirmed]

        patched_files_acc: List[PatchedFile] = []
        unresolved: List[VulnerabilityFinding] = []

        for iteration in range(1, max_iterations + 1):
            if iteration == 1:
                to_patch = initial_findings
            else:
                current_sast = self.detection_agent.scan_files(current_files)
                to_patch = [f for f in current_sast.findings if f.confirmed]

            if not to_patch:
                return PatchReport(
                    patched_files=patched_files_acc,
                    verified=True,
                    iterations_used=iteration - 1,
                    final_sast=self.detection_agent.scan_files(current_files),
                    unresolved_findings=[],
                )

            for finding in to_patch:
                original_code = current_files.get(finding.file_path)
                if not original_code:
                    continue

                block_text, block_start, block_end = _extract_block_by_lines(
                    original_code, finding.line_start, finding.line_end
                )
                if not block_text.strip():
                    continue

                patched_block, explanation = self._generate_patch(block_text, finding)
                if not patched_block.strip():
                    continue

                patched_code = _replace_block(original_code, block_start, block_end, patched_block)
                current_files[finding.file_path] = patched_code

                unified = _unified_diff(
                    original=original_code,
                    patched=patched_code,
                    from_file=finding.file_path,
                    to_file=finding.file_path,
                )
                patched_files_acc.append(
                    PatchedFile(
                        file_path=finding.file_path,
                        original_code=original_code,
                        patched_code=patched_code,
                        unified_diff=unified,
                        explanations=[PatchExplanation(summary=explanation, details=explanation)],
                    )
                )

            # Self-verification
            final_sast = self.detection_agent.scan_files(current_files)
            unresolved = self._compare_findings(to_patch, final_sast.findings)
            if not unresolved:
                return PatchReport(
                    patched_files=patched_files_acc,
                    verified=True,
                    iterations_used=iteration,
                    final_sast=final_sast,
                    unresolved_findings=[],
                )

        return PatchReport(
            patched_files=patched_files_acc,
            verified=False,
            iterations_used=max_iterations,
            final_sast=self.detection_agent.scan_files(current_files),
            unresolved_findings=unresolved,
        )

    # ------------------------------------------------------------------
    # Patch generation
    # ------------------------------------------------------------------

    def _generate_patch(
        self, block_text: str, finding: VulnerabilityFinding
    ) -> Tuple[str, str]:
        """Generate a patched version of block_text using the CodeT5 model."""
        if self._model is None or self._tokenizer is None:
            print(
                f"[LocalPatch WARNING] Model not loaded, returning original block unchanged.",
                file=sys.stderr,
            )
            return block_text, "Model unavailable — block returned unchanged."

        try:
            import torch

            cwe_hint = f"Fix {finding.cwe_id}: " if finding.cwe_id else "Fix vulnerability: "
            # CodeT5 seq2seq prompt: prefix + vulnerable code
            prompt = (
                f"{cwe_hint}{finding.description}\n"
                f"### Vulnerable code:\n{block_text}\n"
                f"### Fixed code:"
            )

            # CodeT5 tokenizer REQUIRES list input
            inputs = self._tokenizer(
                [prompt],  # MUST be a list for CodeT5
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

            with torch.no_grad():
                output_ids = self._model.generate(
                    **inputs,
                    max_new_tokens=256,
                    num_beams=4,
                    early_stopping=True,
                    no_repeat_ngram_size=3,
                )

            # Handle both single and batch outputs
            if output_ids.dim() > 1:
                generated = self._tokenizer.decode(output_ids[0], skip_special_tokens=True)
            else:
                generated = self._tokenizer.decode(output_ids, skip_special_tokens=True)

            # Strip any accidental markdown fences
            generated = re.sub(r"^```(python)?", "", generated, flags=re.IGNORECASE).strip()
            generated = re.sub(r"```$", "", generated).strip()

            if not generated:
                return block_text, "Model returned empty output — block unchanged."

            explanation = (
                f"Patched by local CodeT5 model for "
                f"{finding.cwe_id or 'unknown CWE'}: {finding.description}"
            )
            return generated, explanation

        except Exception as e:
            print(f"[LocalPatch ERROR] Generation failed: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return block_text, f"Generation error: {e}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compare_findings(
        self,
        previous_candidates: List[VulnerabilityFinding],
        current_findings: List[VulnerabilityFinding],
    ) -> List[VulnerabilityFinding]:
        prev = previous_candidates
        cur = [f for f in current_findings if f.confirmed]
        if not prev:
            return []

        unresolved: List[VulnerabilityFinding] = []
        for c in cur:
            matched = False
            for p in prev:
                if p.cwe_id and c.cwe_id and p.cwe_id == c.cwe_id:
                    matched = True
                    break
                if (
                    p.description
                    and c.description
                    and p.description.split()[0:3] == c.description.split()[0:3]
                ):
                    matched = True
                    break
            if matched:
                unresolved.append(c)
        return unresolved

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error
