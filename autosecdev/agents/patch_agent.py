from __future__ import annotations

import difflib
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from autosecdev.llm.client import LLMClient
from autosecdev.rag.cwe_chroma import CWEChromaKB
from autosecdev.schemas import PatchExplanation, PatchReport, PatchedFile, SASTReport, VulnerabilityFinding


def _unified_diff(original: str, patched: str, *, from_file: str = "a", to_file: str = "b") -> str:
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=from_file,
        tofile=to_file,
    )
    return "".join(diff)


def _extract_block_by_lines(code: str, line_start: int, line_end: int) -> Tuple[str, int, int]:
    """
    Best-effort block extraction for Python given approximate line range.
    Returns: (block_text, block_start_line_1_based, block_end_line_1_based)
    """
    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return "", 1, 1

    ls = max(1, int(line_start))
    le = min(n, int(line_end))

    # Backtrack to the nearest "def " at indentation 0 before/at ls.
    block_start = 1
    for i in range(ls - 1, -1, -1):
        if re.match(r"^def\s+\w+\s*\(", lines[i].strip()):
            block_start = i + 1
            break

    # Forward: stop at next top-level def/class after the block_start (excluding itself).
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
    be = max(bs, block_end)  # block_end is 1-based exclusive? We treat as 1-based end line inclusive earlier.
    # Our extractor returns block_end_line_1_based as `block_end`, where slicing uses up to block_end (exclusive index).
    # So `block_end` from extractor corresponds to exclusive 0-based index. We'll keep consistent:
    # extractor sets block_end to j where next top-level def/class starts; it uses lines[block_start-1:block_end]
    # Therefore we replace lines[block_start-1:block_end].
    be_exclusive = be
    patched_lines = lines[:bs] + new_block.splitlines() + lines[be_exclusive:]
    return "\n".join(patched_lines) + ("\n" if code.endswith("\n") else "")


class PatchAgent:
    def __init__(self, *, llm: Optional[LLMClient] = None, sast_agent: Optional[Any] = None, rag_kb: Optional[CWEChromaKB] = None) -> None:
        self.llm = llm or LLMClient()
        self.sast_agent = sast_agent  # injected later to avoid circular import
        self.rag_kb = rag_kb or CWEChromaKB()
        self._init_rag_kb()  # Initialize RAG KB on first use
    
    def _init_rag_kb(self) -> None:
        """Initialize RAG KB from CVEfixes CWE XML if not already populated."""
        if not self.rag_kb._enabled:
            return
        # Check if already populated
        cwe_ids = self.rag_kb.get_cwe_ids()
        if cwe_ids and len(cwe_ids) > 50:  # Already populated
            return
        # Try to load from CVEfixes data
        from pathlib import Path
        possible_paths = [
            Path("CVEfixes_v1.0.0/Data/cwec_v4.4.xml"),
            Path("../CVEfixes_v1.0.0/Data/cwec_v4.4.xml"),
            Path("./CVEfixes_v1.0.0/Data/cwec_v4.4.xml"),
        ]
        for xml_path in possible_paths:
            if xml_path.exists():
                try:
                    self.rag_kb.build_from_cvefixes_cwe_xml(xml_path)
                    import sys
                    print(f"[RAG] Initialized CWE KB from {xml_path}", file=sys.stderr)
                except Exception as e:
                    import sys
                    print(f"[RAG ERROR] Failed to populate from {xml_path}: {e}", file=sys.stderr)
                return
        import sys
        print(f"[RAG WARNING] CWE XML not found at any expected path. RAG context will be limited.", file=sys.stderr)
        self._init_rag_kb()  # Initialize RAG KB on first use
    
    def _init_rag_kb(self) -> None:
        """Initialize RAG KB from CVEfixes CWE XML if not already populated."""
        if not self.rag_kb._enabled:
            return
        # Check if already populated
        cwe_ids = self.rag_kb.get_cwe_ids()
        if cwe_ids and len(cwe_ids) > 50:  # Already populated
            return
        # Try to load from CVEfixes data
        from pathlib import Path
        possible_paths = [
            Path("CVEfixes_v1.0.0/Data/cwec_v4.4.xml"),
            Path("../CVEfixes_v1.0.0/Data/cwec_v4.4.xml"),
            Path("./CVEfixes_v1.0.0/Data/cwec_v4.4.xml"),
        ]
        for xml_path in possible_paths:
            if xml_path.exists():
                try:
                    self.rag_kb.build_from_cvefixes_cwe_xml(xml_path)
                    import sys
                    print(f"[RAG] Initialized CWE KB from {xml_path}", file=sys.stderr)
                except Exception as e:
                    import sys
                    print(f"[RAG ERROR] Failed to populate from {xml_path}: {e}", file=sys.stderr)
                return
        import sys
        print(f"[RAG WARNING] CWE XML not found at any expected path. RAG context will be limited.", file=sys.stderr)

    def _candidates_to_prompt(self, finding: VulnerabilityFinding, *, iteration: int) -> str:
        cwe_part = f"Assigned CWE: {finding.cwe_id}" if finding.cwe_id else "Assigned CWE: unknown"
        return (
            f"Finding:\n"
            f"- File: {finding.file_path}\n"
            f"- Lines: {finding.line_start}-{finding.line_end}\n"
            f"- Severity: {finding.severity}\n"
            f"- {cwe_part}\n"
            f"- Description: {finding.description}\n"
            f"- Existing code snippet:\n{finding.code_snippet}\n\n"
            f"Patch iteration attempt: {iteration}\n"
        )

    def patch(self, files: Dict[str, str], sast: SASTReport, *, max_iterations: int = 3) -> PatchReport:
        if self.sast_agent is None:
            raise ValueError("PatchAgent requires sast_agent for self-verification.")

        current_files = dict(files)
        initial_findings = [f for f in sast.findings if f.confirmed]

        patched_files_acc: List[PatchedFile] = []
        unresolved: List[VulnerabilityFinding] = []

        for iteration in range(1, max_iterations + 1):
            # Apply patches for currently confirmed findings.
            if iteration == 1:
                to_patch = initial_findings
            else:
                # Re-run SAST on current files to see what remains.
                current_sast = self.sast_agent.scan_files(current_files)
                to_patch = [f for f in current_sast.findings if f.confirmed]

            if not to_patch:
                return PatchReport(
                    patched_files=patched_files_acc,
                    verified=True,
                    iterations_used=iteration - 1,
                    final_sast=self.sast_agent.scan_files(current_files),
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

                patched_block, explanation = self._patch_block(block_text, finding, iteration=iteration)
                if not patched_block.strip():
                    continue

                patched_code = _replace_block(original_code, block_start, block_end, patched_block)
                current_files[finding.file_path] = patched_code

                unified = _unified_diff(original=original_code, patched=patched_code, from_file=finding.file_path, to_file=finding.file_path)
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
            final_sast = self.sast_agent.scan_files(current_files)
            unresolved = self._compare_findings(to_patch, final_sast.findings)
            if not unresolved:
                return PatchReport(
                    patched_files=patched_files_acc,
                    verified=True,
                    iterations_used=iteration,
                    final_sast=final_sast,
                    unresolved_findings=[],
                )

            # If not verified, continue loop with next iteration prompt.

        return PatchReport(
            patched_files=patched_files_acc,
            verified=False,
            iterations_used=max_iterations,
            final_sast=self.sast_agent.scan_files(current_files),
            unresolved_findings=unresolved,
        )

    def _compare_findings(self, previous_candidates: List[VulnerabilityFinding], current_findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """
        Best-effort 'same vulnerability still detected' check.
        Matching: same CWE (if present) OR overlapping description keywords.
        """
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
                if p.description and c.description and p.description.split()[0:3] == c.description.split()[0:3]:
                    matched = True
                    break
            if matched:
                unresolved.append(c)
        return unresolved

    def _patch_block(self, block_text: str, finding: VulnerabilityFinding, *, iteration: int) -> Tuple[str, str]:
        # RAG context (CWE-only) best-effort.
        cwe_context = ""
        if finding.cwe_id:
            docs = self.rag_kb.query(f"{finding.cwe_id}: {finding.description}", k=3)
            top = docs[:3]
            cwe_context = "\n\n".join([f"{d['metadata'].get('cwe_id','')}\n{d['text']}" for d in top if d.get("text")])  # type: ignore[arg-type]

        # Add delay before LLM call to avoid rate limiting (increased from 2s)
        import sys
        print(f"[PATCH] Waiting 5s before calling LLM for {finding.cwe_id} (iteration {iteration})...", file=sys.stderr)
        time.sleep(5)

        prompt = (
            "You are an expert secure software engineer.\n"
            "Fix the vulnerability in the provided Python block.\n\n"
            "Rules:\n"
            "1) Return ONLY the patched Python block (no markdown).\n"
            "2) Keep the function signature the same.\n"
            "3) Do not change unrelated logic.\n"
            "4) If a safe fix is unclear, apply the least risky mitigation.\n\n"
            "RAG CWE context (may be empty):\n"
            f"{cwe_context}\n\n"
            "Vulnerability details:\n"
            f"{self._candidates_to_prompt(finding, iteration=iteration)}\n"
            "Vulnerable block:\n"
            f"{block_text}\n\n"
            "Patched block:"
        )

        response = self.llm.complete(prompt, temperature=0.0).strip()
        
        # Validate LLM response
        if not response:
            import sys
            print(f"[PATCH WARNING] LLM returned empty response for {finding.cwe_id} at iteration {iteration}", file=sys.stderr)
            return "", "LLM failed to generate patch"

        # Some LLMs return backticks; strip minimal.
        response = re.sub(r"^```(python)?", "", response, flags=re.IGNORECASE).strip()
        response = re.sub(r"```$", "", response).strip()

        explanation = (
            f"Patched based on {finding.cwe_id or 'unknown CWE'}: "
            f"replaced the vulnerable pattern with a safer implementation while preserving behavior."
        )
        return response, explanation

