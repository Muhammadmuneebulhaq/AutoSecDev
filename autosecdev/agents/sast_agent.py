from __future__ import annotations

import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from autosecdev.llm.client import LLMClient
from autosecdev.schemas import SASTReport, VulnerabilityFinding
from autosecdev.utils.json_utils import extract_first_json_object


def _run_cmd_json(cmd: List[str], cwd: Optional[str] = None, timeout_s: int = 120) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, timeout=timeout_s, capture_output=True, text=True)
    except FileNotFoundError:
        return {"error": f"command-not-found: {' '.join(cmd)}", "results": []}
    try:
        parsed = json.loads(proc.stdout)
        if proc.returncode != 0:
            parsed["_nonzero_exit_code"] = proc.returncode
            if proc.stderr.strip():
                parsed["_stderr"] = proc.stderr.strip()
        return parsed
    except Exception:
        if proc.returncode != 0:
            return {"error": proc.stderr.strip() or f"command-failed-exit-{proc.returncode}", "raw": proc.stdout.strip()}
        return {"error": "non-json-bandit-or-semgrep-output", "raw": proc.stdout.strip()}


def _run_cmd_json_fallback(cmds: List[List[str]], cwd: Optional[str] = None, timeout_s: int = 120) -> Dict[str, Any]:
    """
    Try multiple command variants (Windows-safe): binary first, then python -m fallback.
    """
    last_error: Dict[str, Any] = {"error": "no-command-provided", "results": []}
    for cmd in cmds:
        out = _run_cmd_json(cmd, cwd=cwd, timeout_s=timeout_s)
        # If command exists, return output (even if non-zero). If missing, try next fallback.
        if "command-not-found" not in str(out.get("error", "")):
            return out
        last_error = out
    return last_error


class SASTAgent:
    """
    Stage 1: run Bandit + Semgrep and normalize into a candidate finding list.
    Stage 2: LLM confirms/dismisses + assigns severity and CWE (best-effort).
    """

    def __init__(self, llm: Optional[LLMClient] = None) -> None:
        self.llm = llm or LLMClient()

    def scan_files(self, files: Dict[str, str]) -> SASTReport:
        with tempfile.TemporaryDirectory(prefix="autosecdev_sast_") as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            all_findings: List[VulnerabilityFinding] = []
            bandit_json_acc: Dict[str, Any] = {"results": []}
            semgrep_json_acc: Dict[str, Any] = {"results": []}

            for file_path, code in files.items():
                p = tmp_dir_path / Path(file_path).name
                p.write_text(code, encoding="utf-8", errors="ignore")
                bandit_json = self._run_bandit(p)
                semgrep_json = self._run_semgrep(p)

                bandit_candidates = self._normalize_bandit(bandit_json, original_file_path=file_path)
                semgrep_candidates = self._normalize_semgrep(semgrep_json, original_file_path=file_path)
                candidates = bandit_candidates + semgrep_candidates
                if not candidates:
                    candidates = self._heuristic_candidates(code, original_file_path=file_path)

                bandit_json_acc["results"].extend(bandit_json.get("results", []) if isinstance(bandit_json, dict) else [])
                semgrep_json_acc["results"].extend(semgrep_json.get("results", []) if isinstance(semgrep_json, dict) else [])

                confirmed = self._llm_confirm_and_enrich(code, file_path, candidates)
                all_findings.extend(confirmed)

            # Keep raw tool output for traceability.
            return SASTReport(
                findings=all_findings,
                bandit_json=bandit_json_acc if bandit_json_acc.get("results") else None,
                semgrep_json=semgrep_json_acc if semgrep_json_acc.get("results") else None,
            )

    def _run_bandit(self, path: Path) -> Dict[str, Any]:
        # Bandit returns JSON with top-level "results".
        return _run_cmd_json_fallback(
            [
                ["bandit", "-f", "json", str(path)],
                [sys.executable, "-m", "bandit", "-f", "json", str(path)],
            ]
        )

    def _run_semgrep(self, path: Path) -> Dict[str, Any]:
        # semgrep auto config; can be heavy. Use best-effort.
        return _run_cmd_json_fallback(
            [
                ["semgrep", "--json", "--config", "auto", str(path)],
                [sys.executable, "-m", "semgrep", "--json", "--config", "auto", str(path)],
            ]
        )

    def _normalize_bandit(self, bandit_json: Dict[str, Any], *, original_file_path: str) -> List[Dict[str, Any]]:
        results = bandit_json.get("results") if isinstance(bandit_json, dict) else None
        if not isinstance(results, list):
            return []
        candidates: List[Dict[str, Any]] = []
        for r in results:
            line = r.get("line_number") or r.get("line") or 1
            severity = (r.get("issue_severity") or "unknown").lower()
            cwe_id = None
            if isinstance(r.get("issue_cwe"), dict) and r["issue_cwe"].get("id"):
                cwe_id = f"CWE-{r['issue_cwe']['id']}"
            candidates.append(
                {
                    "file_path": original_file_path,
                    "line_start": int(line),
                    "line_end": int(line),
                    "cwe_id": cwe_id,
                    "severity": severity,
                    "description": str(r.get("issue_text") or r.get("test_name") or "Bandit finding"),
                    "code_snippet": str(r.get("code") or "").strip(),
                    "tool_sources": ["bandit"],
                    "candidate_type": str(r.get("test_id") or "bandit"),
                }
            )
        return candidates

    def _normalize_semgrep(self, semgrep_json: Dict[str, Any], *, original_file_path: str) -> List[Dict[str, Any]]:
        results = semgrep_json.get("results") if isinstance(semgrep_json, dict) else None
        if not isinstance(results, list):
            return []
        candidates: List[Dict[str, Any]] = []
        for r in results:
            loc = r.get("location") or {}
            start = loc.get("start") or {}
            line = start.get("line") or 1
            # semgrep doesn't always give a CWE id; use ruleId and message for context.
            severity = (r.get("extra", {}) or {}).get("severity") or r.get("config", {}).get("severity") or "unknown"
            severity = str(severity).lower()
            code_snippet = ""
            if isinstance(r.get("extra"), dict):
                code_snippet = str(r["extra"].get("lines") or "").strip()
            candidates.append(
                {
                    "file_path": original_file_path,
                    "line_start": int(line),
                    "line_end": int(line),
                    "severity": severity,
                    "description": str(r.get("extra", {}).get("message") or r.get("check_id") or r.get("ruleId") or "Semgrep finding"),
                    "code_snippet": code_snippet,
                    "tool_sources": ["semgrep"],
                    "candidate_type": str(r.get("check_id") or r.get("ruleId") or "semgrep"),
                }
            )
        return candidates

    def _heuristic_candidates(self, code: str, *, original_file_path: str) -> List[Dict[str, Any]]:
        """
        Lightweight fallback detections for demos when external tools are unavailable.
        """
        lines = code.splitlines()
        candidates: List[Dict[str, Any]] = []
        patterns = [
            (r"\beval\(", "Potential code execution via eval()", "CWE-78", "high"),
            (r"\bexec\(", "Potential code execution via exec()", "CWE-78", "high"),
            (r"subprocess\.(Popen|call|run)\(.*shell\s*=\s*True", "Shell injection risk with shell=True", "CWE-78", "high"),
            (r"pickle\.loads\(", "Unsafe deserialization with pickle.loads()", "CWE-502", "high"),
            (r"yaml\.load\(", "Unsafe YAML load may execute arbitrary code", "CWE-502", "high"),
            (r"hashlib\.md5\(", "Weak hash algorithm (MD5) for security context", "CWE-327", "medium"),
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

    def _llm_confirm_and_enrich(
        self, code: str, file_path: str, candidates: List[Dict[str, Any]]
    ) -> List[VulnerabilityFinding]:
        if not candidates:
            return []

        # Truncate code for prompt size; tool findings already include line numbers.
        code_lines = code.splitlines()
        head = "\n".join(code_lines[:250])
        tail = "\n".join(code_lines[-200:]) if len(code_lines) > 450 else ""

        candidates_trimmed = candidates[:25]
        payload = {
            "file_path": file_path,
            "code_preview_head": head,
            "code_preview_tail": tail,
            "tool_candidates": candidates_trimmed,
            "required_output": {
                "findings": [
                    {
                        "file_path": "string",
                        "line_start": 1,
                        "line_end": 1,
                        "cwe_id": "CWE-XXX or null",
                        "severity": "low|medium|high|critical|unknown",
                        "description": "string",
                        "code_snippet": "string",
                        "confirmed": True,
                        "tool_sources": ["bandit|semgrep"],
                    }
                ]
            },
        }

        prompt = (
            "You are a software security expert. You will be given a Python file snippet and a list of vulnerability candidates\n"
            "produced by Bandit and Semgrep.\n\n"
            "Task: For each candidate, decide whether it is a true positive based on code context. If false positive, set confirmed=false.\n"
            "Also assign severity and best-effort CWE ID (or null if unknown).\n"
            "Return ONLY valid JSON in this exact structure: {\"findings\": [ ... ]}.\n\n"
            f"INPUT_JSON:\n{json.dumps(payload)}"
        )

        response = self.llm.complete(prompt, temperature=0.0)
        parsed = extract_first_json_object(response) if response else None
        if isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
            out: List[VulnerabilityFinding] = []
            for item in parsed["findings"]:
                try:
                    out.append(VulnerabilityFinding(**item))
                except Exception:
                    continue
            # If model returned partial/invalid JSON, fall back to confirming candidates.
            if out:
                return out

        # Fallback: confirm everything (better than returning nothing for demos).
        out: List[VulnerabilityFinding] = []
        for c in candidates_trimmed:
            out.append(
                VulnerabilityFinding(
                    file_path=c["file_path"],
                    line_start=c["line_start"],
                    line_end=c["line_end"],
                    cwe_id=c.get("cwe_id"),
                    severity=str(c.get("severity") or "unknown"),
                    description=str(c.get("description") or "Finding"),
                    code_snippet=str(c.get("code_snippet") or "").strip(),
                    confirmed=True,
                    tool_sources=c.get("tool_sources") or [],
                )
            )
        return out

