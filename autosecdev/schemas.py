from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    cwe_id: Optional[str] = None
    severity: Literal["low", "medium", "high", "critical", "unknown"] = "unknown"
    description: str
    code_snippet: str
    confirmed: bool
    tool_sources: List[str] = Field(default_factory=list)


class SASTReport(BaseModel):
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    # Optional raw tool output for debugging and research appendix.
    bandit_json: Optional[Dict[str, Any]] = None
    semgrep_json: Optional[Dict[str, Any]] = None


class PatchExplanation(BaseModel):
    summary: str
    details: str


class PatchedFile(BaseModel):
    file_path: str
    original_code: str
    patched_code: str
    unified_diff: str
    explanations: List[PatchExplanation] = Field(default_factory=list)


class PatchReport(BaseModel):
    patched_files: List[PatchedFile] = Field(default_factory=list)
    verified: bool
    iterations_used: int
    # If unresolved, the SAST results after the final iteration.
    final_sast: Optional[SASTReport] = None
    # If unresolved, keep the findings that couldn't be fixed.
    unresolved_findings: List[VulnerabilityFinding] = Field(default_factory=list)


class GithubWebhookRequest(BaseModel):
    # FastAPI doesn't validate the raw GitHub payload fully; this is the part we use.
    action: Optional[str] = None
    pull_request: Optional[Dict[str, Any]] = None
    repository: Optional[Dict[str, Any]] = None
    sender: Optional[Dict[str, Any]] = None


class PipelineRequest(BaseModel):
    repo_full_name: Optional[str] = None
    pull_number: Optional[int] = None
    # If you're not running via GitHub, you can pass code directly:
    files: Optional[List[Dict[str, str]]] = None  # [{ "file_path": "...", "code": "..." }]


class PipelineResult(BaseModel):
    sast: SASTReport
    patch: PatchReport
    # Markdown for GitHub PR comments and Streamlit.
    report_markdown: str

