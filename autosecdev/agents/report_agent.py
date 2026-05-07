from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from autosecdev.schemas import PatchReport, SASTReport, VulnerabilityFinding


def _severity_counts(findings: List[VulnerabilityFinding]) -> Dict[str, int]:
    c = Counter([f.severity for f in findings])
    return dict(c)


class ReportAgent:
    def render_markdown(self, sast: SASTReport, patch: PatchReport) -> str:
        findings = sast.findings
        confirmed = [f for f in findings if f.confirmed]
        counts = _severity_counts(confirmed)

        md = []
        md.append("# AutoSecDev Security Report")
        md.append("")
        md.append("## Summary")
        md.append(f"- Findings detected: **{len(confirmed)}**")
        md.append(f"- Verified patched: **{patch.verified}**")
        md.append(f"- Patch iterations used: **{patch.iterations_used}**")
        if counts:
            parts = ", ".join([f"{k}={v}" for k, v in sorted(counts.items(), key=lambda x: x[0])])
            md.append(f"- Severity breakdown: {parts}")
        md.append("")

        md.append("## Detected Vulnerabilities (Confirmed)")
        if not confirmed:
            md.append("_No confirmed vulnerabilities._")
        else:
            for f in confirmed:
                cwe = f.cwe_id or "CWE-unknown"
                md.append(f"### {cwe} | {f.severity.upper()}")
                md.append(f"- File: `{f.file_path}`")
                md.append(f"- Lines: `{f.line_start}-{f.line_end}`")
                md.append(f"- Description: {f.description}")
                if f.code_snippet:
                    md.append("```python")
                    md.append(f.code_snippet)
                    md.append("```")
                md.append("")

        md.append("## Patch Diffs")
        if not patch.patched_files:
            md.append("_No patches generated._")
        else:
            for pf in patch.patched_files:
                md.append(f"### Patched: `{pf.file_path}`")
                md.append("```diff")
                md.append(pf.unified_diff)
                md.append("```")
                for exp in pf.explanations:
                    md.append(f"**Explanation:** {exp.summary}")
                md.append("")

        if patch.unresolved_findings:
            md.append("## Unresolved Findings")
            for f in patch.unresolved_findings:
                md.append(f"- `{f.cwe_id or 'CWE-unknown'}` ({f.severity}): {f.description}")
            md.append("")

        return "\n".join(md).strip() + "\n"

