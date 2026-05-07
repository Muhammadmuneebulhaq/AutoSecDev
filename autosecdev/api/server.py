from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request

from autosecdev.agents.patch_agent import PatchAgent
from autosecdev.agents.report_agent import ReportAgent
from autosecdev.agents.sast_agent import SASTAgent
from autosecdev.github.github_client import GithubClient
from autosecdev.settings import settings


app = FastAPI(title="AutoSecDev")


def run_pipeline(files: Dict[str, str]) -> Dict[str, Any]:
    sast_agent = SASTAgent()
    sast_report = sast_agent.scan_files(files)

    patch_agent = PatchAgent(sast_agent=sast_agent)
    patch_report = patch_agent.patch(files, sast_report, max_iterations=settings.max_patch_iterations)

    report_agent = ReportAgent()
    report_markdown = report_agent.render_markdown(sast_report, patch_report)

    return {
        "sast": sast_report.model_dump(),
        "patch": patch_report.model_dump(),
        "report_markdown": report_markdown,
        "verified": patch_report.verified,
    }


@app.post("/webhook/github", tags=["github"])
async def github_webhook(request: Request) -> Dict[str, Any]:
    payload = await request.json()

    repo = (payload.get("repository") or {}).get("full_name")
    pr = (payload.get("pull_request") or {}).get("number")
    if not repo or not pr:
        raise HTTPException(status_code=400, detail="Missing repository.full_name or pull_request.number")

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(status_code=401, detail="Missing GITHUB_TOKEN env var for GitHub API access")

    github = GithubClient(token=token)

    changed_files = github.list_pr_files(repo, int(pr))
    py_files = [f for f in changed_files if str(f.get("filename") or "").endswith(".py")]
    if not py_files:
        return {"ok": True, "message": "No Python files changed; nothing to scan."}

    head_sha = ((payload.get("pull_request") or {}).get("head") or {}).get("sha") or payload.get("after")
    if not head_sha:
        head_sha = (payload.get("pull_request") or {}).get("head", {}).get("sha")
    if not head_sha:
        raise HTTPException(status_code=400, detail="Missing pull_request.head.sha for ref")

    files: Dict[str, str] = {}
    for f in py_files:
        path = str(f.get("filename"))
        content = github.get_file_content(repo, path, ref=head_sha)
        if content:
            # Use repository-relative path so diffs are meaningful.
            files[path] = content

    if not files:
        return {"ok": True, "message": "No readable Python file contents found."}

    result = run_pipeline(files)
    body = result["report_markdown"]
    github.post_pr_comment(repo, int(pr), body=body)

    return {"ok": True, "message": "Pipeline completed and PR comment posted.", "verified": result["verified"]}


@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", tags=["manual"])
async def scan_manual(request_body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Manual scan endpoint. Expected body:
      { "files": [ { "file_path": "...", "code": "..." }, ... ] }
    """
    files_list = request_body.get("files") or []
    if not isinstance(files_list, list) or not files_list:
        raise HTTPException(status_code=400, detail="Expected request body: {\"files\": [{\"file_path\": \"...\", \"code\": \"...\"}]} ")

    files: Dict[str, str] = {}
    for item in files_list:
        fp = item.get("file_path")
        code = item.get("code")
        if not fp or code is None:
            continue
        files[str(fp)] = str(code)

    if not files:
        raise HTTPException(status_code=400, detail="No valid files passed.")

    return run_pipeline(files)

