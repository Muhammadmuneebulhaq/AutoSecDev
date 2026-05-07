from __future__ import annotations

import base64
from typing import Dict, List, Optional, Tuple

import requests


class GithubClient:
    def __init__(self, *, token: str) -> None:
        self.token = token
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
            }
        )

    def _split_repo(self, repo_full_name: str) -> Tuple[str, str]:
        owner, repo = repo_full_name.split("/", 1)
        return owner, repo

    def list_pr_files(self, repo_full_name: str, pull_number: int) -> List[Dict]:
        owner, repo = self._split_repo(repo_full_name)
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/files?per_page=100"
        r = self.session.get(url, timeout=60)
        r.raise_for_status()
        return list(r.json())

    def get_file_content(self, repo_full_name: str, path: str, *, ref: str) -> Optional[str]:
        owner, repo = self._split_repo(repo_full_name)
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
        r = self.session.get(url, timeout=60)
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("encoding") != "base64":
            return None
        b64 = data.get("content") or ""
        if not b64:
            return None
        raw = base64.b64decode(b64).decode("utf-8", errors="ignore")
        return raw

    def post_pr_comment(self, repo_full_name: str, pull_number: int, *, body: str) -> None:
        owner, repo = self._split_repo(repo_full_name)
        url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pull_number}/comments"
        payload = {"body": body}
        r = self.session.post(url, json=payload, timeout=60)
        r.raise_for_status()

