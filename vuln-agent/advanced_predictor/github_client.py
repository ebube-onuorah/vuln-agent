"""
GitHub PR diff fetcher.

Supports public repos without a token; private repos require GITHUB_TOKEN env var.
PR URL formats accepted:
  - https://github.com/owner/repo/pull/123
  - github.com/owner/repo/pull/123
  - owner/repo#123
"""

import os
import re
import requests
from typing import Optional, Tuple


GITHUB_API = "https://api.github.com"
_TOKEN = os.getenv("GITHUB_TOKEN", "")

# PR URL patterns
_PATTERNS = [
    r"(?:https?://)?github\.com/([^/]+)/([^/]+)/pull/(\d+)",
    r"([^/\s]+)/([^#\s]+)#(\d+)",
]


def parse_pr_url(url: str) -> Tuple[str, str, int]:
    """
    Parse a GitHub PR URL or shorthand into (owner, repo, pr_number).
    Raises ValueError on invalid input.
    """
    url = url.strip().rstrip("/")
    for pattern in _PATTERNS:
        m = re.match(pattern, url)
        if m:
            owner, repo, number = m.groups()
            return owner, repo, int(number)
    raise ValueError(
        f"Unrecognized PR format: '{url}'. "
        "Expected https://github.com/owner/repo/pull/123 or owner/repo#123"
    )


def _headers() -> dict:
    h = {"Accept": "application/vnd.github.v3.diff", "User-Agent": "vuln-predictor/1.0"}
    if _TOKEN:
        h["Authorization"] = f"Bearer {_TOKEN}"
    return h


def fetch_pr_diff(url: str) -> dict:
    """
    Fetch the unified diff for a GitHub pull request.

    Returns:
        {
            "diff": str,
            "title": str,
            "owner": str,
            "repo": str,
            "pr_number": int,
            "author": str,
            "base": str,
            "head": str,
            "files_count": int,
            "additions": int,
            "deletions": int,
        }

    Raises:
        ValueError: bad URL format
        requests.HTTPError: GitHub API error (404 = private/not found, 403 = rate-limited)
    """
    owner, repo, pr_number = parse_pr_url(url)

    # Fetch PR metadata first
    meta_url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}"
    meta_resp = requests.get(
        meta_url,
        headers={**_headers(), "Accept": "application/vnd.github.v3+json"},
        timeout=10,
    )
    meta_resp.raise_for_status()
    meta = meta_resp.json()

    title = meta.get("title", "")
    author = meta.get("user", {}).get("login", "")
    base = meta.get("base", {}).get("ref", "")
    head = meta.get("head", {}).get("ref", "")
    additions = meta.get("additions", 0)
    deletions = meta.get("deletions", 0)
    files_count = meta.get("changed_files", 0)

    # Fetch diff
    diff_url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}"
    diff_resp = requests.get(
        diff_url,
        headers=_headers(),
        timeout=15,
    )
    diff_resp.raise_for_status()
    diff_text = diff_resp.text

    if not diff_text.strip():
        raise ValueError("PR has no diff content (may be empty or merged without changes).")

    return {
        "diff": diff_text,
        "title": title,
        "owner": owner,
        "repo": repo,
        "pr_number": pr_number,
        "author": author,
        "base": base,
        "head": head,
        "files_count": files_count,
        "additions": additions,
        "deletions": deletions,
    }
