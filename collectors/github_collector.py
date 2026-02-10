from __future__ import annotations

import os
from typing import Any

import requests

import config
from utils.helpers import dump_json, load_json, utc_now_iso


def _build_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request_json(url: str, params: dict[str, Any] | None = None) -> Any:
    response = requests.get(url, params=params, headers=_build_headers(), timeout=20)
    response.raise_for_status()
    return response.json()


def collect_github_metadata() -> dict[str, Any]:
    base = "https://api.github.com/repos/pallets/jinja"
    output_path = config.DATA_DIR / "github_metadata.json"
    try:
        repo_info = _request_json(base)
        contributors = _request_json(f"{base}/contributors", params={"per_page": 100})
        releases = _request_json(f"{base}/releases", params={"per_page": 30})
    except requests.RequestException as exc:
        if output_path.exists():
            cached = load_json(output_path)
            cached["status"] = "cached"
            cached["error"] = str(exc)
            cached["collected_at"] = utc_now_iso()
            dump_json(output_path, cached)
            return cached
        fallback = {
            "collector": "github_api",
            "status": "error",
            "collected_at": utc_now_iso(),
            "error": str(exc),
            "repo": {},
            "top_contributors": [],
            "releases": [],
        }
        dump_json(output_path, fallback)
        return fallback

    payload = {
        "collector": "github_api",
        "status": "ok",
        "collected_at": utc_now_iso(),
        "repo": {
            "name": repo_info.get("name"),
            "full_name": repo_info.get("full_name"),
            "stargazers_count": repo_info.get("stargazers_count"),
            "forks_count": repo_info.get("forks_count"),
            "open_issues_count": repo_info.get("open_issues_count"),
            "created_at": repo_info.get("created_at"),
            "updated_at": repo_info.get("updated_at"),
            "default_branch": repo_info.get("default_branch"),
        },
        "top_contributors": [
            {
                "login": contributor.get("login"),
                "contributions": contributor.get("contributions", 0),
            }
            for contributor in contributors[:20]
        ],
        "releases": [
            {
                "name": release.get("name"),
                "tag_name": release.get("tag_name"),
                "published_at": release.get("published_at"),
                "prerelease": release.get("prerelease", False),
            }
            for release in releases
        ],
    }

    dump_json(output_path, payload)
    return payload
