from __future__ import annotations

from typing import Any


def collect_github_metadata() -> dict[str, Any]:
    return {
        "collector": "github_api",
        "status": "pending",
        "items": [],
    }
