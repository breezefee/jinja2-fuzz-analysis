from __future__ import annotations

from pathlib import Path
from typing import Any


def collect_commits(repo_root: Path) -> dict[str, Any]:
    return {
        "collector": "pydriller",
        "repo_root": str(repo_root),
        "status": "pending",
        "commit_count": 0,
    }
