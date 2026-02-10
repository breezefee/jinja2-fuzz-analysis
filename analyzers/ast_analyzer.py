from __future__ import annotations

from pathlib import Path
from typing import Any


def analyze_ast(source_root: Path) -> dict[str, Any]:
    return {
        "analyzer": "ast",
        "source_root": str(source_root),
        "status": "pending",
    }
