from __future__ import annotations

from pathlib import Path
from typing import Any


def analyze_libcst(source_root: Path) -> dict[str, Any]:
    return {
        "analyzer": "libcst",
        "source_root": str(source_root),
        "status": "pending",
    }
