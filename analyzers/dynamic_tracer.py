from __future__ import annotations

from typing import Any


def trace_execution() -> dict[str, Any]:
    return {
        "analyzer": "pysnooper",
        "status": "pending",
        "trace_files": [],
    }
