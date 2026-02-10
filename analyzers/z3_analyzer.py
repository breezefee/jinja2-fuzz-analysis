from __future__ import annotations

from typing import Any


def analyze_constraints() -> dict[str, Any]:
    return {
        "analyzer": "z3",
        "status": "pending",
        "models": [],
    }
