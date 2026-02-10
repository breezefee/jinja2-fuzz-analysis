from __future__ import annotations

from analyzers.z3_analyzer import analyze_constraints


def test_z3_analyzer_smoke() -> None:
    result = analyze_constraints()
    assert result["analyzer"] == "z3"
    assert result["status"] == "pending"
