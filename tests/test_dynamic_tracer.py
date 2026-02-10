from __future__ import annotations

from pathlib import Path

from analyzers.dynamic_tracer import trace_execution
from config import TRACE_DIR


def test_dynamic_tracer_smoke() -> None:
    result = trace_execution()
    assert result["analyzer"] == "pysnooper"
    assert result["status"] == "ok"
    assert result["trace_files"]
    assert Path(TRACE_DIR / "trace_summary.json").exists()
