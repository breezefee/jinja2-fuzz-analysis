from __future__ import annotations

from analyzers.libcst_analyzer import analyze_libcst
from config import JINJA_SRC_ROOT


def test_libcst_analyzer_smoke() -> None:
    result = analyze_libcst(JINJA_SRC_ROOT)
    assert result["analyzer"] == "libcst"
    assert result["status"] == "pending"
