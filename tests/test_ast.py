from __future__ import annotations

from analyzers.ast_analyzer import analyze_ast
from config import JINJA_SRC_ROOT


def test_ast_analyzer_smoke() -> None:
    result = analyze_ast(JINJA_SRC_ROOT)
    assert result["analyzer"] == "ast"
    assert result["status"] == "ok"
