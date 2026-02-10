from __future__ import annotations

from main import run


def test_main_run_subset() -> None:
    result = run(["ast", "libcst", "z3"])
    assert result["ast"]["status"] == "ok"
    assert result["libcst"]["status"] == "ok"
    assert result["z3"]["status"] == "ok"
