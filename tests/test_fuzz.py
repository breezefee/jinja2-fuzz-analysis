from __future__ import annotations

from fuzzers.fuzz_engine import run_all_targets


def test_fuzz_engine_smoke() -> None:
    result = run_all_targets(100)
    assert result["fuzzer"] == "atheris"
    assert result["status"] == "planned"
    assert len(result["targets"]) == 5
