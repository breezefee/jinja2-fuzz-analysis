from __future__ import annotations

from pathlib import Path

import config
from visualizers.code_charts import build_code_charts
from visualizers.commit_charts import build_commit_charts
from visualizers.fuzz_charts import build_fuzz_charts
from visualizers.network_charts import build_network_chart


def _assert_outputs_exist(outputs: list[str]) -> None:
    assert outputs
    for output in outputs:
        assert Path(output).exists()


def test_commit_charts_build() -> None:
    result = build_commit_charts()
    assert result["status"] == "ok"
    assert len(result["outputs"]) == 5
    _assert_outputs_exist(result["outputs"])


def test_code_charts_build() -> None:
    result = build_code_charts()
    assert result["status"] == "ok"
    assert len(result["outputs"]) == 5
    _assert_outputs_exist(result["outputs"])


def test_fuzz_charts_build() -> None:
    result = build_fuzz_charts()
    assert result["status"] == "ok"
    assert len(result["outputs"]) == 2
    _assert_outputs_exist(result["outputs"])


def test_network_charts_build() -> None:
    result = build_network_chart()
    assert result["status"] == "ok"
    assert len(result["outputs"]) == 2
    _assert_outputs_exist(result["outputs"])


def test_output_chart_count() -> None:
    png_count = len(list(config.OUTPUT_DIR.glob("*.png")))
    assert png_count >= 14
