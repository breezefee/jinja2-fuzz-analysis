from __future__ import annotations

from collections import Counter
from typing import Any

from visualizers.style import apply_warm_style, save_figure, truncate_label

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

import config
from utils.helpers import load_json


def _load_fuzz_results() -> dict[str, Any]:
    return load_json(config.DATA_DIR / "fuzz_results.json")


def _chart_coverage_trend(fuzz_data: dict[str, Any]) -> str:
    records: list[dict[str, Any]] = []
    for target in fuzz_data.get("targets", []):
        trend = target.get("summary", {}).get("trend", [])
        for point in trend:
            records.append(
                {
                    "target": target["target"],
                    "iteration": int(point.get("iteration", 0)),
                    "exceptions": int(point.get("total_exceptions", 0)),
                }
            )

    if not records:
        records = [{"target": "none", "iteration": 0, "exceptions": 0}]

    frame = pd.DataFrame(records)
    palette_size = max(1, frame["target"].nunique())
    fig, ax = plt.subplots(figsize=(12, 7))
    sns.lineplot(
        data=frame,
        x="iteration",
        y="exceptions",
        hue="target",
        marker="o",
        palette=sns.color_palette(list(config.WARM_PALETTE), n_colors=palette_size),
        linewidth=2,
        ax=ax,
    )
    ax.set_title("Fuzz 覆盖率趋势（迭代次数 vs 发现异常数）")
    ax.set_xlabel("迭代次数")
    ax.set_ylabel("累计异常数")
    ax.legend(title="Target")
    return save_figure(fig, "11_Fuzz覆盖率趋势.png")


def _chart_exception_distribution(fuzz_data: dict[str, Any]) -> str:
    exception_counter: Counter[str] = Counter()
    for target in fuzz_data.get("targets", []):
        counter = target.get("summary", {}).get("exception_counts", {})
        for key, value in counter.items():
            exception_counter[key] += int(value)

    if not exception_counter:
        exception_counter["None"] = 0
    top_items = exception_counter.most_common(10)
    frame = pd.DataFrame(
        {
            "exception": [truncate_label(item[0], 20) for item in top_items],
            "count": [int(item[1]) for item in top_items],
        }
    )
    fig, ax = plt.subplots(figsize=(11, 6))
    sns.barplot(
        data=frame,
        x="exception",
        y="count",
        color=config.WARM_PALETTE[1],
        edgecolor="#7A2E23",
        ax=ax,
    )
    ax.set_title("Crash/异常分类统计")
    ax.set_xlabel("异常类型")
    ax.set_ylabel("出现次数")
    ax.tick_params(axis="x", rotation=45)
    return save_figure(fig, "12_Crash异常分类统计.png")


def build_fuzz_charts() -> dict[str, Any]:
    apply_warm_style(config.WARM_PALETTE)
    fuzz_data = _load_fuzz_results()
    outputs = [
        _chart_coverage_trend(fuzz_data),
        _chart_exception_distribution(fuzz_data),
    ]
    return {
        "chart_group": "fuzz",
        "status": "ok",
        "outputs": outputs,
    }
