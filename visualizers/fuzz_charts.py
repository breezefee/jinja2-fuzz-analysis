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
    rows: list[dict[str, Any]] = []
    for target in fuzz_data.get("targets", []):
        counts = target.get("summary", {}).get("exception_counts", {})
        total = sum(int(v) for v in counts.values())
        rows.append({"Target": target["target"], "异常次数": total})

    if not rows:
        rows = [{"Target": "N/A", "异常次数": 0}]

    frame = pd.DataFrame(rows).sort_values("异常次数", ascending=True)
    colors = list(config.WARM_PALETTE[: len(frame)])

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.barh(
        frame["Target"],
        frame["异常次数"],
        color=colors,
        edgecolor="#7A2E23",
        height=0.55,
    )
    for bar in bars:
        w = bar.get_width()
        ax.text(
            w + max(frame["异常次数"]) * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{int(w):,}",
            va="center",
            fontsize=12,
            fontweight="bold",
            color="#4A4A48",
        )
    ax.set_title("各 Fuzz Target 异常触发统计")
    ax.set_xlabel("累计异常次数")
    ax.set_ylabel("")
    ax.set_xlim(0, max(frame["异常次数"]) * 1.15)
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
