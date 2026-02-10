from __future__ import annotations

from pathlib import Path
from typing import Any

from visualizers.style import apply_warm_style, save_figure, truncate_label, warm_cmap

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from wordcloud import WordCloud

import config


def _find_wordcloud_font() -> str | None:
    candidates = [
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for font in candidates:
        if Path(font).exists():
            return font
    return None


def _load_commit_inputs() -> tuple[dict[str, Any], pd.DataFrame]:
    summary = pd.read_json(config.DATA_DIR / "commit_summary.json", typ="series").to_dict()
    commits_df = pd.read_csv(config.DATA_DIR / "commits.csv")
    commits_df["date"] = pd.to_datetime(commits_df["date"], errors="coerce", utc=True)
    return summary, commits_df


def _chart_yearly_trend(summary: dict[str, Any]) -> str:
    yearly = summary.get("frequency_by_year", {})
    years = sorted(yearly.keys())
    values = [int(yearly[year]) for year in years]
    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(years, values, color=config.WARM_PALETTE[0], edgecolor="#7A2E23", linewidth=0.6)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(value), ha="center", va="bottom", fontsize=8)
    ax.set_title("Jinja2 年度提交趋势图")
    ax.set_xlabel("年份")
    ax.set_ylabel("提交数量")
    ax.tick_params(axis="x", rotation=45)
    return save_figure(fig, "01_年度提交趋势图.png")


def _chart_author_pie(summary: dict[str, Any]) -> str:
    authors = summary.get("top_authors", [])[:10]
    labels = [truncate_label(str(item[0]), 20) for item in authors]
    values = [int(item[1]) for item in authors]
    fig, ax = plt.subplots(figsize=(9, 9))
    colors = sns.color_palette(list(config.WARM_PALETTE), n_colors=max(3, len(values)))
    ax.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        startangle=160,
        colors=colors,
        textprops={"fontsize": 9},
    )
    ax.set_title("作者贡献饼图 (Top10)")
    return save_figure(fig, "02_作者贡献饼图.png")


def _chart_time_heatmap(commits_df: pd.DataFrame) -> str:
    weekday_map = {
        0: "周一",
        1: "周二",
        2: "周三",
        3: "周四",
        4: "周五",
        5: "周六",
        6: "周日",
    }
    pivot = (
        commits_df.pivot_table(index="hour", columns="weekday", values="hash", aggfunc="count")
        .fillna(0)
        .reindex(columns=sorted(weekday_map.keys()), fill_value=0)
    )
    pivot.columns = [weekday_map[int(col)] for col in pivot.columns]
    fig, ax = plt.subplots(figsize=(11, 6))
    sns.heatmap(pivot, cmap=warm_cmap(), linewidths=0.2, ax=ax, cbar_kws={"label": "提交数量"})
    ax.set_title("提交时间热力图 (小时 × 星期)")
    ax.set_xlabel("星期")
    ax.set_ylabel("小时")
    return save_figure(fig, "03_提交时间热力图.png")


def _chart_wordcloud(commits_df: pd.DataFrame) -> str:
    text = " ".join(commits_df["message"].fillna("").astype(str).tolist())
    if not text.strip():
        text = "jinja fuzz analysis security template parser sandbox"
    cloud = WordCloud(
        width=1200,
        height=700,
        background_color="#fff9f2",
        colormap="autumn",
        max_words=240,
        font_path=_find_wordcloud_font(),
    ).generate(text)
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.imshow(cloud, interpolation="bilinear")
    ax.axis("off")
    ax.set_title("提交消息词云")
    return save_figure(fig, "04_提交消息词云.png")


def _chart_bugfix_trend(commits_df: pd.DataFrame) -> str:
    bug_df = commits_df.copy()
    bug_df["date"] = bug_df["date"].dt.tz_convert(None)
    bug_df["month"] = bug_df["date"].dt.to_period("M").astype(str)
    bug_month = bug_df.groupby("month", as_index=False)["is_bugfix"].sum()
    bug_month["month"] = pd.to_datetime(bug_month["month"], errors="coerce")
    bug_month = bug_month.dropna().sort_values("month")
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(
        bug_month["month"],
        bug_month["is_bugfix"],
        color=config.WARM_PALETTE[2],
        marker="o",
        linewidth=2,
        markersize=3,
    )
    ax.fill_between(
        bug_month["month"],
        bug_month["is_bugfix"],
        color=config.WARM_PALETTE[3],
        alpha=0.25,
    )
    ax.set_title("Bug 修复频率趋势")
    ax.set_xlabel("月份")
    ax.set_ylabel("修复提交数")
    ax.tick_params(axis="x", rotation=45)
    return save_figure(fig, "05_Bug修复频率趋势.png")


def build_commit_charts() -> dict[str, Any]:
    apply_warm_style(config.WARM_PALETTE)
    summary, commits_df = _load_commit_inputs()
    outputs = [
        _chart_yearly_trend(summary),
        _chart_author_pie(summary),
        _chart_time_heatmap(commits_df),
        _chart_wordcloud(commits_df),
        _chart_bugfix_trend(commits_df),
    ]
    return {
        "chart_group": "commit",
        "status": "ok",
        "outputs": outputs,
    }
