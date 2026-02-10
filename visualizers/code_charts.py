from __future__ import annotations

from typing import Any

from visualizers.style import apply_warm_style, save_figure, truncate_label

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

import config
from utils.helpers import load_json


def _load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    ast_data = load_json(config.DATA_DIR / "ast_analysis.json")
    libcst_data = load_json(config.DATA_DIR / "libcst_analysis.json")
    z3_data = load_json(config.DATA_DIR / "z3_results.json")
    return ast_data, libcst_data, z3_data


def _chart_complexity_distribution(ast_data: dict[str, Any]) -> str:
    complexity_values = [int(item["complexity"]) for item in ast_data.get("top_complex_functions", [])]
    if not complexity_values:
        complexity_values = [0]
    fig, ax = plt.subplots(figsize=(11, 6))
    sns.histplot(complexity_values, bins=20, color=config.WARM_PALETTE[1], edgecolor="#7A2E23", ax=ax)
    ax.set_title("函数圈复杂度分布")
    ax.set_xlabel("圈复杂度")
    ax.set_ylabel("函数数量")
    return save_figure(fig, "06_圈复杂度分布.png")


def _chart_type_coverage(libcst_data: dict[str, Any]) -> str:
    module_cov = libcst_data["type_annotation_coverage"]["module_coverage"]
    rows = []
    for item in module_cov:
        coverage = (
            float(item.get("parameter_coverage", 0.0))
            + float(item.get("return_coverage", 0.0))
            + float(item.get("variable_coverage", 0.0))
        ) / 3.0
        rows.append({"module": truncate_label(str(item["file"]), 20), "coverage": coverage * 100})
    frame = pd.DataFrame(rows).sort_values("coverage", ascending=False).head(15)
    fig, ax = plt.subplots(figsize=(12, 7))
    sns.barplot(
        data=frame,
        x="module",
        y="coverage",
        color=config.WARM_PALETTE[2],
        edgecolor="#7A2E23",
        ax=ax,
    )
    ax.set_title("类型注解覆盖率（按模块）")
    ax.set_xlabel("模块")
    ax.set_ylabel("覆盖率 (%)")
    ax.tick_params(axis="x", rotation=45)
    return save_figure(fig, "07_类型注解覆盖率.png")


def _chart_arg_distribution(ast_data: dict[str, Any]) -> str:
    dist = ast_data.get("function_arg_distribution", {})
    x = [int(key) for key in dist.keys()]
    y = [int(value) for value in dist.values()]
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.bar(x, y, color=config.WARM_PALETTE[3], edgecolor="#7A2E23", linewidth=0.7)
    ax.set_title("函数参数数量分布")
    ax.set_xlabel("参数数量")
    ax.set_ylabel("函数数量")
    return save_figure(fig, "08_函数参数数量分布.png")


def _chart_exception_pattern(libcst_data: dict[str, Any]) -> str:
    dist = libcst_data["exception_patterns"]["except_type_distribution"]
    top_items = list(dist.items())[:8]
    labels = [truncate_label(str(item[0]), 20) for item in top_items]
    sizes = [int(item[1]) for item in top_items]
    fig, ax = plt.subplots(figsize=(9, 9))
    ax.pie(
        sizes,
        labels=labels,
        autopct="%1.1f%%",
        startangle=170,
        colors=sns.color_palette(list(config.WARM_PALETTE), n_colors=max(3, len(sizes))),
        textprops={"fontsize": 9},
    )
    ax.set_title("异常处理模式分布")
    return save_figure(fig, "09_异常处理模式分布.png")


def _chart_z3_results(z3_data: dict[str, Any]) -> str:
    sat_count = int(z3_data["filter_type_propagation"]["sat_count"])
    unsat_count = int(z3_data["filter_type_propagation"]["unsat_count"])
    valid_templates = int(z3_data["template_syntax_constraints"]["valid_model_count"])
    generated = int(z3_data["generated_templates"]["template_count"])

    frame = pd.DataFrame(
        [
            {"category": "过滤器链 SAT", "count": sat_count},
            {"category": "过滤器链 UNSAT", "count": unsat_count},
            {"category": "语法可满足模型", "count": valid_templates},
            {"category": "自动生成模板", "count": generated},
        ]
    )
    fig, ax = plt.subplots(figsize=(11, 6))
    sns.barplot(
        data=frame,
        x="category",
        y="count",
        color=config.WARM_PALETTE[0],
        edgecolor="#7A2E23",
        ax=ax,
    )
    for index, row in frame.iterrows():
        ax.text(index, row["count"] + 0.05, int(row["count"]), ha="center", va="bottom", fontsize=9)
    ax.set_title("模板语法 Z3 约束求解结果")
    ax.set_xlabel("类别")
    ax.set_ylabel("数量")
    ax.tick_params(axis="x", rotation=45)
    return save_figure(fig, "10_Z3约束求解结果.png")


def build_code_charts() -> dict[str, Any]:
    apply_warm_style(config.WARM_PALETTE)
    ast_data, libcst_data, z3_data = _load_inputs()
    outputs = [
        _chart_complexity_distribution(ast_data),
        _chart_type_coverage(libcst_data),
        _chart_arg_distribution(ast_data),
        _chart_exception_pattern(libcst_data),
        _chart_z3_results(z3_data),
    ]
    return {
        "chart_group": "code",
        "status": "ok",
        "outputs": outputs,
    }
