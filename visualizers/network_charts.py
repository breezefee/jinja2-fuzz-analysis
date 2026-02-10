from __future__ import annotations

from typing import Any

from visualizers.style import apply_warm_style, save_figure, truncate_label

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import seaborn as sns

import config
from utils.helpers import load_json


def _load_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    ast_data = load_json(config.DATA_DIR / "ast_analysis.json")
    commit_data = load_json(config.DATA_DIR / "commit_summary.json")
    return ast_data, commit_data


def _chart_dependency_network(ast_data: dict[str, Any]) -> str:
    edges = ast_data.get("dependency_edges", [])
    graph = nx.DiGraph()
    for edge in edges:
        source = str(edge["source"])
        target = str(edge["target"])
        graph.add_edge(source, target)

    if graph.number_of_nodes() > 90:
        degrees = sorted(graph.degree, key=lambda item: item[1], reverse=True)[:90]
        keep_nodes = {node for node, _ in degrees}
        graph = graph.subgraph(keep_nodes).copy()

    fig, ax = plt.subplots(figsize=(13, 9))
    if graph.number_of_nodes() == 0:
        ax.text(0.5, 0.5, "无依赖数据", ha="center", va="center", fontsize=14)
        ax.axis("off")
        return save_figure(fig, "13_导入依赖关系图.png")

    pos = nx.spring_layout(graph, seed=42, k=0.65)
    degrees = dict(graph.degree)
    node_sizes = [110 + degrees[node] * 28 for node in graph.nodes]
    node_colors = [config.WARM_PALETTE[degree % len(config.WARM_PALETTE)] for degree in degrees.values()]
    nx.draw_networkx_nodes(
        graph,
        pos,
        node_size=node_sizes,
        node_color=node_colors,
        alpha=0.9,
        linewidths=0.4,
        edgecolors="#7A2E23",
        ax=ax,
    )
    nx.draw_networkx_edges(graph, pos, width=0.6, alpha=0.35, edge_color="#B65E2B", arrows=False, ax=ax)

    labels = {node: truncate_label(node.split(".")[-1], 16) for node in graph.nodes}
    nx.draw_networkx_labels(graph, pos, labels=labels, font_size=8, font_color="#3B1F12", ax=ax)
    ax.set_title("导入依赖关系图")
    ax.axis("off")
    return save_figure(fig, "13_导入依赖关系图.png")


def _chart_file_hotspots(commit_data: dict[str, Any]) -> str:
    top_files = commit_data.get("top_files", [])[:20]
    frame = pd.DataFrame(
        {
            "file": [truncate_label(str(item[0]), 20) for item in top_files],
            "count": [int(item[1]) for item in top_files],
        }
    )
    fig, ax = plt.subplots(figsize=(12, 8))
    sns.barplot(
        data=frame,
        y="file",
        x="count",
        color=config.WARM_PALETTE[4],
        edgecolor="#7A2E23",
        ax=ax,
    )
    ax.set_title("文件修改热点 Top20")
    ax.set_xlabel("修改次数")
    ax.set_ylabel("文件")
    return save_figure(fig, "14_文件修改热点Top20.png")


def build_network_chart() -> dict[str, Any]:
    apply_warm_style(config.WARM_PALETTE)
    ast_data, commit_data = _load_inputs()
    outputs = [
        _chart_dependency_network(ast_data),
        _chart_file_hotspots(commit_data),
    ]
    return {
        "chart_group": "network",
        "status": "ok",
        "outputs": outputs,
    }
