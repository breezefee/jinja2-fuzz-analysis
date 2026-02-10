from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

_MPL_CONFIG_DIR = Path(__file__).resolve().parents[1] / ".cache" / "matplotlib"
_MPL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_MPL_CONFIG_DIR))

import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import seaborn as sns

import config


def apply_warm_style(palette: Sequence[str] | None = None) -> None:
    chosen_palette = list(palette or config.WARM_PALETTE)
    sns.set_theme(style="whitegrid", palette=chosen_palette)
    plt.rcParams["figure.dpi"] = config.PLOT_DPI
    plt.rcParams["savefig.dpi"] = config.PLOT_DPI
    plt.rcParams["font.sans-serif"] = list(config.CN_FONT_FAMILIES)
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["axes.titlesize"] = 14
    plt.rcParams["axes.labelsize"] = 12
    plt.rcParams["xtick.labelsize"] = 10
    plt.rcParams["ytick.labelsize"] = 10
    plt.rcParams["legend.fontsize"] = 9
    plt.rcParams["axes.facecolor"] = "#FFF8F1"
    plt.rcParams["figure.facecolor"] = "#FFFDF8"
    plt.rcParams["grid.alpha"] = 0.3


def warm_cmap() -> mcolors.LinearSegmentedColormap:
    return mcolors.LinearSegmentedColormap.from_list(
        "warm_custom",
        list(config.WARM_PALETTE),
    )


def truncate_label(text: str, max_len: int = 20) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def save_figure(fig: plt.Figure, filename: str) -> str:
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = config.OUTPUT_DIR / filename
    fig.tight_layout(pad=2.0)
    fig.savefig(path, format="png", dpi=config.PLOT_DPI)
    plt.close(fig)
    return str(path)
