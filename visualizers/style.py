from __future__ import annotations

from collections.abc import Sequence
import os
from pathlib import Path

_MPL_CONFIG_DIR = Path(__file__).resolve().parents[1] / ".cache" / "matplotlib"
_MPL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_MPL_CONFIG_DIR))

import matplotlib.pyplot as plt
import seaborn as sns


def apply_warm_style(palette: Sequence[str]) -> None:
    sns.set_theme(style="whitegrid", palette=list(palette))
    plt.rcParams["figure.dpi"] = 150
