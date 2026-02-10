from __future__ import annotations

from collections.abc import Sequence
import os
from pathlib import Path

_MPL_CONFIG_DIR = Path(__file__).resolve().parents[1] / ".cache" / "matplotlib"
_MPL_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_MPL_CONFIG_DIR))

import matplotlib


def configure_matplotlib_font(preferred_families: Sequence[str]) -> None:
    matplotlib.rcParams["font.sans-serif"] = list(preferred_families)
    matplotlib.rcParams["axes.unicode_minus"] = False
