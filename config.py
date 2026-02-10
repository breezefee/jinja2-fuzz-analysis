from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
JINJA_REPO_ROOT = Path("/mnt/c/Users/l/Desktop/opensource/group4/jinja")
JINJA_SRC_ROOT = JINJA_REPO_ROOT / "src" / "jinja2"

DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_DIR = PROJECT_ROOT / "output"
DOCS_DIR = PROJECT_ROOT / "docs"

CRASH_DIR = DATA_DIR / "crashes"
TRACE_DIR = DATA_DIR / "traces"
FUZZ_COVERAGE_DIR = DATA_DIR / "fuzz_coverage"

DEFAULT_FUZZ_ITERATIONS = 10_000
PLOT_DPI = 150
BUG_KEYWORDS = ("fix", "bug", "patch")

WARM_PALETTE = (
    "#E85A4F",
    "#E98074",
    "#F4A460",
    "#DEB887",
    "#D2691E",
)

CN_FONT_FAMILIES = (
    "WenQuanYi Micro Hei",
    "SimHei",
    "DejaVu Sans",
)


@dataclass(frozen=True)
class RuntimePaths:
    project_root: Path = PROJECT_ROOT
    jinja_repo_root: Path = JINJA_REPO_ROOT
    jinja_src_root: Path = JINJA_SRC_ROOT
    data_dir: Path = DATA_DIR
    output_dir: Path = OUTPUT_DIR
    docs_dir: Path = DOCS_DIR
    crash_dir: Path = CRASH_DIR
    trace_dir: Path = TRACE_DIR
    fuzz_coverage_dir: Path = FUZZ_COVERAGE_DIR


RUNTIME_PATHS = RuntimePaths()
