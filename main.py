from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import Any

import config
from analyzers.ast_analyzer import analyze_ast
from analyzers.dynamic_tracer import trace_execution
from analyzers.libcst_analyzer import analyze_libcst
from analyzers.z3_analyzer import analyze_constraints
from collectors.commit_collector import collect_commits
from collectors.github_collector import collect_github_metadata
from fuzzers.fuzz_engine import run_all_targets
from utils.font_config import configure_matplotlib_font
from utils.helpers import dump_json, ensure_directories
from visualizers.code_charts import build_code_charts
from visualizers.commit_charts import build_commit_charts
from visualizers.fuzz_charts import build_fuzz_charts
from visualizers.network_charts import build_network_chart
from visualizers.style import apply_warm_style

TaskFn = Callable[[], dict[str, Any]]


def _build_task_registry() -> dict[str, TaskFn]:
    return {
        "commit_collect": lambda: collect_commits(config.JINJA_REPO_ROOT),
        "github_collect": collect_github_metadata,
        "ast": lambda: analyze_ast(config.JINJA_SRC_ROOT),
        "libcst": lambda: analyze_libcst(config.JINJA_SRC_ROOT),
        "z3": analyze_constraints,
        "trace": trace_execution,
        "fuzz": lambda: run_all_targets(config.DEFAULT_FUZZ_ITERATIONS),
        "chart_commit": build_commit_charts,
        "chart_code": build_code_charts,
        "chart_fuzz": build_fuzz_charts,
        "chart_network": build_network_chart,
    }


def _prepare_runtime() -> None:
    ensure_directories(
        [
            config.DATA_DIR,
            config.OUTPUT_DIR,
            config.DOCS_DIR,
            config.CRASH_DIR,
            config.TRACE_DIR,
            config.FUZZ_COVERAGE_DIR,
        ]
    )
    configure_matplotlib_font(config.CN_FONT_FAMILIES)
    apply_warm_style(config.WARM_PALETTE)


def run(selected_tasks: list[str]) -> dict[str, Any]:
    registry = _build_task_registry()
    results: dict[str, Any] = {}
    for name in selected_tasks:
        results[name] = registry[name]()
    return results


def parse_args() -> argparse.Namespace:
    registry = _build_task_registry()
    parser = argparse.ArgumentParser(description="Jinja2 fuzz and analysis pipeline")
    parser.add_argument(
        "--tasks",
        nargs="+",
        default=list(registry.keys()),
        choices=list(registry.keys()),
        help="Tasks to execute",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=config.DATA_DIR / "run_summary.json",
        help="Summary JSON output path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    _prepare_runtime()
    results = run(args.tasks)
    dump_json(args.summary, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
