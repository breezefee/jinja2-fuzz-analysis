from __future__ import annotations

import argparse
import atexit
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import atheris

from utils.helpers import dump_json, utc_now_iso


class TargetRecorder:
    def __init__(self, target: str, runs: int, summary_path: Path) -> None:
        self.target = target
        self.runs = runs
        self.summary_path = summary_path
        self.iterations = 0
        self.exception_counter: Counter[str] = Counter()
        self.exception_samples: dict[str, str] = {}
        self.trend: list[dict[str, int]] = []
        self.milestone = max(1, runs // 40)

    def step(self) -> None:
        self.iterations += 1
        if self.iterations % self.milestone == 0:
            self.trend.append(
                {
                    "iteration": self.iterations,
                    "unique_exceptions": len(self.exception_counter),
                    "total_exceptions": int(sum(self.exception_counter.values())),
                }
            )

    def record_exception(self, exc: Exception, sample: str) -> None:
        key = type(exc).__name__
        self.exception_counter[key] += 1
        self.exception_samples.setdefault(key, sample[:240])

    def finalize(self) -> None:
        payload = {
            "target": self.target,
            "status": "ok",
            "collected_at": utc_now_iso(),
            "runs_configured": self.runs,
            "iterations_observed": self.iterations,
            "exception_counts": dict(self.exception_counter.most_common()),
            "exception_samples": self.exception_samples,
            "trend": self.trend,
        }
        dump_json(self.summary_path, payload)


def build_argument_parser(target: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"Atheris fuzz target: {target}")
    parser.add_argument("--runs", type=int, default=10_000, help="Fuzz iterations")
    parser.add_argument("--max-len", type=int, default=2048, help="Maximum mutation length")
    parser.add_argument("--crash-dir", type=Path, required=True, help="Crash output directory")
    parser.add_argument(
        "--coverage-dir", type=Path, required=True, help="Coverage summary output directory"
    )
    return parser


def run_atheris_target(
    target: str,
    test_one_input: Callable[[bytes], None],
    runs: int,
    max_len: int,
    crash_dir: Path,
    coverage_dir: Path,
    recorder: TargetRecorder,
) -> None:
    crash_dir.mkdir(parents=True, exist_ok=True)
    coverage_dir.mkdir(parents=True, exist_ok=True)
    atexit.register(recorder.finalize)
    fuzzer_args = [
        target,
        f"-atheris_runs={runs}",
        f"-artifact_prefix={crash_dir}/{target}_",
        f"-max_len={max_len}",
        "-print_final_stats=1",
    ]
    atheris.Setup(fuzzer_args, test_one_input)
    atheris.Fuzz()
