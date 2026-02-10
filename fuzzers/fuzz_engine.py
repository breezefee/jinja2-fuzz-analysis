from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import config
from utils.helpers import dump_json, ensure_directories, utc_now_iso

FUZZ_TARGET_MODULES = {
    "parse": "fuzzers.fuzz_parse",
    "render": "fuzzers.fuzz_render",
    "sandbox": "fuzzers.fuzz_sandbox",
    "lexer": "fuzzers.fuzz_lexer",
    "markup": "fuzzers.fuzz_markup",
}


def _parse_coverage_metrics(output_text: str) -> dict[str, Any]:
    cov_matches = re.findall(r"cov:\s*(\d+)", output_text)
    feat_matches = re.findall(r"ft:\s*(\d+)", output_text)
    corp_matches = re.findall(r"corp:\s*(\d+)", output_text)
    exec_matches = re.findall(r"exec/s:\s*([0-9]+)", output_text)
    return {
        "cov": int(cov_matches[-1]) if cov_matches else 0,
        "features": int(feat_matches[-1]) if feat_matches else 0,
        "corpus": int(corp_matches[-1]) if corp_matches else 0,
        "exec_per_sec": int(exec_matches[-1]) if exec_matches else 0,
    }


def _crash_files_for_target(target: str, crash_dir: Path) -> list[str]:
    return sorted(str(path) for path in crash_dir.glob(f"{target}_*"))


def _summary_path(target: str, coverage_dir: Path) -> Path:
    return coverage_dir / f"{target}_summary.json"


def _load_summary_with_retry(summary_path: Path, retries: int = 8) -> dict[str, Any]:
    for _ in range(retries):
        if not summary_path.exists():
            time.sleep(0.05)
            continue
        try:
            return json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            time.sleep(0.05)
    return {}


def run_target(
    target: str,
    iterations: int,
    crash_dir: Path | None = None,
    coverage_dir: Path | None = None,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    if target not in FUZZ_TARGET_MODULES:
        raise ValueError(f"Unknown target: {target}")

    crash_dir = crash_dir or config.CRASH_DIR
    coverage_dir = coverage_dir or config.FUZZ_COVERAGE_DIR
    ensure_directories([crash_dir, coverage_dir])

    summary_path = _summary_path(target, coverage_dir)
    command = [
        sys.executable,
        "-m",
        FUZZ_TARGET_MODULES[target],
        "--runs",
        str(iterations),
        "--crash-dir",
        str(crash_dir),
        "--coverage-dir",
        str(coverage_dir),
    ]
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )

    summary = _load_summary_with_retry(summary_path)

    coverage_metrics = _parse_coverage_metrics((process.stdout or "") + "\n" + (process.stderr or ""))
    coverage_payload = {
        "target": target,
        "iterations": iterations,
        "coverage_metrics": coverage_metrics,
        "return_code": process.returncode,
        "summary_path": str(summary_path),
    }
    dump_json(coverage_dir / f"{target}_coverage.json", coverage_payload)

    stderr_tail = (process.stderr or "").splitlines()[-20:]
    stdout_tail = (process.stdout or "").splitlines()[-20:]
    return {
        "target": target,
        "iterations": iterations,
        "status": "ok" if process.returncode == 0 else "error",
        "return_code": process.returncode,
        "coverage_metrics": coverage_metrics,
        "crash_files": _crash_files_for_target(target, crash_dir),
        "summary": summary,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
    }


def run_all_targets(
    iterations: int,
    execute: bool = False,
    crash_dir: Path | None = None,
    coverage_dir: Path | None = None,
) -> dict[str, Any]:
    crash_dir = crash_dir or config.CRASH_DIR
    coverage_dir = coverage_dir or config.FUZZ_COVERAGE_DIR
    ensure_directories([crash_dir, coverage_dir])

    targets = list(FUZZ_TARGET_MODULES.keys())
    if execute:
        target_results = [
            run_target(target, iterations, crash_dir=crash_dir, coverage_dir=coverage_dir)
            for target in targets
        ]
        status = "ok" if all(item["status"] == "ok" for item in target_results) else "error"
    else:
        target_results = [
            {
                "target": target,
                "iterations": iterations,
                "status": "planned",
                "coverage_metrics": {},
                "crash_files": [],
                "summary": {},
            }
            for target in targets
        ]
        status = "planned"

    payload = {
        "fuzzer": "atheris",
        "status": status,
        "collected_at": utc_now_iso(),
        "iterations": iterations,
        "targets": target_results,
    }
    dump_json(config.DATA_DIR / "fuzz_results.json", payload)
    return payload
