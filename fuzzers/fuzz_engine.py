from __future__ import annotations

from typing import Any

from fuzzers import fuzz_lexer, fuzz_markup, fuzz_parse, fuzz_render, fuzz_sandbox

FUZZ_TARGETS = {
    fuzz_parse.TARGET_NAME: fuzz_parse.fuzz_entry,
    fuzz_render.TARGET_NAME: fuzz_render.fuzz_entry,
    fuzz_markup.TARGET_NAME: fuzz_markup.fuzz_entry,
    fuzz_sandbox.TARGET_NAME: fuzz_sandbox.fuzz_entry,
    fuzz_lexer.TARGET_NAME: fuzz_lexer.fuzz_entry,
}


def run_target(target: str, iterations: int) -> dict[str, Any]:
    if target not in FUZZ_TARGETS:
        raise ValueError(f"Unknown target: {target}")
    return {
        "target": target,
        "iterations": iterations,
        "status": "pending",
        "exceptions": [],
    }


def run_all_targets(iterations: int) -> dict[str, Any]:
    return {
        "fuzzer": "atheris",
        "iterations": iterations,
        "targets": [run_target(name, iterations) for name in FUZZ_TARGETS],
    }
