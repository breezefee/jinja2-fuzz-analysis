from __future__ import annotations

from pathlib import Path
from typing import Any

import pysnooper
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment

import config
from utils.helpers import dump_json, utc_now_iso


def _trace_parse_factory(log_path: Path):
    @pysnooper.snoop(output=str(log_path), depth=2)
    def _trace_parse(template: str) -> str:
        env = Environment()
        parsed = env.parse(template)
        return type(parsed).__name__

    return _trace_parse


def _trace_render_factory(log_path: Path):
    @pysnooper.snoop(output=str(log_path), depth=2)
    def _trace_render(template: str, context: dict[str, Any]) -> str:
        env = Environment()
        return env.from_string(template).render(**context)

    return _trace_render


def _trace_compile_factory(log_path: Path):
    @pysnooper.snoop(output=str(log_path), depth=2)
    def _trace_compile(template: str) -> int:
        env = Environment()
        code = env.compile(template, raw=True)
        return len(code)

    return _trace_compile


def _trace_sandbox_factory(log_path: Path):
    @pysnooper.snoop(output=str(log_path), depth=2)
    def _trace_sandbox(template: str, context: dict[str, Any]) -> str:
        env = SandboxedEnvironment()
        return env.from_string(template).render(**context)

    return _trace_sandbox


def _run_cases(label: str, runner: Any, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for case in cases:
        name = case["name"]
        args = case.get("args", [])
        kwargs = case.get("kwargs", {})
        try:
            output = runner(*args, **kwargs)
            records.append(
                {
                    "stage": label,
                    "case": name,
                    "status": "ok",
                    "output_preview": str(output)[:200],
                }
            )
        except Exception as exc:
            records.append(
                {
                    "stage": label,
                    "case": name,
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
    return records


def trace_execution() -> dict[str, Any]:
    config.TRACE_DIR.mkdir(parents=True, exist_ok=True)
    trace_files = {
        "parse": config.TRACE_DIR / "trace_parse.txt",
        "render": config.TRACE_DIR / "trace_render.txt",
        "compile": config.TRACE_DIR / "trace_compile.txt",
        "sandbox": config.TRACE_DIR / "trace_sandbox.txt",
    }
    for path in trace_files.values():
        path.write_text("", encoding="utf-8")

    parse_runner = _trace_parse_factory(trace_files["parse"])
    render_runner = _trace_render_factory(trace_files["render"])
    compile_runner = _trace_compile_factory(trace_files["compile"])
    sandbox_runner = _trace_sandbox_factory(trace_files["sandbox"])

    records: list[dict[str, Any]] = []
    records.extend(
        _run_cases(
            "parse",
            parse_runner,
            [
                {"name": "simple_expr", "args": ["Hello {{ name }}"]},
                {"name": "loop_block", "args": ["{% for i in items %}{{ i }}{% endfor %}"]},
                {"name": "broken_syntax", "args": ["{% if x %}"]},
            ],
        )
    )
    records.extend(
        _run_cases(
            "render",
            render_runner,
            [
                {
                    "name": "basic_render",
                    "args": ["{{ user|upper }}", {"user": "jinja"}],
                },
                {
                    "name": "scope_chain",
                    "args": [
                        "{% for i in nums %}{{ loop.index }}:{{ i }} {% endfor %}",
                        {"nums": [1, 2, 3]},
                    ],
                },
                {
                    "name": "undefined_name",
                    "args": ["{{ unknown + 1 }}", {}],
                },
            ],
        )
    )
    records.extend(
        _run_cases(
            "compile",
            compile_runner,
            [
                {"name": "compile_expr", "args": ["{{ value }}"]},
                {"name": "compile_if", "args": ["{% if flag %}A{% else %}B{% endif %}"]},
                {"name": "compile_broken", "args": ["{% for x in items %}"]},
            ],
        )
    )
    records.extend(
        _run_cases(
            "sandbox",
            sandbox_runner,
            [
                {
                    "name": "safe_attr",
                    "args": ["{{ obj.name }}", {"obj": type("Safe", (), {"name": "ok"})()}],
                },
                {
                    "name": "dunder_attempt",
                    "args": ["{{ obj.__class__.__mro__ }}", {"obj": "x"}],
                },
            ],
        )
    )

    summary = {
        "analyzer": "pysnooper",
        "status": "ok",
        "collected_at": utc_now_iso(),
        "records": records,
        "trace_files": [str(path) for path in trace_files.values()],
    }
    dump_json(config.TRACE_DIR / "trace_summary.json", summary)
    return summary
