from __future__ import annotations

import ast
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

from radon.complexity import cc_rank, cc_visit

import config
from utils.helpers import dump_json, utc_now_iso


def _decorator_name(node: ast.expr) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _import_name(node: ast.ImportFrom | ast.Import) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.append(alias.name)
    else:
        base = node.module or ""
        for alias in node.names:
            if base:
                names.append(f"{base}.{alias.name}")
            else:
                names.append(alias.name)
    return names


def _function_arg_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    total = len(node.args.posonlyargs) + len(node.args.args) + len(node.args.kwonlyargs)
    if node.args.vararg is not None:
        total += 1
    if node.args.kwarg is not None:
        total += 1
    return total


class _AstCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.function_count = 0
        self.async_function_count = 0
        self.class_count = 0
        self.imports: list[str] = []
        self.decorators: Counter[str] = Counter()
        self.arg_distribution: Counter[int] = Counter()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.function_count += 1
        self.arg_distribution[_function_arg_count(node)] += 1
        for decorator in node.decorator_list:
            self.decorators[_decorator_name(decorator)] += 1
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.async_function_count += 1
        self.arg_distribution[_function_arg_count(node)] += 1
        for decorator in node.decorator_list:
            self.decorators[_decorator_name(decorator)] += 1
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_count += 1
        for decorator in node.decorator_list:
            self.decorators[_decorator_name(decorator)] += 1
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        self.imports.extend(_import_name(node))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        self.imports.extend(_import_name(node))
        self.generic_visit(node)


def _summarize_complexity(scores: list[int]) -> dict[str, Any]:
    if not scores:
        return {
            "count": 0,
            "average": 0.0,
            "median": 0.0,
            "max": 0,
            "min": 0,
        }
    return {
        "count": len(scores),
        "average": round(statistics.fmean(scores), 3),
        "median": round(float(statistics.median(scores)), 3),
        "max": max(scores),
        "min": min(scores),
    }


def analyze_ast(source_root: Path) -> dict[str, Any]:
    py_files = sorted(source_root.rglob("*.py"))
    total_functions = 0
    total_async_functions = 0
    total_classes = 0
    decorator_counter: Counter[str] = Counter()
    arg_distribution: Counter[int] = Counter()
    dependency_counter: Counter[str] = Counter()
    complexity_scores: list[int] = []
    complexity_grade_counter: Counter[str] = Counter()
    file_imports: dict[str, list[str]] = {}
    dependency_edges: list[dict[str, str]] = []
    file_metrics: list[dict[str, Any]] = []
    parse_failures: list[dict[str, str]] = []
    complexity_blocks: list[dict[str, Any]] = []

    for file_path in py_files:
        rel_path = str(file_path.relative_to(source_root))
        source = file_path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(file_path))
        except Exception as exc:
            parse_failures.append({"file": rel_path, "error": str(exc)})
            continue

        collector = _AstCollector()
        collector.visit(tree)

        total_functions += collector.function_count
        total_async_functions += collector.async_function_count
        total_classes += collector.class_count
        decorator_counter.update(collector.decorators)
        arg_distribution.update(collector.arg_distribution)

        imports = sorted(set(collector.imports))
        file_imports[rel_path] = imports
        for dependency in imports:
            dependency_counter[dependency] += 1
            dependency_edges.append({"source": rel_path, "target": dependency})

        try:
            cc_blocks = cc_visit(source)
        except Exception as exc:
            parse_failures.append({"file": rel_path, "error": f"radon:{exc}"})
            cc_blocks = []

        for block in cc_blocks:
            complexity = int(block.complexity)
            complexity_scores.append(complexity)
            complexity_grade_counter[str(cc_rank(complexity))] += 1
            complexity_blocks.append(
                {
                    "file": rel_path,
                    "name": block.name,
                    "lineno": int(block.lineno),
                    "complexity": complexity,
                    "rank": str(cc_rank(complexity)),
                }
            )

        file_metrics.append(
            {
                "file": rel_path,
                "functions": collector.function_count,
                "async_functions": collector.async_function_count,
                "classes": collector.class_count,
                "imports": len(imports),
                "decorators": int(sum(collector.decorators.values())),
            }
        )

    summary = {
        "analyzer": "ast",
        "status": "ok",
        "source_root": str(source_root),
        "collected_at": utc_now_iso(),
        "totals": {
            "python_files": len(py_files),
            "functions": total_functions,
            "async_functions": total_async_functions,
            "classes": total_classes,
        },
        "complexity_summary": _summarize_complexity(complexity_scores),
        "complexity_rank_distribution": dict(sorted(complexity_grade_counter.items())),
        "top_complex_functions": sorted(
            complexity_blocks, key=lambda item: item["complexity"], reverse=True
        )[:30],
        "dependency_edges": dependency_edges,
        "top_dependencies": dependency_counter.most_common(30),
        "file_imports": file_imports,
        "decorator_usage": dict(decorator_counter.most_common(60)),
        "function_arg_distribution": {
            str(arg_count): count
            for arg_count, count in sorted(arg_distribution.items(), key=lambda x: x[0])
        },
        "file_metrics": file_metrics,
        "parse_failures": parse_failures,
    }
    dump_json(config.DATA_DIR / "ast_analysis.json", summary)
    return summary
