from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

import libcst as cst

import config
from utils.helpers import dump_json, utc_now_iso

STRING_METHODS = {
    "format",
    "replace",
    "split",
    "join",
    "strip",
    "lstrip",
    "rstrip",
    "startswith",
    "endswith",
    "lower",
    "upper",
    "title",
    "find",
    "rfind",
    "partition",
    "rpartition",
}


def _annotation_text(module: cst.Module, annotation: cst.Annotation | None) -> str:
    if annotation is None:
        return ""
    try:
        return module.code_for_node(annotation.annotation)
    except Exception:
        return ""


def _is_string_like_expression(expr: cst.CSTNode | None) -> bool:
    return isinstance(expr, (cst.SimpleString, cst.FormattedString, cst.ConcatenatedString))


def _parameter_iter(params: cst.Parameters) -> list[cst.Param]:
    items: list[cst.Param] = []
    items.extend(params.posonly_params)
    items.extend(params.params)
    items.extend(params.kwonly_params)
    if isinstance(params.star_arg, cst.Param):
        items.append(params.star_arg)
    if isinstance(params.star_kwarg, cst.Param):
        items.append(params.star_kwarg)
    return items


class _LibCstCollector(cst.CSTVisitor):
    def __init__(self, module: cst.Module, rel_path: str) -> None:
        self.module = module
        self.rel_path = rel_path
        self.class_stack: list[str] = []

        self.function_count = 0
        self.class_count = 0

        self.total_params = 0
        self.annotated_params = 0
        self.total_returns = 0
        self.annotated_returns = 0
        self.total_assignments = 0
        self.annotated_assignments = 0

        self.try_blocks = 0
        self.except_handlers = 0
        self.bare_except = 0
        self.finally_blocks = 0
        self.except_type_counter: Counter[str] = Counter()

        self.string_literals = 0
        self.fstrings = 0
        self.string_addition = 0
        self.string_methods: Counter[str] = Counter()

        self.fuzz_entry_points: list[dict[str, Any]] = []

    def visit_ClassDef(self, node: cst.ClassDef) -> Any:
        self.class_count += 1
        self.class_stack.append(node.name.value)

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        _ = original_node
        if self.class_stack:
            self.class_stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> Any:
        self.function_count += 1
        params = _parameter_iter(node.params)

        typed_param_names: list[str] = []
        for param in params:
            self.total_params += 1
            annotation = _annotation_text(self.module, param.annotation)
            if annotation:
                self.annotated_params += 1
                if re.search(r"\b(str|bytes)\b", annotation):
                    typed_param_names.append(param.name.value)
            if not annotation and param.default is not None and _is_string_like_expression(
                param.default
            ):
                typed_param_names.append(param.name.value)

        self.total_returns += 1
        if node.returns is not None:
            self.annotated_returns += 1

        function_name = node.name.value
        if not function_name.startswith("_") and typed_param_names:
            qualified = ".".join([*self.class_stack, function_name]) if self.class_stack else function_name
            self.fuzz_entry_points.append(
                {
                    "file": self.rel_path,
                    "function": qualified,
                    "typed_parameters": typed_param_names,
                }
            )

    def visit_Assign(self, node: cst.Assign) -> Any:
        self.total_assignments += len(node.targets)

    def visit_AnnAssign(self, node: cst.AnnAssign) -> Any:
        _ = node
        self.total_assignments += 1
        self.annotated_assignments += 1

    def visit_Try(self, node: cst.Try) -> Any:
        self.try_blocks += 1
        self.except_handlers += len(node.handlers)
        for handler in node.handlers:
            if handler.type is None:
                self.bare_except += 1
                self.except_type_counter["<bare>"] += 1
            else:
                try:
                    value = self.module.code_for_node(handler.type)
                except Exception:
                    value = "<unknown>"
                self.except_type_counter[value] += 1
        if node.finalbody is not None:
            self.finally_blocks += 1

    def visit_SimpleString(self, node: cst.SimpleString) -> Any:
        _ = node
        self.string_literals += 1

    def visit_FormattedString(self, node: cst.FormattedString) -> Any:
        _ = node
        self.fstrings += 1

    def visit_BinaryOperation(self, node: cst.BinaryOperation) -> Any:
        if isinstance(node.operator, cst.Add) and (
            _is_string_like_expression(node.left) or _is_string_like_expression(node.right)
        ):
            self.string_addition += 1

    def visit_Call(self, node: cst.Call) -> Any:
        if isinstance(node.func, cst.Attribute):
            method_name = node.func.attr.value
            if method_name in STRING_METHODS:
                self.string_methods[method_name] += 1

    def module_coverage(self) -> dict[str, Any]:
        return {
            "file": self.rel_path,
            "parameter_coverage": (
                self.annotated_params / self.total_params if self.total_params else 0.0
            ),
            "return_coverage": (
                self.annotated_returns / self.total_returns if self.total_returns else 0.0
            ),
            "variable_coverage": (
                self.annotated_assignments / self.total_assignments
                if self.total_assignments
                else 0.0
            ),
        }


def analyze_libcst(source_root: Path) -> dict[str, Any]:
    py_files = sorted(source_root.rglob("*.py"))
    total_functions = 0
    total_classes = 0
    total_params = 0
    annotated_params = 0
    total_returns = 0
    annotated_returns = 0
    total_assignments = 0
    annotated_assignments = 0

    try_blocks = 0
    except_handlers = 0
    bare_except = 0
    finally_blocks = 0
    except_type_counter: Counter[str] = Counter()

    string_literals = 0
    fstrings = 0
    string_addition = 0
    string_method_counter: Counter[str] = Counter()

    fuzz_entry_points: list[dict[str, Any]] = []
    module_coverages: list[dict[str, Any]] = []
    parse_failures: list[dict[str, str]] = []

    for file_path in py_files:
        rel_path = str(file_path.relative_to(source_root))
        source = file_path.read_text(encoding="utf-8")
        try:
            module = cst.parse_module(source)
        except Exception as exc:
            parse_failures.append({"file": rel_path, "error": str(exc)})
            continue

        collector = _LibCstCollector(module, rel_path)
        module.visit(collector)

        total_functions += collector.function_count
        total_classes += collector.class_count
        total_params += collector.total_params
        annotated_params += collector.annotated_params
        total_returns += collector.total_returns
        annotated_returns += collector.annotated_returns
        total_assignments += collector.total_assignments
        annotated_assignments += collector.annotated_assignments

        try_blocks += collector.try_blocks
        except_handlers += collector.except_handlers
        bare_except += collector.bare_except
        finally_blocks += collector.finally_blocks
        except_type_counter.update(collector.except_type_counter)

        string_literals += collector.string_literals
        fstrings += collector.fstrings
        string_addition += collector.string_addition
        string_method_counter.update(collector.string_methods)

        fuzz_entry_points.extend(collector.fuzz_entry_points)
        module_coverages.append(collector.module_coverage())

    results = {
        "analyzer": "libcst",
        "status": "ok",
        "source_root": str(source_root),
        "collected_at": utc_now_iso(),
        "totals": {
            "python_files": len(py_files),
            "functions": total_functions,
            "classes": total_classes,
        },
        "type_annotation_coverage": {
            "parameter": {
                "total": total_params,
                "annotated": annotated_params,
                "coverage": (annotated_params / total_params) if total_params else 0.0,
            },
            "return": {
                "total": total_returns,
                "annotated": annotated_returns,
                "coverage": (annotated_returns / total_returns) if total_returns else 0.0,
            },
            "variable": {
                "total": total_assignments,
                "annotated": annotated_assignments,
                "coverage": (
                    annotated_assignments / total_assignments if total_assignments else 0.0
                ),
            },
            "module_coverage": sorted(module_coverages, key=lambda item: item["file"]),
        },
        "exception_patterns": {
            "try_blocks": try_blocks,
            "except_handlers": except_handlers,
            "bare_except": bare_except,
            "finally_blocks": finally_blocks,
            "except_type_distribution": dict(except_type_counter.most_common(50)),
        },
        "string_patterns": {
            "string_literals": string_literals,
            "fstrings": fstrings,
            "string_addition": string_addition,
            "method_calls": dict(string_method_counter.most_common(50)),
        },
        "fuzz_entry_points": sorted(
            fuzz_entry_points, key=lambda item: (item["file"], item["function"])
        ),
        "parse_failures": parse_failures,
    }
    dump_json(config.DATA_DIR / "libcst_analysis.json", results)
    return results
