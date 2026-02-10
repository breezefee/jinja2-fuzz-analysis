from __future__ import annotations

from typing import Any

from z3 import (
    And,
    Bool,
    Contains,
    Distinct,
    Implies,
    Int,
    Not,
    Or,
    Solver,
    String,
    sat,
)

import config
from utils.helpers import dump_json, utc_now_iso

TYPE_NAME_MAP = {
    0: "str",
    1: "int",
    2: "list",
    3: "bool",
    4: "bytes",
}

FILTER_RULES: dict[str, tuple[set[int], int]] = {
    "lower": ({0}, 0),
    "upper": ({0}, 0),
    "length": ({0, 2, 4}, 1),
    "int": ({0, 1, 3}, 1),
    "list": ({0, 2}, 2),
    "bool": ({0, 1, 2, 3, 4}, 3),
    "escape": ({0}, 0),
}


def _int_model_value(model: Any, expr: Any, default: int = 0) -> int:
    value = model.eval(expr, model_completion=True)
    try:
        return int(value.as_long())
    except Exception:
        return default


def _str_model_value(model: Any, expr: Any, default: str) -> str:
    value = model.eval(expr, model_completion=True)
    try:
        return value.as_string()
    except Exception:
        return default


def _template_syntax_constraints() -> dict[str, Any]:
    expr_open = Int("expr_open")
    expr_close = Int("expr_close")
    stmt_open = Int("stmt_open")
    stmt_close = Int("stmt_close")

    solver = Solver()
    solver.add(expr_open >= 1, expr_open <= 3)
    solver.add(stmt_open >= 0, stmt_open <= 3)
    solver.add(expr_close == expr_open)
    solver.add(stmt_close == stmt_open)
    solver.add(expr_open + stmt_open <= 4)

    models: list[dict[str, Any]] = []
    while len(models) < 5 and solver.check() == sat:
        model = solver.model()
        eo = _int_model_value(model, expr_open)
        so = _int_model_value(model, stmt_open)
        template = "".join(["{{ value }}"] * eo + ["{% if flag %}X{% endif %}"] * so)
        models.append(
            {
                "expr_blocks": eo,
                "stmt_blocks": so,
                "template": template,
                "length": len(template),
            }
        )
        solver.add(Or(expr_open != eo, stmt_open != so))

    invalid_solver = Solver()
    invalid_solver.add(expr_open == 2, expr_close == 1)
    invalid_status = str(invalid_solver.check())

    return {
        "valid_model_count": len(models),
        "valid_models": models,
        "invalid_example_status": invalid_status,
    }


def _solve_filter_chain(chain: list[str]) -> dict[str, Any]:
    steps = [Int(f"t_{index}") for index in range(len(chain) + 1)]
    solver = Solver()
    valid_values = list(TYPE_NAME_MAP.keys())
    for var in steps:
        solver.add(Or(*[var == value for value in valid_values]))

    for index, filter_name in enumerate(chain):
        allowed, output_type = FILTER_RULES[filter_name]
        solver.add(
            Or(*[And(steps[index] == input_type, steps[index + 1] == output_type) for input_type in allowed])
        )

    status = solver.check()
    path: list[str] = []
    if status == sat:
        model = solver.model()
        path = [TYPE_NAME_MAP[_int_model_value(model, step)] for step in steps]

    return {"chain": chain, "status": str(status), "type_path": path}


def _filter_type_propagation() -> dict[str, Any]:
    chains = [
        ["lower", "length"],
        ["list", "length"],
        ["int", "lower"],
        ["escape", "bool"],
        ["length", "upper"],
    ]
    results = [_solve_filter_chain(chain) for chain in chains]
    return {
        "chains": results,
        "sat_count": sum(1 for item in results if item["status"] == "sat"),
        "unsat_count": sum(1 for item in results if item["status"] != "sat"),
    }


def _sandbox_security_verification() -> dict[str, Any]:
    enable_sandbox = Bool("enable_sandbox")
    allow_private_attribute = Bool("allow_private_attribute")
    allow_dunder_attribute = Bool("allow_dunder_attribute")
    allow_call = Bool("allow_call")

    secure_policy = Implies(
        enable_sandbox,
        And(Not(allow_private_attribute), Not(allow_dunder_attribute), allow_call),
    )

    safe_solver = Solver()
    safe_solver.add(enable_sandbox)
    safe_solver.add(secure_policy)
    safe_status = safe_solver.check()
    safe_model_repr: dict[str, bool] = {}
    if safe_status == sat:
        safe_model = safe_solver.model()
        safe_model_repr = {
            "enable_sandbox": bool(safe_model.eval(enable_sandbox)),
            "allow_private_attribute": bool(safe_model.eval(allow_private_attribute)),
            "allow_dunder_attribute": bool(safe_model.eval(allow_dunder_attribute)),
            "allow_call": bool(safe_model.eval(allow_call)),
        }

    unsafe_solver = Solver()
    unsafe_solver.add(enable_sandbox)
    unsafe_solver.add(Not(secure_policy))
    unsafe_status = unsafe_solver.check()
    unsafe_model_repr: dict[str, bool] = {}
    if unsafe_status == sat:
        unsafe_model = unsafe_solver.model()
        unsafe_model_repr = {
            "enable_sandbox": bool(unsafe_model.eval(enable_sandbox)),
            "allow_private_attribute": bool(unsafe_model.eval(allow_private_attribute)),
            "allow_dunder_attribute": bool(unsafe_model.eval(allow_dunder_attribute)),
            "allow_call": bool(unsafe_model.eval(allow_call)),
        }

    return {
        "safe_policy_status": str(safe_status),
        "safe_model": safe_model_repr,
        "unsafe_counterexample_status": str(unsafe_status),
        "unsafe_counterexample_model": unsafe_model_repr,
    }


def _generate_templates() -> dict[str, Any]:
    variable_name = String("variable_name")
    condition_name = String("condition_name")
    filter_name = String("filter_name")

    solver = Solver()
    solver.add(variable_name != "")
    solver.add(condition_name != "")
    solver.add(filter_name != "")
    solver.add(Not(Contains(variable_name, " ")))
    solver.add(Not(Contains(condition_name, " ")))
    solver.add(Or(filter_name == "lower", filter_name == "upper", filter_name == "escape"))
    solver.add(Distinct(variable_name, condition_name))

    generated: list[str] = []
    while len(generated) < 4 and solver.check() == sat:
        model = solver.model()
        var = _str_model_value(model, variable_name, "value")
        cond = _str_model_value(model, condition_name, "flag")
        filt = _str_model_value(model, filter_name, "lower")

        template = f"{{{{ {var}|{filt} }}}}{{% if {cond} %}}OK{{% endif %}}"
        generated.append(template)

        solver.add(
            Or(
                variable_name != var,
                condition_name != cond,
                filter_name != filt,
            )
        )

    return {
        "generated_templates": generated,
        "template_count": len(generated),
    }


def analyze_constraints() -> dict[str, Any]:
    syntax_results = _template_syntax_constraints()
    filter_results = _filter_type_propagation()
    sandbox_results = _sandbox_security_verification()
    generation_results = _generate_templates()

    payload = {
        "analyzer": "z3",
        "status": "ok",
        "collected_at": utc_now_iso(),
        "template_syntax_constraints": syntax_results,
        "filter_type_propagation": filter_results,
        "sandbox_security_verification": sandbox_results,
        "generated_templates": generation_results,
    }
    dump_json(config.DATA_DIR / "z3_results.json", payload)
    return payload
