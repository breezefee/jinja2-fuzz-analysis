from __future__ import annotations

import atheris
from jinja2 import Environment

from fuzzers.target_utils import TargetRecorder, build_argument_parser, run_atheris_target

TARGET_NAME = "render"


def _build_context(provider: atheris.FuzzedDataProvider) -> dict[str, object]:
    size = provider.ConsumeIntInRange(0, 6)
    context: dict[str, object] = {}
    for _ in range(size):
        key = provider.ConsumeUnicodeNoSurrogates(8) or "k"
        kind = provider.ConsumeIntInRange(0, 3)
        if kind == 0:
            value: object = provider.ConsumeUnicodeNoSurrogates(32)
        elif kind == 1:
            value = provider.ConsumeIntInRange(-1000, 1000)
        elif kind == 2:
            value = provider.ConsumeBool()
        else:
            value = [
                provider.ConsumeUnicodeNoSurrogates(8)
                for _ in range(provider.ConsumeIntInRange(0, 4))
            ]
        context[key] = value
    return context


def fuzz_entry(data: bytes, recorder: TargetRecorder | None = None) -> None:
    if recorder is not None:
        recorder.step()
    provider = atheris.FuzzedDataProvider(data)
    template = provider.ConsumeUnicodeNoSurrogates(1024)
    context = _build_context(provider)
    env = Environment(
        trim_blocks=provider.ConsumeBool(),
        lstrip_blocks=provider.ConsumeBool(),
        autoescape=provider.ConsumeBool(),
    )
    try:
        env.from_string(template).render(**context)
    except Exception as exc:
        if recorder is not None:
            recorder.record_exception(exc, template)


def main() -> None:
    parser = build_argument_parser(TARGET_NAME)
    args = parser.parse_args()
    summary_path = args.coverage_dir / f"{TARGET_NAME}_summary.json"
    recorder = TargetRecorder(TARGET_NAME, args.runs, summary_path)

    def _test_one_input(data: bytes) -> None:
        fuzz_entry(data, recorder=recorder)

    run_atheris_target(
        target=TARGET_NAME,
        test_one_input=_test_one_input,
        runs=args.runs,
        max_len=args.max_len,
        crash_dir=args.crash_dir,
        coverage_dir=args.coverage_dir,
        recorder=recorder,
    )


if __name__ == "__main__":
    main()
