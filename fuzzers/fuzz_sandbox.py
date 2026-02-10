from __future__ import annotations

import atheris

from fuzzers.target_utils import TargetRecorder, build_argument_parser, run_atheris_target

with atheris.instrument_imports():
    from jinja2.sandbox import SandboxedEnvironment

TARGET_NAME = "sandbox"


def _sandbox_context(provider: atheris.FuzzedDataProvider) -> dict[str, object]:
    return {
        "name": provider.ConsumeUnicodeNoSurrogates(16),
        "value": provider.ConsumeIntInRange(-500, 500),
        "items": [
            provider.ConsumeUnicodeNoSurrogates(8)
            for _ in range(provider.ConsumeIntInRange(0, 5))
        ],
        "obj": type(
            "Obj",
            (),
            {
                "name": provider.ConsumeUnicodeNoSurrogates(8),
                "_private": provider.ConsumeUnicodeNoSurrogates(8),
            },
        )(),
    }


def fuzz_entry(data: bytes, recorder: TargetRecorder | None = None) -> None:
    if recorder is not None:
        recorder.step()
    provider = atheris.FuzzedDataProvider(data)
    template = provider.ConsumeUnicodeNoSurrogates(1200)
    env = SandboxedEnvironment(
        trim_blocks=provider.ConsumeBool(),
        lstrip_blocks=provider.ConsumeBool(),
        autoescape=provider.ConsumeBool(),
    )
    context = _sandbox_context(provider)
    try:
        env.from_string(template).render(**context)
    except Exception as exc:
        if recorder is not None:
            recorder.record_exception(exc, template)


def main() -> None:
    parser = build_argument_parser(TARGET_NAME)
    args = parser.parse_args()
    summary_path = args.coverage_dir / f"{TARGET_NAME}_summary.json"
    recorder = TargetRecorder(TARGET_NAME, args.runs, summary_path, args.crash_dir)

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
