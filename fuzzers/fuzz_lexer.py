from __future__ import annotations

import atheris
from jinja2 import Environment

from fuzzers.target_utils import TargetRecorder, build_argument_parser, run_atheris_target

TARGET_NAME = "lexer"


def fuzz_entry(data: bytes, recorder: TargetRecorder | None = None) -> None:
    if recorder is not None:
        recorder.step()
    provider = atheris.FuzzedDataProvider(data)
    source = provider.ConsumeUnicodeNoSurrogates(1500)
    env = Environment(
        trim_blocks=provider.ConsumeBool(),
        lstrip_blocks=provider.ConsumeBool(),
    )
    try:
        list(env.lex(source))
    except Exception as exc:
        if recorder is not None:
            recorder.record_exception(exc, source)


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
