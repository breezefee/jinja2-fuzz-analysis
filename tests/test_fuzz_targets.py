from __future__ import annotations

from fuzzers.fuzz_lexer import fuzz_entry as fuzz_lexer_entry
from fuzzers.fuzz_markup import fuzz_entry as fuzz_markup_entry
from fuzzers.fuzz_parse import fuzz_entry as fuzz_parse_entry
from fuzzers.fuzz_render import fuzz_entry as fuzz_render_entry
from fuzzers.fuzz_sandbox import fuzz_entry as fuzz_sandbox_entry


def test_fuzz_targets_smoke() -> None:
    payload = b"{{ user.name }}{% if x %}x{% endif %}"
    fuzz_parse_entry(payload)
    fuzz_render_entry(payload)
    fuzz_sandbox_entry(payload)
    fuzz_lexer_entry(payload)
    fuzz_markup_entry(payload)
