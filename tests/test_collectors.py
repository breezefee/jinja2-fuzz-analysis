from __future__ import annotations

from collectors.commit_collector import is_bugfix_message


def test_bugfix_message_detection() -> None:
    assert is_bugfix_message("fix: parser edge case")
    assert is_bugfix_message("bug: sandbox validation")
    assert is_bugfix_message("patch tokenization")
    assert not is_bugfix_message("docs: update readme")
