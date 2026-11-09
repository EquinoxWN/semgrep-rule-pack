"""Annotation parsing: placement, comment styles and malformed input."""

from __future__ import annotations

from pathlib import Path

import pytest

from semgrep_rule_pack.annotations import (
    MAX_FIXTURE_BYTES,
    Annotation,
    AnnotationError,
    lines_for,
    parse_annotations,
    read_fixture,
)


def test_annotation_applies_to_the_next_line_in_both_comment_styles() -> None:
    text = "# ruleid: python-a\nx()\n  // ok: go-b\ny()\n"
    assert parse_annotations(text) == [
        Annotation("ruleid", ("python-a",), 2),
        Annotation("ok", ("go-b",), 4),
    ]


def test_several_rule_ids_in_one_annotation() -> None:
    [ann] = parse_annotations("// ruleid: go-a, go-b\ncall()\n")
    assert ann.rule_ids == ("go-a", "go-b")
    assert lines_for([ann], "ruleid", "go-b") == {2}
    assert lines_for([ann], "ok", "go-b") == set()


def test_no_annotations_in_plain_code() -> None:
    assert parse_annotations("") == []
    assert parse_annotations("x = 1  # a comment that says ruleid elsewhere\n") == []


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("# ruleid: python-a\n", "not followed by code"),
        ("# ruleid: python-a\n\nx()\n", "not followed by code"),
        ("# ruleid: python-a\n# ok: python-b\nx()\n", "stacked"),
        ("# todoruleid: python-a\nx()\n", "malformed or unsupported"),
        ("# ruleid: Python_A\nx()\n", "malformed or unsupported"),
        ("# ruleid:\nx()\n", "malformed or unsupported"),
        ("# ok: python-a, python-a\nx()\n", "named twice"),
    ],
)
def test_malformed_annotations_are_rejected_with_the_line(text: str, reason: str) -> None:
    with pytest.raises(AnnotationError, match=reason) as info:
        parse_annotations(text, "f.py")
    assert str(info.value).startswith("f.py:1:")


def test_oversized_fixture_is_refused(tmp_path: Path) -> None:
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * (MAX_FIXTURE_BYTES // 6 + 1), encoding="utf-8")
    with pytest.raises(AnnotationError, match="exceeds"):
        read_fixture(big)
