"""Parse `ruleid:` and `ok:` test annotations from fixture files (semgrep --test conventions)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

MAX_FIXTURE_BYTES = 1_000_000
_RULE_ID = r"[a-z0-9][a-z0-9.-]*"
_ANNOTATION = re.compile(rf"^\s*(?:#|//)\s*(ruleid|ok):\s*({_RULE_ID}(?:\s*,\s*{_RULE_ID})*)\s*$")
_LOOKS_LIKE = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok|todoruleid|todook)\b")

Kind = Literal["ruleid", "ok"]


class AnnotationError(ValueError):
    """A fixture annotation that cannot be used."""


@dataclass(frozen=True)
class Annotation:
    """One annotation: the rules it names and the 1-based line it applies to."""

    kind: Kind
    rule_ids: tuple[str, ...]
    line: int


def parse_annotations(text: str, source: str = "<text>") -> list[Annotation]:
    """Annotations in a fixture; each applies to the line right below it."""
    lines = text.splitlines()
    found: list[Annotation] = []
    for index, raw in enumerate(lines):
        match = _ANNOTATION.match(raw)
        if match is None:
            if _LOOKS_LIKE.match(raw):
                raise AnnotationError(f"{source}:{index + 1}: malformed or unsupported annotation")
            continue
        target = index + 2
        if target > len(lines) or not lines[target - 1].strip():
            raise AnnotationError(f"{source}:{index + 1}: annotation is not followed by code")
        if _ANNOTATION.match(lines[target - 1]):
            raise AnnotationError(f"{source}:{index + 1}: stacked annotations are not supported")
        kind: Kind = "ruleid" if match.group(1) == "ruleid" else "ok"
        ids = tuple(part.strip() for part in match.group(2).split(","))
        if len(set(ids)) != len(ids):
            raise AnnotationError(f"{source}:{index + 1}: a rule is named twice")
        found.append(Annotation(kind, ids, target))
    return found


def read_fixture(path: Path) -> list[Annotation]:
    """Annotations of one fixture file, refusing oversized files."""
    size = path.stat().st_size
    if size > MAX_FIXTURE_BYTES:
        raise AnnotationError(f"{path}: {size} bytes exceeds {MAX_FIXTURE_BYTES}")
    return parse_annotations(path.read_text(encoding="utf-8"), str(path))


def lines_for(annotations: list[Annotation], kind: Kind, rule_id: str) -> set[int]:
    """Lines annotated with `kind` for one rule."""
    return {a.line for a in annotations if a.kind == kind and rule_id in a.rule_ids}
