"""Shared helpers: a minimal valid rule file and fixture written to a temp folder."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

VALID_RULE: dict[str, Any] = {
    "id": "python-demo-rule",
    "languages": ["python"],
    "severity": "ERROR",
    "message": "eval() runs arbitrary code; parse the input with ast.literal_eval instead.",
    "metadata": {
        "category": "security",
        "bug-class": "unsafe-deserialization",
        "cwe": ["CWE-502: Deserialization of Untrusted Data"],
        "owasp": ["A08:2021 - Software and Data Integrity Failures"],
        "confidence": "HIGH",
        "safe-pattern": "ast.literal_eval(text)",
        "references": ["https://docs.python.org/3/library/ast.html"],
    },
    "pattern": "eval(...)",
}

VALID_FIXTURE = """import ast

# ruleid: python-demo-rule
eval(text)
# ok: python-demo-rule
ast.literal_eval(text)
"""


def write_pack(
    root: Path, rule: dict[str, Any] | None = None, fixture: str = VALID_FIXTURE
) -> Path:
    """Write one rule file plus fixture under root/python and return root."""
    folder = root / "python"
    folder.mkdir(parents=True, exist_ok=True)
    doc = {"rules": [rule if rule is not None else copy.deepcopy(VALID_RULE)]}
    (folder / "demo.yaml").write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    (folder / "demo.py").write_text(fixture, encoding="utf-8")
    return root


@pytest.fixture
def rule() -> dict[str, Any]:
    """A deep copy of the valid rule, free to mutate."""
    return copy.deepcopy(VALID_RULE)
