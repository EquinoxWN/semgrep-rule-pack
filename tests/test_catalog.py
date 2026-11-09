"""Rule pack validation: the real pack loads; each broken convention is reported."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from conftest import VALID_FIXTURE, write_pack

from semgrep_rule_pack.catalog import BUG_CLASSES, CatalogError, load_catalog

PACK = Path(__file__).resolve().parents[1] / "rules"


def test_the_shipped_pack_is_valid_and_covers_every_bug_class() -> None:
    catalog = load_catalog(PACK)
    rules = catalog.rules
    assert len(rules) == 19
    assert {r.bug_class for r in rules} == BUG_CLASSES
    assert {lang for r in rules for lang in r.languages} >= {"python", "go", "java", "typescript"}
    taint = [r.id for r in rules if r.mode == "taint"]
    assert sorted(taint) == [
        "go-tainted-shell",
        "go-tainted-sql",
        "python-tainted-shell",
        "python-tainted-sql",
        "ts-tainted-shell",
        "ts-tainted-sql",
    ]


def test_a_minimal_valid_pack_loads(tmp_path: Path) -> None:
    catalog = load_catalog(write_pack(tmp_path))
    assert [r.id for r in catalog.rules] == ["python-demo-rule"]
    assert catalog.files[0].fixture.name == "demo.py"


def _problems(tmp_path: Path, rule: dict[str, Any], fixture: str = VALID_FIXTURE) -> str:
    """Load a pack with one rule and return the joined problems."""
    with pytest.raises(CatalogError) as info:
        load_catalog(write_pack(tmp_path, rule, fixture))
    return "\n".join(info.value.problems)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda r: r.update(id="Demo_Rule"), "kebab-case"),
        (lambda r: r.update(id="go-demo-rule"), "must start with 'python-'"),
        (lambda r: r.update(languages=["cobol"]), "languages"),
        (lambda r: r.update(languages=[]), "languages"),
        (lambda r: r.update(severity="HIGH"), "severity"),
        (lambda r: r.update(message="bad"), "message must explain"),
        (
            lambda r: r.update(message="Use cursor.execute('... WHERE id = $1', [v]) for safety."),
            r"\$<digit>",
        ),
        (lambda r: r.update(mode="join"), "mode must be"),
        (lambda r: r.pop("pattern"), "search rule needs"),
        (
            lambda r: r.update(
                mode="taint",
                **{
                    "pattern-sources": [{"pattern": "input()"}],
                    "pattern-sinks": [{"pattern": "eval(...)"}],
                },
            ),
            "pattern-sanitizers",
        ),
        (lambda r: r.pop("metadata"), "metadata mapping"),
        (lambda r: r["metadata"].update(category="style"), "category"),
        (lambda r: r["metadata"].update({"bug-class": "xss"}), "bug-class"),
        (lambda r: r["metadata"].update(confidence="SURE"), "confidence"),
        (lambda r: r["metadata"].update(cwe=["89"]), "cwe"),
        (lambda r: r["metadata"].update(owasp=[]), "owasp"),
        (lambda r: r["metadata"].pop("safe-pattern"), "safe-pattern"),
        (lambda r: r["metadata"].update(references=["http://example.com"]), "references"),
    ],
)
def test_each_schema_violation_is_reported(
    tmp_path: Path, rule: dict[str, Any], change: Any, expected: str
) -> None:
    change(rule)
    assert __import__("re").search(expected, _problems(tmp_path, rule))


def test_fixture_must_show_the_rule_firing_and_staying_quiet(
    tmp_path: Path, rule: dict[str, Any]
) -> None:
    no_ok = "# ruleid: python-demo-rule\neval(text)\n"
    assert "no 'ok: python-demo-rule'" in _problems(tmp_path / "a", rule, no_ok)
    no_hit = "# ok: python-demo-rule\nast.literal_eval(text)\n"
    assert "no 'ruleid: python-demo-rule'" in _problems(tmp_path / "b", rule, no_hit)


def test_annotation_naming_an_unknown_rule_is_reported(
    tmp_path: Path, rule: dict[str, Any]
) -> None:
    fixture = VALID_FIXTURE + "# ok: python-other\nx()\n"
    assert "unknown rule python-other" in _problems(tmp_path, rule, fixture)


def test_bad_annotation_in_fixture_is_reported(tmp_path: Path, rule: dict[str, Any]) -> None:
    assert "not followed by code" in _problems(
        tmp_path, rule, VALID_FIXTURE + "# ok: python-demo-rule\n"
    )


def test_missing_or_ambiguous_fixture(tmp_path: Path) -> None:
    root = write_pack(tmp_path)
    (root / "python" / "demo.py").unlink()
    with pytest.raises(CatalogError, match="found 0"):
        load_catalog(root)
    (root / "python" / "demo.py").write_text(VALID_FIXTURE, encoding="utf-8")
    (root / "python" / "demo.go").write_text("package x\n", encoding="utf-8")
    with pytest.raises(CatalogError, match="found 2"):
        load_catalog(root)


def test_duplicate_rule_ids_across_files(tmp_path: Path) -> None:
    root = write_pack(tmp_path)
    for suffix in (".yaml", ".py"):
        src = root / "python" / f"demo{suffix}"
        (root / "python" / f"copy{suffix}").write_text(
            src.read_text(encoding="utf-8"), encoding="utf-8"
        )
    with pytest.raises(CatalogError, match="already defined"):
        load_catalog(root)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("rules: [", "invalid YAML"),
        ("rules: []\n", "non-empty 'rules'"),
        ("- a\n", "non-empty 'rules'"),
        ("rules: [1]\n", "must be a mapping"),
    ],
)
def test_malformed_rule_files(tmp_path: Path, text: str, expected: str) -> None:
    root = write_pack(tmp_path)
    (root / "python" / "demo.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(CatalogError, match=expected):
        load_catalog(root)


def test_empty_or_missing_pack_folder(tmp_path: Path) -> None:
    with pytest.raises(CatalogError, match="not a directory"):
        load_catalog(tmp_path / "nope")
    with pytest.raises(CatalogError, match="no rule files"):
        load_catalog(tmp_path)


def test_oversized_rule_file_is_refused(tmp_path: Path) -> None:
    root = write_pack(tmp_path)
    (root / "python" / "demo.yaml").write_text("# pad\n" * 50_000, encoding="utf-8")
    with pytest.raises(CatalogError, match="exceeds"):
        load_catalog(root)
