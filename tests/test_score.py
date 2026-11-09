"""Scoring findings against annotations, without running semgrep."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_pack

from semgrep_rule_pack.catalog import Catalog, load_catalog
from semgrep_rule_pack.runner import Finding
from semgrep_rule_pack.score import ScoreError, score

FIXTURE = """# ruleid: python-demo-rule
eval(a)
# ruleid: python-demo-rule
eval(b)
# ok: python-demo-rule
ast.literal_eval(c)
# ok: python-demo-rule
ast.literal_eval(d)
"""


@pytest.fixture
def catalog(tmp_path: Path) -> Catalog:
    """A one-rule pack: lines 2 and 4 must fire, lines 6 and 8 must not."""
    return load_catalog(write_pack(tmp_path, fixture=FIXTURE))


def _hit(
    catalog: Catalog, line: int, rule_id: str = "python-demo-rule", path: Path | None = None
) -> Finding:
    """A finding on the catalog's fixture (or `path`)."""
    return Finding(rule_id, path or catalog.files[0].fixture, line, line, "ERROR", "m")


def test_exact_findings_pass(catalog: Catalog) -> None:
    report = score(catalog, [_hit(catalog, 2), _hit(catalog, 4)])
    [s] = report.scores
    assert report.passed
    assert (s.true_positives, s.false_positives, s.false_negatives, s.true_negatives) == (
        2,
        0,
        0,
        2,
    )
    assert s.precision == s.recall == 1.0


def test_a_missed_line_fails(catalog: Catalog) -> None:
    [s] = score(catalog, [_hit(catalog, 2)]).scores
    assert not s.passed
    assert s.missed_lines == (4,)
    assert s.recall == 0.5


def test_a_finding_on_an_ok_line_fails(catalog: Catalog) -> None:
    report = score(catalog, [_hit(catalog, 2), _hit(catalog, 4), _hit(catalog, 6)])
    [s] = report.scores
    assert not report.passed
    assert s.unexpected_lines == (6,)
    assert s.true_negatives == 1
    assert s.precision == pytest.approx(2 / 3)


def test_a_finding_on_an_unannotated_line_fails(catalog: Catalog) -> None:
    [s] = score(catalog, [_hit(catalog, 2), _hit(catalog, 4), _hit(catalog, 3)]).scores
    assert s.unexpected_lines == (3,)


def test_no_findings_at_all_fails_with_zero_recall(catalog: Catalog) -> None:
    report = score(catalog, [])
    assert not report.passed
    assert report.scores[0].recall == 0.0
    assert report.totals()["false_negatives"] == 2


def test_findings_in_other_files_do_not_count(catalog: Catalog, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere.py"
    report = score(catalog, [_hit(catalog, 2), _hit(catalog, 4), _hit(catalog, 6, path=other)])
    assert report.passed


def test_unknown_rule_is_an_error(catalog: Catalog) -> None:
    with pytest.raises(ScoreError, match="unknown rule"):
        score(catalog, [_hit(catalog, 2, rule_id="python-ghost")])


def test_report_dict_carries_totals(catalog: Catalog) -> None:
    d = score(catalog, [_hit(catalog, 2), _hit(catalog, 4)]).to_dict()
    assert d["passed"] is True
    assert d["totals"] == {
        "rules": 1,
        "rules_passed": 1,
        "true_positives": 2,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 2,
    }
