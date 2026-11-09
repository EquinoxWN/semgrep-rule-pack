"""Compare semgrep findings with fixture annotations and score each rule."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass

from semgrep_rule_pack.annotations import lines_for
from semgrep_rule_pack.catalog import Catalog
from semgrep_rule_pack.runner import Finding


@dataclass(frozen=True)
class RuleScore:
    """Outcome of one rule on its own fixture."""

    rule_id: str
    bug_class: str
    mode: str
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    missed_lines: tuple[int, ...]
    unexpected_lines: tuple[int, ...]

    @property
    def passed(self) -> bool:
        """Every `ruleid` line found and nothing else reported."""
        return self.false_positives == 0 and self.false_negatives == 0

    @property
    def precision(self) -> float:
        """Share of findings that were expected (1.0 when there are none)."""
        hits = self.true_positives + self.false_positives
        return self.true_positives / hits if hits else 1.0

    @property
    def recall(self) -> float:
        """Share of expected lines that were found (1.0 when none are expected)."""
        wanted = self.true_positives + self.false_negatives
        return self.true_positives / wanted if wanted else 1.0


@dataclass(frozen=True)
class Report:
    """Scores for every rule in the catalog."""

    scores: tuple[RuleScore, ...]

    @property
    def passed(self) -> bool:
        """True when every rule passed."""
        return all(s.passed for s in self.scores)

    def totals(self) -> dict[str, int]:
        """Summed confusion counts across rules."""
        return {
            "rules": len(self.scores),
            "rules_passed": sum(s.passed for s in self.scores),
            "true_positives": sum(s.true_positives for s in self.scores),
            "false_positives": sum(s.false_positives for s in self.scores),
            "false_negatives": sum(s.false_negatives for s in self.scores),
            "true_negatives": sum(s.true_negatives for s in self.scores),
        }

    def to_dict(self) -> dict[str, object]:
        """JSON-ready form."""
        return {
            "passed": self.passed,
            "totals": self.totals(),
            "rules": [
                {**asdict(s), "passed": s.passed, "precision": s.precision, "recall": s.recall}
                for s in self.scores
            ],
        }


class ScoreError(ValueError):
    """Findings that cannot belong to the catalog."""


def score(catalog: Catalog, findings: Iterable[Finding]) -> Report:
    """Score each rule only on its own fixture, as `semgrep --test` does."""
    known = {rule.id for rule in catalog.rules}
    by_rule: dict[tuple[str, str], set[int]] = {}
    for f in findings:
        if f.rule_id not in known:
            raise ScoreError(f"finding for unknown rule {f.rule_id} at {f.path}:{f.line}")
        by_rule.setdefault((f.rule_id, str(f.path.resolve())), set()).add(f.line)
    scores: list[RuleScore] = []
    for rule_file in catalog.files:
        fixture = str(rule_file.fixture.resolve())
        annotations = list(rule_file.annotations)
        for rule in rule_file.rules:
            expected = lines_for(annotations, "ruleid", rule.id)
            negatives = lines_for(annotations, "ok", rule.id)
            got = by_rule.get((rule.id, fixture), set())
            scores.append(
                RuleScore(
                    rule_id=rule.id,
                    bug_class=rule.bug_class,
                    mode=rule.mode,
                    true_positives=len(expected & got),
                    false_positives=len(got - expected),
                    false_negatives=len(expected - got),
                    true_negatives=len(negatives - got),
                    missed_lines=tuple(sorted(expected - got)),
                    unexpected_lines=tuple(sorted(got - expected)),
                )
            )
    return Report(tuple(scores))
