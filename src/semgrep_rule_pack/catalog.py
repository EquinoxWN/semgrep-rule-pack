"""Load the rule pack and check every rule against the pack's schema and fixture conventions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from semgrep_rule_pack.annotations import Annotation, AnnotationError, lines_for, read_fixture

MAX_RULE_FILE_BYTES = 256_000
LANGUAGES = {"python", "go", "java", "typescript", "javascript"}
PREFIXES = {"python": "python-", "go": "go-", "java": "java-", "typescript": "ts-"}
SEVERITIES = {"ERROR", "WARNING", "INFO"}
CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
BUG_CLASSES = {"sql-injection", "command-injection", "unsafe-deserialization", "weak-crypto"}
SEARCH_KEYS = {"pattern", "patterns", "pattern-either", "pattern-regex"}
TAINT_KEYS = ("pattern-sources", "pattern-sinks", "pattern-sanitizers")
FIXTURE_SUFFIXES = {".py", ".go", ".java", ".ts", ".js"}
_ID = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)+$")
_CWE = re.compile(r"^CWE-\d+: \S")
# Semgrep replaces $1, $2 ... in messages with regex groups, which garbles text like "WHERE id = $1".
_NUMBERED_METAVAR = re.compile(r"\$\d")


class CatalogError(ValueError):
    """The rule pack breaks its own conventions; `problems` lists every violation."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Rule:
    """The fields of one rule that the harness and reports use."""

    id: str
    path: Path
    mode: str
    languages: tuple[str, ...]
    severity: str
    bug_class: str
    confidence: str
    cwe: tuple[str, ...]


@dataclass(frozen=True)
class RuleFile:
    """One YAML rule file, its rules and its annotated fixture."""

    path: Path
    fixture: Path
    rules: tuple[Rule, ...]
    annotations: tuple[Annotation, ...]


@dataclass(frozen=True)
class Catalog:
    """Every rule file of the pack."""

    root: Path
    files: tuple[RuleFile, ...]

    @property
    def rules(self) -> list[Rule]:
        """All rules in file order."""
        return [rule for f in self.files for rule in f.rules]


def _check_rule(raw: Any, where: str) -> tuple[Rule | None, list[str]]:
    """Validate one rule mapping; return the rule or the problems found."""
    if not isinstance(raw, dict):
        return None, [f"{where}: a rule must be a mapping"]
    problems: list[str] = []
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not _ID.match(rule_id):
        return None, [f"{where}: id must be lower-case kebab-case, got {rule_id!r}"]
    at = f"{where}: {rule_id}"
    languages = raw.get("languages")
    if (
        not isinstance(languages, list)
        or not languages
        or not all(isinstance(lang, str) and lang in LANGUAGES for lang in languages)
    ):
        problems.append(f"{at}: languages must be a non-empty subset of {sorted(LANGUAGES)}")
        languages = []
    elif not rule_id.startswith(PREFIXES.get(languages[0], "\0")):
        problems.append(f"{at}: id must start with {PREFIXES.get(languages[0])!r}")
    severity = raw.get("severity")
    if severity not in SEVERITIES:
        problems.append(f"{at}: severity must be one of {sorted(SEVERITIES)}")
    message = raw.get("message")
    if not isinstance(message, str) or len(message.strip()) < 20:
        problems.append(f"{at}: message must explain the bug and the fix (20+ characters)")
    elif _NUMBERED_METAVAR.search(message):
        problems.append(f"{at}: message contains $<digit>, which semgrep would substitute")
    mode = raw.get("mode", "search")
    if mode == "taint":
        problems.extend(
            f"{at}: taint rule needs a non-empty {key} list"
            for key in TAINT_KEYS
            if not isinstance(raw.get(key), list) or not raw[key]
        )
    elif mode == "search":
        if not SEARCH_KEYS.intersection(raw):
            problems.append(f"{at}: search rule needs one of {sorted(SEARCH_KEYS)}")
    else:
        problems.append(f"{at}: mode must be search or taint, got {mode!r}")
    meta = raw.get("metadata")
    if not isinstance(meta, dict):
        problems.append(f"{at}: metadata mapping is required")
        meta = {}
    if meta.get("category") != "security":
        problems.append(f"{at}: metadata.category must be security")
    bug_class = meta.get("bug-class")
    if bug_class not in BUG_CLASSES:
        problems.append(f"{at}: metadata.bug-class must be one of {sorted(BUG_CLASSES)}")
    confidence = meta.get("confidence")
    if confidence not in CONFIDENCE:
        problems.append(f"{at}: metadata.confidence must be one of {sorted(CONFIDENCE)}")
    cwe = meta.get("cwe")
    if (
        not isinstance(cwe, list)
        or not cwe
        or not all(isinstance(c, str) and _CWE.match(c) for c in cwe)
    ):
        problems.append(f"{at}: metadata.cwe must list entries like 'CWE-89: name'")
        cwe = []
    owasp = meta.get("owasp")
    if not isinstance(owasp, list) or not owasp:
        problems.append(f"{at}: metadata.owasp must be a non-empty list")
    safe = meta.get("safe-pattern")
    if not isinstance(safe, str) or not safe.strip():
        problems.append(f"{at}: metadata.safe-pattern must name the safe alternative")
    refs = meta.get("references")
    if (
        not isinstance(refs, list)
        or not refs
        or not all(isinstance(r, str) and r.startswith("https://") for r in refs)
    ):
        problems.append(f"{at}: metadata.references must be a non-empty list of https URLs")
    if problems:
        return None, problems
    return (
        Rule(
            id=rule_id,
            path=Path(where),
            mode=str(mode),
            languages=tuple(languages),
            severity=str(severity),
            bug_class=str(bug_class),
            confidence=str(confidence),
            cwe=tuple(cwe),
        ),
        [],
    )


def _fixture_for(path: Path) -> tuple[Path | None, list[str]]:
    """The single fixture next to a rule file (same name, a source-code suffix)."""
    found = [p for p in path.parent.glob(path.stem + ".*") if p.suffix in FIXTURE_SUFFIXES]
    if len(found) != 1:
        return None, [f"{path}: expected exactly one fixture {path.stem}.<ext>, found {len(found)}"]
    return found[0], []


def load_rule_file(path: Path) -> tuple[RuleFile | None, list[str]]:
    """Parse and validate one rule file and its fixture."""
    size = path.stat().st_size
    if size > MAX_RULE_FILE_BYTES:
        return None, [f"{path}: {size} bytes exceeds {MAX_RULE_FILE_BYTES}"]
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return None, [f"{path}: invalid YAML: {exc}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list) or not doc["rules"]:
        return None, [f"{path}: top level must be a mapping with a non-empty 'rules' list"]
    problems: list[str] = []
    rules: list[Rule] = []
    for raw in doc["rules"]:
        rule, errs = _check_rule(raw, str(path))
        problems += errs
        if rule is not None:
            rules.append(rule)
    fixture, errs = _fixture_for(path)
    problems += errs
    if fixture is None:
        return None, problems
    try:
        annotations = read_fixture(fixture)
    except AnnotationError as exc:
        return None, [*problems, str(exc)]
    known = {r.id for r in rules}
    for ann in annotations:
        problems += [
            f"{fixture}:{ann.line - 1}: names unknown rule {rid}"
            for rid in ann.rule_ids
            if rid not in known
        ]
    for rule in rules:
        if not lines_for(annotations, "ruleid", rule.id):
            problems.append(
                f"{fixture}: no 'ruleid: {rule.id}' case (the rule is never shown to fire)"
            )
        if not lines_for(annotations, "ok", rule.id):
            problems.append(
                f"{fixture}: no 'ok: {rule.id}' case (the rule is never shown to stay quiet)"
            )
    if problems:
        return None, problems
    return RuleFile(path, fixture, tuple(rules), tuple(annotations)), []


def load_catalog(root: Path) -> Catalog:
    """Load every rule file under `root`; raise CatalogError listing all problems."""
    if not root.is_dir():
        raise CatalogError([f"{root}: not a directory"])
    paths = sorted(p for p in root.rglob("*") if p.suffix in {".yaml", ".yml"} and p.is_file())
    if not paths:
        raise CatalogError([f"{root}: no rule files (*.yaml)"])
    problems: list[str] = []
    files: list[RuleFile] = []
    for path in paths:
        rule_file, errs = load_rule_file(path)
        problems += errs
        if rule_file is not None:
            files.append(rule_file)
    seen: dict[str, Path] = {}
    for f in files:
        for rule in f.rules:
            if rule.id in seen:
                problems.append(f"{f.path}: rule id {rule.id} already defined in {seen[rule.id]}")
            seen[rule.id] = f.path
    if problems:
        raise CatalogError(problems)
    return Catalog(root, tuple(files))
