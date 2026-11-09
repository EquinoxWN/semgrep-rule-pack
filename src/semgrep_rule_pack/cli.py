"""`srp`: validate the rule pack, score it against its fixtures, or scan code with it."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from semgrep_rule_pack.catalog import Catalog, CatalogError, load_catalog
from semgrep_rule_pack.runner import SemgrepError, SemgrepRunner
from semgrep_rule_pack.score import ScoreError, score

DEFAULT_EXCLUDES = (
    ".venv",
    "node_modules",
    ".tmp",
    ".git",
    ".gomodcache",
    ".gocache",
    ".m2",
    "target",
    "dist",
    "build",
)


def write_json_atomic(path: Path, payload: object) -> None:
    """Write JSON to a sibling temp file, then rename it over `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _positive(value: str) -> float:
    """argparse type: a positive number."""
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def split_command(text: str) -> list[str]:
    """Split a command line, keeping Windows backslashes and dropping surrounding quotes."""
    parts = [
        part[1:-1] if len(part) > 1 and part[0] == part[-1] and part[0] in "\"'" else part
        for part in shlex.split(text, posix=False)
    ]
    if not parts:
        raise argparse.ArgumentTypeError("command must not be empty")
    return parts


def _parser() -> argparse.ArgumentParser:
    """Command-line interface definition."""
    p = argparse.ArgumentParser(prog="srp", description=__doc__)
    p.add_argument(
        "--rules", type=Path, default=Path("rules"), help="rule pack folder (default: rules)"
    )
    p.add_argument(
        "--semgrep",
        type=split_command,
        default=["semgrep"],
        help="semgrep command (default: semgrep)",
    )
    p.add_argument("--timeout", type=_positive, default=600.0, help="scan timeout in seconds")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="check every rule's schema, metadata and fixture annotations")
    t = sub.add_parser("test", help="run the pack on its fixtures and score every rule")
    t.add_argument("--json", type=Path, help="write the score report here")
    s = sub.add_parser("scan", help="scan code with the pack and summarise the findings")
    s.add_argument("paths", nargs="+", type=Path)
    s.add_argument("--json", type=Path, help="write the findings here")
    s.add_argument("--show", type=int, default=20, help="findings to print (default 20)")
    s.add_argument("--fail-on-findings", action="store_true", help="exit 1 when anything is found")
    return p


def _load(rules: Path) -> Catalog | None:
    """Load the catalog, printing problems instead of a traceback."""
    try:
        return load_catalog(rules)
    except CatalogError as exc:
        for problem in exc.problems:
            print(f"invalid: {problem}", file=sys.stderr)
        return None


def _cmd_test(catalog: Catalog, runner: SemgrepRunner, out: Path | None) -> int:
    """Score every rule on its own fixture."""
    result = runner.scan(catalog.root, [f.fixture for f in catalog.files])
    report = score(catalog, result.findings)
    print(f"{'rule':34} {'mode':6} {'class':23} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  result")
    for s in report.scores:
        verdict = (
            "pass"
            if s.passed
            else f"FAIL missed={list(s.missed_lines)} unexpected={list(s.unexpected_lines)}"
        )
        print(
            f"{s.rule_id:34} {s.mode:6} {s.bug_class:23} {s.true_positives:3} "
            f"{s.false_positives:3} {s.false_negatives:3} {s.true_negatives:3}  {verdict}"
        )
    t = report.totals()
    print(
        f"{t['rules_passed']}/{t['rules']} rules pass: {t['true_positives']} expected findings found, "
        f"{t['false_negatives']} missed, {t['false_positives']} unexpected, "
        f"{t['true_negatives']} ok cases quiet (semgrep {result.version}, {result.seconds:.1f} s)"
    )
    if out is not None:
        payload = report.to_dict()
        payload.update(
            {
                "semgrep": result.version,
                "seconds": round(result.seconds, 2),
                "recorded_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        )
        write_json_atomic(out, payload)
    return 0 if report.passed else 1


def _cmd_scan(catalog: Catalog, runner: SemgrepRunner, args: argparse.Namespace) -> int:
    """Scan user code and summarise findings per rule."""
    missing = [p for p in args.paths if not p.exists()]
    if missing:
        print(f"srp: no such path: {missing[0]}", file=sys.stderr)
        return 2
    result = runner.scan(catalog.root, args.paths, DEFAULT_EXCLUDES)
    per_rule = Counter(f.rule_id for f in result.findings)
    for f in sorted(result.findings, key=lambda f: (str(f.path), f.line))[: max(args.show, 0)]:
        print(f"{f.path}:{f.line}: {f.rule_id}")
    for rule_id, count in sorted(per_rule.items()):
        print(f"{count:5}  {rule_id}")
    files = len({f.path for f in result.findings})
    print(f"{len(result.findings)} findings in {files} files ({result.seconds:.1f} s)")
    if args.json is not None:
        write_json_atomic(
            args.json,
            {
                "recorded_utc": datetime.now(UTC).isoformat(timespec="seconds"),
                "semgrep": result.version,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "path": f.path.as_posix(),
                        "line": f.line,
                        "severity": f.severity,
                    }
                    for f in result.findings
                ],
            },
        )
    return 1 if args.fail_on_findings and result.findings else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    args = _parser().parse_args(argv)
    catalog = _load(args.rules)
    if catalog is None:
        return 1
    if args.command == "validate":
        files = len(catalog.files)
        print(
            f"{len(catalog.rules)} rules in {files} files are valid, each with ruleid and ok cases"
        )
        return 0
    runner = SemgrepRunner(args.semgrep, timeout_s=args.timeout)
    try:
        if args.command == "test":
            return _cmd_test(catalog, runner, args.json)
        return _cmd_scan(catalog, runner, args)
    except (SemgrepError, ScoreError) as exc:
        print(f"srp: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
