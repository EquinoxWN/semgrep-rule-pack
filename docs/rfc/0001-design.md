# RFC 0001: semgrep-rule-pack design

- **Status:** Accepted (M1 built)
- **Author:** EquinoxWN
- **Created:** 2026-11-09

## Problem (Define)

The other repositories in this portfolio build SQL text with f-strings and `fmt.Sprintf`, load YAML
and model checkpoints, and hash data with SHA-1. A reviewer catches such a line once, in one repo;
the same mistake then reappears elsewhere. A rule pack turns each bug class into a check that runs
on every repo, but only if each rule is shown to fire on the bug, to stay quiet on the safe
alternative, and to follow request input only until it passes a sanitizer. Rules without tests
drift: a rule that fails to parse is reported by Semgrep as an error while the scan still exits 0.

**Users:** developers and reviewers of Python, Go, Java and TypeScript services who want the same
security checks across all their repositories.

**Critical-to-quality measures and targets**

| CTQ | Target | Measured by |
|---|---|---|
| Every rule fires on each annotated vulnerable line (recall on fixtures) | 100% | `srp test` |
| No rule fires on a line not annotated `ruleid` (precision on fixtures) | 100% | `srp test` |
| Taint rules fire exactly when no sanitizer or safe API sits between source and sink | 0 mismatches over the generated matrix | `test_semgrep_e2e.py` |
| Every rule carries CWE, OWASP, confidence, safe pattern, references, `ruleid` and `ok` cases | 100% of rules | `srp validate` |
| Semgrep errors never pass silently | any error fails the run | `runner.parse_output` tests |

## Goals (M1)

- Rules for the bug classes found in the other repos: SQL string building, unsafe deserialization
  (pickle, YAML, `torch.load(weights_only=False)`, Java `ObjectInputStream`), weak crypto (MD5,
  SHA-1, DES, RC4, ECB, predictable random tokens), in Python, Go, Java and TypeScript.
- Taint rules that follow request input (Flask, Django, FastAPI parameters, Go `*http.Request`,
  Express `req.*`) to SQL text and shell commands, unless it passes a sanitizer (`int()`,
  `shlex.quote()`, `strconv.Atoi`, `Number()` ...) or goes through the safe API (bound parameters,
  argument lists).
- A harness (`srp`) that validates the pack, scores each rule against its annotated fixture, and
  scans code with the pack.

## Non-goals

- SARIF upload to GitHub code scanning and a per-rule completeness gate in CI (M2).
- Cross-file or cross-function taint (needs Semgrep Pro); M1 rules are intraprocedural, as in
  Semgrep OSS.
- A hosted service, autofix, or rules for languages the portfolio does not use.

## Design

```
rules/<language>/<topic>.yaml      rules (search mode and taint mode)
rules/<language>/<topic>.<ext>     fixture: annotated vulnerable and safe code, never run
src/semgrep_rule_pack/
  annotations.py   parse `ruleid:` / `ok:` comments (semgrep --test convention)
  catalog.py       load YAML safely, check schema, metadata and fixture coverage
  runner.py        semgrep subprocess: timeout, isolated home, metrics off, strict JSON
  score.py         per-rule TP / FP / FN / TN on the rule's own fixture
  cli.py           srp validate | test | scan
```

- **Two tiers per bug class.** Search-mode rules (`*-sql-string-building`, confidence MEDIUM)
  flag every SQL text built by formatting, whatever the source: broad, meant for audits. Taint
  rules (`*-tainted-sql`, `*-tainted-shell`, confidence HIGH) flag only request input that reaches
  the SQL text or shell command unsanitized: precise, meant to block a merge. See ADR 0002.
- **Sinks are the dangerous argument only.** Taint sinks use `focus-metavariable` on the SQL text
  or the shell string, so values passed as bound parameters or list arguments are not sinks.
- **Fixtures follow `semgrep --test`.** `srp test` is stricter than `semgrep --test`: it also
  rejects stacked or malformed annotations, requires at least one `ok:` case per rule, and counts
  true negatives.
- **Strict runner.** Semgrep reports a rule parse error in its JSON `errors` while exiting 0;
  `runner.parse_output` raises on any error. The runner gives Semgrep a temporary home with a
  read-only settings file (Semgrep's own rewrite of that file races with its reads on Windows) and
  passes `--metrics=off --disable-version-check`, so a scan makes no network calls.

## Alternatives considered

| Option | Why not |
|---|---|
| Use the Semgrep Registry packs (`p/python`, `p/owasp-top-ten`) as they are | Hundreds of rules, many outside these bug classes; their findings on this portfolio would need triage anyway, and a registry pull needs network and changes over time. M1 keeps a small, pinned, tested pack; registry rules remain a source of ideas (upstream contribution is M3). |
| CodeQL queries | Stronger interprocedural taint, but needs a database build per language (Java and Go need a compiling build), is far slower per run, and its licence limits use on non-open-source code. Semgrep runs on source text in seconds and its rules read like the code they match. |
| Bandit, gosec and eslint-plugin-security, one per language | Mature, but each has its own config, suppression and output format, none has taint mode across request input to sinks, and custom checks need plugin code. One Semgrep pack covers all four languages with one test convention. |
| Rely on `semgrep --test` alone, no harness | It does not fail a rule that has no `ok:` case, does not count true negatives, and the scan path hides rule parse errors behind exit code 0. The harness adds these checks in about 400 lines. |

## Measurement plan (Measure)

- `srp test`: per-rule TP, FP, FN, TN on the fixtures; target 100% precision and recall.
- `tests/test_semgrep_e2e.py`: a generated matrix (Python 4 sources x 4 sinks x 3 variants, Go
  3 x 2 x 2) where each vulnerable variant must fire and each sanitized or safe-API variant must
  not.
- Hand mutations of the harness and of the taint rules (`docs/quality/2026-11-01.md`): each must
  make a test fail.
- A read-only scan of portfolio repositories with `srp scan`, findings triaged in
  `docs/results/m1.md`.

## Milestones

- **M1:** Rules for SQL string building, unsafe deserialization and weak crypto; taint mode from
  request input to queries and shell commands unless sanitized; the `srp` harness.
- **M2:** Each rule ships `ruleid:` / `ok:` test files as a CI gate (in place since M1), and CI
  uploads SARIF to GitHub code scanning.
- **M3:** False-positive reports feed rule refinements; docs per vulnerability; rules that caught
  real bugs in earlier code, with commit links.

## Risks and open questions

- Taint is intraprocedural in Semgrep OSS: input passed through a helper function in another file
  is not followed. Pattern rules partly compensate.
- Name-based matching: the TypeScript SQL sink requires the receiver to be named like a database
  handle (`db`, `pool`, `client` ...), and Go's pgx detection relies on a context-like first
  argument (`ctx`, `r.Context()`). Other names are missed.
- Pattern rules cannot tell an internal identifier from user data; the portfolio scan shows the
  resulting noise (see results).
