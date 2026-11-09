# ADR 0002: Ship a broad pattern rule and a precise taint rule for each injection class

- **Status:** Accepted

## Context

SQL injection can be checked two ways in Semgrep OSS. A pattern rule flags every query whose text
is built with formatting (`cur.execute(f"... {x}")`, `db.Query(fmt.Sprintf(...))`). A taint rule
flags only request input that reaches the query text without a sanitizer. On this portfolio the
pattern rule reports 23 SQL-building sites in five repositories (see `docs/results/m1.md`), and
none of them carries request input: they splice table names from code or config, often through a
quoting helper. A merge-blocking check with that noise would be switched off. A taint-only pack
would miss the same bug when the input arrives through a helper in another function, which
Semgrep OSS taint does not follow.

## Decision

Keep both tiers and mark them:

- `*-sql-string-building`: search mode, severity WARNING, confidence MEDIUM. For audits and
  review: every site is worth a look, and the message names the safe pattern.
- `*-tainted-sql`, `*-tainted-shell`: taint mode, severity ERROR, confidence HIGH. Sources are
  request objects; sinks are only the SQL text or shell string (`focus-metavariable`); sanitizers
  are conversions to numbers and shell quoting. Fit to block a pull request.

A fixture line where the pattern rule fires and the taint rule does not (a parsed integer in a
`Sprintf`) documents the difference and is tested.

## Consequences

- Users choose the tier by confidence (`--severity ERROR` or a filter on metadata).
- The same line can be reported twice; the fixtures annotate both rules where that happens.
- Every taint rule must list sanitizers (`srp validate` fails otherwise), so the claim "unless it
  passes a sanitizer" is enforced for every taint rule added later.
- Two rules per class means two places to update when a new database API appears; the generated
  matrix test covers the taint side.
