# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/semgrep-rule-pack/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** A rule that misses the bug class it claims to cover (a false negative you can show with a short example), a harness bug that hides semgrep errors or mis-scores a rule, and unsafe handling of the files the harness reads.
- **Out of scope:** Vulnerabilities in Semgrep itself (report those upstream). The fixture files under `rules/` contain deliberately vulnerable code; they are test inputs and are never run.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, tests and a known-vulnerability check (pip-audit) on every push and pull request.
