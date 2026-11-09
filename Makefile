.PHONY: setup lint test rules-test bench audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict on the harness (rules/ holds fixtures, not project code).
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Harness unit tests plus the end-to-end tests that run the real semgrep.
test:
	$(PY) -m pytest -q -rs

# Validate the pack, then score every rule on its annotated fixture; semgrep's own runner agrees.
rules-test:
	srp validate && srp test --json .tmp/score.json && semgrep --test --metrics=off rules

# The per-rule score table with timing (README "Tests and results").
bench: rules-test

# Known vulnerabilities in the installed Python dependencies. The ignored advisories are in
# mcp 1.29.0 and opentelemetry-api 1.37.0, which semgrep 1.184.0 (the latest release) pins exactly;
# see docs/results/m1.md. Remove an ignore as soon as a semgrep release lifts the pin.
AUDIT_IGNORE = --ignore-vuln CVE-2026-59951 --ignore-vuln CVE-2026-116685 --ignore-vuln CVE-2026-116684 --ignore-vuln CVE-2026-116686 --ignore-vuln CVE-2026-114603
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit $(AUDIT_IGNORE)

ci: setup lint test rules-test audit
