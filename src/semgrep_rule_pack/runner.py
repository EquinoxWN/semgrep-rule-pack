"""Run semgrep as a subprocess with a timeout, an isolated home folder and strict JSON parsing."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_OUTPUT_BYTES = 256_000_000
DEFAULT_TIMEOUT_S = 600.0
# Read-only so semgrep never rewrites it: on Windows its rewrite races with its own reads.
_SETTINGS = "has_shown_metrics_notification: true\n"


class SemgrepError(RuntimeError):
    """Semgrep failed, timed out, reported errors or produced unreadable output."""


@dataclass(frozen=True)
class Finding:
    """One semgrep result: rule id (without the config path prefix), file and lines."""

    rule_id: str
    path: Path
    line: int
    end_line: int
    severity: str
    message: str


@dataclass(frozen=True)
class ScanResult:
    """Findings plus the semgrep version and wall time (monotonic clock)."""

    findings: tuple[Finding, ...]
    version: str
    seconds: float


def short_id(check_id: str) -> str:
    """Semgrep prefixes rule ids with the config path in dots; keep the last part."""
    return check_id.rsplit(".", 1)[-1]


def parse_output(raw: str) -> tuple[list[Finding], str]:
    """Strictly parse `semgrep --json` output; any reported error raises."""
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"semgrep output is not JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        raise SemgrepError("semgrep output has no results list")
    errors = doc.get("errors")
    if not isinstance(errors, list):
        raise SemgrepError("semgrep output has no errors list")
    if errors:
        # A rule that fails to parse is reported here while the exit code stays 0.
        first = errors[0]
        detail = first.get("message", first) if isinstance(first, dict) else first
        raise SemgrepError(f"semgrep reported {len(errors)} error(s); first: {detail}")
    findings = [_finding(item) for item in doc["results"]]
    version = doc.get("version")
    return findings, version if isinstance(version, str) else "unknown"


def _finding(item: Any) -> Finding:
    """One result entry as a Finding."""
    try:
        extra = item["extra"]
        return Finding(
            rule_id=short_id(str(item["check_id"])),
            path=Path(str(item["path"])),
            line=int(item["start"]["line"]),
            end_line=int(item["end"]["line"]),
            severity=str(extra.get("severity", "")),
            message=str(extra.get("message", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SemgrepError(f"malformed semgrep result: {exc}") from exc


def isolated_env(home: Path) -> dict[str, str]:
    """Environment that keeps semgrep's settings and logs in `home` and turns off metrics."""
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "SEMGREP_SETTINGS_FILE": str(home / "settings.yml"),
            "SEMGREP_LOG_FILE": str(home / "semgrep.log"),
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "SEMGREP_SEND_METRICS": "off",
        }
    )
    return env


class SemgrepRunner:
    """Runs one semgrep scan per call; no retries, because a local scan is deterministic."""

    def __init__(
        self,
        command: Sequence[str] = ("semgrep",),
        timeout_s: float = DEFAULT_TIMEOUT_S,
        jobs: int = 2,
    ) -> None:
        """Command prefix, overall timeout in seconds and parallel jobs."""
        if not command:
            raise ValueError("command must not be empty")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if jobs < 1:
            raise ValueError("jobs must be at least 1")
        self.command = list(command)
        self.timeout_s = timeout_s
        self.jobs = jobs

    def scan(
        self, config: Path, targets: Sequence[Path], excludes: Sequence[str] = ()
    ) -> ScanResult:
        """Scan `targets` with the rules in `config`."""
        if not targets:
            raise ValueError("no targets to scan")
        args = [
            *self.command,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            f"--jobs={self.jobs}",
            "--config",
            str(config),
        ]
        for pattern in excludes:
            args += ["--exclude", pattern]
        args += [str(t) for t in targets]
        with tempfile.TemporaryDirectory(prefix="srp-home-") as tmp:
            home = Path(tmp)
            settings = home / "settings.yml"
            settings.write_text(_SETTINGS, encoding="utf-8")
            settings.chmod(stat.S_IREAD)
            try:
                return self._run(args, isolated_env(home))
            finally:
                settings.chmod(stat.S_IREAD | stat.S_IWRITE)

    def _run(self, args: list[str], env: dict[str, str]) -> ScanResult:
        """Execute semgrep and parse its JSON output."""
        start = time.monotonic()
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SemgrepError(f"semgrep timed out after {self.timeout_s:.0f} s") from exc
        except OSError as exc:
            raise SemgrepError(f"cannot start semgrep ({args[0]}): {exc}") from exc
        seconds = time.monotonic() - start
        if len(proc.stdout) > MAX_OUTPUT_BYTES:
            raise SemgrepError(f"semgrep output exceeds {MAX_OUTPUT_BYTES} bytes")
        # 0: no blocking findings, 1: findings with --error; anything else is a failure.
        if proc.returncode not in (0, 1):
            tail = proc.stderr.strip().splitlines()[-5:]
            raise SemgrepError(f"semgrep exited {proc.returncode}: {' | '.join(tail)}")
        findings, version = parse_output(proc.stdout)
        return ScanResult(tuple(findings), version, seconds)
