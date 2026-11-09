"""The semgrep subprocess wrapper: isolation, timeouts and strict output parsing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from semgrep_rule_pack.runner import SemgrepError, SemgrepRunner, parse_output, short_id

FAKE = [sys.executable, str(Path(__file__).with_name("fake_semgrep.py"))]


def test_short_id_drops_the_config_path_prefix() -> None:
    assert short_id("rules.python.python-tainted-sql") == "python-tainted-sql"
    assert short_id("go-weak-crypto") == "go-weak-crypto"


def test_parse_output_reads_findings() -> None:
    raw = json.dumps(
        {
            "version": "1.0",
            "errors": [],
            "results": [
                {
                    "check_id": "a.b.go-x",
                    "path": "f.go",
                    "start": {"line": 3},
                    "end": {"line": 5},
                    "extra": {"severity": "ERROR", "message": "m"},
                }
            ],
        }
    )
    findings, version = parse_output(raw)
    assert version == "1.0"
    assert [(f.rule_id, f.path.name, f.line, f.end_line) for f in findings] == [
        ("go-x", "f.go", 3, 5)
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "not JSON"),
        ("[]", "no results list"),
        ('{"results": []}', "no errors list"),
        ('{"results": [], "errors": [{"message": "Rule parse error"}]}', "1 error"),
        ('{"results": [{"check_id": "x"}], "errors": []}', "malformed semgrep result"),
        (
            '{"results": [{"check_id": "x", "path": "p", "start": {"line": "a"}, "end": {"line": 1}, "extra": {}}], "errors": []}',
            "malformed",
        ),
    ],
)
def test_parse_output_rejects_bad_or_failing_output(raw: str, expected: str) -> None:
    with pytest.raises(SemgrepError, match=expected):
        parse_output(raw)


def test_scan_isolates_home_and_turns_off_metrics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", "env")
    result = SemgrepRunner(FAKE, timeout_s=60).scan(
        tmp_path, [tmp_path / "x.py"], excludes=[".venv"]
    )
    seen = json.loads(result.version)
    assert seen["SEMGREP_SEND_METRICS"] == "off"
    assert seen["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert Path(seen["HOME"]).name.startswith("srp-home-")
    assert Path(seen["SEMGREP_SETTINGS_FILE"]).parent == Path(seen["HOME"])
    assert not Path(seen["HOME"]).exists(), "the temporary home must be removed after the scan"
    argv = seen["argv"]
    assert "--metrics=off" in argv
    assert "--disable-version-check" in argv
    assert argv[argv.index("--exclude") + 1] == ".venv"
    assert result.seconds >= 0


def test_exit_code_one_with_findings_is_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", "ok")
    result = SemgrepRunner(FAKE, timeout_s=60).scan(tmp_path, [tmp_path / "x.py"])
    assert [f.rule_id for f in result.findings] == ["python-demo-rule"]


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("crash", "exited 2: boom"), ("garbage", "not JSON"), ("errors", "Rule parse error")],
)
def test_failures_raise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, expected: str
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", mode)
    with pytest.raises(SemgrepError, match=expected):
        SemgrepRunner(FAKE, timeout_s=60).scan(tmp_path, [tmp_path])


def test_timeout_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", "sleep")
    with pytest.raises(SemgrepError, match="timed out"):
        SemgrepRunner(FAKE, timeout_s=1).scan(tmp_path, [tmp_path])


def test_missing_executable_raises(tmp_path: Path) -> None:
    with pytest.raises(SemgrepError, match="cannot start"):
        SemgrepRunner([str(tmp_path / "no-such-semgrep")]).scan(tmp_path, [tmp_path])


@pytest.mark.parametrize("kwargs", [{"command": []}, {"timeout_s": 0}, {"jobs": 0}])
def test_invalid_runner_settings(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="must"):
        SemgrepRunner(**kwargs)  # type: ignore[arg-type]


def test_scan_needs_targets(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no targets"):
        SemgrepRunner(FAKE).scan(tmp_path, [])
