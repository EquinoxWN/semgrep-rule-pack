"""The srp command line, with a fake semgrep so no real scan runs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from conftest import write_pack

from semgrep_rule_pack.cli import main, split_command, write_json_atomic

PACK = Path(__file__).resolve().parents[1] / "rules"
FAKE = f'"{sys.executable}" "{Path(__file__).with_name("fake_semgrep.py")}"'


def test_validate_the_shipped_pack(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--rules", str(PACK), "validate"]) == 0
    assert "19 rules in 7 files are valid" in capsys.readouterr().out


def test_validate_reports_every_problem_and_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = write_pack(tmp_path)
    (root / "python" / "demo.py").write_text("# ok: python-demo-rule\nx()\n", encoding="utf-8")
    assert main(["--rules", str(root), "validate"]) == 1
    assert "invalid:" in capsys.readouterr().err


def test_test_command_scores_and_writes_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", "ok")
    root = write_pack(tmp_path / "pack")
    out = tmp_path / "out" / "score.json"
    assert main(["--rules", str(root), "--semgrep", FAKE, "test", "--json", str(out)]) == 0
    assert "1/1 rules pass" in capsys.readouterr().out
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["recorded_utc"].endswith("+00:00")
    assert not list(out.parent.glob("*.tmp"))


def test_test_command_fails_when_a_rule_misses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", "ok")
    fixture = "# ok: python-demo-rule\nx()\n# ruleid: python-demo-rule\neval(a)\n# ruleid: python-demo-rule\neval(b)\n"
    root = write_pack(tmp_path, fixture=fixture)
    assert main(["--rules", str(root), "--semgrep", FAKE, "test"]) == 1
    assert "FAIL missed=[6]" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["errors", "crash", "garbage"])
def test_semgrep_failures_exit_1_with_a_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", mode)
    assert main(["--rules", str(write_pack(tmp_path)), "--semgrep", FAKE, "test"]) == 1
    assert capsys.readouterr().err.startswith("srp: ")


def test_scan_summarises_and_can_fail_on_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FAKE_SEMGREP", "ok")
    root = write_pack(tmp_path / "pack")
    code = tmp_path / "app.py"
    code.write_text("eval(x)\n", encoding="utf-8")
    out = tmp_path / "findings.json"
    args = ["--rules", str(root), "--semgrep", FAKE, "scan", str(code), "--json", str(out)]
    assert main(args) == 0
    assert "1 findings in 1 files" in capsys.readouterr().out
    assert (
        json.loads(out.read_text(encoding="utf-8"))["findings"][0]["rule_id"] == "python-demo-rule"
    )
    assert main([*args, "--fail-on-findings"]) == 1


def test_scan_rejects_a_missing_path(tmp_path: Path) -> None:
    assert main(["--rules", str(write_pack(tmp_path)), "scan", str(tmp_path / "nope")]) == 2


@pytest.mark.parametrize(
    "args", [["--timeout", "0", "validate"], ["--semgrep", "", "validate"], []]
)
def test_bad_arguments_exit_2(args: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(args)
    assert info.value.code == 2


def test_split_command_keeps_windows_paths() -> None:
    assert split_command(r'"C:\Program Files\py.exe" -m semgrep') == [
        r"C:\Program Files\py.exe",
        "-m",
        "semgrep",
    ]


def test_write_json_atomic_replaces_whole_file(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    write_json_atomic(target, {"a": 1})
    write_json_atomic(target, {"b": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"b": 2}
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]
