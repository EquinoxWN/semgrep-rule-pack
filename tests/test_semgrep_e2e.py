"""End to end with the real semgrep: the pack scores perfectly and taint respects sanitizers."""

from __future__ import annotations

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from semgrep_rule_pack.cli import main
from semgrep_rule_pack.runner import SemgrepRunner, isolated_env

PACK = Path(__file__).resolve().parents[1] / "rules"
SEMGREP = shutil.which("semgrep")
pytestmark = [
    pytest.mark.semgrep,
    pytest.mark.skipif(SEMGREP is None, reason="semgrep is not installed (pip install -e .[dev])"),
]

PY_SOURCES = {
    "flask-args": 'request.args.get("v")',
    "flask-form": 'request.form["v"]',
    "flask-json": 'flask.request.get_json()["v"]',
    "django-get": 'request.GET["v"]',
}
# sink name -> (rule, vulnerable, sanitized, safe API)
PY_SINKS = {
    "execute-fstring": (
        "python-tainted-sql",
        'cur.execute(f"SELECT * FROM t WHERE c = {v}")',
        'cur.execute(f"SELECT * FROM t WHERE c = {int(v)}")',
        'cur.execute("SELECT * FROM t WHERE c = ?", (v,))',
    ),
    "execute-concat": (
        "python-tainted-sql",
        'cur.execute("SELECT * FROM t WHERE c = " + v)',
        'cur.execute("SELECT * FROM t WHERE c = " + str(int(v)))',
        'cur.execute("SELECT * FROM t WHERE c = %s", [v])',
    ),
    "os-system": (
        "python-tainted-shell",
        'os.system("echo " + v)',
        'os.system("echo " + shlex.quote(v))',
        'subprocess.run(["echo", v], check=True)',
    ),
    "run-shell": (
        "python-tainted-shell",
        'subprocess.run(f"echo {v}", shell=True)',
        'subprocess.run(f"echo {shlex.quote(v)}", shell=True)',
        'subprocess.run(["sh", "-c", "echo hello"], check=True)',
    ),
}

GO_SOURCES = {
    "form": 'r.FormValue("v")',
    "query": 'r.URL.Query().Get("v")',
    "path": 'r.PathValue("v")',
}
GO_SINKS = {
    "query": (
        "go-tainted-sql",
        'db.Query("SELECT * FROM t WHERE c = " + v)',
        'db.Query("SELECT * FROM t WHERE c = $1", v)',
    ),
    "shell": (
        "go-tainted-shell",
        'exec.Command("sh", "-c", "echo "+v).Run()',
        'exec.Command("echo", v).Run()',
    ),
}


def _python_matrix(path: Path) -> set[tuple[str, int]]:
    """Write every source x sink x variant as its own handler; return the lines that must fire."""
    lines = [
        "import os",
        "import shlex",
        "import subprocess",
        "import flask",
        "from flask import request",
        "app = flask.Flask(__name__)",
        "cur = None",
        "",
    ]
    expected: set[tuple[str, int]] = set()
    n = 0
    for source in PY_SOURCES.values():
        for rule, vulnerable, sanitized, safe in PY_SINKS.values():
            for code, fires in ((vulnerable, True), (sanitized, False), (safe, False)):
                n += 1
                lines += [
                    f'@app.get("/case{n}")',
                    f"def case{n}():",
                    f"    v = {source}",
                    f"    {code}",
                    "",
                ]
                if fires:
                    expected.add((rule, len(lines) - 1))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return expected


def _go_matrix(path: Path) -> set[tuple[str, int]]:
    """Same matrix for Go handlers."""
    lines = ["package m", "", 'import (\n\t"database/sql"\n\t"net/http"\n\t"os/exec"\n)', ""]
    lines = "\n".join(lines).split("\n")
    expected: set[tuple[str, int]] = set()
    n = 0
    for source in GO_SOURCES.values():
        for rule, vulnerable, safe in GO_SINKS.values():
            for code, fires in ((vulnerable, True), (safe, False)):
                n += 1
                lines += [
                    f"func case{n}(db *sql.DB, w http.ResponseWriter, r *http.Request) {{",
                    f"\tv := {source}",
                    f"\t{code}",
                    "}",
                    "",
                ]
                if fires:
                    expected.add((rule, len(lines) - 2))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return expected


def test_srp_test_scores_every_rule_perfectly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "score.json"
    assert main(["--rules", str(PACK), "test", "--json", str(out)]) == 0
    assert "19/19 rules pass" in capsys.readouterr().out


def test_semgrep_own_test_runner_agrees(tmp_path: Path) -> None:
    assert SEMGREP is not None
    home = tmp_path / "home"
    home.mkdir()
    settings = home / "settings.yml"
    settings.write_text("has_shown_metrics_notification: true\n", encoding="utf-8")
    settings.chmod(stat.S_IREAD)
    proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [SEMGREP, "--test", "--metrics=off", str(PACK)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=isolated_env(home),
        timeout=600,
        check=False,
    )
    settings.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert "19/19" in proc.stdout


@pytest.mark.parametrize(
    ("language", "config", "build"),
    [
        ("python", "python/taint-request-to-sink.yaml", _python_matrix),
        ("go", "go/sql-and-crypto.yaml", _go_matrix),
    ],
)
def test_taint_fires_exactly_when_no_sanitizer_or_safe_api_is_used(
    tmp_path: Path, language: str, config: str, build: object
) -> None:
    target = tmp_path / ("matrix.py" if language == "python" else "matrix.go")
    expected = build(target)  # type: ignore[operator]
    result = SemgrepRunner(timeout_s=600).scan(PACK / config, [target])
    got = {(f.rule_id, f.line) for f in result.findings if "tainted" in f.rule_id}
    assert expected, "the matrix must contain vulnerable cases"
    assert got == expected, f"missed={sorted(expected - got)} unexpected={sorted(got - expected)}"
