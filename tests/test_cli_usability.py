import io
from pathlib import Path

import pytest
from conftest import Writer

from sigma_blindspot import cli
from sigma_blindspot.console import ColorMode, color_enabled, paint, paint_counts
from sigma_blindspot.runner import (
    DEFAULT_JOBS,
    RULES_PER_WORKER,
    auto_jobs,
    default_jobs,
    prove_all,
)
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sigma.loader import load_rules
from sigma_blindspot.sysmon.parser import load_config

type Capture = pytest.CaptureFixture[str]

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = FIXTURES / "sysmon.xml"
RULES = FIXTURES / "rules"
BLIND = "\x1b[1;31mBLIND\x1b[0m"
VERDICTS = ("BLIND", "MISSED", "PARTIAL", "RULE_UNSAT", "UNKNOWN", "OK", "SKIPPED")
EMPTY = tuple(verdict for verdict in VERDICTS if verdict != "MISSED")


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def run(capsys: Capture, *arguments: str) -> tuple[int, str, str]:
    code = cli.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def failing(capsys: Capture, *arguments: str) -> str:
    with pytest.raises(SystemExit) as stopped:
        cli.main(arguments)
    assert stopped.value.code == cli.EXIT_ERROR
    return capsys.readouterr().err


@pytest.mark.parametrize("command", ["doctor", "inspect", "check-event", "analyze"])
def test_every_command_has_a_description_and_powershell_examples(
    capsys: Capture, command: str
) -> None:
    code, out, _ = run(capsys, "help", command)
    assert code == cli.EXIT_OK
    assert out.startswith(f"usage: sigma-blindspot {command}")
    assert "Example" in out and "(PowerShell)" in out and "Exit codes" in out
    assert f"sigma-blindspot {command}" in out.split("(PowerShell)", 1)[1]


@pytest.mark.parametrize("columns", ["60", "200"])
def test_help_without_a_command_shows_the_overview(
    capsys: Capture, monkeypatch: pytest.MonkeyPatch, columns: str
) -> None:
    monkeypatch.setenv("COLUMNS", columns)
    code, out, _ = run(capsys, "help")
    assert code == cli.EXIT_OK
    assert "Getting started (PowerShell):" in out and "help COMMAND" in out
    commands = out.split("commands:\n", 1)[1].split("\n\n", 1)[0].splitlines()
    named = [line for line in commands if line[2] != " "]
    assert [line.split()[0] for line in named] == [
        "doctor",
        "inspect",
        "check-event",
        "analyze",
        "help",
    ]
    assert all(line.startswith("  ") for line in commands)


def test_analyze_help_explains_every_verdict_and_exit_code(capsys: Capture) -> None:
    _, out, _ = run(capsys, "help", "analyze")
    verdicts = out.split("Verdicts:", 1)[1]
    assert all(f"\n  {verdict} " in verdicts for verdict in VERDICTS)
    assert "--fail-on-blind and at least one rule is BLIND, MISSED or PARTIAL" in out
    assert all(group in out for group in ("inputs:", "output:", "performance:"))


def test_usage_errors_point_to_the_help(capsys: Capture) -> None:
    err = failing(capsys, "analyze", str(CONFIG))
    assert "error: the following arguments are required: RULES" in err
    assert err.endswith("hint: run 'sigma-blindspot analyze --help' for the options and examples\n")


def test_a_folder_given_as_the_config_is_explained(capsys: Capture) -> None:
    code, _, err = run(capsys, "analyze", str(RULES), str(CONFIG))
    assert code == cli.EXIT_ERROR
    assert err == (
        f"error: {RULES}: this is a folder, a file is expected\n"
        "hint: run 'sigma-blindspot analyze --help' for the expected arguments and examples\n"
    )


def test_a_config_that_is_not_xml_is_explained(capsys: Capture) -> None:
    code, _, err = run(capsys, "inspect", str(RULES / "linux_shell.yml"))
    assert code == cli.EXIT_ERROR
    assert err.endswith(
        "hint: CONFIG must be a Sysmon XML configuration, such as sysmonconfig.xml\n"
    )


def test_a_folder_without_rules_gives_a_warning(capsys: Capture, tmp_path: Path) -> None:
    code, out, err = run(capsys, "analyze", str(CONFIG), str(tmp_path))
    assert (code, out) == (cli.EXIT_OK, f"0 rules: {', '.join(f'0 {v}' for v in EMPTY)}\n")
    assert err == f"warning: no Sigma rule file (*.yml) in {tmp_path}\n"


def test_colors_are_off_when_the_output_is_not_a_terminal(capsys: Capture) -> None:
    _, out, _ = run(capsys, "analyze", str(CONFIG), str(RULES))
    assert "\x1b" not in out


def test_color_always_paints_verdicts_and_counts_only(capsys: Capture, write: Writer) -> None:
    rule = write(
        "rule.yml",
        (RULES / "process_ccmexec_child.yml")
        .read_text(encoding="utf-8")
        .replace("Child process of the SCCM client", '"\\e[32mBLIND"'),
    )
    _, out, _ = run(capsys, "analyze", str(CONFIG), str(rule), "--color", "always")
    first, summary = out.splitlines()
    assert first.startswith(f"{BLIND} {rule} ")
    assert '"\\u001b[32mBLIND"' in first and first.count("\x1b") == 2
    assert summary == (f"1 rule: 1 {BLIND}, 0 PARTIAL, 0 RULE_UNSAT, 0 UNKNOWN, 0 OK, 0 SKIPPED")


def test_color_never_wins_over_a_terminal(capsys: Capture) -> None:
    _, out, _ = run(capsys, "analyze", str(CONFIG), str(RULES), "--color", "never")
    assert "\x1b" not in out


def test_check_event_paints_the_decision(capsys: Capture, write: Writer) -> None:
    events = write("events.jsonl", '{"EventID": 1, "Image": "C:\\\\x.exe"}\n')
    _, out, _ = run(capsys, "check-event", str(CONFIG), str(events), "--color", "always")
    assert out.splitlines() == [
        f"{events}:1: EventID 1 \x1b[32mLOGGED\x1b[0m matched no exclude filter",
        "1 event: 1 \x1b[32mlogged\x1b[0m, 0 dropped, 0 unknown",
    ]


@pytest.mark.parametrize(
    ("mode", "terminal", "environ", "expected"),
    [
        pytest.param(ColorMode.AUTO, True, {}, True, id="auto-terminal"),
        pytest.param(ColorMode.AUTO, False, {}, False, id="auto-redirected"),
        pytest.param(ColorMode.AUTO, True, {"NO_COLOR": "1"}, False, id="no-color"),
        pytest.param(ColorMode.AUTO, True, {"TERM": "dumb"}, False, id="dumb-terminal"),
        pytest.param(ColorMode.ALWAYS, False, {"NO_COLOR": "1"}, True, id="always"),
        pytest.param(ColorMode.NEVER, True, {}, False, id="never"),
    ],
)
def test_color_decision(
    mode: ColorMode, terminal: bool, environ: dict[str, str], expected: bool
) -> None:
    stream = Terminal() if terminal else io.StringIO()
    assert color_enabled(mode, stream, environ, lambda _: True) is expected


def test_a_console_without_colors_falls_back_to_plain_text() -> None:
    assert color_enabled(ColorMode.AUTO, Terminal(), {}, lambda _: False) is False


def test_only_known_words_and_non_zero_counts_are_painted() -> None:
    assert paint("BLIND", False) == "BLIND"
    assert paint("rules", True) == "rules"
    assert paint_counts("3 rules: 0 BLIND, 2 OK", True) == "3 rules: 0 BLIND, 2 \x1b[32mOK\x1b[0m"


def test_only_lists_the_chosen_verdicts_and_keeps_the_full_summary(capsys: Capture) -> None:
    _, everything, _ = run(capsys, "analyze", str(CONFIG), str(RULES))
    _, out, _ = run(capsys, "analyze", str(CONFIG), str(RULES), "--only", "partial, ok")
    lines = out.splitlines()
    assert [line.split(" ", 1)[0] for line in lines[:-1]] == ["PARTIAL", "OK"]
    assert lines[-1] == everything.splitlines()[-1]


def test_only_rejects_unknown_verdicts(capsys: Capture) -> None:
    err = failing(capsys, "analyze", str(CONFIG), str(RULES), "--only", "BLIND,NOPE")
    assert "unknown verdict NOPE; choose among BLIND, MISSED, PARTIAL" in err


def test_only_needs_the_text_format(capsys: Capture) -> None:
    err = failing(capsys, "analyze", str(CONFIG), str(RULES), "--only", "BLIND", "--format", "json")
    assert "error: --only works with --format text" in err


def test_only_missed_without_samples_gives_a_warning(capsys: Capture) -> None:
    _, _, err = run(capsys, "analyze", str(CONFIG), str(RULES), "--only", "MISSED")
    assert err == "warning: MISSED needs --samples DIR; without it no rule is MISSED\n"


@pytest.mark.parametrize("output", ["text", "markdown"])
def test_output_writes_what_the_terminal_would_show(
    capsys: Capture, tmp_path: Path, output: str
) -> None:
    target = tmp_path / "report.txt"
    _, shown, _ = run(capsys, "analyze", str(CONFIG), str(RULES), "--format", output)
    code, out, _ = run(
        capsys, "analyze", str(CONFIG), str(RULES), "--format", output, "--output", str(target)
    )
    assert code == cli.EXIT_OK
    assert target.read_bytes().decode("utf-8") == shown
    assert out.splitlines() == [
        "10 rules: 5 BLIND, 1 PARTIAL, 1 RULE_UNSAT, 1 UNKNOWN, 1 OK, 1 SKIPPED",
        f"report written to {target}",
    ]


def test_output_never_overwrites_an_input(capsys: Capture) -> None:
    before = CONFIG.read_bytes()
    code, _, err = run(capsys, "analyze", str(CONFIG), str(RULES), "--output", str(CONFIG))
    assert code == cli.EXIT_ERROR
    assert err.startswith(f"error: {CONFIG}: refusing to overwrite an input file")
    assert CONFIG.read_bytes() == before


def test_progress_is_shown_on_a_terminal_and_cleared(
    capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminal = Terminal()
    monkeypatch.setattr("sys.stderr", terminal)
    code = cli.main(["analyze", str(CONFIG), str(RULES)])
    shown = terminal.getvalue()
    assert code == cli.EXIT_OK
    assert "\rproving rules 9/9" in shown
    assert shown.endswith("\r" + " " * len("proving rules 9/9") + "\r")
    assert "proving" not in capsys.readouterr().out


def test_no_progress_when_stderr_is_not_a_terminal(capsys: Capture) -> None:
    _, _, err = run(capsys, "analyze", str(CONFIG), str(RULES))
    assert err == ""


@pytest.mark.parametrize(
    ("rules", "processors", "expected"),
    [
        pytest.param(9, 8, 1, id="few-rules"),
        pytest.param(2 * RULES_PER_WORKER, 8, 2, id="two-workers"),
        pytest.param(2420, 8, 8, id="capped-by-processors"),
        pytest.param(2420, None, 1, id="unknown-processors"),
    ],
)
def test_auto_jobs(rules: int, processors: int | None, expected: int) -> None:
    assert auto_jobs(rules, processors) == expected


def test_the_default_uses_few_workers() -> None:
    assert default_jobs(2420, 12) == DEFAULT_JOBS == 2
    assert default_jobs(2 * RULES_PER_WORKER - 1, 12) == 1
    assert default_jobs(2420, 1) == 1


def test_jobs_accepts_auto_and_rejects_words(capsys: Capture) -> None:
    code, _, _ = run(capsys, "analyze", str(CONFIG), str(RULES), "--jobs", "auto")
    assert code == cli.EXIT_OK
    err = failing(capsys, "analyze", str(CONFIG), str(RULES), "--jobs", "many")
    assert "argument --jobs: expected a whole number, got 'many', or auto" in err


@pytest.mark.parametrize("jobs", [1, 2])
def test_prove_all_reports_progress_for_every_rule(jobs: int) -> None:
    config = load_config(CONFIG)
    rules = [item for item in load_rules([RULES]) if isinstance(item, LoadedRule)]
    seen: list[int] = []
    proofs = prove_all(config, CONFIG.read_bytes(), rules, 2000, jobs, progress=seen.append)
    assert seen == list(range(1, len(rules) + 1)) and len(proofs) == len(rules)
