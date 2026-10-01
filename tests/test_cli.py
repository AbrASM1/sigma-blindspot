import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest
from conftest import DOC_SAMPLE, Writer, line_of
from hypothesis import HealthCheck, given, settings
from strategies import encode, encodings, render, xml_documents

from sigma_blindspot import cli, doctor
from sigma_blindspot.doctor import Check, check_distribution
from sigma_blindspot.sysmon.model import EventFilter

type Capture = pytest.CaptureFixture[str]

EVENTS = """\
{"EventID": 6, "Signature": "Microsoft Windows"}
{"EventID": 3, "DestinationPort": "443", "Image": "C:\\\\chrome.exe"}

{"EventID": 5, "Image": "C:\\\\x.exe"}
{"EventID": 1, "Image": "C:\\\\x.exe"}
"""


def printable(output: str) -> bool:
    return all(" " <= character <= "~" for line in output.splitlines() for character in line)


def run(capsys: Capture, *arguments: str) -> tuple[int, str, str]:
    code = cli.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_doctor_reports_working_dependencies(capsys: Capture) -> None:
    code, out, err = run(capsys, "doctor")
    lines = out.splitlines()
    assert (code, err) == (cli.EXIT_OK, "")
    assert lines[0] == f"sigma-blindspot {metadata.version('sigma-blindspot')}"
    assert lines[1].startswith("python 3.") and lines[1].endswith(": OK")
    assert lines[2] == f"pysigma {metadata.version('pysigma')}: OK"
    assert lines[3] == "z3-solver 5.1.0.0: OK"


def test_doctor_fails_when_a_check_fails(capsys: Capture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "run_checks", lambda: (Check("z3-solver", None, "not installed"),))
    code, out, _ = run(capsys, "doctor")
    assert code == cli.EXIT_FAILURE
    assert out.splitlines()[1] == "z3-solver missing: FAIL (not installed)"


def test_check_distribution_reports_missing_and_broken_packages() -> None:
    def broken() -> None:
        raise RuntimeError("cannot load libz3")

    assert check_distribution("no-such-distribution", broken) == Check(
        "no-such-distribution", None, "not installed"
    )
    assert check_distribution("pysigma", broken) == Check(
        "pysigma", metadata.version("pysigma"), "RuntimeError: cannot load libz3"
    )


def test_inspect_lists_filters_with_their_lines(capsys: Capture, write: Writer) -> None:
    path = write("sysmon.xml", DOC_SAMPLE)
    code, out, err = run(capsys, "inspect", str(path))
    lines = out.splitlines()

    def at(needle: str) -> str:
        return f"{path}:{line_of(DOC_SAMPLE, needle)}:"

    assert (code, err) == (cli.EXIT_OK, "")
    assert lines[0] == f"{path}: schema 4.82, 4 filters"
    assert lines[1:4] == [
        f'{at("<DriverLoad")} DriverLoad onmatch="exclude"',
        f'{at(">microsoft<")}   Signature condition="contains" value="microsoft"',
        f'{at(">windows<")}   Signature condition="contains" value="windows"',
    ]
    assert f'{at("<ProcessTerminate")} ProcessTerminate onmatch="include"' in lines
    assert f'{at(">443<")}   DestinationPort condition="is" value="443"' in lines
    assert f"{path}: no filter for ImageLoad (7), dropped by assumed default" in lines
    assert f"{path}: no filter for RegistryEvent (12, 13, 14), logged by assumed default" in lines
    assert not any("no filter for NetworkConnect" in line for line in lines)


def test_inspect_shows_rules_and_group_relations(capsys: Capture, write: Writer) -> None:
    text = "\n".join(
        [
            '<Sysmon schemaversion="4.90">',
            "  <EventFiltering>",
            '    <RuleGroup name="" groupRelation="or">',
            '      <ProcessCreate onmatch="include">',
            '        <Rule name="T1059" groupRelation="and">',
            '          <Image condition="end with">\\cmd.exe</Image>',
            "        </Rule>",
            "      </ProcessCreate>",
            "    </RuleGroup>",
            "  </EventFiltering>",
            "</Sysmon>",
        ]
    )
    path = write("sysmon.xml", text)
    _, out, _ = run(capsys, "inspect", str(path))
    assert out.splitlines()[1:4] == [
        f'{path}:{line_of(text, "<ProcessCreate")}: ProcessCreate onmatch="include" '
        'groupRelation="or"',
        f'{path}:{line_of(text, "<Rule ")}:   Rule groupRelation="and" name="T1059"',
        f'{path}:{line_of(text, "cmd.exe")}:     Image condition="end with" value="\\\\cmd.exe"',
    ]


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(filters=xml_documents, encoding=encodings)
def test_inspect_output_is_printable_ascii(
    capsys: Capture, write: Writer, filters: tuple[EventFilter, ...], encoding: str
) -> None:
    text, _ = render(filters, encoding)
    path = write("config.xml", encode(text, encoding))
    code, out, _ = run(capsys, "inspect", str(path))
    assert code == cli.EXIT_OK and printable(out)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names exclude control characters")
def test_control_characters_in_paths_cannot_reach_the_terminal(
    capsys: Capture, write: Writer
) -> None:
    config = write("evil\x1b]0;title\x07\x1b[31m\n.xml", DOC_SAMPLE)
    events = write("events\r.jsonl", '{"EventID": 6, "Signature": "Microsoft"}\n')
    code, out, err = run(capsys, "check-event", str(config), str(events))
    assert (code, err) == (cli.EXIT_OK, "")
    assert printable(out) and len(out.splitlines()) == 2
    assert "evil\\x1b]0;title\\x07\\x1b[31m\\x0a.xml" in out and "events\\x0d.jsonl" in out


def test_check_event_prints_a_verdict_per_event(capsys: Capture, write: Writer) -> None:
    config = write("sysmon.xml", DOC_SAMPLE)
    events = write("events.jsonl", EVENTS)

    def at(needle: str) -> str:
        return f"{config}:{line_of(DOC_SAMPLE, needle)}"

    code, out, err = run(capsys, "check-event", str(config), str(events))
    assert (code, err) == (cli.EXIT_OK, "")
    assert out.splitlines() == [
        f"{events}:1: EventID 6 DROPPED matched an exclude filter "
        f"({at('>microsoft<')}, {at('>windows<')})",
        f"{events}:2: EventID 3 LOGGED matched an include filter ({at('>443<')})",
        f"{events}:4: EventID 5 DROPPED matched no include filter ({at('<ProcessTerminate')})",
        f"{events}:5: EventID 1 LOGGED no filter for this event type, assumed default",
        "4 events: 2 logged, 2 dropped",
    ]


def test_reports_config_errors_with_their_location(capsys: Capture, write: Writer) -> None:
    text = '<Sysmon schemaversion="4.90">\n  <EventFiltering>\n    <Bogus onmatch="include"/>\n'
    path = write("r\u00e8gles.xml", text + "  </EventFiltering>\n</Sysmon>\n")
    code, out, err = run(capsys, "inspect", str(path))
    location = str(path).encode("ascii", "backslashreplace").decode("ascii")
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert (
        err == f"error: {location}:{line_of(text, 'Bogus')}: <Bogus> is not a Sysmon event filter\n"
    )
    assert "r\\xe8gles.xml" in err


def test_reports_event_errors_with_their_location(capsys: Capture, write: Writer) -> None:
    config = write("sysmon.xml", DOC_SAMPLE)
    events = write("events.jsonl", '{"EventID": 1}\n{"EventID": 1,\n')
    code, out, err = run(capsys, "check-event", str(config), str(events))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith(f"error: {events}:2: invalid JSON: ")


def test_reports_unreadable_files(capsys: Capture, tmp_path: Path) -> None:
    code, out, err = run(capsys, "inspect", str(tmp_path / "missing.xml"))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith("error: [Errno 2]") and "missing.xml" in err


def test_version(capsys: Capture) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out == f"sigma-blindspot {metadata.version('sigma-blindspot')}\n"


def test_a_command_is_required(capsys: Capture) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main([])
    assert stopped.value.code == cli.EXIT_ERROR
    assert "required: COMMAND" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="EPIPE on a closed pipe is POSIX behaviour")
def test_stops_quietly_when_the_reader_closes_the_pipe(write: Writer) -> None:
    path = write("sysmon.xml", DOC_SAMPLE)
    script = (
        f"from sigma_blindspot.cli import main; raise SystemExit(main(['inspect', {str(path)!r}]))"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert process.stdout is not None
    process.stdout.close()
    _, err = process.communicate(timeout=60)
    assert (process.returncode, err) == (cli.EXIT_FAILURE, b"")
