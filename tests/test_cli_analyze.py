import hashlib
import json
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest
from conftest import Writer, line_of

from sigma_blindspot import cli
from sigma_blindspot.sigma.evaluate import evaluate
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sigma.loader import parse_rules
from sigma_blindspot.sysmon.model import Event
from sigma_blindspot.sysmon.parser import load_config

type Capture = pytest.CaptureFixture[str]

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = FIXTURES / "sysmon.xml"
RULES = FIXTURES / "rules"
DROPPED = "every matching event is dropped by the config"


def run(capsys: Capture, *arguments: str) -> tuple[int, str, str]:
    code = cli.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def at(needle: str) -> str:
    return f"{CONFIG}:{line_of(CONFIG.read_text(encoding='utf-8'), needle)}"


def rule(name: str) -> Path:
    return RULES / name


def test_analyze_prints_one_verdict_per_rule_sorted_by_verdict(capsys: Capture) -> None:
    code, out, err = run(capsys, "analyze", str(CONFIG), str(RULES))
    assert (code, err) == (cli.EXIT_OK, "")
    assert out.splitlines() == [
        f'BLIND {rule("file_vbs_dropped.yml")} "VBScript file written" file_event (11): '
        f"{DROPPED} ({at('<FileCreate')})",
        f'BLIND {rule("image_load_dbghelp.yml")} "Debug help library loaded" image_load (7): '
        "ImageLoad (7) is not logged without a filter",
        f'BLIND {rule("network_smb_outbound.yml")} "Outbound SMB from rundll32" '
        f"network_connection (3): {DROPPED} ({at('<NetworkConnect')})",
        f'BLIND {rule("process_ccmexec_child.yml")} "Child process of the SCCM client" '
        f"process_creation (1): {DROPPED} ({at('ccmexec.exe')})",
        f'PARTIAL {rule("process_script_hosts.yml")} "Script host or service host started" '
        f"process_creation (1): never fires: #1 selection_svchost ({at('svchost.exe')})",
        f'RULE_UNSAT {rule("process_contradiction.yml")} "Image that is both cmd and '
        'powershell" process_creation (1): the rule contradicts itself',
        f'UNKNOWN {rule("process_access_lsass.yml")} "Process opened LSASS" process_access '
        "(10): Sysmon default unverified (probe P1)",
        f'UNKNOWN {rule("process_regex.yml")} "Random looking executable name" '
        "process_creation (1): unsupported: regular expression (re)",
        f'OK {rule("process_encoded_powershell.yml")} "Encoded PowerShell command line" '
        "process_creation (1): an event can match the rule and be logged",
        f'SKIPPED {rule("linux_shell.yml")} "Shell started on Linux": not a Sysmon log source',
        "10 rules: 4 BLIND, 1 PARTIAL, 1 RULE_UNSAT, 2 UNKNOWN, 1 OK, 1 SKIPPED",
    ]


def test_analyze_writes_json_with_confirmed_examples(capsys: Capture) -> None:
    code, out, _ = run(capsys, "analyze", str(CONFIG), str(RULES), "--format", "json")
    document = json.loads(out)
    assert code == cli.EXIT_OK
    assert document["schema_version"] == 1
    assert document["tool"] == {
        "name": "sigma-blindspot",
        "version": metadata.version("sigma-blindspot"),
    }
    assert document["config"] == {
        "source": str(CONFIG),
        "sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
    }
    assert document["summary"] == {
        "BLIND": 4,
        "PARTIAL": 1,
        "RULE_UNSAT": 1,
        "UNKNOWN": 2,
        "OK": 1,
        "SKIPPED": 1,
    }
    results = {entry["source"]: entry for entry in document["results"]}
    blind = results[str(rule("process_ccmexec_child.yml"))]
    assert blind["lines"] == [line_of(CONFIG.read_text(encoding="utf-8"), "ccmexec.exe")]
    ok = results[str(rule("process_encoded_powershell.yml"))]
    example = Event(ok["example"]["event_id"], ok["example"]["fields"])
    (loaded,) = parse_rules(rule("process_encoded_powershell.yml").read_bytes(), "rule.yml")
    assert isinstance(loaded, LoadedRule)
    assert evaluate(loaded.condition, example) is True
    assert load_config(CONFIG).evaluate(example).logged is True


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        pytest.param((str(RULES),), cli.EXIT_FAILURE, id="blind-rules"),
        pytest.param((str(rule("process_encoded_powershell.yml")),), cli.EXIT_OK, id="all-ok"),
        pytest.param((str(rule("process_script_hosts.yml")),), cli.EXIT_FAILURE, id="partial"),
    ],
)
def test_fail_on_blind_sets_the_exit_code(
    capsys: Capture, rules: tuple[str, ...], expected: int
) -> None:
    code, _, _ = run(capsys, "analyze", str(CONFIG), *rules, "--fail-on-blind")
    assert code == expected


def test_jobs_do_not_change_the_output(capsys: Capture) -> None:
    for output in ("text", "json"):
        single = run(capsys, "analyze", str(CONFIG), str(RULES), "--format", output)
        parallel = run(
            capsys, "analyze", str(CONFIG), str(RULES), "--format", output, "--jobs", "2"
        )
        assert single == parallel


def test_output_does_not_depend_on_the_hash_seed() -> None:
    script = (
        "from sigma_blindspot.cli import main; "
        f"raise SystemExit(main(['analyze', {str(CONFIG)!r}, {str(RULES)!r}, '--format', 'json']))"
    )
    outputs = {
        subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout
        for seed in ("1", "2")
    }
    assert len(outputs) == 1


def test_broken_rule_files_are_skipped_not_fatal(capsys: Capture, write: Writer) -> None:
    broken = write("broken.yml", "title: [unclosed\n")
    code, out, _ = run(capsys, "analyze", str(CONFIG), str(broken))
    assert code == cli.EXIT_OK
    assert out.splitlines()[0].startswith(f"SKIPPED {broken}: ParserError: ")


def test_rule_titles_are_printed_as_ascii(capsys: Capture, write: Writer) -> None:
    path = write(
        "rule.yml",
        rule("process_ccmexec_child.yml")
        .read_text(encoding="utf-8")
        .replace("Child process", "Processus enfant \u00e9\u202e"),
    )
    _, out, _ = run(capsys, "analyze", str(CONFIG), str(path))
    assert '"Processus enfant \\u00e9\\u202e of the SCCM client"' in out
    assert out.isascii()


def test_invalid_inputs_exit_with_2(capsys: Capture, write: Writer, tmp_path: Path) -> None:
    bad = write(
        "bad.xml",
        '<Sysmon schemaversion="4.90"><EventFiltering><Bogus onmatch="include"/>'
        "</EventFiltering></Sysmon>",
    )
    code, out, err = run(capsys, "analyze", str(bad), str(RULES))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith(f"error: {bad}:1: <Bogus> is not a Sysmon event filter")
    code, out, err = run(capsys, "analyze", str(CONFIG), str(tmp_path / "missing"))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith("error: [Errno 2]")


@pytest.mark.parametrize("option", ["--timeout-ms", "--jobs"])
def test_counts_must_be_positive(capsys: Capture, option: str) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(["analyze", str(CONFIG), str(RULES), option, "0"])
    assert stopped.value.code == cli.EXIT_ERROR
    assert "must be at least 1, got 0" in capsys.readouterr().err
