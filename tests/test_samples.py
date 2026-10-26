import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from conftest import line_of

from sigma_blindspot import cli
from sigma_blindspot.errors import EventError
from sigma_blindspot.prover.prove import Proof, Prover, Verdict
from sigma_blindspot.report.markdown import escape
from sigma_blindspot.report.sarif import artifact_uri
from sigma_blindspot.samples import DROPPED, Sample, check_samples, load_samples
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sigma.loader import parse_rules
from sigma_blindspot.sysmon.evtx_json import SYSMON_PROVIDER
from sigma_blindspot.sysmon.parser import load_config

type Capture = pytest.CaptureFixture[str]

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = FIXTURES / "sysmon.xml"
RULES = FIXTURES / "rules"
SAMPLES = FIXTURES / "samples"
POWERSHELL = RULES / "process_encoded_powershell.yml"
POWERSHELL_ID = "2c6c4f5e-1d2b-4c7e-9a8f-0b3d5e6f7a81"
SCRIPT_HOSTS = RULES / "process_script_hosts.yml"
SCRIPT_HOSTS_ID = "4b8d2e6f-3a1c-4d5e-9f7a-2c3d4e5f6a73"
PROCESS_CREATION = SAMPLES / "regression_data" / "rules" / "windows" / "process_creation"
CCMEXEC = "C:\\Windows\\CCM\\CcmExec.exe"
DRIVER = """title: Driver loaded from a Temp folder
id: 3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|contains: '\\Temp\\'
    condition: selection
"""
ENCODED = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -enc SQBFAFgA",
}


def run(capsys: Capture, *arguments: str) -> tuple[int, str, str]:
    code = cli.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def at(needle: str) -> int:
    return line_of(CONFIG.read_text(encoding="utf-8"), needle)


def loaded(path: Path) -> LoadedRule:
    (rule,) = parse_rules(path.read_bytes(), str(path))
    assert isinstance(rule, LoadedRule)
    return rule


def exported(event_id: int, fields: dict[str, str]) -> dict[str, object]:
    system = {"Provider": {"#attributes": {"Name": SYSMON_PROVIDER}}, "EventID": event_id}
    return {"Event": {"System": system, "EventData": fields}}


def regression(root: Path, rule_id: str, *events: tuple[int, dict[str, str]]) -> Path:
    folder = root / "regression_data" / "rules" / "windows" / "sample"
    folder.mkdir(parents=True, exist_ok=True)
    sample = folder / f"{rule_id}.evtx"
    (folder / "info.yml").write_text(
        f"rule_metadata:\n"
        f"    - id: {rule_id}\n"
        f"regression_tests_info:\n"
        f"    - type: evtx\n"
        f"      provider: {SYSMON_PROVIDER}\n"
        f"      path: {sample.relative_to(root).as_posix()}\n",
        encoding="utf-8",
    )
    documents = (json.dumps(exported(event_id, fields)) for event_id, fields in events)
    sample.with_suffix(".json").write_text("\n".join(documents), encoding="utf-8")
    return root


def checked(rule: Path, root: Path, proof: Proof | None = None) -> Proof:
    config = load_config(CONFIG)
    proved = Prover(config).prove(loaded(rule)) if proof is None else proof
    (result,) = check_samples(config, (proved,), load_samples(root))
    return result


def test_load_samples_keeps_the_sysmon_samples_of_each_rule() -> None:
    folder = PROCESS_CREATION / "process_encoded_powershell"
    assert load_samples(SAMPLES)[POWERSHELL_ID] == (
        Sample(POWERSHELL_ID, 1, folder / f"{POWERSHELL_ID}.json"),
    )


def test_an_ok_rule_whose_recorded_attack_is_dropped_is_missed() -> None:
    proof = checked(POWERSHELL, SAMPLES)
    sample = str(PROCESS_CREATION / "process_encoded_powershell" / f"{POWERSHELL_ID}.json")
    assert (proof.verdict, proof.reason, proof.lines) == (
        Verdict.MISSED,
        DROPPED,
        (at("ccmexec.exe"),),
    )
    assert [(item.source, item.event_id, item.reason) for item in proof.recorded] == [
        (sample, 1, "matched an exclude filter")
    ]
    assert proof.example is not None


def test_a_partial_rule_whose_recorded_attack_is_dropped_is_missed() -> None:
    proof = checked(SCRIPT_HOSTS, SAMPLES)
    assert (proof.verdict, proof.lines) == (Verdict.MISSED, (at("ccmexec.exe"),))
    assert [branch.verdict for branch in proof.branches] == [Verdict.BLIND, Verdict.OK]


def test_a_logged_recorded_attack_keeps_the_verdict(tmp_path: Path) -> None:
    root = regression(
        tmp_path,
        POWERSHELL_ID,
        (1, {**ENCODED, "ParentImage": CCMEXEC}),
        (1, {**ENCODED, "ParentImage": "C:\\Windows\\explorer.exe"}),
    )
    proof = checked(POWERSHELL, root)
    assert (proof.verdict, proof.recorded) == (Verdict.OK, ())


def test_samples_without_a_matching_event_keep_the_verdict(tmp_path: Path) -> None:
    root = regression(tmp_path, POWERSHELL_ID, (1, {"Image": "C:\\Windows\\System32\\cmd.exe"}))
    assert checked(POWERSHELL, root).verdict is Verdict.OK


@pytest.mark.parametrize(
    ("rule", "event_id", "fields"),
    [
        pytest.param(
            None,
            6,
            {"ImageLoaded": "C:\\Windows\\Temp\\x.sys"},
            id="unknown-decision",
        ),
        pytest.param(
            "process_regex.yml",
            1,
            {"Image": "C:\\Users\\Public\\a1b2c3.exe"},
            id="undecided-match",
        ),
    ],
)
def test_an_undecided_sample_never_makes_a_rule_missed(
    tmp_path: Path, rule: str | None, event_id: int, fields: dict[str, str]
) -> None:
    path = tmp_path / "driver.yml" if rule is None else RULES / rule
    if rule is None:
        path.write_text(DRIVER, encoding="utf-8")
    proof = Prover(load_config(CONFIG)).prove(loaded(path))
    assert proof.verdict is Verdict.UNKNOWN
    root = regression(tmp_path, str(loaded(path).rule_id), (event_id, fields))
    forced = replace(proof, verdict=Verdict.OK)
    assert checked(path, root, forced) == forced


def test_only_ok_and_partial_rules_are_checked() -> None:
    config = load_config(CONFIG)
    proof = Prover(config).prove(loaded(POWERSHELL))
    blind = replace(proof, verdict=Verdict.BLIND)
    assert check_samples(config, (blind,), load_samples(SAMPLES)) == (blind,)


def test_analyze_with_samples_prints_missed_rules(capsys: Capture) -> None:
    code, out, err = run(capsys, "analyze", str(CONFIG), str(RULES), "--samples", str(SAMPLES))
    assert (code, err) == (cli.EXIT_OK, "")
    lines = out.splitlines()
    where = f"({CONFIG}:{at('ccmexec.exe')})"
    assert lines[5:7] == [
        f'MISSED {POWERSHELL} "Encoded PowerShell command line" process_creation (1): '
        f"{DROPPED} {where}",
        f'MISSED {SCRIPT_HOSTS} "Script host or service host started" process_creation (1): '
        f"{DROPPED} {where}",
    ]
    assert lines[-1] == (
        "10 rules: 5 BLIND, 2 MISSED, 0 PARTIAL, 1 RULE_UNSAT, 1 UNKNOWN, 0 OK, 1 SKIPPED"
    )


def test_analyze_with_samples_writes_the_recorded_events_in_json(capsys: Capture) -> None:
    arguments = (str(CONFIG), str(POWERSHELL), "--samples", str(SAMPLES), "--format", "json")
    _, out, _ = run(capsys, "analyze", *arguments)
    document = json.loads(out)
    assert document["samples"] == str(SAMPLES)
    assert document["summary"]["MISSED"] == 1
    (result,) = document["results"]
    assert result["verdict"] == "MISSED"
    assert result["recorded"] == [
        {
            "source": str(
                PROCESS_CREATION / "process_encoded_powershell" / f"{POWERSHELL_ID}.json"
            ),
            "event_id": 1,
            "reason": "matched an exclude filter",
            "lines": [at("ccmexec.exe")],
        }
    ]


def test_analyze_with_samples_reports_missed_rules_in_markdown_and_sarif(
    capsys: Capture,
) -> None:
    arguments = (str(CONFIG), str(POWERSHELL), "--samples", str(SAMPLES))
    _, out, _ = run(capsys, "analyze", *arguments, "--format", "markdown")
    assert "| MISSED | 1 |" in out
    assert "## BLIND, MISSED and PARTIAL rules by configuration line" in out
    assert f"### {escape(str(CONFIG))}:{at('ccmexec.exe')}, 1 rule" in out
    _, out, _ = run(capsys, "analyze", *arguments, "--format", "sarif")
    (run_,) = json.loads(out)["runs"]
    (result,) = run_["results"]
    region: dict[str, Any] = result["locations"][0]["physicalLocation"]
    assert (result["ruleId"], result["ruleIndex"]) == ("MISSED", 2)
    assert run_["tool"]["driver"]["rules"][2]["id"] == "MISSED"
    assert region == {
        "artifactLocation": {"uri": artifact_uri(str(CONFIG))},
        "region": {"startLine": at("ccmexec.exe")},
    }


def test_fail_on_blind_counts_missed_rules(capsys: Capture) -> None:
    plain = run(capsys, "analyze", str(CONFIG), str(POWERSHELL), "--fail-on-blind")
    sampled = run(
        capsys,
        "analyze",
        str(CONFIG),
        str(POWERSHELL),
        "--fail-on-blind",
        "--samples",
        str(SAMPLES),
    )
    assert (plain[0], sampled[0]) == (cli.EXIT_OK, cli.EXIT_FAILURE)


def test_samples_do_not_depend_on_jobs(capsys: Capture) -> None:
    arguments = ("analyze", str(CONFIG), str(RULES), "--samples", str(SAMPLES), "--format", "json")
    assert run(capsys, *arguments) == run(capsys, *arguments, "--jobs", "2")


def info(root: Path, text: str) -> Path:
    folder = root / "regression_data" / "rules"
    folder.mkdir(parents=True)
    (folder / "info.yml").write_text(text, encoding="utf-8")
    return folder / "info.yml"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param("rule_metadata: [unclosed\n", ":2: invalid YAML: ", id="yaml"),
        pytest.param("- a list\n", ": expected a mapping", id="not-a-mapping"),
        pytest.param(
            "rule_metadata: [1]\n", ": rule_metadata must be a list of mappings", id="ids"
        ),
        pytest.param(
            f"regression_tests_info:\n  - provider: {SYSMON_PROVIDER}\n",
            ": path must be a value",
            id="no-path",
        ),
        pytest.param(
            f"regression_tests_info:\n  - provider: {SYSMON_PROVIDER}\n"
            "    path: x.evtx\n    match_count: one\n",
            ": match_count must be an integer",
            id="count",
        ),
        pytest.param(
            f"regression_tests_info:\n  - provider: {SYSMON_PROVIDER}\n    path: ../x.evtx\n",
            ": sample path outside ",
            id="outside",
        ),
    ],
)
def test_a_broken_info_file_is_an_error(
    capsys: Capture, tmp_path: Path, text: str, message: str
) -> None:
    path = info(tmp_path, text)
    code, out, err = run(
        capsys, "analyze", str(CONFIG), str(POWERSHELL), "--samples", str(tmp_path)
    )
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith(f"error: {path}{message}")


def test_a_broken_sample_is_an_error(capsys: Capture, tmp_path: Path) -> None:
    root = regression(tmp_path, POWERSHELL_ID)
    (sample,) = root.rglob("*.json")
    sample.write_text("{broken", encoding="utf-8")
    code, _, err = run(capsys, "analyze", str(CONFIG), str(POWERSHELL), "--samples", str(root))
    assert code == cli.EXIT_ERROR
    assert err.startswith(f"error: {sample}:1: invalid JSON: ")


def test_samples_need_a_regression_data_folder(capsys: Capture, tmp_path: Path) -> None:
    code, _, err = run(capsys, "analyze", str(CONFIG), str(POWERSHELL), "--samples", str(tmp_path))
    assert code == cli.EXIT_ERROR
    assert err == f"error: {tmp_path}: no regression_data folder\n"


def test_load_samples_raises_event_errors(tmp_path: Path) -> None:
    info(tmp_path, "- a list\n")
    with pytest.raises(EventError, match="expected a mapping"):
        load_samples(tmp_path)
