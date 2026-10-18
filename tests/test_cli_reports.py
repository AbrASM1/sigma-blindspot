import hashlib
import json
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest
from conftest import Writer, line_of

from sigma_blindspot import cli
from sigma_blindspot.report.markdown import escape
from sigma_blindspot.report.navigator import LAYER_VERSION, techniques
from sigma_blindspot.report.sarif import SARIF_VERSION, SCHEMA, artifact_uri

type Capture = pytest.CaptureFixture[str]
type Section = tuple[str, list[tuple[str, str]]]

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = FIXTURES / "sysmon.xml"
TEXT = CONFIG.read_text(encoding="utf-8")
RULES = FIXTURES / "rules"
VERSION = metadata.version("sigma-blindspot")
CORE = """<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="end with">\\a.exe</Image>
        <Image condition="end with">\\b.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""
EITHER = """title: Either a or b
id: 0e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\a.exe'
            - '\\b.exe'
    condition: selection
"""
ONLY = """title: Only a
id: 1f2a3b4c-5d6e-4f7a-8b9c-1d2e3f4a5b6c
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\a.exe'
    condition: selection
"""


def run(capsys: Capture, *arguments: str) -> tuple[int, str, str]:
    code = cli.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def rule(name: str) -> Path:
    return RULES / name


def line(needle: str, config: str = TEXT) -> int:
    return line_of(config, needle)


def sections(out: str) -> list[Section]:
    found: list[Section] = []
    for text in out.splitlines():
        if text.startswith("### "):
            found.append((text.removeprefix("### "), []))
        elif found and text.startswith("| ") and not text.startswith(("| Verdict", "| ---")):
            cells = text.removeprefix("| ").removesuffix(" |").split(" | ")
            found[-1][1].append((cells[0], cells[2]))
    return found


def summary(result: dict[str, Any]) -> tuple[object, ...]:
    (location,) = result["locations"]
    physical = location["physicalLocation"]
    related = [
        (item["physicalLocation"]["artifactLocation"]["uri"], item["message"]["text"])
        for item in result["relatedLocations"]
    ]
    start = physical.get("region", {}).get("startLine")
    return (
        result["ruleId"],
        result["ruleIndex"],
        physical["artifactLocation"]["uri"],
        start,
        related,
    )


def results(document: dict[str, Any]) -> list[tuple[object, ...]]:
    (run_,) = document["runs"]
    return [summary(result) for result in run_["results"]]


def test_markdown_groups_blind_and_partial_rules_by_config_line(capsys: Capture) -> None:
    code, out, err = run(capsys, "analyze", str(CONFIG), str(RULES), "--format", "markdown")
    assert (code, err) == (cli.EXIT_OK, "")
    lines = out.splitlines()
    assert lines[:16] == [
        "# sigma-blindspot analysis",
        "",
        f"- Configuration: {escape(str(CONFIG))}",
        f"- SHA-256: {hashlib.sha256(CONFIG.read_bytes()).hexdigest()}",
        f"- sigma-blindspot {VERSION}",
        "",
        "| Verdict | Rules |",
        "| --- | --- |",
        "| BLIND | 4 |",
        "| PARTIAL | 1 |",
        "| RULE_UNSAT | 1 |",
        "| UNKNOWN | 2 |",
        "| OK | 1 |",
        "| SKIPPED | 1 |",
        "| Total | 10 |",
        "",
    ]
    config = escape(str(CONFIG))
    assert sections(out) == [
        (
            f"{config}:{line('svchost.exe')}, 1 rule",
            [("PARTIAL", escape(str(rule("process_script_hosts.yml"))))],
        ),
        (
            f"{config}:{line('ccmexec.exe')}, 1 rule",
            [("BLIND", escape(str(rule("process_ccmexec_child.yml"))))],
        ),
        (
            f"{config}:{line('<NetworkConnect')}, 1 rule",
            [("BLIND", escape(str(rule("network_smb_outbound.yml"))))],
        ),
        (
            f"{config}:{line('<FileCreate')}, 1 rule",
            [("BLIND", escape(str(rule("file_vbs_dropped.yml"))))],
        ),
        (
            "No configuration line, 1 rule",
            [("BLIND", escape(str(rule("image_load_dbghelp.yml"))))],
        ),
    ]


def test_markdown_counts_the_rules_each_line_blinds(capsys: Capture, write: Writer) -> None:
    config = write("config.xml", CORE)
    either, only = write("either.yml", EITHER), write("only.yml", ONLY)
    _, out, _ = run(capsys, "analyze", str(config), str(either), str(only), "--format", "markdown")
    where = escape(str(config))
    assert sections(out) == [
        (
            f"{where}:{line('a.exe', CORE)}, 2 rules",
            [("BLIND", escape(str(either))), ("BLIND", escape(str(only)))],
        ),
        (f"{where}:{line('b.exe', CORE)}, 1 rule", [("BLIND", escape(str(either)))]),
    ]


def test_markdown_without_blind_rules_says_so(capsys: Capture) -> None:
    arguments = (str(CONFIG), str(rule("process_encoded_powershell.yml")), "--format", "markdown")
    _, out, _ = run(capsys, "analyze", *arguments)
    assert out.splitlines()[-3:] == [
        "## BLIND and PARTIAL rules by configuration line",
        "",
        "None.",
    ]


@pytest.mark.parametrize(
    ("text", "escaped"),
    [
        pytest.param("plain text, (1) / 2.", "plain text, (1) / 2.", id="plain"),
        pytest.param("a|b", "a\\|b", id="pipe"),
        pytest.param("<b>&amp;</b>", "\\<b\\>\\&amp;\\</b\\>", id="html"),
        pytest.param("[x](y) ![i](j)", "\\[x\\](y) !\\[i\\](j)", id="links"),
        pytest.param("`c` *e* _u_ ~s~ $m$", "\\`c\\` \\*e\\* \\_u\\_ \\~s\\~ \\$m\\$", id="inline"),
        pytest.param("C:\\x", "C:\\\\x", id="backslash"),
        pytest.param("one\r\ntwo\nthree", "one two three", id="breaks"),
    ],
)
def test_markdown_escapes_every_inline_construct(text: str, escaped: str) -> None:
    assert escape(text) == escaped


def test_markdown_escapes_rule_titles(capsys: Capture, write: Writer) -> None:
    title = '"pipe | <i>x</i> `c` \\u00e9\\nnext"'
    path = write(
        "rule.yml",
        rule("process_ccmexec_child.yml")
        .read_text(encoding="utf-8")
        .replace("Child process of the SCCM client", "")
        .replace("title: ", f"title: {title}"),
    )
    _, out, _ = run(capsys, "analyze", str(CONFIG), str(path), "--format", "markdown")
    assert "| BLIND | pipe \\| \\<i\\>x\\</i\\> \\`c\\` \\xe9 next | " in out
    assert out.isascii()


def test_sarif_reports_blind_and_partial_rules_at_their_config_lines(capsys: Capture) -> None:
    code, out, err = run(capsys, "analyze", str(CONFIG), str(RULES), "--format", "sarif")
    assert (code, err) == (cli.EXIT_OK, "")
    document = json.loads(out)
    assert (document["$schema"], document["version"]) == (SCHEMA, SARIF_VERSION)
    (run_,) = document["runs"]
    driver = run_["tool"]["driver"]
    assert (driver["name"], driver["version"]) == ("sigma-blindspot", VERSION)
    assert [item["id"] for item in driver["rules"]] == ["BLIND", "PARTIAL"]
    config = artifact_uri(str(CONFIG))
    assert run_["artifacts"] == [
        {
            "location": {"uri": config},
            "hashes": {"sha-256": hashlib.sha256(CONFIG.read_bytes()).hexdigest()},
        }
    ]

    def rule_file(name: str) -> list[tuple[str, str]]:
        return [(artifact_uri(str(rule(name))), "Sigma rule")]

    assert results(document) == [
        ("BLIND", 0, config, line("<FileCreate"), rule_file("file_vbs_dropped.yml")),
        ("BLIND", 0, config, None, rule_file("image_load_dbghelp.yml")),
        ("BLIND", 0, config, line("<NetworkConnect"), rule_file("network_smb_outbound.yml")),
        ("BLIND", 0, config, line("ccmexec.exe"), rule_file("process_ccmexec_child.yml")),
        ("PARTIAL", 1, config, line("svchost.exe"), rule_file("process_script_hosts.yml")),
    ]
    partial = run_["results"][-1]
    assert partial["message"]["text"] == (
        'Some branches of Sigma rule "Script host or service host started" can never fire: '
        "#1 selection_svchost."
    )
    assert partial["properties"] == {"tags": ["attack.execution", "attack.t1059.005"]}


def test_sarif_relates_the_other_responsible_lines(capsys: Capture, write: Writer) -> None:
    config = write("config.xml", CORE)
    either = write("either.yml", EITHER)
    _, out, _ = run(capsys, "analyze", str(config), str(either), "--format", "sarif")
    uri = artifact_uri(str(config))
    assert results(json.loads(out)) == [
        (
            "BLIND",
            0,
            uri,
            line("a.exe", CORE),
            [(artifact_uri(str(either)), "Sigma rule"), (uri, "Also responsible")],
        )
    ]


def test_artifact_uris_are_relative_references_or_file_uris(tmp_path: Path) -> None:
    assert artifact_uri("rules/a b%.yml") == "rules/a%20b%25.yml"
    assert artifact_uri(str(tmp_path / "x.xml")) == (tmp_path / "x.xml").as_uri()


def test_navigator_layer_marks_techniques_whose_rules_are_all_blind(
    capsys: Capture, tmp_path: Path
) -> None:
    target = tmp_path / "layer.json"
    plain = run(capsys, "analyze", str(CONFIG), str(RULES))
    with_layer = run(capsys, "analyze", str(CONFIG), str(RULES), "--navigator", str(target))
    assert with_layer == plain
    layer = json.loads(target.read_text(encoding="utf-8"))
    assert layer["versions"]["layer"] == LAYER_VERSION
    assert (layer["domain"], layer["filters"]) == ("enterprise-attack", {"platforms": ["Windows"]})
    assert [
        (item["techniqueID"], item["comment"], item["metadata"]) for item in layer["techniques"]
    ] == [
        (
            "T1021.002",
            "The only analysed rule is BLIND",
            [
                {
                    "name": "Outbound SMB from rundll32",
                    "value": str(rule("network_smb_outbound.yml")),
                }
            ],
        ),
        (
            "T1072",
            "The only analysed rule is BLIND",
            [
                {
                    "name": "Child process of the SCCM client",
                    "value": str(rule("process_ccmexec_child.yml")),
                }
            ],
        ),
    ]


def test_techniques_come_from_attack_technique_tags() -> None:
    tags = ["attack.execution", "attack.t1059.001", "attack.T1059.001", "attack.t1059"]
    assert techniques([*tags, "attack.g0016", "attack.s0002", "car.2013-05-004"]) == (
        "T1059.001",
        "T1059",
    )


@pytest.mark.parametrize(
    "target", [CONFIG, rule("process_ccmexec_child.yml")], ids=["config", "rule"]
)
def test_the_layer_never_overwrites_an_input(capsys: Capture, target: Path) -> None:
    before = target.read_bytes()
    code, out, err = run(capsys, "analyze", str(CONFIG), str(RULES), "--navigator", str(target))
    assert (code, out) == (cli.EXIT_ERROR, "")
    assert err.startswith(f"error: {target}: refusing to overwrite an input file")
    assert target.read_bytes() == before
