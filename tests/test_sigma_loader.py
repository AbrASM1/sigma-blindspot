import textwrap
from pathlib import Path

import pytest
from conftest import Writer

from sigma_blindspot.sigma.ir import (
    And,
    Contains,
    Equals,
    Glob,
    LoadedRule,
    Match,
    Node,
    Not,
    Or,
    Prefix,
    Skipped,
    Suffix,
    Unsupported,
    Wildcard,
)
from sigma_blindspot.sigma.loader import Loaded, load_rules, parse_rules

SOURCE = "rule.yml"
IMAGE = "Image"
COMMAND_LINE = "CommandLine"
USER = "User"


def rule_text(
    detection: str, logsource: str = "category: process_creation\nproduct: windows"
) -> str:
    return (
        "title: fixture\n"
        f"logsource:\n{textwrap.indent(logsource, '  ')}\n"
        f"detection:\n{textwrap.indent(textwrap.dedent(detection), '  ')}"
    )


def parse(text: str) -> tuple[Loaded, ...]:
    return parse_rules(text.encode(), SOURCE)


def loaded_rule(text: str) -> LoadedRule:
    (loaded,) = parse(text)
    assert isinstance(loaded, LoadedRule)
    return loaded


def branches(detection: str) -> tuple[Node, ...]:
    return tuple(branch.condition for branch in loaded_rule(rule_text(detection)).branches)


def selection(item: str) -> str:
    return f"sel:\n  {item}\ncondition: sel\n"


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        pytest.param(
            r"Image: 'C:\Windows\CMD.exe'",
            Match(IMAGE, Equals("c:\\windows\\cmd.exe")),
            id="equals",
        ),
        pytest.param(
            "CommandLine|contains: ' -EncodedCommand '",
            Match(COMMAND_LINE, Contains(" -encodedcommand ")),
            id="contains",
        ),
        pytest.param(
            r"Image|startswith: 'C:\Users\'", Match(IMAGE, Prefix("c:\\users\\")), id="startswith"
        ),
        pytest.param(
            r"Image|endswith: '\cmd.exe'", Match(IMAGE, Suffix("\\cmd.exe")), id="endswith"
        ),
        pytest.param(
            "CommandLine: '*a*B*'",
            Match(COMMAND_LINE, Glob((Wildcard.ANY, "a", Wildcard.ANY, "b", Wildcard.ANY))),
            id="inner-wildcard",
        ),
        pytest.param(
            r"Image|endswith: '\cmd?.exe'",
            Match(IMAGE, Glob((Wildcard.ANY, "\\cmd", Wildcard.ONE, ".exe"))),
            id="single-wildcard",
        ),
        pytest.param(
            r"CommandLine: 'a\*b\?'", Match(COMMAND_LINE, Equals("a*b?")), id="escaped-wildcards"
        ),
        pytest.param("CommandLine: '**'", Match(COMMAND_LINE, Contains("")), id="any-value"),
        pytest.param("CommandLine: ''", Match(COMMAND_LINE, Equals("")), id="empty-value"),
        pytest.param("DestinationPort: 443", Match("DestinationPort", Equals("443")), id="number"),
        pytest.param(
            "CommandLine|contains|all:\n    - ' /c '\n    - 'whoami'",
            And((Match(COMMAND_LINE, Contains(" /c ")), Match(COMMAND_LINE, Contains("whoami")))),
            id="contains-all",
        ),
        pytest.param(
            "CommandLine|windash|contains: ' -s '",
            Or(
                tuple(
                    Match(COMMAND_LINE, Contains(f" {dash}s "))
                    for dash in ("-", "/", "\u2013", "\u2014", "\u2015")
                )
            ),
            id="windash",
        ),
        pytest.param("Image|neq: 'a'", Not(Match(IMAGE, Equals("a"))), id="neq"),
        pytest.param("Image|cased: 'A'", Unsupported("case-sensitive match (cased)"), id="cased"),
        pytest.param("Image|re: '.*'", Unsupported("regular expression (re)"), id="re"),
        pytest.param(
            "DestinationIp|cidr: '10.0.0.0/8'", Unsupported("CIDR network (cidr)"), id="cidr"
        ),
        pytest.param("Image: null", Unsupported("null value"), id="null"),
        pytest.param("Image|exists: true", Unsupported("field existence (exists)"), id="exists"),
        pytest.param(
            "ProcessId|gt: 5", Unsupported("numeric comparison (lt, lte, gt, gte)"), id="compare"
        ),
        pytest.param(
            "Image|fieldref: ParentImage", Unsupported("field reference (fieldref)"), id="fieldref"
        ),
        pytest.param("Image: true", Unsupported("boolean value"), id="bool"),
        pytest.param("UtcTime|minute: 5", Unsupported("timestamp modifier"), id="timestamp"),
        pytest.param(
            r"Image|expand: '%dir%\x.exe'", Unsupported("placeholder (expand)"), id="placeholder"
        ),
    ],
)
def test_converts_each_value_construct(item: str, expected: Node) -> None:
    assert branches(selection(item)) == (expected,)


def test_fields_of_a_map_combine_with_and() -> None:
    detection = """\
        sel:
          Image|endswith: '\\cmd.exe'
          User: SYSTEM
          ParentImage: null
        condition: sel
        """
    assert branches(detection) == (
        And(
            (
                Match(IMAGE, Suffix("\\cmd.exe")),
                Match(USER, Equals("system")),
                Unsupported("null value"),
            )
        ),
    )


def test_a_value_list_at_the_top_is_split_into_branches() -> None:
    detection = """\
        sel:
          Image|endswith:
            - '\\a.exe'
            - '\\b.exe'
        condition: sel
        """
    assert branches(detection) == (Match(IMAGE, Suffix("\\a.exe")), Match(IMAGE, Suffix("\\b.exe")))


def test_a_list_of_maps_is_an_or_split_into_branches() -> None:
    detection = """\
        sel:
          - Image|endswith: '\\a.exe'
            User: x
          - CommandLine|contains: y
        condition: sel
        """
    rule = loaded_rule(rule_text(detection))
    assert [branch.label for branch in rule.branches] == ["#1 sel", "#2 sel"]
    assert tuple(branch.condition for branch in rule.branches) == (
        And((Match(IMAGE, Suffix("\\a.exe")), Match(USER, Equals("x")))),
        Match(COMMAND_LINE, Contains("y")),
    )


SELECTIONS = """\
selection_img:
  Image: a
selection_user:
  User: b
filter:
  CommandLine: c
"""


@pytest.mark.parametrize(
    ("condition", "labels", "expected"),
    [
        pytest.param(
            "1 of selection_*",
            ["#1 selection_img", "#2 selection_user"],
            (Match(IMAGE, Equals("a")), Match(USER, Equals("b"))),
            id="one-of",
        ),
        pytest.param(
            "all of selection_*",
            ["#1 selection_img, selection_user"],
            (And((Match(IMAGE, Equals("a")), Match(USER, Equals("b")))),),
            id="all-of",
        ),
        pytest.param(
            "selection_img and not filter",
            ["#1 selection_img, filter"],
            (And((Match(IMAGE, Equals("a")), Not(Match(COMMAND_LINE, Equals("c"))))),),
            id="not-filter",
        ),
        pytest.param(
            "selection_img or (selection_user and not filter)",
            ["#1 selection_img", "#2 selection_user, filter"],
            (
                Match(IMAGE, Equals("a")),
                And((Match(USER, Equals("b")), Not(Match(COMMAND_LINE, Equals("c"))))),
            ),
            id="or-at-the-top",
        ),
        pytest.param(
            "\n  - selection_img\n  - selection_user",
            ["#1 selection_img", "#2 selection_user"],
            (Match(IMAGE, Equals("a")), Match(USER, Equals("b"))),
            id="condition-list",
        ),
    ],
)
def test_converts_conditions_into_top_level_or_branches(
    condition: str, labels: list[str], expected: tuple[Node, ...]
) -> None:
    rule = loaded_rule(rule_text(f"{SELECTIONS}condition: {condition}\n"))
    assert [branch.label for branch in rule.branches] == labels
    assert tuple(branch.condition for branch in rule.branches) == expected


def test_a_keyword_search_is_unsupported() -> None:
    assert branches("keywords:\n  - mimikatz\ncondition: keywords\n") == (
        Unsupported("keyword search"),
    )


def test_keeps_rule_metadata() -> None:
    text = """\
title: Run key
id: 9d2b7c38-8e64-4c3a-9b1e-0f5e1a6c2d4b
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: registry_set
  product: windows
detection:
  sel:
    TargetObject|contains: '\\CurrentVersion\\Run\\'
  condition: sel
"""
    rule = loaded_rule(text)
    assert (rule.source, rule.title, rule.rule_id) == (
        SOURCE,
        "Run key",
        "9d2b7c38-8e64-4c3a-9b1e-0f5e1a6c2d4b",
    )
    assert (rule.category, rule.event_ids) == ("registry_set", (13,))
    assert rule.tags == ("attack.persistence", "attack.t1547.001")


CORRELATION = """\
title: Many processes
name: many
correlation:
  type: event_count
  rules:
    - base_rule
  group-by:
    - User
  timespan: 1h
  condition:
    gte: 10
"""

FILTER = """\
title: Filter admin
logsource:
  category: process_creation
  product: windows
filter:
  rules:
    - 9d2b7c38-8e64-4c3a-9b1e-0f5e1a6c2d4b
  selection:
    User: admin
  condition: not selection
"""


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            rule_text(selection("Image: a"), "category: process_creation\nproduct: linux"),
            Skipped(SOURCE, "fixture", "not a Sysmon log source"),
            id="other-product",
        ),
        pytest.param(
            rule_text(selection("EventID: 4688"), "product: windows\nservice: security"),
            Skipped(SOURCE, "fixture", "not a Sysmon log source"),
            id="windows-service",
        ),
        pytest.param(
            rule_text(selection("ScriptBlockText: a"), "category: ps_script\nproduct: windows"),
            Skipped(SOURCE, "fixture", "not a Sysmon log source"),
            id="unmapped-category",
        ),
        pytest.param(
            rule_text(selection("Image: a"), "product: windows"),
            Skipped(SOURCE, "fixture", "not a Sysmon log source"),
            id="no-category",
        ),
        pytest.param(
            CORRELATION, Skipped(SOURCE, "Many processes", "correlation rule"), id="correlation"
        ),
        pytest.param(FILTER, Skipped(SOURCE, "Filter admin", "filter rule"), id="filter"),
        pytest.param(
            rule_text("sel:\n  Image: a\ncondition: nope\n"),
            Skipped(
                SOURCE, "fixture", "SigmaConditionError: Detection 'nope' not defined in detections"
            ),
            id="unknown-identifier",
        ),
        pytest.param("", Skipped(SOURCE, None, "no rule in file"), id="empty-file"),
    ],
)
def test_skips_what_it_cannot_analyse(text: str, expected: Skipped) -> None:
    assert parse(text) == (expected,)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        pytest.param(b"title: [unclosed", "ParserError: ", id="invalid-yaml"),
        pytest.param(b"42\n", "AttributeError: ", id="not-a-mapping"),
        pytest.param(
            rule_text(selection("Image|bogus: a")).encode(),
            "SigmaModifierError: Unknown modifier 'bogus'",
            id="unknown-modifier",
        ),
        pytest.param(b"title: caf\xe9\n", "ReaderError: ", id="not-utf8"),
    ],
)
def test_a_file_that_fails_to_load_is_skipped_with_its_error(data: bytes, reason: str) -> None:
    (skipped,) = parse_rules(data, SOURCE)
    assert isinstance(skipped, Skipped)
    assert (skipped.source, skipped.title) == (SOURCE, None)
    assert skipped.reason.startswith(reason)


def test_reads_every_document_of_a_rule_collection() -> None:
    text = """\
action: global
title: Global
logsource:
  product: windows
detection:
  condition: sel
---
logsource:
  category: process_creation
detection:
  sel:
    Image: a
---
logsource:
  category: image_load
detection:
  sel:
    ImageLoaded: b
"""
    rules = parse(text)
    assert [item.category for item in rules if isinstance(item, LoadedRule)] == [
        "process_creation",
        "image_load",
    ]


def test_loads_files_and_directories_in_a_stable_order(write: Writer, tmp_path: Path) -> None:
    rule = rule_text(selection("Image: a"))
    for name in ("rules/b.yml", "rules/a/z.yml", "rules/a/y.yml", "rules/c.yaml", "rules/d.txt"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(rule)
    single = write("single.rule", rule)
    loaded = load_rules([tmp_path / "rules", single])
    expected = [tmp_path / "rules/a/y.yml", tmp_path / "rules/a/z.yml", tmp_path / "rules/b.yml"]
    assert [item.source for item in loaded] == [*map(str, expected), str(single)]


def test_a_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_rules([tmp_path / "missing"])
