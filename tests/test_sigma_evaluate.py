import re

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sigma.types import SigmaString
from strategies import events, literals, sigma_nodes, supported_nodes, texts

from sigma_blindspot.sigma.evaluate import evaluate, pattern_matches
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
    Pattern,
    Prefix,
    Suffix,
    Unsupported,
    Wildcard,
)
from sigma_blindspot.sigma.loader import parse_rules
from sigma_blindspot.sysmon.model import Event

ANY, ONE = Wildcard.ANY, Wildcard.ONE
UNKNOWN = Unsupported("unknown")
YES = Match("Image", Contains(""))
NO = Match("Missing", Contains(""))


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        (Equals("cmd.exe"), "cmd.exe", True),
        (Equals("cmd.exe"), "cmd.exe ", False),
        (Prefix("c:\\users\\"), "c:\\users\\a\\x.exe", True),
        (Prefix("c:\\users\\"), "c:\\windows\\x.exe", False),
        (Suffix("\\cmd.exe"), "c:\\windows\\cmd.exe", True),
        (Suffix("\\cmd.exe"), "c:\\windows\\xcmd.exe", False),
        (Contains(" -enc "), "powershell -enc aaa", True),
        (Contains(""), "", True),
        (Glob((ANY, "a", ANY, "b", ANY)), "xaybz", True),
        (Glob((ANY, "a", ANY, "b", ANY)), "xbyaz", False),
        (Glob(("a", ONE, "c")), "abc", True),
        (Glob(("a", ONE, "c")), "ac", False),
        (Glob(("a", ONE, "c")), "abbc", False),
        (Glob(("a.c",)), "abc", False),
        (Glob((ANY, "\n", ANY)), "a\nb", True),
        (Glob((ANY,)), "line\nbreak", True),
    ],
)
def test_patterns_match_folded_values(pattern: Pattern, value: str, expected: bool) -> None:
    assert pattern_matches(pattern, value) is expected


def test_matching_ignores_case_and_requires_the_field() -> None:
    event = Event(1, {"Image": "C:\\Windows\\CMD.EXE"})
    assert evaluate(Match("Image", Suffix("\\cmd.exe")), event) is True
    assert evaluate(Match("CommandLine", Contains("")), event) is False
    assert evaluate(Not(Match("CommandLine", Contains(""))), event) is True


def test_the_event_id_field_is_the_event_id() -> None:
    assert evaluate(Match("EventID", Equals("13")), Event(13, {})) is True
    assert evaluate(Match("EventID", Equals("13")), Event(12, {"EventID": "13"})) is False


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        (UNKNOWN, None),
        (Not(UNKNOWN), None),
        (And(()), True),
        (Or(()), False),
        (And((NO, UNKNOWN)), False),
        (And((YES, UNKNOWN)), None),
        (Or((YES, UNKNOWN)), True),
        (Or((NO, UNKNOWN)), None),
    ],
)
def test_unsupported_parts_are_unknown_unless_the_rest_decides(
    node: Node, expected: bool | None
) -> None:
    assert evaluate(node, Event(1, {"Image": "a"})) is expected


@given(value=texts.map(str.lower), literal=literals)
def test_globs_agree_with_the_patterns_they_generalise(value: str, literal: str) -> None:
    pairs: list[tuple[Pattern, Pattern]] = [
        (Glob((literal,)), Equals(literal)),
        (Glob((literal, ANY)), Prefix(literal)),
        (Glob((ANY, literal)), Suffix(literal)),
        (Glob((ANY, literal, ANY)), Contains(literal)),
    ]
    assert all(
        pattern_matches(glob, value) is pattern_matches(plain, value) for glob, plain in pairs
    )


@given(raw=st.text(alphabet="ab*?\\", max_size=6), value=st.text(alphabet="aAb*?\\", max_size=6))
def test_sigma_strings_match_like_pysigma_regular_expressions(raw: str, value: str) -> None:
    rule = "title: t\nlogsource: {category: process_creation, product: windows}\n"
    rule += f"detection:\n  sel:\n    Image: '{raw}'\n  condition: sel\n"
    (loaded,) = parse_rules(rule.encode(), "rule.yml")
    assert isinstance(loaded, LoadedRule)
    regex = SigmaString(raw).to_regex().regexp.to_plain()
    expected = re.fullmatch(regex, value, re.IGNORECASE | re.DOTALL) is not None
    assert evaluate(loaded.condition, Event(1, {"Image": value})) is expected


@given(node=sigma_nodes, other=sigma_nodes, event=events)
def test_three_valued_logic_keeps_negation_laws(node: Node, other: Node, event: Event) -> None:
    assert evaluate(Not(Not(node)), event) is evaluate(node, event)
    assert evaluate(Not(And((node, other))), event) is evaluate(Or((Not(node), Not(other))), event)
    assert evaluate(Not(Or((node, other))), event) is evaluate(And((Not(node), Not(other))), event)


@given(node=supported_nodes, event=events)
def test_supported_rules_always_decide_and_ignore_ascii_case(node: Node, event: Event) -> None:
    shouted = Event(event.event_id, {name: value.upper() for name, value in event.fields.items()})
    outcome = evaluate(node, event)
    assert outcome is not None and evaluate(node, shouted) is outcome
