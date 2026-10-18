from collections.abc import Sequence

import pytest
import z3
from hypothesis import assume, given
from hypothesis import strategies as st
from strategies import FIELDS, configs, supported_nodes, texts

from sigma_blindspot.prover.encode import encode_config
from sigma_blindspot.prover.search import Search, minimal
from sigma_blindspot.prover.strings import MAX_CHAR, Unrepresentable, lit, read
from sigma_blindspot.sigma.evaluate import evaluate
from sigma_blindspot.sigma.ir import And, Equals, Match, Node
from sigma_blindspot.sysmon.conditions import fold
from sigma_blindspot.sysmon.events import TAG_BY_EVENT_ID
from sigma_blindspot.sysmon.model import Event, SysmonConfig

representable = st.text(st.characters(max_codepoint=MAX_CHAR, exclude_categories=()))
complete_events = st.builds(
    Event,
    event_id=st.sampled_from((1, 12, 13)),
    fields=st.fixed_dictionaries({name: texts for name in FIELDS}),
)


def satisfiable(node: Node, event: Event, event_id: int | None) -> bool:
    search = Search(timeout_ms=60_000)
    pins = tuple(Match(name, Equals(fold(value))) for name, value in event.fields.items())
    encoded = search.encode(And((node, *pins)), event_id)
    outcome = search.check(search.solver(), (encoded,))
    assert outcome.result != z3.unknown, outcome.why_unknown
    return bool(outcome.result == z3.sat)


def config_node(config: SysmonConfig, event_id: int) -> Node:
    filters = config.filters_for(TAG_BY_EVENT_ID[event_id])
    assume(filters)
    return And(tuple(item.node for item in encode_config(filters)))


@given(text=representable)
def test_literals_read_back_unchanged(text: str) -> None:
    solver = z3.Solver()
    solver.add(z3.String("x") == lit(text))
    assert solver.check() == z3.sat
    assert read(solver.model()[z3.String("x")]) == text


def test_literals_keep_backslash_sequences_literal() -> None:
    text = "c:\\users\\u0041\\x\\u{41}"
    solver = z3.Solver()
    solver.add(z3.Length(lit(text)) == len(text))
    assert solver.check() == z3.sat


def test_characters_beyond_z3_are_rejected() -> None:
    with pytest.raises(Unrepresentable, match="U\\+E0001"):
        lit("a\U000e0001")


@given(config=configs, event=complete_events)
def test_the_config_translation_agrees_with_the_emulator(
    config: SysmonConfig, event: Event
) -> None:
    node = config_node(config, event.event_id)
    assert evaluate(node, event) is config.evaluate(event).logged


@given(config=configs, event=complete_events)
def test_the_config_search_agrees_with_the_emulator(config: SysmonConfig, event: Event) -> None:
    node = config_node(config, event.event_id)
    assert satisfiable(node, event, None) is config.evaluate(event).logged


@given(node=supported_nodes, event=complete_events)
def test_the_rule_search_agrees_with_the_evaluator(node: Node, event: Event) -> None:
    assert satisfiable(node, event, event.event_id) is evaluate(node, event)


@pytest.mark.parametrize(("event_id", "expected"), [(13, True), (12, False)])
def test_the_event_id_field_is_the_event_id(event_id: int, expected: bool) -> None:
    rule = Match("EventID", Equals("13"))
    assert satisfiable(rule, Event(event_id, {}), event_id) is expected


@given(
    weights=st.lists(st.integers(min_value=0, max_value=5), max_size=12), limit=st.integers(1, 20)
)
def test_quickxplain_returns_a_minimal_inconsistent_subset(weights: list[int], limit: int) -> None:
    assume(sum(weights) >= limit)
    items = list(enumerate(weights))

    def inconsistent(part: Sequence[tuple[int, int]]) -> bool:
        return sum(weight for _, weight in part) >= limit

    core = minimal(items, inconsistent)
    assert inconsistent(core)
    assert all(not inconsistent([item for item in core if item != left]) for left in core)
