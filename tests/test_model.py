from collections.abc import Iterator
from dataclasses import replace
from typing import cast

import pytest
from conftest import DOC_RULE_GROUPS, DOC_SAMPLE, line_of
from hypothesis import given
from hypothesis import strategies as st
from strategies import (
    SOURCE,
    config_of,
    configs,
    event_filters,
    events,
    filterable_events,
    process_events,
    relations,
)

from sigma_blindspot.sysmon.conditions import Operator
from sigma_blindspot.sysmon.events import (
    TAG_BY_EVENT_ID,
    UNFILTERABLE_EVENT_IDS,
    EventTag,
    logged_without_filter,
)
from sigma_blindspot.sysmon.model import (
    Condition,
    Decision,
    Event,
    EventFilter,
    OnMatch,
    Reason,
    Relation,
    Rule,
    SysmonConfig,
)
from sigma_blindspot.sysmon.parser import parse_config

LEGACY = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="end with">\\cmd.exe</Image>
      <Image condition="end with">\\powershell.exe</Image>
      <ParentImage condition="image">explorer.exe</ParentImage>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
"""

LEGACY_RULE = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="end with">\\cmd.exe</Image>
      <Rule groupRelation="or">
        <CommandLine condition="contains">/c</CommandLine>
        <CommandLine condition="contains">/k</CommandLine>
      </Rule>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
"""

GROUPED_RULE = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule name="encoded" groupRelation="and">
          <Image condition="end with">\\powershell.exe</Image>
          <CommandLine condition="contains any">-enc ;-encodedcommand</CommandLine>
        </Rule>
        <ParentImage condition="image">winword.exe</ParentImage>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""

SEVERAL_FILTERS = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="first" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">cmd.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="second" groupRelation="or">
      <ProcessCreate onmatch='include'>
        <Image condition="image">powershell.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="exclude">
        <CommandLine condition="contains">safe</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""

ABSENT_FIELDS = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Details condition="is not">x</Details>
      </RegistryEvent>
      <RegistryEvent onmatch="exclude">
        <NewName condition="excludes">x</NewName>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""

type Case = tuple[str, int, dict[str, str], bool, Reason, tuple[str, ...]]

CASES: list[Case] = [
    (
        DOC_SAMPLE,
        6,
        {"Signature": "Microsoft Windows"},
        False,
        Reason.EXCLUDED,
        (">microsoft<", ">windows<"),
    ),
    (DOC_SAMPLE, 6, {"Signature": "Acme Corp"}, True, Reason.NOT_EXCLUDED, ()),
    (DOC_SAMPLE, 5, {"Image": "C:\\x.exe"}, False, Reason.NOT_INCLUDED, ("<ProcessTerminate",)),
    (
        DOC_SAMPLE,
        3,
        {"DestinationPort": "443", "Image": "a.exe"},
        True,
        Reason.INCLUDED,
        (">443<",),
    ),
    (
        DOC_SAMPLE,
        3,
        {"DestinationPort": "80", "Image": "C:\\iexplore.exe"},
        False,
        Reason.EXCLUDED,
        ("iexplore.exe",),
    ),
    (
        DOC_SAMPLE,
        3,
        {"DestinationPort": "22", "Image": "a.exe"},
        False,
        Reason.NOT_INCLUDED,
        ('<NetworkConnect onmatch="include"',),
    ),
    (DOC_SAMPLE, 1, {"Image": "C:\\x.exe"}, True, Reason.DEFAULT, ()),
    (DOC_SAMPLE, 7, {"ImageLoaded": "C:\\x.dll"}, False, Reason.DEFAULT, ()),
    (DOC_SAMPLE, 4, {}, True, Reason.UNFILTERABLE, ()),
    (
        DOC_RULE_GROUPS,
        1,
        {"Image": "C:\\Windows\\System32\\timeout.exe", "CommandLine": "timeout /t 100"},
        True,
        Reason.INCLUDED,
        ('"create"', ">100<"),
    ),
    (
        DOC_RULE_GROUPS,
        1,
        {"Image": "C:\\Windows\\System32\\timeout.exe", "CommandLine": "timeout /t 5"},
        False,
        Reason.NOT_INCLUDED,
        ("<ProcessCreate",),
    ),
    (DOC_RULE_GROUPS, 5, {"Image": "C:\\ping.exe"}, True, Reason.INCLUDED, ("ping.exe",)),
    (DOC_RULE_GROUPS, 5, {"Image": "TIMEOUT.EXE"}, True, Reason.INCLUDED, ('"terminate"',)),
    (DOC_RULE_GROUPS, 5, {"Image": "notepad.exe"}, False, Reason.NOT_INCLUDED, ("<ProcessT",)),
    (DOC_RULE_GROUPS, 7, {"ImageLoaded": "a.dll"}, False, Reason.NOT_INCLUDED, ("<ImageLoad",)),
    (DOC_RULE_GROUPS, 11, {"TargetFilename": "a"}, True, Reason.DEFAULT, ()),
    (
        LEGACY,
        1,
        {"Image": "C:\\cmd.exe", "ParentImage": "C:\\explorer.exe"},
        True,
        Reason.INCLUDED,
        ("cmd.exe", "explorer.exe"),
    ),
    (
        LEGACY,
        1,
        {"Image": "C:\\powershell.exe", "ParentImage": "C:\\explorer.exe"},
        True,
        Reason.INCLUDED,
        ("powershell.exe", "explorer.exe"),
    ),
    (
        LEGACY,
        1,
        {"Image": "C:\\cmd.exe", "ParentImage": "C:\\services.exe"},
        False,
        Reason.NOT_INCLUDED,
        ("<ProcessCreate",),
    ),
    (
        LEGACY_RULE,
        1,
        {"Image": "C:\\cmd.exe", "CommandLine": "cmd /c whoami"},
        True,
        Reason.INCLUDED,
        ("cmd.exe", "/c"),
    ),
    (
        LEGACY_RULE,
        1,
        {"Image": "C:\\cmd.exe", "CommandLine": "cmd /q"},
        False,
        Reason.NOT_INCLUDED,
        ("<ProcessCreate",),
    ),
    (
        LEGACY_RULE,
        1,
        {"Image": "C:\\pwsh.exe", "CommandLine": "pwsh /c"},
        False,
        Reason.NOT_INCLUDED,
        ("<ProcessCreate",),
    ),
    (
        GROUPED_RULE,
        1,
        {"Image": "C:\\powershell.exe", "CommandLine": "powershell -enc AAA", "ParentImage": "x"},
        True,
        Reason.INCLUDED,
        ("powershell.exe", "-enc"),
    ),
    (
        GROUPED_RULE,
        1,
        {"Image": "C:\\powershell.exe", "CommandLine": "powershell -c", "ParentImage": "x"},
        False,
        Reason.NOT_INCLUDED,
        ("<ProcessCreate",),
    ),
    (
        GROUPED_RULE,
        1,
        {"Image": "C:\\cmd.exe", "CommandLine": "cmd", "ParentImage": "C:\\WINWORD.EXE"},
        True,
        Reason.INCLUDED,
        ("winword.exe",),
    ),
    (SEVERAL_FILTERS, 1, {"Image": "C:\\cmd.exe"}, True, Reason.INCLUDED, ("cmd.exe",)),
    (SEVERAL_FILTERS, 1, {"Image": "C:\\powershell.exe"}, True, Reason.INCLUDED, ("powershell",)),
    (
        SEVERAL_FILTERS,
        1,
        {"Image": "C:\\notepad.exe"},
        False,
        Reason.NOT_INCLUDED,
        ('onmatch="include"', "onmatch='include'"),
    ),
    (
        SEVERAL_FILTERS,
        1,
        {"Image": "C:\\cmd.exe", "CommandLine": "safe mode"},
        False,
        Reason.EXCLUDED,
        ("safe",),
    ),
    (ABSENT_FIELDS, 12, {"TargetObject": "HKLM"}, False, Reason.NOT_INCLUDED, ('"include"',)),
    (ABSENT_FIELDS, 13, {"Details": "DWORD (1)"}, True, Reason.INCLUDED, ("<Details",)),
]


def responsible_lines(text: str, needles: tuple[str, ...]) -> tuple[int, ...]:
    return tuple(sorted(line_of(text, needle) for needle in needles))


@pytest.mark.parametrize(("text", "event_id", "fields", "logged", "reason", "needles"), CASES)
def test_emulates_sysmon_filtering(
    text: str,
    event_id: int,
    fields: dict[str, str],
    logged: bool,
    reason: Reason,
    needles: tuple[str, ...],
) -> None:
    config = parse_config(text.encode(), SOURCE)
    expected = Decision(logged, reason, responsible_lines(text, needles))
    assert config.evaluate(Event(event_id, fields)) == expected


def test_events_reject_unknown_event_ids() -> None:
    with pytest.raises(ValueError, match="unknown Sysmon event ID 30"):
        Event(30, {})


def test_event_fields_are_immutable() -> None:
    fields = {"Image": "a"}
    event = Event(1, fields)
    fields["Image"] = "b"
    assert event.fields == {"Image": "a"}
    with pytest.raises(TypeError):
        cast(dict[str, str], event.fields)["Image"] = "c"


def test_rules_need_a_condition() -> None:
    with pytest.raises(ValueError, match="at least one condition"):
        Rule(Relation.AND, (), 1)


def holds(item: Condition | Rule, event: Event) -> bool:
    match item:
        case Condition(field=name, operator=operator, value=value):
            return name in event.fields and operator.matches(event.fields[name], value)
        case Rule(relation=relation, conditions=found):
            outcomes = [holds(condition, event) for condition in found]
            return any(outcomes) if relation is Relation.OR else all(outcomes)


def filter_holds(event_filter: EventFilter, event: Event) -> bool:
    items = event_filter.items
    if event_filter.group_relation is Relation.OR:
        return any(holds(item, event) for item in items)
    if event_filter.group_relation is Relation.AND:
        return bool(items) and all(holds(item, event) for item in items)
    conditions = [item for item in items if isinstance(item, Condition)]
    by_field = {condition.field for condition in conditions}
    fields_hold = all(
        any(holds(condition, event) for condition in conditions if condition.field == name)
        for name in by_field
    )
    rules_hold = all(holds(item, event) for item in items if isinstance(item, Rule))
    return bool(items) and fields_hold and rules_hold


def reference_logged(config: SysmonConfig, event: Event) -> bool:
    tag = TAG_BY_EVENT_ID.get(event.event_id)
    if tag is None:
        return True
    filters = [item for item in config.filters if item.tag is tag]
    includes = [item for item in filters if item.onmatch is OnMatch.INCLUDE]
    excludes = [item for item in filters if item.onmatch is OnMatch.EXCLUDE]
    if not filters:
        return logged_without_filter(tag)
    if any(filter_holds(item, event) for item in excludes):
        return False
    return not includes or any(filter_holds(item, event) for item in includes)


def conditions_of(config: SysmonConfig) -> Iterator[Condition]:
    for event_filter in config.filters:
        for item in event_filter.items:
            yield from item.conditions if isinstance(item, Rule) else (item,)


@given(config=configs, event=events)
def test_emulator_agrees_with_a_reference_written_from_the_documentation(
    config: SysmonConfig, event: Event
) -> None:
    assert config.evaluate(event).logged is reference_logged(config, event)


@given(config=configs, event=events)
def test_decision_lines_point_to_the_responsible_elements(
    config: SysmonConfig, event: Event
) -> None:
    decision = config.evaluate(event)
    lines = set(decision.lines)
    matching = {item.line for item in conditions_of(config) if holds(item, event)}
    match decision.reason:
        case Reason.INCLUDED | Reason.EXCLUDED:
            assert lines and lines <= matching
        case Reason.NOT_INCLUDED:
            assert lines and lines <= {item.line for item in config.filters}
        case _:
            assert not lines


@given(config=configs, event=events, data=st.data())
def test_filter_order_does_not_change_decisions(
    config: SysmonConfig, event: Event, data: st.DataObject
) -> None:
    shuffled = data.draw(st.permutations(config.filters))
    assert config_of(*shuffled).evaluate(event) == config.evaluate(event)


@given(config=configs, event=filterable_events, onmatch=st.sampled_from(OnMatch), data=st.data())
def test_a_matching_filter_decides_unless_an_exclude_matches(
    config: SysmonConfig, event: Event, onmatch: OnMatch, data: st.DataObject
) -> None:
    tag = TAG_BY_EVENT_ID[event.event_id]
    name = data.draw(st.sampled_from(sorted(event.fields)))
    condition = Condition(name, Operator.IS, event.fields[name], 100_000)
    added = EventFilter(tag, onmatch, data.draw(st.none() | relations), (condition,), 100_001)
    before = config.evaluate(event)
    after = config_of(*config.filters, added).evaluate(event)
    excluded = onmatch is OnMatch.EXCLUDE or before.reason is Reason.EXCLUDED
    assert after.logged is not excluded
    assert after.reason is (Reason.EXCLUDED if excluded else Reason.INCLUDED)


@given(
    first=event_filters,
    second=event_filters,
    event=process_events,
    onmatch=st.sampled_from(OnMatch),
)
def test_filters_with_the_same_tag_and_onmatch_combine_with_or(
    first: EventFilter, second: EventFilter, event: Event, onmatch: OnMatch
) -> None:
    pair = [replace(item, tag=EventTag.PROCESS_CREATE, onmatch=onmatch) for item in (first, second)]
    alone = [config_of(item).evaluate(event).logged for item in pair]
    combined = config_of(*pair).evaluate(event).logged
    assert combined is (any(alone) if onmatch is OnMatch.INCLUDE else all(alone))


@given(
    onmatch=st.sampled_from(OnMatch),
    relation=st.none() | relations,
    event=process_events,
)
def test_empty_include_logs_nothing_and_empty_exclude_logs_everything(
    onmatch: OnMatch, relation: Relation | None, event: Event
) -> None:
    empty = EventFilter(EventTag.PROCESS_CREATE, onmatch, relation, (), 1)
    assert config_of(empty).evaluate(event).logged is (onmatch is OnMatch.EXCLUDE)


@given(config=configs, event_id=st.sampled_from(sorted(UNFILTERABLE_EVENT_IDS)))
def test_unfilterable_events_are_always_logged(config: SysmonConfig, event_id: int) -> None:
    assert config.evaluate(Event(event_id, {})) == Decision(True, Reason.UNFILTERABLE)


@pytest.mark.parametrize("event_id", sorted(TAG_BY_EVENT_ID))
def test_event_types_without_filter_follow_the_assumed_default(event_id: int) -> None:
    tag = TAG_BY_EVENT_ID[event_id]
    decision = config_of().evaluate(Event(event_id, {}))
    assert decision == Decision(logged_without_filter(tag), Reason.DEFAULT)
