import codecs
from dataclasses import replace
from itertools import groupby
from typing import Final
from xml.sax.saxutils import escape, quoteattr

from hypothesis import strategies as st

from sigma_blindspot.sysmon.conditions import Operator
from sigma_blindspot.sysmon.events import EventTag
from sigma_blindspot.sysmon.model import (
    Condition,
    Event,
    EventFilter,
    OnMatch,
    Relation,
    Rule,
    SysmonConfig,
)

SOURCE: Final = "config.xml"
FIELDS: Final = ("Image", "CommandLine", "User")
TAGS: Final = (EventTag.PROCESS_CREATE, EventTag.REGISTRY_EVENT)
EVENT_IDS: Final = (1, 3, 4, 12, 13)
BYTE_ORDER_MARKS: Final = {
    "utf-8": ("UTF-8", b"", "utf-8"),
    "utf-8-bom": ("UTF-8", codecs.BOM_UTF8, "utf-8"),
    "utf-16-le": ("UTF-16", codecs.BOM_UTF16_LE, "utf-16-le"),
    "utf-16-be": ("UTF-16", codecs.BOM_UTF16_BE, "utf-16-be"),
}

texts = st.text(alphabet="aAb\\;", max_size=3)
lines = st.integers(min_value=1, max_value=99_000)
relations = st.sampled_from(Relation)
operators = st.sampled_from(Operator)
encodings = st.sampled_from(sorted(BYTE_ORDER_MARKS))

conditions = st.builds(
    Condition, field=st.sampled_from(FIELDS), operator=operators, value=texts, line=lines
)
rules = st.builds(
    Rule,
    relation=relations,
    conditions=st.lists(conditions, min_size=1, max_size=3).map(tuple),
    line=lines,
)
event_filters = st.builds(
    EventFilter,
    tag=st.sampled_from(TAGS),
    onmatch=st.sampled_from(OnMatch),
    group_relation=st.none() | relations,
    items=st.lists(conditions | rules, max_size=4).map(tuple),
    line=lines,
)
configs = st.lists(event_filters, max_size=5).map(lambda found: config_of(*found))
event_fields = st.dictionaries(st.sampled_from(FIELDS), texts)
events = st.builds(Event, event_id=st.sampled_from(EVENT_IDS), fields=event_fields)
process_events = st.builds(Event, event_id=st.just(1), fields=event_fields)
filterable_events = st.builds(
    Event,
    event_id=st.sampled_from((1, 3, 12, 13)),
    fields=st.dictionaries(st.sampled_from(FIELDS), texts, min_size=1),
)

xml_texts = st.text(
    st.characters(exclude_categories=("Cs", "Cc", "Cn")) | st.sampled_from("\t\n\r"), max_size=12
)
xml_names = st.none() | xml_texts
field_names = st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,10}", fullmatch=True).filter(
    lambda name: name not in ("Rule", "RuleGroup")
)
xml_conditions = st.builds(
    Condition,
    field=field_names,
    operator=operators,
    value=xml_texts,
    line=st.just(0),
    name=xml_names,
)
xml_rules = st.builds(
    Rule,
    relation=relations,
    conditions=st.lists(xml_conditions, min_size=1, max_size=3).map(tuple),
    line=st.just(0),
    name=xml_names,
)
xml_filters = st.builds(
    EventFilter,
    tag=st.sampled_from(EventTag),
    onmatch=st.sampled_from(OnMatch),
    group_relation=st.none() | relations,
    items=st.lists(xml_conditions | xml_rules, max_size=4).map(tuple),
    line=st.just(0),
)
xml_documents = st.lists(xml_filters, max_size=5).map(tuple)


def config_of(*filters: EventFilter) -> SysmonConfig:
    return SysmonConfig("4.90", filters, SOURCE)


def encode(text: str, encoding: str) -> bytes:
    _, mark, codec = BYTE_ORDER_MARKS[encoding]
    return mark + text.encode(codec)


class _Document:
    def __init__(self) -> None:
        self.parts: list[str] = []
        self.line = 1

    def write(self, text: str) -> int:
        start = self.line
        self.parts.append(text)
        self.line += text.count("\n")
        return start


def _attributes(**values: str | None) -> str:
    return "".join(f" {key}={quoteattr(value)}" for key, value in values.items() if value)


def _condition(document: _Document, condition: Condition, indent: str) -> Condition:
    operator = None if condition.operator is Operator.IS else condition.operator
    attributes = _attributes(condition=operator)
    named = "" if condition.name is None else f" name={quoteattr(condition.name)}"
    value = escape(condition.value, {"\r": "&#13;"})
    tag = condition.field
    line = document.write(f"{indent}<{tag}{attributes}{named}>{value}</{tag}>\n")
    return replace(condition, line=line)


def _rule(document: _Document, rule: Rule, indent: str) -> Rule:
    named = "" if rule.name is None else f" name={quoteattr(rule.name)}"
    line = document.write(f"{indent}<Rule{_attributes(groupRelation=rule.relation)}{named}>\n")
    found = tuple(_condition(document, condition, indent + "  ") for condition in rule.conditions)
    document.write(f"{indent}</Rule>\n")
    return replace(rule, conditions=found, line=line)


def _item(document: _Document, item: Condition | Rule, indent: str) -> Condition | Rule:
    match item:
        case Rule():
            return _rule(document, item, indent)
        case Condition():
            return _condition(document, item, indent)


def _filter(document: _Document, event_filter: EventFilter, indent: str) -> EventFilter:
    tag = event_filter.tag
    line = document.write(f"{indent}<{tag}{_attributes(onmatch=event_filter.onmatch)}>\n")
    items = tuple(_item(document, item, indent + "  ") for item in event_filter.items)
    document.write(f"{indent}</{tag}>\n")
    return replace(event_filter, items=items, line=line)


def render(filters: tuple[EventFilter, ...], encoding: str) -> tuple[str, SysmonConfig]:
    declared, _, _ = BYTE_ORDER_MARKS[encoding]
    document = _Document()
    document.write(f'<?xml version="1.0" encoding="{declared}"?>\n')
    document.write('<Sysmon schemaversion="4.90">\n')
    document.write("  <HashAlgorithms>md5,sha256</HashAlgorithms>\n")
    document.write("  <EventFiltering>\n")
    rendered: list[EventFilter] = []
    for relation, group in groupby(filters, key=lambda event_filter: event_filter.group_relation):
        if relation is None:
            rendered.extend(_filter(document, event_filter, "    ") for event_filter in group)
            continue
        document.write(f'    <RuleGroup name=""{_attributes(groupRelation=relation)}>\n')
        rendered.extend(_filter(document, event_filter, "      ") for event_filter in group)
        document.write("    </RuleGroup>\n")
    document.write("  </EventFiltering>\n")
    document.write("</Sysmon>\n")
    return "".join(document.parts), config_of(*rendered)
