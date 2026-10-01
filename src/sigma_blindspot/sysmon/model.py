from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import chain
from types import MappingProxyType

from sigma_blindspot.sysmon.conditions import Operator
from sigma_blindspot.sysmon.events import (
    EVENT_IDS,
    TAG_BY_EVENT_ID,
    EventTag,
    logged_without_filter,
)
from sigma_blindspot.sysmon.semantics import Semantic, assumes

type Lines = tuple[int, ...]


class OnMatch(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class Relation(StrEnum):
    AND = "and"
    OR = "or"


class Reason(StrEnum):
    UNFILTERABLE = "cannot be filtered"
    DEFAULT = "no filter for this event type, assumed default"
    INCLUDED = "matched an include filter"
    EXCLUDED = "matched an exclude filter"
    NOT_INCLUDED = "matched no include filter"
    NOT_EXCLUDED = "matched no exclude filter"


def _combine(relation: Relation, parts: Iterable[Lines]) -> Lines:
    collected = tuple(parts)
    if not collected or (relation is Relation.AND and not all(collected)):
        return ()
    return tuple(sorted(set(chain.from_iterable(collected))))


@dataclass(frozen=True, slots=True)
class Event:
    event_id: int
    fields: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.event_id not in EVENT_IDS:
            raise ValueError(f"unknown Sysmon event ID {self.event_id}")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))


@dataclass(frozen=True, slots=True)
class Condition:
    field: str
    operator: Operator
    value: str
    line: int
    name: str | None = None

    @assumes(Semantic.ABSENT_FIELD)
    def matching_lines(self, event: Event) -> Lines:
        actual = event.fields.get(self.field)
        if actual is None or not self.operator.matches(actual, self.value):
            return ()
        return (self.line,)


@dataclass(frozen=True, slots=True)
class Rule:
    relation: Relation
    conditions: tuple[Condition, ...]
    line: int
    name: str | None = None

    def __post_init__(self) -> None:
        if not self.conditions:
            raise ValueError("a Rule needs at least one condition")

    @assumes(Semantic.RULE_RELATION)
    def matching_lines(self, event: Event) -> Lines:
        return _combine(self.relation, (item.matching_lines(event) for item in self.conditions))


@dataclass(frozen=True, slots=True)
class EventFilter:
    tag: EventTag
    onmatch: OnMatch
    group_relation: Relation | None
    items: tuple[Condition | Rule, ...]
    line: int

    def matching_lines(self, event: Event) -> Lines:
        if self.group_relation is None:
            return self._legacy_matching_lines(event)
        return _combine(self.group_relation, (item.matching_lines(event) for item in self.items))

    @assumes(Semantic.LEGACY_RULE)
    def _legacy_matching_lines(self, event: Event) -> Lines:
        by_field: dict[str, list[Lines]] = {}
        rules: list[Lines] = []
        for item in self.items:
            match item:
                case Rule():
                    rules.append(item.matching_lines(event))
                case Condition():
                    by_field.setdefault(item.field, []).append(item.matching_lines(event))
        fields = (_combine(Relation.OR, lines) for lines in by_field.values())
        return _combine(Relation.AND, chain(fields, rules))


@dataclass(frozen=True, slots=True)
class Decision:
    logged: bool
    reason: Reason
    lines: Lines = ()


@assumes(Semantic.SEVERAL_FILTERS)
def _decide(filters: tuple[EventFilter, ...], event: Event) -> Decision:
    includes = tuple(item for item in filters if item.onmatch is OnMatch.INCLUDE)
    excludes = tuple(item for item in filters if item.onmatch is OnMatch.EXCLUDE)
    excluded = _combine(Relation.OR, (item.matching_lines(event) for item in excludes))
    if excluded:
        return Decision(False, Reason.EXCLUDED, excluded)
    if not includes:
        return Decision(True, Reason.NOT_EXCLUDED)
    included = _combine(Relation.OR, (item.matching_lines(event) for item in includes))
    if included:
        return Decision(True, Reason.INCLUDED, included)
    filter_lines = _combine(Relation.OR, ((item.line,) for item in includes))
    return Decision(False, Reason.NOT_INCLUDED, filter_lines)


@dataclass(frozen=True, slots=True)
class SysmonConfig:
    schema_version: str
    filters: tuple[EventFilter, ...]
    source: str
    _by_tag: Mapping[EventTag, tuple[EventFilter, ...]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        grouped: dict[EventTag, list[EventFilter]] = {}
        for event_filter in self.filters:
            grouped.setdefault(event_filter.tag, []).append(event_filter)
        by_tag = {tag: tuple(group) for tag, group in grouped.items()}
        object.__setattr__(self, "_by_tag", MappingProxyType(by_tag))

    def filters_for(self, tag: EventTag) -> tuple[EventFilter, ...]:
        return self._by_tag.get(tag, ())

    def evaluate(self, event: Event) -> Decision:
        tag = TAG_BY_EVENT_ID.get(event.event_id)
        if tag is None:
            return Decision(True, Reason.UNFILTERABLE)
        filters = self.filters_for(tag)
        if not filters:
            return Decision(logged_without_filter(tag), Reason.DEFAULT)
        return _decide(filters, event)
