from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from sigma_blindspot.sigma.ir import (
    And,
    Contains,
    Equals,
    LessThan,
    Match,
    MoreThan,
    Node,
    Not,
    Or,
    Prefix,
    Suffix,
)
from sigma_blindspot.sysmon.conditions import Operator, fold, split_values
from sigma_blindspot.sysmon.model import (
    Condition,
    EventFilter,
    Lines,
    OnMatch,
    Relation,
    Rule,
)
from sigma_blindspot.sysmon.semantics import Semantic, assumes

type Translator = Callable[[str, str], Node]

_NOTHING: Final = Or(())


@dataclass(frozen=True, slots=True)
class Tracked:
    node: Node
    lines: Lines


def _negate(translate: Translator) -> Translator:
    return lambda field, value: Not(translate(field, value))


def _every(translate: Translator) -> Translator:
    return lambda field, value: And(tuple(translate(field, item) for item in split_values(value)))


def _some(translate: Translator) -> Translator:
    return lambda field, value: Or(tuple(translate(field, item) for item in split_values(value)))


def _is(field: str, value: str) -> Node:
    return Match(field, Equals(value))


def _contains(field: str, value: str) -> Node:
    return Match(field, Contains(value))


def _begin_with(field: str, value: str) -> Node:
    return Match(field, Prefix(value))


def _end_with(field: str, value: str) -> Node:
    return Match(field, Suffix(value))


def _image(field: str, value: str) -> Node:
    if "\\" in value:
        return _is(field, value)
    return Or((_is(field, value), _end_with(field, "\\" + value)))


@assumes(Semantic.LEXICAL_COMPARISON)
def _less_than(field: str, value: str) -> Node:
    return Match(field, LessThan(value))


@assumes(Semantic.LEXICAL_COMPARISON)
def _more_than(field: str, value: str) -> Node:
    return Match(field, MoreThan(value))


_TRANSLATORS: Final[Mapping[Operator, Translator]] = MappingProxyType(
    {
        Operator.IS: _is,
        Operator.IS_ANY: _some(_is),
        Operator.IS_NOT: _negate(_is),
        Operator.CONTAINS: _contains,
        Operator.CONTAINS_ANY: _some(_contains),
        Operator.CONTAINS_ALL: _every(_contains),
        Operator.EXCLUDES: _negate(_contains),
        Operator.EXCLUDES_ANY: _negate(_every(_contains)),
        Operator.EXCLUDES_ALL: _negate(_some(_contains)),
        Operator.BEGIN_WITH: _begin_with,
        Operator.END_WITH: _end_with,
        Operator.NOT_BEGIN_WITH: _negate(_begin_with),
        Operator.NOT_END_WITH: _negate(_end_with),
        Operator.LESS_THAN: _less_than,
        Operator.MORE_THAN: _more_than,
        Operator.IMAGE: _image,
    }
)


def translate_condition(condition: Condition) -> Node:
    return _TRANSLATORS[condition.operator](condition.field, fold(condition.value))


def _combined(relation: Relation, nodes: tuple[Node, ...]) -> Node:
    if not nodes:
        return _NOTHING
    return And(nodes) if relation is Relation.AND else Or(nodes)


@assumes(Semantic.RULE_RELATION)
def _item(item: Condition | Rule) -> Node:
    match item:
        case Rule():
            return _combined(item.relation, tuple(map(translate_condition, item.conditions)))
        case Condition():
            return translate_condition(item)


@assumes(Semantic.LEGACY_RULE)
def _legacy(event_filter: EventFilter) -> Node:
    by_field: dict[str, list[Node]] = {}
    rules: list[Node] = []
    for item in event_filter.items:
        match item:
            case Rule():
                rules.append(_item(item))
            case Condition():
                by_field.setdefault(item.field, []).append(translate_condition(item))
    fields = (Or(tuple(group)) for group in by_field.values())
    return _combined(Relation.AND, (*fields, *rules))


def translate_filter(event_filter: EventFilter) -> Node:
    if event_filter.group_relation is None:
        return _legacy(event_filter)
    return _combined(event_filter.group_relation, tuple(map(_item, event_filter.items)))


def _exclusions(event_filter: EventFilter) -> Iterator[Tracked]:
    if event_filter.group_relation is Relation.OR:
        for item in event_filter.items:
            yield Tracked(Not(_item(item)), (item.line,))
    else:
        yield Tracked(Not(translate_filter(event_filter)), (event_filter.line,))


@assumes(Semantic.SEVERAL_FILTERS)
def encode_config(filters: tuple[EventFilter, ...]) -> tuple[Tracked, ...]:
    includes = [item for item in filters if item.onmatch is OnMatch.INCLUDE]
    excludes = [item for item in filters if item.onmatch is OnMatch.EXCLUDE]
    tracked = [found for item in excludes for found in _exclusions(item)]
    if includes:
        lines = tuple(sorted({item.line for item in includes}))
        tracked.append(Tracked(Or(tuple(map(translate_filter, includes))), lines))
    return tuple(tracked)
