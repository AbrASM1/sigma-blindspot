import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import chain
from pathlib import Path
from types import MappingProxyType
from typing import Final, NoReturn
from xml.parsers import expat

from sigma_blindspot.errors import ConfigError
from sigma_blindspot.sysmon.conditions import Operator
from sigma_blindspot.sysmon.events import EventTag
from sigma_blindspot.sysmon.model import (
    Condition,
    EventFilter,
    OnMatch,
    Relation,
    Rule,
    SysmonConfig,
)
from sigma_blindspot.sysmon.semantics import Semantic, assumes

_ROOT: Final = "Sysmon"
_EVENT_FILTERING: Final = "EventFiltering"
_RULE_GROUP: Final = "RuleGroup"
_RULE: Final = "Rule"
_XML_WHITESPACE: Final = " \t\r\n"
_SCHEMA_VERSION: Final = re.compile(r"[0-9]+\.[0-9]+")


@dataclass(frozen=True, slots=True)
class _Element:
    tag: str
    attributes: Mapping[str, str]
    text: str
    children: tuple["_Element", ...]
    line: int


@dataclass(slots=True)
class _OpenElement:
    tag: str
    attributes: dict[str, str]
    line: int
    text: list[str] = field(default_factory=list)
    children: list[_Element] = field(default_factory=list)

    def close(self) -> _Element:
        return _Element(
            self.tag,
            MappingProxyType(self.attributes),
            "".join(self.text),
            tuple(self.children),
            self.line,
        )


def _read_tree(data: bytes, source: str) -> _Element:
    parser = expat.ParserCreate()
    parser.buffer_text = True
    stack = [_OpenElement("", {}, 0)]

    def start(tag: str, attributes: dict[str, str]) -> None:
        stack.append(_OpenElement(tag, attributes, parser.CurrentLineNumber))

    def end(_: str) -> None:
        element = stack.pop().close()
        stack[-1].children.append(element)

    def text(content: str) -> None:
        stack[-1].text.append(content)

    def doctype(*_: object) -> NoReturn:
        raise ConfigError("DOCTYPE declarations are not allowed", parser.CurrentLineNumber, source)

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = doctype
    try:
        parser.Parse(data, True)
    except expat.ExpatError as error:
        raise ConfigError(expat.ErrorString(error.code), error.lineno, source) from error
    return stack[0].children[0]


def _member[E: StrEnum](kind: type[E], raw: str | None) -> E | None:
    return next((candidate for candidate in kind if candidate == raw), None)


@dataclass(frozen=True, slots=True)
class _Interpreter:
    source: str

    def fail(self, element: _Element, message: str) -> NoReturn:
        raise ConfigError(message, element.line, self.source)

    def check(
        self, element: _Element, required: tuple[str, ...] = (), optional: tuple[str, ...] = ()
    ) -> None:
        missing = [name for name in required if name not in element.attributes]
        unknown = sorted(element.attributes.keys() - {*required, *optional})
        if missing:
            self.fail(element, f"<{element.tag}> requires attribute {missing[0]!r}")
        if unknown:
            self.fail(element, f"<{element.tag}> does not allow attribute {unknown[0]!r}")

    def check_container(
        self, element: _Element, required: tuple[str, ...] = (), optional: tuple[str, ...] = ()
    ) -> None:
        self.check(element, required, optional)
        if element.text.strip(_XML_WHITESPACE):
            self.fail(element, f"<{element.tag}> cannot contain text")

    def choice[E: StrEnum](
        self, element: _Element, attribute: str, kind: type[E], default: E | None = None
    ) -> E:
        raw = element.attributes.get(attribute, default)
        member = _member(kind, raw)
        if member is None:
            allowed = ", ".join(repr(candidate.value) for candidate in kind)
            self.fail(element, f"<{element.tag}> {attribute}={raw!r} is not one of {allowed}")
        return member

    def config(self, root: _Element) -> SysmonConfig:
        if root.tag != _ROOT:
            self.fail(root, f"the root element must be <{_ROOT}>, not <{root.tag}>")
        self.check_container(root, required=("schemaversion",))
        version = root.attributes["schemaversion"]
        if not _SCHEMA_VERSION.fullmatch(version):
            self.fail(root, f"schemaversion {version!r} is not a MAJOR.MINOR version")
        sections = [child for child in root.children if child.tag == _EVENT_FILTERING]
        if len(sections) > 1:
            self.fail(sections[1], f"<{_EVENT_FILTERING}> appears more than once")
        filters = tuple(chain.from_iterable(map(self.event_filtering, sections)))
        return SysmonConfig(version, filters, self.source)

    def event_filtering(self, element: _Element) -> tuple[EventFilter, ...]:
        self.check_container(element)
        return tuple(chain.from_iterable(map(self.block, element.children)))

    def block(self, element: _Element) -> tuple[EventFilter, ...]:
        if element.tag == _RULE_GROUP:
            return self.rule_group(element)
        return (self.event_filter(element, None),)

    def rule_group(self, element: _Element) -> tuple[EventFilter, ...]:
        self.check_container(element, required=("groupRelation",), optional=("name",))
        relation = self.choice(element, "groupRelation", Relation)
        return tuple(self.event_filter(child, relation) for child in element.children)

    def event_filter(self, element: _Element, relation: Relation | None) -> EventFilter:
        tag = _member(EventTag, element.tag)
        if tag is None:
            self.fail(element, f"<{element.tag}> is not a Sysmon event filter")
        self.check_container(element, required=("onmatch",))
        onmatch = self.choice(element, "onmatch", OnMatch)
        items = tuple(map(self.item, element.children))
        return EventFilter(tag, onmatch, relation, items, element.line)

    def item(self, element: _Element) -> Condition | Rule:
        if element.tag == _RULE:
            return self.rule(element)
        return self.condition(element)

    def rule(self, element: _Element) -> Rule:
        self.check_container(element, required=("groupRelation",), optional=("name",))
        relation = self.choice(element, "groupRelation", Relation)
        if not element.children:
            self.fail(element, f"<{_RULE}> needs at least one condition")
        conditions = tuple(map(self.condition, element.children))
        return Rule(relation, conditions, element.line, element.attributes.get("name"))

    @assumes(Semantic.LITERAL_WHITESPACE)
    def condition(self, element: _Element) -> Condition:
        if element.tag in (_RULE, _RULE_GROUP):
            self.fail(element, f"<{element.tag}> is not allowed here")
        self.check(element, optional=("condition", "name"))
        if element.children:
            self.fail(element.children[0], f"field <{element.tag}> cannot contain elements")
        operator = self.choice(element, "condition", Operator, Operator.IS)
        name = element.attributes.get("name")
        return Condition(element.tag, operator, element.text, element.line, name)


def parse_config(data: bytes, source: str) -> SysmonConfig:
    return _Interpreter(source).config(_read_tree(data, source))


def load_config(path: Path) -> SysmonConfig:
    return parse_config(path.read_bytes(), str(path))
