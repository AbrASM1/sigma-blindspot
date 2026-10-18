import re
from collections.abc import Iterable, Mapping
from functools import cache
from types import MappingProxyType
from typing import Final

from sigma_blindspot.sigma.ir import (
    And,
    Contains,
    Equals,
    Glob,
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
from sigma_blindspot.sysmon.conditions import fold
from sigma_blindspot.sysmon.jsonl import EVENT_ID_KEY
from sigma_blindspot.sysmon.model import Event

_GLOB_SYNTAX: Final[Mapping[Wildcard, str]] = MappingProxyType(
    {Wildcard.ANY: ".*", Wildcard.ONE: "."}
)


def _glob_piece(part: str | Wildcard) -> str:
    return _GLOB_SYNTAX[part] if isinstance(part, Wildcard) else re.escape(part)


@cache
def glob_regex(parts: tuple[str | Wildcard, ...]) -> re.Pattern[str]:
    return re.compile("".join(map(_glob_piece, parts)), re.DOTALL)


def pattern_matches(pattern: Pattern, value: str) -> bool:
    match pattern:
        case Equals(value=text):
            return value == text
        case Prefix(value=text):
            return value.startswith(text)
        case Suffix(value=text):
            return value.endswith(text)
        case Contains(value=text):
            return text in value
        case Glob(parts=parts):
            return glob_regex(parts).fullmatch(value) is not None


def _all(outcomes: Iterable[bool | None]) -> bool | None:
    found = set(outcomes)
    return False if False in found else None if None in found else True


def _any(outcomes: Iterable[bool | None]) -> bool | None:
    found = set(outcomes)
    return True if True in found else None if None in found else False


def field_value(event: Event, name: str) -> str | None:
    return str(event.event_id) if name == EVENT_ID_KEY else event.fields.get(name)


def evaluate(node: Node, event: Event) -> bool | None:
    match node:
        case Match(field=name, pattern=pattern):
            actual = field_value(event, name)
            return actual is not None and pattern_matches(pattern, fold(actual))
        case Not(arg=arg):
            outcome = evaluate(arg, event)
            return None if outcome is None else not outcome
        case And(args=args):
            return _all(evaluate(arg, event) for arg in args)
        case Or(args=args):
            return _any(evaluate(arg, event) for arg in args)
        case Unsupported():
            return None
