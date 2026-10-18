import errno
import os
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaString,
    SigmaTimestampPart,
    SigmaType,
    SpecialChars,
)

from sigma_blindspot.sigma.ir import (
    And,
    Branch,
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
    Skipped,
    Suffix,
    Unsupported,
    Wildcard,
)
from sigma_blindspot.sysmon.conditions import fold
from sigma_blindspot.sysmon.events import SIGMA_CATEGORY_TO_EVENT_IDS

type Loaded = LoadedRule | Skipped

PRODUCT: Final = "windows"
RULE_SUFFIX: Final = ".yml"
_WILDCARDS: Final[Mapping[SpecialChars, Wildcard]] = MappingProxyType(
    {SpecialChars.WILDCARD_MULTI: Wildcard.ANY, SpecialChars.WILDCARD_SINGLE: Wildcard.ONE}
)
_UNSUPPORTED_VALUES: Final[tuple[tuple[type[SigmaType], str], ...]] = (
    (SigmaCasedString, "case-sensitive match (cased)"),
    (SigmaTimestampPart, "timestamp modifier"),
    (SigmaRegularExpression, "regular expression (re)"),
    (SigmaCIDRExpression, "CIDR network (cidr)"),
    (SigmaNull, "null value"),
    (SigmaExists, "field existence (exists)"),
    (SigmaCompareExpression, "numeric comparison (lt, lte, gt, gte)"),
    (SigmaFieldReference, "field reference (fieldref)"),
    (SigmaBool, "boolean value"),
    (SigmaQueryExpression, "query expression"),
)


def _flatten[T: (And, Or)](kind: type[T], args: Iterable[Node]) -> Node:
    flat = tuple(item for arg in args for item in (arg.args if isinstance(arg, kind) else (arg,)))
    return flat[0] if len(flat) == 1 else kind(flat)


def _string_pattern(parts: tuple[str | Wildcard, ...]) -> Pattern:
    leading = parts[:1] == (Wildcard.ANY,)
    trailing = len(parts) > 1 and parts[-1] is Wildcard.ANY
    core = parts[leading : len(parts) - trailing]
    if any(isinstance(part, Wildcard) for part in core):
        return Glob(parts)
    text = "".join(part for part in core if isinstance(part, str))
    if leading and (trailing or not core):
        return Contains(text)
    if leading:
        return Suffix(text)
    if trailing:
        return Prefix(text)
    return Equals(text)


def _string(field: str, value: SigmaString) -> Node:
    if any(isinstance(part, Placeholder) for part in value.s):
        return Unsupported("placeholder (expand)")
    parts: list[str | Wildcard] = []
    for part in value.s:
        piece = _WILDCARDS[part] if isinstance(part, SpecialChars) else fold(str(part))
        previous = parts[-1] if parts else None
        if isinstance(piece, str) and isinstance(previous, str):
            parts[-1] = previous + piece
        elif piece != "" and not (piece is Wildcard.ANY and previous is Wildcard.ANY):
            parts.append(piece)
    return Match(field, _string_pattern(tuple(parts)))


def _value(field: str, value: SigmaType) -> Node:
    reason = next((text for kind, text in _UNSUPPORTED_VALUES if isinstance(value, kind)), None)
    if reason is not None:
        return Unsupported(reason)
    match value:
        case SigmaString():
            return _string(field, value)
        case SigmaNumber():
            return Match(field, Equals(fold(str(value))))
        case SigmaExpansion():
            return _flatten(Or, (_value(field, item) for item in value.values))
    return Unsupported(f"value type {type(value).__name__}")


def _node(item: object) -> Node:
    match item:
        case ConditionAND(args=args):
            return _flatten(And, map(_node, args))
        case ConditionOR(args=args):
            return _flatten(Or, map(_node, args))
        case ConditionNOT(args=[arg]):
            return Not(_node(arg))
        case ConditionFieldEqualsValueExpression(field=field, value=value):
            return _value(field, value)
        case ConditionValueExpression():
            return Unsupported("keyword search")
    return Unsupported(f"condition node {type(item).__name__}")


def _identifiers(item: object) -> Iterator[str]:
    node: object = item
    while node is not None:
        if isinstance(node, ConditionIdentifier):
            yield node.identifier
        node = getattr(node, "parent", None)
    for arg in getattr(item, "args", ()):
        yield from _identifiers(arg)


def _top_level(item: object) -> Iterator[object]:
    if isinstance(item, ConditionOR) and isinstance(item.parent, ConditionOR | None):
        for arg in item.args:
            yield from _top_level(arg)
    else:
        yield item


def _branch(number: int, item: object) -> Branch:
    names = ", ".join(dict.fromkeys(_identifiers(item)))
    return Branch(f"#{number} {names}" if names else f"#{number}", _node(item))


def _describe(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"


def _in_scope(rule: SigmaRule) -> bool:
    logsource = rule.logsource
    return (
        logsource.product == PRODUCT
        and not logsource.service
        and logsource.category in SIGMA_CATEGORY_TO_EVENT_IDS
    )


def _rule(source: str, rule: SigmaRule | SigmaCorrelationRule) -> Loaded:
    if isinstance(rule, SigmaCorrelationRule):
        return Skipped(source, rule.title, "correlation rule")
    if not _in_scope(rule) or rule.logsource.category is None:
        return Skipped(source, rule.title, "not a Sysmon log source")
    try:
        trees = [condition.parsed for condition in rule.detection.parsed_condition]
    except Exception as error:
        return Skipped(source, rule.title, _describe(error))
    items = [item for tree in trees for item in _top_level(tree)]
    return LoadedRule(
        source=source,
        title=rule.title,
        rule_id=None if rule.id is None else str(rule.id),
        category=rule.logsource.category,
        event_ids=SIGMA_CATEGORY_TO_EVENT_IDS[rule.logsource.category],
        tags=tuple(f"{tag.namespace}.{tag.name}" for tag in rule.tags),
        branches=tuple(_branch(number, item) for number, item in enumerate(items, start=1)),
    )


def parse_rules(data: bytes, source: str) -> tuple[Loaded, ...]:
    try:
        collection = SigmaCollection.from_yaml(data, collect_filters=True, resolve_references=False)
    except Exception as error:
        return (Skipped(source, None, _describe(error)),)
    rules = tuple(_rule(source, rule) for rule in collection.rules)
    filters = tuple(Skipped(source, item.title, "filter rule") for item in collection.filters)
    return rules + filters or (Skipped(source, None, "no rule in file"),)


def _load_file(path: Path) -> tuple[Loaded, ...]:
    try:
        data = path.read_bytes()
    except OSError as error:
        return (Skipped(str(path), None, _describe(error)),)
    return parse_rules(data, str(path))


def rule_files(path: Path) -> tuple[Path, ...]:
    if not path.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(path))
    if not path.is_dir():
        return (path,)
    found = (item for item in path.rglob(f"*{RULE_SUFFIX}") if item.is_file())
    return tuple(sorted(found, key=lambda item: item.relative_to(path).parts))


def load_rules(paths: Iterable[Path]) -> tuple[Loaded, ...]:
    files = tuple(file for path in paths for file in rule_files(path))
    return tuple(loaded for file in files for loaded in _load_file(file))
