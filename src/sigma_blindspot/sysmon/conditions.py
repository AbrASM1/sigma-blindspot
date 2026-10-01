from collections.abc import Callable, Mapping
from enum import StrEnum
from operator import eq, ne
from types import MappingProxyType
from typing import Final

from sigma_blindspot.sysmon.semantics import Semantic, assumes

type Predicate = Callable[[str, str], bool]


class Operator(StrEnum):
    IS = "is"
    IS_ANY = "is any"
    IS_NOT = "is not"
    CONTAINS = "contains"
    CONTAINS_ANY = "contains any"
    CONTAINS_ALL = "contains all"
    EXCLUDES = "excludes"
    EXCLUDES_ANY = "excludes any"
    EXCLUDES_ALL = "excludes all"
    BEGIN_WITH = "begin with"
    END_WITH = "end with"
    NOT_BEGIN_WITH = "not begin with"
    NOT_END_WITH = "not end with"
    LESS_THAN = "less than"
    MORE_THAN = "more than"
    IMAGE = "image"

    def matches(self, field: str, value: str) -> bool:
        return _PREDICATES[self](fold(field), fold(value))


@assumes(Semantic.CASE_FOLDING)
def fold(text: str) -> str:
    return text.lower()


@assumes(Semantic.EMPTY_LIST_ITEM)
def split_values(value: str) -> tuple[str, ...]:
    return tuple(item for item in value.split(";") if item)


def _negate(predicate: Predicate) -> Predicate:
    return lambda field, value: not predicate(field, value)


def _contains(field: str, value: str) -> bool:
    return value in field


def _is_any(field: str, value: str) -> bool:
    return field in split_values(value)


def _contains_any(field: str, value: str) -> bool:
    return any(item in field for item in split_values(value))


def _contains_all(field: str, value: str) -> bool:
    return all(item in field for item in split_values(value))


def _image(field: str, value: str) -> bool:
    return value in (field, field.rpartition("\\")[2])


@assumes(Semantic.LEXICAL_COMPARISON)
def _less_than(field: str, value: str) -> bool:
    return field < value


@assumes(Semantic.LEXICAL_COMPARISON)
def _more_than(field: str, value: str) -> bool:
    return field > value


_PREDICATES: Final[Mapping[Operator, Predicate]] = MappingProxyType(
    {
        Operator.IS: eq,
        Operator.IS_ANY: _is_any,
        Operator.IS_NOT: ne,
        Operator.CONTAINS: _contains,
        Operator.CONTAINS_ANY: _contains_any,
        Operator.CONTAINS_ALL: _contains_all,
        Operator.EXCLUDES: _negate(_contains),
        Operator.EXCLUDES_ANY: _negate(_contains_all),
        Operator.EXCLUDES_ALL: _negate(_contains_any),
        Operator.BEGIN_WITH: str.startswith,
        Operator.END_WITH: str.endswith,
        Operator.NOT_BEGIN_WITH: _negate(str.startswith),
        Operator.NOT_END_WITH: _negate(str.endswith),
        Operator.LESS_THAN: _less_than,
        Operator.MORE_THAN: _more_than,
        Operator.IMAGE: _image,
    }
)
