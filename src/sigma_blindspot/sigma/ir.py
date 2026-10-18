from dataclasses import dataclass
from enum import Enum


class Wildcard(Enum):
    ANY = "*"
    ONE = "?"


@dataclass(frozen=True, slots=True)
class Equals:
    value: str


@dataclass(frozen=True, slots=True)
class Prefix:
    value: str


@dataclass(frozen=True, slots=True)
class Suffix:
    value: str


@dataclass(frozen=True, slots=True)
class Contains:
    value: str


@dataclass(frozen=True, slots=True)
class Glob:
    parts: tuple[str | Wildcard, ...]


type Pattern = Equals | Prefix | Suffix | Contains | Glob


@dataclass(frozen=True, slots=True)
class Match:
    field: str
    pattern: Pattern


@dataclass(frozen=True, slots=True)
class Unsupported:
    reason: str


@dataclass(frozen=True, slots=True)
class Not:
    arg: "Node"


@dataclass(frozen=True, slots=True)
class And:
    args: tuple["Node", ...]


@dataclass(frozen=True, slots=True)
class Or:
    args: tuple["Node", ...]


type Node = And | Or | Not | Match | Unsupported


@dataclass(frozen=True, slots=True)
class Branch:
    label: str
    condition: Node


@dataclass(frozen=True, slots=True)
class LoadedRule:
    source: str
    title: str
    rule_id: str | None
    category: str
    event_ids: tuple[int, ...]
    tags: tuple[str, ...]
    branches: tuple[Branch, ...]

    @property
    def condition(self) -> Node:
        return Or(tuple(branch.condition for branch in self.branches))


@dataclass(frozen=True, slots=True)
class Skipped:
    source: str
    title: str | None
    reason: str


def unsupported(node: Node) -> tuple[str, ...]:
    match node:
        case Unsupported(reason=reason):
            return (reason,)
        case Not(arg=arg):
            return unsupported(arg)
        case And(args=args) | Or(args=args):
            return tuple(dict.fromkeys(reason for arg in args for reason in unsupported(arg)))
        case Match():
            return ()


def fields(node: Node) -> tuple[str, ...]:
    match node:
        case Match(field=name):
            return (name,)
        case Not(arg=arg):
            return fields(arg)
        case And(args=args) | Or(args=args):
            return tuple(dict.fromkeys(name for arg in args for name in fields(arg)))
        case Unsupported():
            return ()
