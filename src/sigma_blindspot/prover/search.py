import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

import z3

from sigma_blindspot.prover.languages import Languages, Literal, check_pattern
from sigma_blindspot.prover.strings import read
from sigma_blindspot.sigma.evaluate import pattern_matches
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
    fields,
)
from sigma_blindspot.sysmon.jsonl import EVENT_ID_KEY
from sigma_blindspot.sysmon.semantics import Semantic, assumes

type Formula = Any
type Values = tuple[tuple[str, str], ...]
type Truth = Callable[["Atom"], bool]

MAX_ROUNDS: Final = 1000
_FILLER: Final = "x"


@dataclass(frozen=True, slots=True)
class Atom:
    field: str
    pattern: Pattern


@dataclass(frozen=True, slots=True)
class Encoded:
    formula: Formula
    node: Node
    event_id: int | None


@dataclass(frozen=True, slots=True)
class Outcome:
    result: Any
    values: Values = ()
    core: tuple[str, ...] = ()
    why_unknown: str = ""


class GaveUp(Exception):
    pass


class Undecided(Enum):
    UNDECIDED = "undecided"


UNDECIDED: Final = Undecided.UNDECIDED


def minimal[T](items: Sequence[T], inconsistent: Callable[[Sequence[T]], bool]) -> list[T]:
    def explain(base: list[T], extended: bool, part: Sequence[T]) -> list[T]:
        if extended and inconsistent(base):
            return []
        if len(part) <= 1:
            return list(part)
        first, second = part[: len(part) // 2], part[len(part) // 2 :]
        right = explain([*base, *first], True, second)
        left = explain([*base, *right], bool(right), first)
        return [*left, *right]

    return explain([], False, items)


def _constant(name: str, pattern: Pattern, event_id: int | None) -> bool | None:
    if name == EVENT_ID_KEY and event_id is not None:
        return pattern_matches(pattern, str(event_id))
    return None


def _holds(node: Node, event_id: int | None, truth: Truth) -> bool:
    match node:
        case Match(field=name, pattern=pattern):
            fixed = _constant(name, pattern, event_id)
            return truth(Atom(name, pattern)) if fixed is None else fixed
        case Not(arg=arg):
            return not _holds(arg, event_id, truth)
        case And(args=args):
            return all(_holds(arg, event_id, truth) for arg in args)
        case Or(args=args):
            return any(_holds(arg, event_id, truth) for arg in args)
        case Unsupported(reason=reason):
            raise ValueError(f"cannot encode an unsupported construct: {reason}")


def _justify(
    node: Node, wanted: bool, event_id: int | None, truth: Truth, found: dict[Atom, bool]
) -> None:
    match node:
        case Match(field=name, pattern=pattern):
            if _constant(name, pattern, event_id) is None:
                found[Atom(name, pattern)] = wanted
        case Not(arg=arg):
            _justify(arg, not wanted, event_id, truth, found)
        case And(args=args) if wanted:
            for arg in args:
                _justify(arg, wanted, event_id, truth, found)
        case Or(args=args) if not wanted:
            for arg in args:
                _justify(arg, wanted, event_id, truth, found)
        case And(args=args) | Or(args=args):
            chosen = next(arg for arg in args if _holds(arg, event_id, truth) is wanted)
            _justify(chosen, wanted, event_id, truth, found)


def _subsumed(kept: Pattern, dropped: Pattern) -> bool:
    match kept, dropped:
        case _, Prefix(value="") | Suffix(value="") | Contains(value=""):
            return True
        case Prefix(value=inner), Prefix(value=outer):
            return inner.startswith(outer)
        case Suffix(value=inner), Suffix(value=outer):
            return inner.endswith(outer)
        case Prefix(value=inner) | Suffix(value=inner) | Contains(value=inner), Contains(
            value=outer
        ):
            return outer in inner
    return False


def _glob_text(parts: tuple[str | Wildcard, ...]) -> str:
    return "".join(
        _FILLER if part is Wildcard.ONE else "" if part is Wildcard.ANY else part for part in parts
    )


def _candidates(kept: Sequence[Pattern]) -> Iterator[str]:
    prefixes = sorted((pattern.value for pattern in kept if isinstance(pattern, Prefix)), key=len)
    suffixes = sorted((pattern.value for pattern in kept if isinstance(pattern, Suffix)), key=len)
    middle = "".join(pattern.value for pattern in kept if isinstance(pattern, Contains))
    head = prefixes[-1] if prefixes else ""
    tail = suffixes[-1] if suffixes else ""
    yield head + middle + tail
    yield head + _FILLER + middle + _FILLER + tail
    yield from (_glob_text(pattern.parts) for pattern in kept if isinstance(pattern, Glob))
    yield _FILLER


def quick_witness(literals: Sequence[Literal]) -> str | Undecided | None:
    def fits(text: str) -> bool:
        folded = not any("A" <= character <= "Z" for character in text)
        return folded and all(
            pattern_matches(pattern, text) is holds for pattern, holds in literals
        )

    kept = [pattern for pattern, holds in literals if holds]
    dropped = [pattern for pattern, holds in literals if not holds]
    exact = next((pattern.value for pattern in kept if isinstance(pattern, Equals)), None)
    if exact is not None:
        return exact if fits(exact) else None
    if any(_subsumed(pattern, other) for pattern in kept for other in dropped):
        return None
    return next((text for text in _candidates(kept) if fits(text)), UNDECIDED)


def _named(item: Encoded) -> Iterable[str]:
    return (name for name in fields(item.node) if name != EVENT_ID_KEY or item.event_id is None)


class Search:
    def __init__(self, timeout_ms: int) -> None:
        self._timeout_ms = timeout_ms
        self._context = z3.Context()
        self._languages = Languages(self._context)
        self._atoms: dict[Atom, Formula] = {}
        self._witnesses: dict[frozenset[Literal], str | None] = {}
        self._theory = z3.Solver(ctx=self._context)
        self._value = z3.String("value", self._context)

    def solver(self) -> Any:
        solver = z3.Solver(ctx=self._context)
        solver.set("core.minimize", True)
        return solver

    def _atom(self, atom: Atom) -> Formula:
        if atom not in self._atoms:
            check_pattern(atom.pattern)
            self._atoms[atom] = z3.Bool(f"atom:{len(self._atoms)}", self._context)
        return self._atoms[atom]

    def _skeleton(self, node: Node, event_id: int | None) -> Formula:
        match node:
            case Match(field=name, pattern=pattern):
                fixed = _constant(name, pattern, event_id)
                if fixed is not None:
                    return z3.BoolVal(fixed, self._context)
                return self._atom(Atom(name, pattern))
            case Not(arg=arg):
                return z3.Not(self._skeleton(arg, event_id))
            case And(args=args):
                parts = [self._skeleton(arg, event_id) for arg in args]
                return z3.And(parts) if parts else z3.BoolVal(True, self._context)
            case Or(args=args):
                parts = [self._skeleton(arg, event_id) for arg in args]
                return z3.Or(parts) if parts else z3.BoolVal(False, self._context)
            case Unsupported(reason=reason):
                raise ValueError(f"cannot encode an unsupported construct: {reason}")

    def encode(self, node: Node, event_id: int | None = None) -> Encoded:
        return Encoded(self._skeleton(node, event_id), node, event_id)

    @staticmethod
    def _remaining(deadline: float) -> int:
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise GaveUp("timeout")
        return remaining

    def _witness(self, literals: frozenset[Literal], deadline: float) -> str | None:
        ordered = sorted(literals, key=lambda literal: (repr(literal[0]), literal[1]))
        quick = quick_witness(ordered)
        if quick is not UNDECIDED:
            return quick
        if literals not in self._witnesses:
            self._theory.push()
            try:
                self._theory.set("timeout", self._remaining(deadline))
                regex = z3.Intersect(self._languages.language(ordered), self._languages.folded)
                self._theory.add(z3.InRe(self._value, regex))
                result = self._theory.check()
                if result == z3.unknown:
                    raise GaveUp(self._theory.reason_unknown())
                found = read(self._theory.model()[self._value]) if result == z3.sat else None
            finally:
                self._theory.pop()
            self._witnesses[literals] = found
        return self._witnesses[literals]

    def _literals(self, model: Any, items: Sequence[Encoded]) -> dict[str, list[Literal]]:
        cache: dict[Atom, bool] = {}

        def truth(atom: Atom) -> bool:
            if atom not in cache:
                cache[atom] = bool(z3.is_true(model.eval(self._atoms[atom], True)))
            return cache[atom]

        found: dict[Atom, bool] = {}
        for item in items:
            _justify(item.node, True, item.event_id, truth, found)
        by_field: dict[str, list[Literal]] = {}
        for atom in sorted(found, key=lambda key: str(self._atoms[key])):
            by_field.setdefault(atom.field, []).append((atom.pattern, found[atom]))
        return by_field

    def _lemma(self, name: str, literals: list[Literal], deadline: float) -> Formula:
        core = minimal(literals, lambda part: self._witness(frozenset(part), deadline) is None)
        atoms = ((self._atoms[Atom(name, pattern)], holds) for pattern, holds in core)
        return z3.Or([z3.Not(atom) if holds else atom for atom, holds in atoms])

    @assumes(Semantic.NAMED_FIELDS)
    def _round(self, model: Any, items: Sequence[Encoded], deadline: float) -> Formula | Values:
        values = {name: "" for item in items for name in _named(item)}
        for name, literals in self._literals(model, items).items():
            found = self._witness(frozenset(literals), deadline)
            if found is None:
                return self._lemma(name, literals, deadline)
            values[name] = found
        return tuple(sorted(values.items()))

    def check(
        self, solver: Any, added: Sequence[Encoded], asserted: Sequence[Encoded] = ()
    ) -> Outcome:
        deadline = time.monotonic() + self._timeout_ms / 1000
        items = [*added, *asserted]
        solver.push()
        try:
            solver.add(*(item.formula for item in added))
            for _ in range(MAX_ROUNDS):
                solver.set("timeout", self._remaining(deadline))
                result = solver.check()
                if result == z3.unsat:
                    return Outcome(result, core=tuple(str(label) for label in solver.unsat_core()))
                if result != z3.sat:
                    return Outcome(result, why_unknown=solver.reason_unknown())
                found = self._round(solver.model(), items, deadline)
                if isinstance(found, tuple):
                    return Outcome(result, values=found)
                solver.add(found)
            return Outcome(z3.unknown, why_unknown="too many rounds")
        except GaveUp as error:
            return Outcome(z3.unknown, why_unknown=str(error))
        finally:
            solver.pop()
