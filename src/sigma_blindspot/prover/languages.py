from collections.abc import Iterable
from typing import Any

import z3

from sigma_blindspot.prover.strings import MAX_CHAR, check_representable, lit
from sigma_blindspot.sigma.ir import (
    Contains,
    Equals,
    Glob,
    LessThan,
    MoreThan,
    Pattern,
    Prefix,
    Suffix,
    Wildcard,
)

type Regex = Any
type Literal = tuple[Pattern, bool]


def check_pattern(pattern: Pattern) -> None:
    match pattern:
        case Glob(parts=parts):
            for part in parts:
                if isinstance(part, str):
                    check_representable(part)
        case LessThan(value=value):
            check_representable(value[:-1])
            if value and ord(value[-1]) > 0:
                check_representable(chr(ord(value[-1]) - 1))
        case _:
            check_representable(pattern.value)


class Languages:
    def __init__(self, context: Any) -> None:
        self._context = context
        self._sort = z3.ReSort(z3.StringSort(context))
        self._anything = z3.Full(self._sort)
        self._one = z3.AllChar(self._sort)
        self.folded = z3.Star(
            z3.Intersect(self._one, z3.Complement(self._characters(ord("A"), ord("Z"))))
        )

    def _text(self, value: str) -> Regex:
        return z3.Re(lit(value, self._context))

    def _union(self, regexes: list[Regex]) -> Regex:
        return z3.Union(*regexes) if regexes else z3.Empty(self._sort)

    def _characters(self, low: int, high: int) -> Regex:
        return z3.Range(lit(chr(low), self._context), lit(chr(high), self._context))

    @staticmethod
    def _concat(*regexes: Regex) -> Regex:
        return regexes[0] if len(regexes) == 1 else z3.Concat(*regexes)

    def _less_than(self, value: str) -> Regex:
        prefixes = [self._text(value[:index]) for index in range(len(value))]
        smaller = [
            self._concat(
                self._text(value[:index]), self._characters(0, ord(character) - 1), self._anything
            )
            for index, character in enumerate(value)
            if ord(character) > 0
        ]
        return self._union([*prefixes, *smaller])

    def _more_than(self, value: str) -> Regex:
        larger = [
            self._concat(
                self._text(value[:index]),
                self._characters(ord(character) + 1, MAX_CHAR),
                self._anything,
            )
            for index, character in enumerate(value)
            if ord(character) < MAX_CHAR
        ]
        longer = self._concat(self._text(value), self._one, self._anything)
        return self._union([longer, *larger])

    def _glob_part(self, part: str | Wildcard) -> Regex:
        if part is Wildcard.ANY:
            return self._anything
        if part is Wildcard.ONE:
            return self._one
        return self._text(part)

    def _glob(self, parts: tuple[str | Wildcard, ...]) -> Regex:
        return self._concat(*([self._glob_part(part) for part in parts] or [self._text("")]))

    def _shaped(self, kind: type, texts: list[Regex]) -> Regex:
        if kind is Prefix:
            return self._concat(self._union(texts), self._anything)
        if kind is Suffix:
            return self._concat(self._anything, self._union(texts))
        if kind is Contains:
            return self._concat(self._anything, self._union(texts), self._anything)
        return self._union(texts)

    def any_of(self, patterns: Iterable[Pattern]) -> Regex:
        shapes: dict[type, list[Regex]] = {}
        others: list[Regex] = []
        for pattern in patterns:
            match pattern:
                case Equals(value=value) | Prefix(value=value) | Suffix(value=value):
                    shapes.setdefault(type(pattern), []).append(self._text(value))
                case Contains(value=value):
                    shapes.setdefault(Contains, []).append(self._text(value))
                case Glob(parts=parts):
                    others.append(self._glob(parts))
                case LessThan(value=value):
                    others.append(self._less_than(value))
                case MoreThan(value=value):
                    others.append(self._more_than(value))
        shaped = [self._shaped(kind, texts) for kind, texts in shapes.items()]
        return self._union([*shaped, *others])

    def language(self, literals: Iterable[Literal]) -> Regex:
        kept = [pattern for pattern, holds in literals if holds]
        dropped = [pattern for pattern, holds in literals if not holds]
        parts = [self.any_of((pattern,)) for pattern in kept]
        if dropped:
            parts.append(z3.Complement(self.any_of(dropped)))
        return z3.Intersect(*parts) if parts else self._anything
