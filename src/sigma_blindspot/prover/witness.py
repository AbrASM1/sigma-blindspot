from collections import deque
from collections.abc import Callable, Iterable, Sequence
from functools import lru_cache
from itertools import chain, count
from typing import Final

from sigma_blindspot.prover.languages import Literal
from sigma_blindspot.sigma.evaluate import pattern_matches
from sigma_blindspot.sigma.ir import Contains, Equals, Prefix, Suffix

MAX_REQUIRED: Final = 12
_FILLERS: Final = "x-_0~!#$%&+=@^q"
_ESCAPED: Final = -1

type State = tuple[int, int, int]


class _Automaton:
    def __init__(self, words: Sequence[str]) -> None:
        self._goto: list[dict[str, int]] = [{}]
        self._fail = [0]
        ends: list[set[int]] = [set()]
        for index, word in enumerate(words):
            node = 0
            for character in word:
                if character not in self._goto[node]:
                    self._goto[node][character] = len(self._goto)
                    self._goto.append({})
                    self._fail.append(0)
                    ends.append(set())
                node = self._goto[node][character]
            ends[node].add(index)
        for child in self._goto[0].values():
            ends[child] |= ends[0]
        queue = deque(self._goto[0].values())
        while queue:
            node = queue.popleft()
            for character, child in self._goto[node].items():
                queue.append(child)
                fallback = self._fail[node]
                while fallback and character not in self._goto[fallback]:
                    fallback = self._fail[fallback]
                self._fail[child] = self._goto[fallback].get(character, 0)
                ends[child] |= ends[self._fail[child]]
        self.ends = [frozenset(found) for found in ends]

    def step(self, node: int, character: str) -> int:
        while node and character not in self._goto[node]:
            node = self._fail[node]
        return self._goto[node].get(character, 0)


class _Trie:
    def __init__(self) -> None:
        self._children: list[dict[str, int]] = [{}]

    def add(self, word: str) -> int:
        node = 0
        for character in word:
            if character not in self._children[node]:
                self._children[node][character] = len(self._children)
                self._children.append({})
            node = self._children[node][character]
        return node

    def step(self, node: int, character: str) -> int:
        return _ESCAPED if node == _ESCAPED else self._children[node].get(character, _ESCAPED)


def applies(literals: Iterable[Literal]) -> bool:
    patterns = [pattern for pattern, _ in literals]
    required = sum(1 for pattern in patterns if isinstance(pattern, Contains))
    simple = all(isinstance(pattern, Equals | Prefix | Suffix | Contains) for pattern in patterns)
    return simple and required <= MAX_REQUIRED


def _folded(text: str) -> bool:
    return not any("A" <= character <= "Z" for character in text)


def _longest(values: Iterable[str], fits: Callable[[str, str], bool]) -> str | None:
    ordered = sorted(values, key=len)
    longest = ordered[-1] if ordered else ""
    return longest if all(fits(longest, value) for value in ordered) else None


def _filler(used: set[str]) -> str:
    candidates = chain(_FILLERS, map(chr, count(0x100)))
    return next(
        character for character in candidates if character not in used and _folded(character)
    )


def exact_witness(literals: Sequence[Literal]) -> str | None:
    kept = [pattern for pattern, holds in literals if holds]
    dropped = [pattern for pattern, holds in literals if not holds]
    if any(isinstance(p, Prefix | Suffix | Contains) and p.value == "" for p in dropped):
        return None
    exact = {pattern.value for pattern in kept if isinstance(pattern, Equals)}
    if exact:
        value = min(exact)
        valid = len(exact) == 1 and _folded(value)
        return value if valid and all(pattern_matches(p, value) is h for p, h in literals) else None
    head = _longest((p.value for p in kept if isinstance(p, Prefix)), str.startswith)
    tail = _longest((p.value for p in kept if isinstance(p, Suffix)), str.endswith)
    if head is None or tail is None:
        return None
    required = sorted({p.value for p in kept if isinstance(p, Contains)} - {""})
    forbidden = sorted({p.value for p in dropped if isinstance(p, Contains)})
    endings = sorted({p.value for p in dropped if isinstance(p, Suffix)})
    words = [*required, *forbidden, *endings, tail]
    automaton = _Automaton(words)
    forbidden_ids = frozenset(range(len(required), len(required) + len(forbidden)))
    ending_ids = frozenset(range(len(required) + len(forbidden), len(words) - 1))
    tail_id = len(words) - 1
    trie = _Trie()
    starts = {trie.add(p.value) for p in dropped if isinstance(p, Prefix)}
    equals = {trie.add(p.value) for p in dropped if isinstance(p, Equals)}
    used = {character for word in (*words, head) for character in word}
    used |= {character for p in dropped if isinstance(p, Prefix | Equals) for character in p.value}
    alphabet = [
        *sorted({character for word in (*words, head) for character in word}),
        _filler(used),
    ]
    full = (1 << len(required)) - 1

    def advance(state: State, character: str) -> State | None:
        node, mask, position = state
        node = automaton.step(node, character)
        found = automaton.ends[node]
        position = trie.step(position, character)
        if found & forbidden_ids or position in starts:
            return None
        for index in found:
            if index < len(required):
                mask |= 1 << index
        return node, mask, position

    def accepts(state: State) -> bool:
        node, mask, position = state
        found = automaton.ends[node]
        return (
            mask == full and tail_id in found and not found & ending_ids and position not in equals
        )

    start: State | None = (0, 0, 0)
    if 0 in starts:
        return None
    for character in head:
        start = None if start is None else advance(start, character)
    if start is None:
        return None
    parents: dict[State, tuple[State, str] | None] = {start: None}
    queue = deque([start])
    while queue:
        state = queue.popleft()
        if accepts(state):
            return head + _path(parents, state)
        for character in alphabet:
            following = advance(state, character)
            if following is not None and following not in parents:
                parents[following] = (state, character)
                queue.append(following)
    return None


@lru_cache(maxsize=1 << 16)
def shared_witness(literals: frozenset[Literal]) -> str | None:
    return exact_witness(sorted(literals, key=repr))


def _path(parents: dict[State, tuple[State, str] | None], state: State) -> str:
    characters: list[str] = []
    link = parents[state]
    while link is not None:
        state, character = link
        characters.append(character)
        link = parents[state]
    return "".join(reversed(characters))
