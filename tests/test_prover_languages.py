import pytest
import z3
from hypothesis import assume, given
from hypothesis import strategies as st
from strategies import literals, patterns

from sigma_blindspot.prover.languages import Languages, Literal, check_pattern
from sigma_blindspot.prover.search import UNDECIDED, quick_witness
from sigma_blindspot.prover.strings import MAX_CHAR, Unrepresentable, lit
from sigma_blindspot.sigma.evaluate import pattern_matches
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

literal_sets = st.lists(st.tuples(patterns, st.booleans()), max_size=4)
edge_texts = st.text(
    alphabet=["\x00", "a", chr(MAX_CHAR), chr(MAX_CHAR + 1), chr(MAX_CHAR + 2), chr(0x10FFFF)],
    max_size=3,
)
edge_patterns: st.SearchStrategy[Pattern] = st.one_of(
    *(st.builds(kind, edge_texts) for kind in (Equals, Prefix, Suffix, Contains)),
    st.builds(LessThan, edge_texts),
    st.builds(MoreThan, edge_texts),
    st.builds(
        Glob,
        st.lists(edge_texts.filter(bool) | st.sampled_from(Wildcard), max_size=3).map(tuple),
    ),
)


def regex_error(pattern: Pattern) -> str | None:
    try:
        Languages(z3.Context()).any_of((pattern,))
    except Unrepresentable as error:
        return str(error)
    return None


@given(pattern=edge_patterns)
def test_the_representability_check_agrees_with_building_the_regex(pattern: Pattern) -> None:
    expected = regex_error(pattern)
    if expected is None:
        check_pattern(pattern)
    else:
        with pytest.raises(Unrepresentable) as raised:
            check_pattern(pattern)
        assert str(raised.value) == expected


def holds(literals: list[Literal], value: str) -> bool:
    return all(pattern_matches(pattern, value) is wanted for pattern, wanted in literals)


@given(chosen=literal_sets, value=literals)
def test_languages_agree_with_the_evaluator(chosen: list[Literal], value: str) -> None:
    context = z3.Context()
    solver = z3.Solver(ctx=context)
    solver.add(z3.InRe(lit(value, context), Languages(context).language(chosen)))
    assert (solver.check() == z3.sat) is holds(chosen, value)


@given(chosen=literal_sets)
def test_quick_decisions_agree_with_z3(chosen: list[Literal]) -> None:
    decided = quick_witness(chosen)
    assume(decided is not UNDECIDED)
    context = z3.Context()
    languages = Languages(context)
    solver = z3.Solver(ctx=context)
    value = z3.String("value", context)
    solver.add(z3.InRe(value, z3.Intersect(languages.language(chosen), languages.folded)))
    if decided is None:
        assert solver.check() == z3.unsat
    else:
        assert isinstance(decided, str) and holds(chosen, decided)
        assert not any("A" <= character <= "Z" for character in decided)
