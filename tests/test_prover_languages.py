import z3
from hypothesis import assume, given
from hypothesis import strategies as st
from strategies import literals, patterns

from sigma_blindspot.prover.languages import Languages, Literal
from sigma_blindspot.prover.search import UNDECIDED, quick_witness
from sigma_blindspot.prover.strings import lit
from sigma_blindspot.sigma.evaluate import pattern_matches

literal_sets = st.lists(st.tuples(patterns, st.booleans()), max_size=4)


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
